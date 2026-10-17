"""Generate a small synthetic PCAP used for the demo and the tests.

The capture is entirely fabricated in memory so the repository never ships real traffic. It contains a
handful of ordinary OT conversations (SCADA polling a PLC, an IEC 104 link, an EtherNet/IP device) plus
a few deliberately insecure services (Telnet, SNMP with a default community, MQTT without TLS) so the
analyser has something to report. It is a teaching fixture, not an attack tool: nothing here is tuned to
evade a device or to be replayed on a live network.
"""
from __future__ import annotations

import struct

from .pcap import write_pcap


def _mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def _ip(s):
    return bytes(int(x) for x in s.split("."))


def _ipv4(src, dst, proto, l4):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0x4000, 64, proto, 0, _ip(src), _ip(dst))
    return h + l4


def _eth(dst, src, etype, payload):
    f = _mac(dst) + _mac(src) + struct.pack("!H", etype) + payload
    return f + b"\0" * max(0, 60 - len(f))


def _tcp(sp, dp, payload=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 1000, 1, 5 << 4, 0x18, 8192, 0, 0) + payload


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def _tcp_frame(src, dst, sp, dp, payload):
    (sip, smac), (dip, dmac) = src, dst
    return _eth(dmac, smac, 0x0800, _ipv4(sip, dip, 6, _tcp(sp, dp, payload)))


def _udp_frame(src, dst, sp, dp, payload):
    (sip, smac), (dip, dmac) = src, dst
    return _eth(dmac, smac, 0x0800, _ipv4(sip, dip, 17, _udp(sp, dp, payload)))


def _ber(tag, value):
    return bytes([tag, len(value)]) + value


# hosts: (ip, mac)
SCADA = ("10.10.10.10", "00:1b:1b:10:00:10")
PLC = ("10.10.20.11", "00:80:f4:20:00:11")
RTU = ("10.10.20.21", "00:a0:45:20:00:21")
DRIVE = ("10.10.20.41", "00:00:bc:20:00:41")
GW = ("10.10.40.5", "00:1b:1b:40:00:05")
BROKER = ("10.10.40.6", "02:00:00:40:00:06")
SW = ("10.10.1.2", "00:80:63:01:00:02")
NMS = ("10.10.10.30", "00:1b:1b:10:00:30")


def _modbus(tid, unit, pdu):
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def _iec104_i(type_id, cot, ca, ioa, value, ns=0, nr=0):
    asdu = bytes([type_id, 1, cot, 0]) + struct.pack("<H", ca) + ioa.to_bytes(3, "little") + value
    return bytes([0x68, 4 + len(asdu)]) + struct.pack("<HH", ns << 1, nr << 1) + asdu


def _iec104_u(code):
    return bytes([0x68, 4, code, 0, 0, 0])


def _snmp_get(community):
    oid = b"\x2b\x06\x01\x02\x01\x01\x05\x00"
    vb = _ber(0x30, _ber(0x30, _ber(0x06, oid) + b"\x05\x00"))
    pdu = _ber(0xA0, _ber(0x02, b"\x4d") + _ber(0x02, b"\0") + _ber(0x02, b"\0") + vb)
    return _ber(0x30, _ber(0x02, b"\0") + _ber(0x04, community.encode()) + pdu)


def _mqtt_connect(user, pw):
    vh = struct.pack("!H", 4) + b"MQTT" + bytes([4, 0xC2]) + struct.pack("!H", 60)
    body = vh + struct.pack("!H", 6) + b"gw-001" + struct.pack("!H", len(user)) + user.encode() \
        + struct.pack("!H", len(pw)) + pw.encode()
    return bytes([0x10, len(body)]) + body


def _enip(cmd):
    return struct.pack("<HHIIQI", cmd, 0, 0, 0, 0, 0)


def _lldp(mac, port, name):
    def tlv(t, v):
        return struct.pack("!H", (t << 9) | len(v)) + v
    return tlv(1, b"\x04" + _mac(mac)) + tlv(2, b"\x05" + port.encode()) + tlv(3, b"\x00\x78") \
        + tlv(5, name.encode()) + tlv(0, b"")


def build(path):
    frames = []
    t = [1_700_000_000.0]

    def add(frame, dt=0.02):
        t[0] += dt
        frames.append((t[0], frame))

    # switch advertises itself over LLDP
    add(_eth("01:80:c2:00:00:0e", SW[1], 0x88CC, _lldp(SW[1], "1/1", "SUB-A-SW01")))

    # SCADA polls the PLC with Read Holding Registers (FC3) — normal
    for i in range(12):
        add(_tcp_frame(SCADA, PLC, 49152, 502, _modbus(i, 1, b"\x03\x00\x00\x00\x0a")))
        add(_tcp_frame(PLC, SCADA, 502, 49152, _modbus(i, 1, b"\x03\x14" + b"\x00" * 20)))

    # SCADA writes a setpoint (FC16) — a normal control action, but worth logging
    add(_tcp_frame(SCADA, PLC, 49152, 502, _modbus(99, 1, b"\x10\x00\x10\x00\x01\x02\x00\x64")))

    # IEC 104 link to the RTU: STARTDT, interrogation, a measurement, then a single command
    add(_tcp_frame(SCADA, RTU, 49200, 2404, _iec104_u(0x07)))         # STARTDT act
    add(_tcp_frame(RTU, SCADA, 2404, 49200, _iec104_u(0x0B)))         # STARTDT con
    add(_tcp_frame(SCADA, RTU, 49200, 2404, _iec104_i(100, 6, 1, 0, b"\x14")))   # C_IC interrogation
    add(_tcp_frame(RTU, SCADA, 2404, 49200, _iec104_i(13, 20, 1, 100, b"\x00\x00\x80\x3f\x00")))  # M_ME_NC float
    add(_tcp_frame(SCADA, RTU, 49200, 2404, _iec104_i(45, 6, 1, 500, b"\x01")))  # C_SC single command

    # EtherNet/IP device discovery + explicit session
    add(_udp_frame(SCADA, DRIVE, 55000, 44818, _enip(0x0063)))       # ListIdentity
    add(_tcp_frame(SCADA, DRIVE, 49300, 44818, _enip(0x0065)))       # RegisterSession

    # ---- the insecure-service samples the analyser should flag ----
    # Telnet to the switch (clear-text management)
    add(_tcp_frame(SCADA, SW, 49400, 23, b"\xff\xfb\x01login: "))
    # SNMP read with a default community string
    add(_udp_frame(NMS, SW, 44000, 161, _snmp_get("public")))
    # MQTT CONNECT over plain 1883 carrying username/password
    add(_tcp_frame(GW, BROKER, 49500, 1883, _mqtt_connect("plantuser", "plant123")))

    write_pcap(path, frames)
    return len(frames)
