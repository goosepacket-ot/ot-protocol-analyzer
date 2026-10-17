"""Protocol dissectors for industrial and infrastructure protocols.

Every dissector returns a list of Event objects. An event says which protocol was seen, which side is
the client/master and which is the server/outstation, what operation was performed and whether that
operation is security-relevant. Dissectors are deliberately tolerant: malformed or truncated payloads
produce a generic event instead of an exception.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .pcap import Packet, mac_str


@dataclass
class Event:
    proto: str
    op: str                      # read | write | control | diag | discovery | session | data | mgmt
    summary: str
    client: Optional[str] = None  # node key that initiates (master / client / publisher)
    server: Optional[str] = None  # node key that answers (slave / server / outstation)
    client_role: str = ""
    server_role: str = ""
    severity: str = ""            # '', info, low, medium, high — set when the operation itself is noteworthy
    finding: str = ""             # short finding title when severity is set
    detail: dict = field(default_factory=dict)


def node(pkt: Packet, side: str) -> str:
    """Node key: IP if present, otherwise MAC."""
    if side == "src":
        return pkt.src_ip or pkt.src_mac
    return pkt.dst_ip or pkt.dst_mac


# ------------------------------------------------------------------------------------------- Modbus/TCP
MODBUS_FC = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers",
             5: "Write Single Coil", 6: "Write Single Register", 7: "Read Exception Status", 8: "Diagnostics",
             11: "Get Comm Event Counter", 15: "Write Multiple Coils", 16: "Write Multiple Registers",
             17: "Report Server ID", 20: "Read File Record", 21: "Write File Record", 22: "Mask Write Register",
             23: "Read/Write Multiple Registers", 43: "Encapsulated Interface (Read Device ID)"}
MODBUS_WRITE = {5, 6, 15, 16, 21, 22, 23}


def modbus(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    out = []
    to_server = pkt.dport == 502
    i = 0
    while i + 8 <= len(pl):  # several ADUs may share one segment
        tid, pid, length, unit = struct.unpack("!HHHB", pl[i:i + 7])
        if pid != 0 or length < 2:
            break
        fc = pl[i + 7]
        base = fc & 0x7F
        name = MODBUS_FC.get(base, f"FC {base}")
        cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
        ev = Event("Modbus/TCP", "read", f"{name} (unit {unit})", cli, srv, "Modbus client (master)", "Modbus server (PLC/RTU/device)",
                   detail={"fc": base, "unit": unit, "direction": "request" if to_server else "response"})
        if fc & 0x80:
            code = pl[i + 8] if i + 8 < len(pl) else None
            ev.op, ev.summary = "data", f"Exception response to {name} (code {code})"
        elif to_server and base in MODBUS_WRITE:
            ev.op, ev.severity, ev.finding = "write", "medium", "Modbus write operation"
        elif to_server and base == 8:
            sub = struct.unpack("!H", pl[i + 8:i + 10])[0] if i + 10 <= len(pl) else None
            ev.op = "diag"
            ev.detail["subfunction"] = sub
            if sub in (1, 4):  # restart communications / force listen-only mode
                ev.severity, ev.finding = "high", "Modbus diagnostic: restart / listen-only mode"
                ev.summary = f"Diagnostics sub-function {sub} ({'Restart Communications' if sub == 1 else 'Force Listen Only Mode'})"
            else:
                ev.severity, ev.finding = "low", "Modbus diagnostics function used"
        elif to_server and base in (43, 17):
            ev.op, ev.severity, ev.finding = "discovery", "low", "Modbus device identification (reconnaissance indicator)"
        out.append(ev)
        i += 6 + length
    return out


# ------------------------------------------------------------------------------------------- DNP3
DNP3_FC = {0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate", 5: "Direct Operate",
           6: "Direct Operate No Ack", 7: "Immediate Freeze", 9: "Freeze and Clear", 13: "Cold Restart",
           14: "Warm Restart", 16: "Initialize Application", 17: "Start Application", 18: "Stop Application",
           20: "Enable Unsolicited", 21: "Disable Unsolicited", 23: "Delay Measurement", 24: "Record Current Time",
           129: "Response", 130: "Unsolicited Response"}


def dnp3(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    if len(pl) < 10 or pl[0:2] != b"\x05\x64":
        return []
    ctrl = pl[3]
    dst, src = struct.unpack("<HH", pl[4:8])
    dir_master = bool(ctrl & 0x80)  # DIR bit: 1 = from master
    fc = pl[12] if len(pl) > 12 else None
    name = DNP3_FC.get(fc, f"FC {fc}") if fc is not None else "link-layer only"
    if dir_master:
        cli, srv = node(pkt, "src"), node(pkt, "dst")
    else:
        cli, srv = node(pkt, "dst"), node(pkt, "src")
    ev = Event("DNP3", "data", f"{name} (link {src}→{dst})", cli, srv, "DNP3 master", "DNP3 outstation (RTU/IED)",
               detail={"fc": fc, "link_src": src, "link_dst": dst})
    if fc in (1,):
        ev.op = "read"
    elif fc in (2, 3, 4, 5, 6):
        ev.op = "control"
        ev.severity, ev.finding = ("medium", "DNP3 control without select-before-operate") if fc in (5, 6) else ("low", "DNP3 control / write operation")
    elif fc in (13, 14, 18):
        ev.op, ev.severity, ev.finding = "control", "high", f"DNP3 {name} command"
    elif fc == 21:
        ev.op, ev.severity, ev.finding = "control", "medium", "DNP3 unsolicited reporting disabled"
    elif fc in (23, 24):
        ev.op = "mgmt"
    return [ev]


# ------------------------------------------------------------------------------------------- IEC 60870-5-104
IEC104_TYPES = {1: "M_SP_NA_1 single point", 3: "M_DP_NA_1 double point", 9: "M_ME_NA_1 normalised value",
                11: "M_ME_NB_1 scaled value", 13: "M_ME_NC_1 short float", 30: "M_SP_TB_1 single point+time",
                31: "M_DP_TB_1 double point+time", 36: "M_ME_TF_1 float+time", 45: "C_SC_NA_1 single command",
                46: "C_DC_NA_1 double command", 47: "C_RC_NA_1 regulating step", 48: "C_SE_NA_1 set-point normalised",
                49: "C_SE_NB_1 set-point scaled", 50: "C_SE_NC_1 set-point float", 58: "C_SC_TA_1 single command+time",
                59: "C_DC_TA_1 double command+time", 100: "C_IC_NA_1 interrogation", 101: "C_CI_NA_1 counter interrogation",
                102: "C_RD_NA_1 read", 103: "C_CS_NA_1 clock sync", 105: "C_RP_NA_1 reset process", 107: "C_TS_TA_1 test+time"}
IEC104_U = {0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act", 0x23: "STOPDT con", 0x43: "TESTFR act", 0x83: "TESTFR con"}
IEC104_CMD = set(range(45, 52)) | set(range(58, 65))


def iec104(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    out = []
    i = 0
    to_server = pkt.dport == 2404
    cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
    while i + 6 <= len(pl) and pl[i] == 0x68:
        ln = pl[i + 1]
        cf1 = pl[i + 2]
        roles = ("IEC 104 controlling station (SCADA)", "IEC 104 controlled station (RTU/gateway)")
        if cf1 & 0x01 == 0 and i + 12 <= len(pl):  # I-format
            tid, vsq, cot = pl[i + 6], pl[i + 7], pl[i + 8] & 0x3F
            ca = struct.unpack("<H", pl[i + 10:i + 12])[0]
            tname = IEC104_TYPES.get(tid, f"type {tid}")
            ev = Event("IEC 60870-5-104", "data", f"I-frame {tname}, COT {cot}, CA {ca}", cli, srv, *roles,
                       detail={"type": tid, "cot": cot, "ca": ca})
            if tid in IEC104_CMD:
                ev.op, ev.severity, ev.finding = "control", "medium", "IEC 104 control command"
            elif tid == 105:
                ev.op, ev.severity, ev.finding = "control", "high", "IEC 104 reset process command"
            elif tid == 103:
                ev.op, ev.severity, ev.finding = "mgmt", "low", "IEC 104 clock synchronisation over the network"
            elif tid in (100, 101, 102):
                ev.op = "read"
            out.append(ev)
        elif cf1 & 0x03 == 0x03:
            out.append(Event("IEC 60870-5-104", "session", IEC104_U.get(cf1, f"U-frame 0x{cf1:02x}"), cli, srv, *roles))
        else:
            out.append(Event("IEC 60870-5-104", "session", "S-frame (acknowledge)", cli, srv, *roles))
        i += 2 + ln
    return out


# ------------------------------------------------------------------------------------------- ISO-on-TCP (S7comm / MMS)
S7_FUNC = {0x04: "Read Var", 0x05: "Write Var", 0x1A: "Request Download", 0x1B: "Download Block", 0x1C: "Download Ended",
           0x1D: "Start Upload", 0x1E: "Upload", 0x1F: "End Upload", 0x28: "PI Service (e.g. start)", 0x29: "PLC Stop",
           0xF0: "Setup Communication"}


def iso_tcp(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    if len(pl) < 7 or pl[0] != 0x03:
        return []
    to_server = pkt.dport == 102
    cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
    cotp_len = pl[4]
    cotp_type = pl[5] & 0xF0
    s7 = 5 + cotp_len  # TPKT(4) + length byte + COTP header
    if cotp_type == 0xE0:
        return [Event("ISO-on-TCP (TPKT/COTP)", "session", "COTP connection request", cli, srv, "client", "server (PLC / IED)")]
    if cotp_type == 0xF0 and len(pl) > s7 and pl[s7] == 0x32:
        rosctr = pl[s7 + 1]
        hdr = 10 if rosctr in (1, 7) else 12
        func = pl[s7 + hdr] if len(pl) > s7 + hdr else None
        name = S7_FUNC.get(func, f"function 0x{func:02x}" if func is not None else "unknown")
        ev = Event("S7comm", "data", f"S7 {name} (ROSCTR {rosctr})", cli, srv, "S7 client (engineering / HMI)", "Siemens S7 PLC",
                   detail={"function": func, "rosctr": rosctr})
        if rosctr == 1:
            if func == 0x04:
                ev.op = "read"
            elif func == 0x05:
                ev.op, ev.severity, ev.finding = "write", "medium", "S7 write variable"
            elif func == 0x29:
                ev.op, ev.severity, ev.finding = "control", "high", "S7 PLC STOP command"
            elif func == 0x28:
                ev.op, ev.severity, ev.finding = "control", "high", "S7 PI service (start / program control)"
            elif func in (0x1A, 0x1B, 0x1C):
                ev.op, ev.severity, ev.finding = "control", "high", "S7 program download to PLC"
            elif func in (0x1D, 0x1E, 0x1F):
                ev.op, ev.severity, ev.finding = "read", "medium", "S7 program upload from PLC"
            elif func == 0xF0:
                ev.op = "session"
        return [ev]
    if cotp_type == 0xF0:
        return [Event("IEC 61850 MMS / ISO-on-TCP", "data", "ISO session data (MMS or other ISO application)", cli, srv,
                      "MMS client (HMI / gateway)", "MMS server (IED)")]
    return []


# ------------------------------------------------------------------------------------------- EtherNet/IP
ENIP_CMD = {0x0001: "NOP", 0x0004: "ListServices", 0x0063: "ListIdentity", 0x0064: "ListInterfaces",
            0x0065: "RegisterSession", 0x0066: "UnRegisterSession", 0x006F: "SendRRData", 0x0070: "SendUnitData"}


def enip(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    if pkt.dport == 2222 or pkt.sport == 2222:
        return [Event("EtherNet/IP implicit I/O", "data", "CIP Class 1 I/O (UDP 2222)", node(pkt, "src"), node(pkt, "dst"),
                      "producer", "consumer")]
    if len(pl) < 24:
        return []
    cmd = struct.unpack("<H", pl[0:2])[0]
    to_server = pkt.dport == 44818
    cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
    name = ENIP_CMD.get(cmd, f"command 0x{cmd:04x}")
    ev = Event("EtherNet/IP", "data", f"Encapsulation {name}", cli, srv, "EtherNet/IP scanner / client", "EtherNet/IP adapter (PLC / device)",
               detail={"command": cmd})
    if cmd == 0x0063 and to_server:
        ev.op, ev.severity, ev.finding = "discovery", "low", "EtherNet/IP ListIdentity (device discovery)"
    elif cmd in (0x0065, 0x0066):
        ev.op = "session"
    return [ev]


# ------------------------------------------------------------------------------------------- PROFINET (L2)
def profinet(pkt: Packet) -> list[Event]:
    pl = pkt.l2_payload
    if len(pl) < 2:
        return []
    fid = struct.unpack("!H", pl[0:2])[0]
    src = pkt.src_mac
    dst = pkt.dst_mac
    if 0x8000 <= fid <= 0xBFFF:
        return [Event("PROFINET RT", "data", f"Cyclic RT frame 0x{fid:04x}", src, dst, "IO provider", "IO consumer", detail={"frame_id": fid})]
    if fid in (0xFEFC, 0xFEFD, 0xFEFE, 0xFEFF) and len(pl) >= 4:
        sid, stype = pl[2], pl[3]
        svc = {3: "Get", 4: "Set", 5: "Identify", 6: "Hello"}.get(sid, f"service {sid}")
        resp = bool(stype & 0x01) and sid != 6
        ev = Event("PROFINET DCP", "discovery", f"DCP {svc} {'response' if resp else 'request'}",
                   dst if resp else src, src if resp else dst, "PROFINET controller / engineering", "PROFINET device",
                   detail={"service": svc, "response": resp})
        name = _dcp_station_name(pl[12:]) if len(pl) > 12 else None
        if name:
            ev.detail["name_of_station"] = name
        if sid == 4 and not resp:
            ev.op, ev.severity, ev.finding = "control", "high", "PROFINET DCP Set (can change station name / IP / reset)"
        elif sid == 5 and not resp:
            ev.severity, ev.finding = "info", "PROFINET DCP Identify (network discovery)"
        return [ev]
    if fid in (0xFC01, 0xFE01):
        return [Event("PROFINET Alarm", "data", "Alarm " + ("high" if fid == 0xFC01 else "low"), src, dst, "IO device", "IO controller")]
    return [Event("PROFINET", "data", f"Frame ID 0x{fid:04x}", src, dst)]


def _dcp_station_name(blocks: bytes) -> Optional[str]:
    i = 0
    while i + 4 <= len(blocks):
        opt, sub = blocks[i], blocks[i + 1]
        ln = struct.unpack("!H", blocks[i + 2:i + 4])[0]
        val = blocks[i + 4:i + 4 + ln]
        if opt == 2 and sub == 2 and len(val) > 2:
            return val[2:].decode("ascii", "replace")
        i += 4 + ln + (ln & 1)
    return None


# ------------------------------------------------------------------------------------------- IEC 61850 GOOSE / SV (L2)
def _ber_items(b: bytes):
    i = 0
    while i + 2 <= len(b):
        tag = b[i]
        ln = b[i + 1]
        i += 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(b[i:i + n], "big")
            i += n
        yield tag, b[i:i + ln]
        i += ln


def goose(pkt: Packet) -> list[Event]:
    pl = pkt.l2_payload
    if len(pl) < 10:
        return []
    appid = struct.unpack("!H", pl[0:2])[0]
    pdu = pl[8:]
    info = {"appid": f"0x{appid:04x}"}
    for tag, val in _ber_items(pdu):
        if tag == 0x61:
            for t, v in _ber_items(val):
                if t == 0x80:
                    info["gocbRef"] = v.decode("ascii", "replace")
                elif t == 0x81:
                    info["timeAllowedToLive"] = int.from_bytes(v, "big")
                elif t == 0x82:
                    info["datSet"] = v.decode("ascii", "replace")
                elif t == 0x83:
                    info["goID"] = v.decode("ascii", "replace")
                elif t == 0x85:
                    info["stNum"] = int.from_bytes(v, "big")
                elif t == 0x86:
                    info["sqNum"] = int.from_bytes(v, "big")
                elif t == 0x87:
                    info["simulation"] = bool(v and v[0])
                elif t == 0x88:
                    info["confRev"] = int.from_bytes(v, "big")
    ev = Event("IEC 61850 GOOSE", "data", f"GOOSE {info.get('gocbRef', '?')} stNum {info.get('stNum')} sqNum {info.get('sqNum')}",
               pkt.src_mac, pkt.dst_mac, "GOOSE publisher (IED)", "GOOSE subscribers (multicast)", detail=info)
    if info.get("simulation"):
        ev.severity, ev.finding = "medium", "GOOSE with simulation/test flag set"
    return [ev]


def sv(pkt: Packet) -> list[Event]:
    pl = pkt.l2_payload
    if len(pl) < 10:
        return []
    appid = struct.unpack("!H", pl[0:2])[0]
    info = {"appid": f"0x{appid:04x}"}
    for tag, val in _ber_items(pl[8:]):
        if tag == 0x60:
            for t, v in _ber_items(val):
                if t == 0x80:
                    info["noASDU"] = int.from_bytes(v, "big")
                elif t == 0xA2:
                    for t2, v2 in _ber_items(v):
                        if t2 == 0x30:
                            for t3, v3 in _ber_items(v2):
                                if t3 == 0x80:
                                    info["svID"] = v3.decode("ascii", "replace")
                            break
    return [Event("IEC 61850 Sampled Values", "data", f"SV stream {info.get('svID', '?')}", pkt.src_mac, pkt.dst_mac,
                  "Merging unit", "SV subscribers", detail=info)]


# ------------------------------------------------------------------------------------------- infrastructure / IT protocols
def snmp(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    to_server = pkt.dport == 161
    if pkt.dport == 162 or pkt.sport == 162:
        cli, srv = node(pkt, "dst"), node(pkt, "src")  # trap: agent → manager
    else:
        cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
    try:
        items = list(_ber_items(pl))
        seq = items[0][1]
        parts = list(_ber_items(seq))
        version = int.from_bytes(parts[0][1], "big")
        vname = {0: "v1", 1: "v2c", 3: "v3"}.get(version, f"v{version}")
        ev = Event("SNMP", "mgmt", f"SNMP {vname}", cli, srv, "SNMP manager (NMS)", "SNMP agent (network device)", detail={"version": vname})
        if version in (0, 1):
            community = parts[1][1].decode("ascii", "replace")
            ev.detail["community"] = community
            if community.lower() in ("public", "private", "admin", "manager"):
                ev.severity, ev.finding = "high", f"SNMP {vname} with default community '{community}'"
            else:
                ev.severity, ev.finding = "medium", f"SNMP {vname} (community string sent in clear text)"
        return [ev]
    except Exception:
        return [Event("SNMP", "mgmt", "SNMP (undecoded)", cli, srv)]


CLEARTEXT = {23: ("Telnet", "Telnet management (clear-text credentials)", "high"),
             21: ("FTP", "FTP (clear-text credentials / file transfer)", "medium"),
             80: ("HTTP", "HTTP management interface (unencrypted)", "medium"),
             69: ("TFTP", "TFTP (unauthenticated file transfer, often used for configs/firmware)", "medium")}


def cleartext(pkt: Packet, port: int) -> list[Event]:
    name, finding, sev = CLEARTEXT[port]
    to_server = pkt.dport == port
    cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
    return [Event(name, "mgmt", f"{name} session", cli, srv, f"{name} client", f"{name} server", severity=sev, finding=finding)]


def mqtt(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    to_server = pkt.dport == 1883
    cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
    if not pl:
        return []
    ptype = pl[0] >> 4
    names = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 8: "SUBSCRIBE", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}
    ev = Event("MQTT", "data", f"MQTT {names.get(ptype, ptype)}", cli, srv, "MQTT client", "MQTT broker")
    if ptype == 1:
        ev.op, ev.severity, ev.finding = "session", "medium", "MQTT over plain TCP 1883 (no TLS)"
        try:
            i, mult, rl = 1, 1, 0
            while True:
                b = pl[i]; rl += (b & 0x7F) * mult; mult *= 128; i += 1
                if not b & 0x80:
                    break
            nlen = struct.unpack("!H", pl[i:i + 2])[0]
            flags = pl[i + 2 + nlen + 1]
            if flags & 0x80:
                ev.severity, ev.finding = "high", "MQTT CONNECT with username/password in clear text"
        except Exception:
            pass
    return [ev]


def opcua(pkt: Packet) -> list[Event]:
    pl = pkt.payload
    to_server = pkt.dport == 4840
    cli, srv = (node(pkt, "src"), node(pkt, "dst")) if to_server else (node(pkt, "dst"), node(pkt, "src"))
    mt = pl[:3]
    if mt not in (b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR"):
        return []
    ev = Event("OPC UA", "data", f"OPC UA {mt.decode()}", cli, srv, "OPC UA client", "OPC UA server")
    if mt == b"OPN" and b"SecurityPolicy#None" in pl:
        ev.op, ev.severity, ev.finding = "session", "medium", "OPC UA secure channel with SecurityPolicy None"
    return [ev]


def bacnet(pkt: Packet) -> list[Event]:
    if not pkt.payload or pkt.payload[0] != 0x81:
        return []
    return [Event("BACnet/IP", "data", "BACnet/IP (BVLC)", node(pkt, "src"), node(pkt, "dst"), "BACnet client", "BACnet device")]


def lldp(pkt: Packet) -> dict:
    """Return {'system_name':..., 'port':..., 'chassis':...} for inventory enrichment."""
    pl = pkt.l2_payload
    out = {}
    i = 0
    while i + 2 <= len(pl):
        hdr = struct.unpack("!H", pl[i:i + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        v = pl[i + 2:i + 2 + ln]
        if t == 0:
            break
        if t == 5:
            out["system_name"] = v.decode("utf-8", "replace")
        elif t == 2 and v:
            out["port"] = v[1:].decode("utf-8", "replace")
        elif t == 6:
            out["system_description"] = v.decode("utf-8", "replace")
        elif t == 1 and v and v[0] == 4 and len(v) == 7:
            out["chassis"] = mac_str(v[1:])
        i += 2 + ln
    return out


TCP_PORTS = {502: modbus, 20000: dnp3, 2404: iec104, 102: iso_tcp, 44818: enip, 1883: mqtt, 4840: opcua}
UDP_PORTS = {20000: dnp3, 2222: enip, 44818: enip, 161: snmp, 162: snmp, 47808: bacnet}
L2_TYPES = {0x8892: profinet, 0x88B8: goose, 0x88BA: sv}


def dissect(pkt: Packet) -> list[Event]:
    if pkt.ethertype in L2_TYPES:
        return L2_TYPES[pkt.ethertype](pkt)
    if pkt.ip_proto == 6 and pkt.payload:
        for port in (pkt.dport, pkt.sport):
            if port in TCP_PORTS:
                return TCP_PORTS[port](pkt)
            if port in CLEARTEXT:
                return cleartext(pkt, port)
    if pkt.ip_proto == 17 and pkt.payload:
        for port in (pkt.dport, pkt.sport):
            if port in UDP_PORTS:
                return UDP_PORTS[port](pkt)
            if port == 69:
                return cleartext(pkt, 69)
    return []
