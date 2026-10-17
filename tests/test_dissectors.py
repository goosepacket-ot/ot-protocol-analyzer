"""Unit tests for individual dissectors, driving them with hand-built Packet objects."""
import struct

from otpa import dissectors as d
from otpa.pcap import Packet


def mk(payload=b"", ethertype=0x0800, proto=6, sport=40000, dport=502,
       src_ip="10.0.0.1", dst_ip="10.0.0.2", src_mac="00:00:00:00:00:01",
       dst_mac="00:00:00:00:00:02", l2=b""):
    return Packet(ts=0.0, raw=b"", src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype,
                  l2_payload=l2, src_ip=src_ip, dst_ip=dst_ip, ip_proto=proto,
                  sport=sport, dport=dport, payload=payload)


def test_modbus_read_vs_write():
    read = d.modbus(mk(struct.pack("!HHHB", 1, 0, 6, 1) + b"\x03\x00\x00\x00\x0a"))
    assert read[0].op == "read" and not read[0].severity
    write = d.modbus(mk(struct.pack("!HHHB", 1, 0, 9, 1) + b"\x10\x00\x10\x00\x01\x02\x00\x64"))
    assert write[0].op == "write" and write[0].severity == "medium"


def test_modbus_restart_is_high():
    evs = d.modbus(mk(struct.pack("!HHHB", 1, 0, 6, 1) + b"\x08\x00\x01\x00\x00"))
    assert evs[0].severity == "high" and "estart" in evs[0].finding


def test_iec104_command_and_startdt():
    u = d.iec104(mk(b"\x68\x04\x07\x00\x00\x00", dport=2404))
    assert u and "STARTDT" in u[0].summary
    i = d.iec104(mk(b"\x68\x0e\x00\x00\x00\x00" + bytes([45, 1, 6, 0]) + b"\x01\x00" + b"\xf4\x01\x00" + b"\x01", dport=2404))
    assert i[0].op == "control" and i[0].detail["type"] == 45


def test_dnp3_cold_restart_high():
    frame = b"\x05\x64\x0b\xc4" + struct.pack("<HH", 10, 1) + b"\x00\x00" + b"\xc0\xc1" + bytes([13]) + b"\x00\x00"
    evs = d.dnp3(mk(frame, dport=20000))
    assert evs and evs[0].severity == "high" and "Cold Restart" in evs[0].summary


def test_snmp_default_community():
    from otpa.sample import _snmp_get
    evs = d.snmp(mk(_snmp_get("public"), proto=17, dport=161))
    assert evs[0].severity == "high" and "public" in evs[0].finding


def test_snmp_custom_community_is_medium():
    from otpa.sample import _snmp_get
    evs = d.snmp(mk(_snmp_get("s3cr3t-ro"), proto=17, dport=161))
    assert evs[0].severity == "medium"


def test_telnet_flagged_high():
    evs = d.dissect(mk(b"\xff\xfb\x01", dport=23))
    assert evs[0].proto == "Telnet" and evs[0].severity == "high"


def test_mqtt_connect_with_credentials():
    from otpa.sample import _mqtt_connect
    evs = d.mqtt(mk(_mqtt_connect("u", "p"), dport=1883))
    assert evs[0].severity == "high" and "username" in evs[0].finding


def test_opcua_security_none():
    from otpa.sample import _enip  # noqa  (ensure sample import path works)
    pl = b"OPNF" + b"\x00" * 4 + b"http://opcfoundation.org/UA/SecurityPolicy#None"
    evs = d.opcua(mk(pl, dport=4840))
    assert evs[0].severity == "medium"


def test_goose_simulation_flag():
    from otpa.sample import _ber
    pdu = _ber(0x80, b"IED1/LLN0$GO$gcb") + _ber(0x85, b"\x01") + _ber(0x86, b"\x02") + _ber(0x87, b"\xff")
    apdu = _ber(0x61, pdu)
    pl = struct.pack("!HHHH", 1, 8 + len(apdu), 0, 0) + apdu
    evs = d.goose(mk(l2=pl, ethertype=0x88B8, proto=None))
    assert evs[0].detail["gocbRef"] == "IED1/LLN0$GO$gcb"
    assert evs[0].severity == "medium"


def test_lldp_parsing():
    def tlv(t, v):
        return struct.pack("!H", (t << 9) | len(v)) + v
    pl = tlv(1, b"\x04\x00\x11\x22\x33\x44\x55") + tlv(2, b"\x05Gi1/0/1") + tlv(5, b"CORE-SW") + tlv(0, b"")
    info = d.lldp(mk(l2=pl, ethertype=0x88CC))
    assert info["system_name"] == "CORE-SW" and info["port"] == "Gi1/0/1"


def test_unknown_port_returns_nothing():
    assert d.dissect(mk(b"hello", dport=12345, sport=12346)) == []
