"""Minimal, dependency-free PCAP / PCAPNG reader and Ethernet/IPv4/TCP/UDP decoder.

Only what an OT traffic assessment needs: Ethernet II (+802.1Q / Q-in-Q), IPv4, TCP, UDP and
raw Layer-2 payloads (PROFINET, GOOSE, SV, LLDP, ARP). IPv6 frames are counted but not decoded.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, Optional

LINKTYPE_ETHERNET = 1


@dataclass
class Packet:
    ts: float
    raw: bytes
    src_mac: str = ""
    dst_mac: str = ""
    vlan: Optional[int] = None
    pcp: Optional[int] = None
    ethertype: int = 0
    l2_payload: bytes = b""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_proto: Optional[int] = None
    ttl: Optional[int] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: int = 0
    payload: bytes = b""
    notes: list = field(default_factory=list)

    @property
    def transport(self) -> str:
        return {6: "TCP", 17: "UDP"}.get(self.ip_proto or -1, "")


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ip_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _read_classic(f: BinaryIO, header: bytes) -> Iterator[tuple[float, bytes, int]]:
    magic = header[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Not a pcap file")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    rest = f.read(20)
    linktype = struct.unpack(endian + "I", rest[16:20])[0]
    div = 1e9 if nano else 1e6
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, data, linktype


def _read_pcapng(f: BinaryIO, first: bytes) -> Iterator[tuple[float, bytes, int]]:
    buf = first + f.read()
    pos = 0
    endian = "<"
    linktypes: list[int] = []
    tsres: list[float] = []
    while pos + 12 <= len(buf):
        btype = struct.unpack(endian + "I", buf[pos:pos + 4])[0]
        if btype == 0x0A0D0D0A:  # Section header: detect byte order
            bom = buf[pos + 8:pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            linktypes, tsres = [], []
        blen = struct.unpack(endian + "I", buf[pos + 4:pos + 8])[0]
        if blen < 12 or pos + blen > len(buf):
            return
        body = buf[pos + 8:pos + blen - 4]
        if btype == 1:  # Interface description
            linktypes.append(struct.unpack(endian + "H", body[0:2])[0])
            res = 1e-6
            opt = body[8:]
            i = 0
            while i + 4 <= len(opt):
                code, olen = struct.unpack(endian + "HH", opt[i:i + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = opt[i + 4]
                    res = 2 ** -(v & 0x7F) if v & 0x80 else 10 ** -v
                i += 4 + ((olen + 3) & ~3)
            tsres.append(res)
        elif btype == 6:  # Enhanced packet
            iface, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
            data = body[20:20 + caplen]
            res = tsres[iface] if iface < len(tsres) else 1e-6
            lt = linktypes[iface] if iface < len(linktypes) else LINKTYPE_ETHERNET
            yield ((ts_hi << 32) | ts_lo) * res, data, lt
        elif btype == 3:  # Simple packet
            olen = struct.unpack(endian + "I", body[:4])[0]
            yield 0.0, body[4:4 + olen], linktypes[0] if linktypes else LINKTYPE_ETHERNET
        pos += blen


def read_frames(path: str) -> Iterator[tuple[float, bytes, int]]:
    with open(path, "rb") as f:
        head = f.read(4)
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f, head)
        else:
            yield from _read_classic(f, head)


def decode(ts: float, data: bytes) -> Optional[Packet]:
    if len(data) < 14:
        return None
    p = Packet(ts=ts, raw=data, dst_mac=mac_str(data[0:6]), src_mac=mac_str(data[6:12]))
    et = struct.unpack("!H", data[12:14])[0]
    off = 14
    while et in (0x8100, 0x88A8) and len(data) >= off + 4:
        tci = struct.unpack("!H", data[off:off + 2])[0]
        if p.vlan is None:
            p.vlan, p.pcp = tci & 0x0FFF, tci >> 13
        et = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    p.ethertype = et
    p.l2_payload = data[off:]
    if et != 0x0800 or len(data) < off + 20:
        return p
    ihl = (data[off] & 0x0F) * 4
    total = struct.unpack("!H", data[off + 2:off + 4])[0]
    frag = struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF
    p.ttl = data[off + 8]
    p.ip_proto = data[off + 9]
    p.src_ip = ip_str(data[off + 12:off + 16])
    p.dst_ip = ip_str(data[off + 16:off + 20])
    l4 = off + ihl
    end = min(len(data), off + total) if total else len(data)
    if frag:
        p.notes.append("ip-fragment")
        return p
    if p.ip_proto == 6 and end >= l4 + 20:
        p.sport, p.dport = struct.unpack("!HH", data[l4:l4 + 4])
        doff = (data[l4 + 12] >> 4) * 4
        p.tcp_flags = data[l4 + 13]
        p.payload = data[l4 + doff:end]
    elif p.ip_proto == 17 and end >= l4 + 8:
        p.sport, p.dport = struct.unpack("!HH", data[l4:l4 + 4])
        p.payload = data[l4 + 8:end]
    return p


def read_packets(path: str) -> Iterator[Packet]:
    for ts, data, lt in read_frames(path):
        if lt != LINKTYPE_ETHERNET:
            continue
        pkt = decode(ts, data)
        if pkt:
            yield pkt


# ---------------------------------------------------------------- writer (used for samples and tests)
def write_pcap(path: str, frames: list[tuple[float, bytes]]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, data in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)
