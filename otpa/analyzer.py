"""Builds an asset inventory, a communication matrix and a list of findings from a capture."""
from __future__ import annotations

import csv
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import dissectors as d
from .pcap import Packet, ip_str, mac_str, read_packets

# Small built-in OUI table (industrial vendors). Use --oui with the IEEE CSV for full coverage.
OUI = {
    "00:80:63": "Hirschmann (Belden)",
    "00:00:bc": "Rockwell Automation",
    "00:80:f4": "Schneider Electric",
    "00:a0:45": "Phoenix Contact",
    "00:1b:1b": "Siemens",
}

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Asset:
    key: str
    ip: Optional[str] = None
    macs: set = field(default_factory=set)
    vendor: str = ""
    names: set = field(default_factory=set)
    roles: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    vlans: set = field(default_factory=set)
    packets: int = 0
    first: float = 0.0
    last: float = 0.0

    def as_dict(self) -> dict:
        return {"key": self.key, "ip": self.ip or "", "mac": ", ".join(sorted(self.macs)), "vendor": self.vendor,
                "name": ", ".join(sorted(self.names)), "roles": sorted(self.roles), "protocols": sorted(self.protocols),
                "vlans": sorted(self.vlans), "packets": self.packets}


@dataclass
class Flow:
    client: str
    server: str
    proto: str
    count: int = 0
    ops: dict = field(default_factory=lambda: defaultdict(int))

    def as_dict(self) -> dict:
        return {"client": self.client, "server": self.server, "protocol": self.proto, "events": self.count,
                "operations": dict(self.ops)}


@dataclass
class Finding:
    severity: str
    title: str
    proto: str
    source: str
    target: str
    count: int = 1
    example: str = ""
    advice: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


ADVICE = {
    "Modbus": "Modbus has no authentication. Restrict which hosts may write with an industrial firewall / DPI rule "
              "(allow-list function codes per source) and log every write.",
    "DNP3": "Allow DNP3 control and restart function codes only from the authorised master; consider DNP3 Secure "
            "Authentication (SAv5/SAv6) where the outstation supports it.",
    "IEC 104": "Permit commands only from the controlling station's IP; IEC 62351-3 (TLS) protects 104 on untrusted links.",
    "S7": "Enable PLC access protection / CPU password and allow S7 stop/download only from the engineering workstation.",
    "PROFINET DCP": "DCP Set should come only from the engineering station during commissioning; enable DCP write "
                    "protection on devices that support it.",
    "GOOSE": "Check that the publisher MAC is the expected IED; GOOSE has no authentication without IEC 62351-6.",
    "SNMP": "Move to SNMPv3 (authPriv) and remove default community strings.",
    "Telnet": "Disable Telnet; use SSH for device management.",
    "FTP": "Replace FTP with SFTP/SCP or restrict it to a maintenance window.",
    "HTTP": "Use HTTPS for management interfaces and restrict access to a management VLAN.",
    "TFTP": "Restrict TFTP to the configuration server and only during maintenance.",
    "MQTT": "Use MQTT over TLS (8883) with per-client credentials or certificates.",
    "OPC UA": "Configure the server to require Sign or SignAndEncrypt with Basic256Sha256 or newer.",
    "EtherNet/IP": "Device discovery is normal from engineering tools; alert when it comes from an unexpected host.",
    "ARP": "Investigate possible ARP spoofing or an IP conflict; enable Dynamic ARP Inspection where switches support it.",
}


def advice_for(title: str) -> str:
    for k, v in ADVICE.items():
        if k.lower() in title.lower():
            return v
    return ""


def load_oui_csv(path: str) -> dict:
    """Load the IEEE MA-L CSV (columns: Registry, Assignment, Organization Name, ...)."""
    table = {}
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if len(row) >= 3 and len(row[1]) == 6:
                a = row[1].lower()
                table[f"{a[0:2]}:{a[2:4]}:{a[4:6]}"] = row[2].strip()
    return table


class Analyzer:
    def __init__(self, oui: Optional[dict] = None):
        self.oui = dict(OUI)
        if oui:
            self.oui.update(oui)
        self.assets: dict[str, Asset] = {}
        self.flows: dict[tuple, Flow] = {}
        self.findings: dict[tuple, Finding] = {}
        self.proto_counts: dict[str, int] = defaultdict(int)
        self.total = 0
        self.first_ts = None
        self.last_ts = None
        self._arp: dict[str, set] = defaultdict(set)
        self._goose_pub: dict[str, set] = defaultdict(set)
        self._mac_of_ip: dict[str, str] = {}

    # ---------------------------------------------------------------- helpers
    def asset(self, key: str, pkt: Optional[Packet] = None) -> Asset:
        a = self.assets.get(key)
        if a is None:
            a = Asset(key=key, ip=key if key and key[0].isdigit() and "." in key else None)
            self.assets[key] = a
        if a.ip is None and ":" in key:
            a.macs.add(key)
        mac = next(iter(a.macs), None) or (self._mac_of_ip.get(a.ip) if a.ip else None)
        if mac and not a.vendor:
            a.vendor = self.oui.get(mac[:8], "")
        return a

    def add_finding(self, sev, title, proto, src, dst, example=""):
        k = (title, src, dst)
        f = self.findings.get(k)
        if f:
            f.count += 1
        else:
            self.findings[k] = Finding(sev, title, proto, src, dst, 1, example, advice_for(title + " " + proto))

    # ---------------------------------------------------------------- main loop
    def feed(self, pkt: Packet) -> None:
        self.total += 1
        self.first_ts = pkt.ts if self.first_ts is None else min(self.first_ts, pkt.ts)
        self.last_ts = pkt.ts if self.last_ts is None else max(self.last_ts, pkt.ts)

        if pkt.src_ip and not pkt.src_mac.startswith("ff:"):
            self._mac_of_ip.setdefault(pkt.src_ip, pkt.src_mac)
        if pkt.dst_ip and not pkt.dst_mac.startswith(("ff:", "01:", "33:")):
            self._mac_of_ip.setdefault(pkt.dst_ip, pkt.dst_mac)
        for side in ("src", "dst"):
            key = d.node(pkt, side)
            if not key or key.startswith(("ff:ff", "01:")) or key == "255.255.255.255":
                continue
            a = self.asset(key)
            if side == "src":
                a.packets += 1
                a.macs.add(pkt.src_mac)
                if not a.vendor:
                    a.vendor = self.oui.get(pkt.src_mac[:8], "")
            if pkt.vlan is not None:
                a.vlans.add(pkt.vlan)

        if pkt.ethertype == 0x0806:
            self._arp_check(pkt)
            self.proto_counts["ARP"] += 1
            return
        if pkt.ethertype == 0x88CC:
            self.proto_counts["LLDP"] += 1
            info = d.lldp(pkt)
            if info.get("system_name"):
                self.asset(pkt.src_mac).names.add(info["system_name"])
                self.asset(pkt.src_mac).roles.add("LLDP-speaking network device")
            return

        events = d.dissect(pkt)
        if not events:
            if pkt.transport:
                self.proto_counts[f"other {pkt.transport}"] += 1
            elif pkt.ethertype:
                self.proto_counts[f"ethertype 0x{pkt.ethertype:04x}"] += 1
            return

        for ev in events:
            self.proto_counts[ev.proto] += 1
            for key, role in ((ev.client, ev.client_role), (ev.server, ev.server_role)):
                if key and not key.startswith(("ff:ff", "01:")):
                    a = self.asset(key)
                    a.protocols.add(ev.proto)
                    if role:
                        a.roles.add(role)
            if ev.client and ev.server:
                fk = (ev.client, ev.server, ev.proto)
                fl = self.flows.setdefault(fk, Flow(ev.client, ev.server, ev.proto))
                fl.count += 1
                fl.ops[ev.op] += 1
            if ev.proto == "IEC 61850 GOOSE":
                self._goose_check(pkt, ev)
            if ev.proto == "PROFINET DCP" and ev.detail.get("name_of_station") and ev.detail.get("response"):
                self.asset(pkt.src_mac).names.add(ev.detail["name_of_station"])
            if ev.severity:
                self.add_finding(ev.severity, ev.finding, ev.proto, ev.client or "", ev.server or "", ev.summary)

    def _arp_check(self, pkt: Packet) -> None:
        pl = pkt.l2_payload
        if len(pl) < 28:
            return
        sha, spa = mac_str(pl[8:14]), ip_str(pl[14:18])
        if spa == "0.0.0.0":
            return
        self._arp[spa].add(sha)
        self._mac_of_ip.setdefault(spa, sha)
        a = self.asset(spa)
        a.macs.add(sha)
        if not a.vendor:
            a.vendor = self.oui.get(sha[:8], "")
        if len(self._arp[spa]) == 2:
            self.add_finding("high", "ARP: one IP claimed by several MAC addresses (spoofing or IP conflict)", "ARP",
                             ", ".join(sorted(self._arp[spa])), spa, f"{spa} is at {', '.join(sorted(self._arp[spa]))}")

    def _goose_check(self, pkt: Packet, ev: d.Event) -> None:
        ref = ev.detail.get("gocbRef")
        if not ref:
            return
        self._goose_pub[ref].add(pkt.src_mac)
        if len(self._goose_pub[ref]) == 2:
            self.add_finding("high", "GOOSE control block published from more than one MAC (possible spoofing)",
                             "IEC 61850 GOOSE", ", ".join(sorted(self._goose_pub[ref])), ref,
                             f"{ref} seen from {', '.join(sorted(self._goose_pub[ref]))}")

    def run(self, packets: Iterable[Packet]) -> "Analyzer":
        for p in packets:
            self.feed(p)
        self._merge_l2_into_l3()
        self._fill_vendors()
        self._cross_zone_writes()
        return self

    def _merge_l2_into_l3(self) -> None:
        """Fold a MAC-only asset (e.g. an LLDP-only switch) into its IP asset when the IP↔MAC is known."""
        mac_to_ip = {m: ip for ip, m in self._mac_of_ip.items()}
        for key in list(self.assets):
            if ":" not in key or "." in key:
                continue
            ip = mac_to_ip.get(key)
            if ip and ip in self.assets:
                src, dst = self.assets.pop(key), self.assets[ip]
                dst.macs |= src.macs | {key}
                dst.names |= src.names
                dst.roles |= src.roles
                dst.protocols |= src.protocols
                dst.vlans |= src.vlans
                dst.packets += src.packets

    def _fill_vendors(self) -> None:
        for a in self.assets.values():
            if not a.vendor:
                mac = next(iter(a.macs), None) or (self._mac_of_ip.get(a.ip) if a.ip else None)
                if mac:
                    a.macs.add(mac)
                    a.vendor = self.oui.get(mac[:8], "")

    def _cross_zone_writes(self) -> None:
        """Flag hosts that both write/control and are not seen polling (likely ad-hoc engineering laptops)."""
        pollers = {f.client for f in self.flows.values() if f.ops.get("read")}
        for f in self.flows.values():
            if (f.ops.get("write") or f.ops.get("control")) and f.client not in pollers:
                self.add_finding("medium", "Write/control traffic from a host that never polls (unexpected engineering source?)",
                                 f.proto, f.client, f.server, f"{f.ops.get('write', 0) + f.ops.get('control', 0)} write/control events")

    # ---------------------------------------------------------------- results
    def result(self, source: str = "") -> dict:
        findings = sorted(self.findings.values(), key=lambda f: (SEV_ORDER.get(f.severity, 9), f.title))
        assets = sorted(self.assets.values(), key=lambda a: (a.ip is None, tuple(int(x) for x in a.ip.split(".")) if a.ip else (), a.key))
        sev = defaultdict(int)
        for f in findings:
            sev[f.severity] += 1
        return {
            "source": source,
            "summary": {"packets": self.total,
                        "duration_s": round((self.last_ts or 0) - (self.first_ts or 0), 3),
                        "assets": len(assets), "flows": len(self.flows), "findings": dict(sev),
                        "protocols": dict(sorted(self.proto_counts.items(), key=lambda kv: -kv[1]))},
            "assets": [a.as_dict() for a in assets if a.packets or a.protocols],
            "flows": [f.as_dict() for f in sorted(self.flows.values(), key=lambda f: (f.proto, f.client, f.server))],
            "findings": [f.as_dict() for f in findings],
        }


def analyze(path: str, oui_csv: Optional[str] = None) -> dict:
    oui = load_oui_csv(oui_csv) if oui_csv else None
    return Analyzer(oui).run(read_packets(path)).result(source=path)
