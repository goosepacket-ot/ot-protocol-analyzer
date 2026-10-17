# ot-protocol-analyzer

**Passive OT/ICS traffic assessment from a PCAP file — no dependencies, no agents, nothing to install on the plant network.**

Point it at a capture taken from a SPAN/mirror port in a substation, plant or utility network and it produces an **asset inventory**, a **communication matrix** (who talks to whom, and how) and a prioritised list of **security findings** — the insecure services, the unexpected control commands and the possible spoofing you want to see before an audit or a IEC 62443 assessment.

It is written in pure Python with **zero third-party packages**, so it runs on a locked-down jump host or an air-gapped analysis laptop where you cannot `pip install` anything.

```
$ otpa analyze capture.pcap --out report/
36 packets, 8 assets, 6 flows, findings: {'high': 3, 'medium': 2, 'low': 1}
  [HIGH  ] MQTT CONNECT with username/password in clear text  (10.10.40.5 -> 10.10.40.6)
  [HIGH  ] SNMP v1 with default community 'public'            (10.10.10.30 -> 10.10.1.2)
  [HIGH  ] Telnet management (clear-text credentials)         (10.10.10.10 -> 10.10.1.2)
  [MEDIUM] IEC 104 control command                            (10.10.10.10 -> 10.10.20.21)
  [MEDIUM] Modbus write operation                             (10.10.10.10 -> 10.10.20.11)
  [LOW   ] EtherNet/IP ListIdentity (device discovery)        (10.10.10.10 -> 10.10.20.41)
reports: report/report.json, report/assets.csv, report/flows.csv, report/findings.csv, report/report.md, report/report.html
```

> **Passive only.** This tool reads a file. It never sends a packet, never touches a device, and is safe to run against production captures. It is a triage and documentation aid, not a replacement for a proper DPI monitoring product — always check its findings against the site's approved communication baseline before acting.

## Why I built it

I have spent 25+ years in industrial / OT networking, and the first question on every assessment is the same: *what is actually on this network, who is talking to the controllers, and what is still running in clear text?* Full monitoring platforms answer that, but on a short engagement you often just have a `.pcap` and a laptop. This is the tool I wanted for that moment — small enough to read in an afternoon, honest about its limits, and dependency-free so it runs anywhere.

## Install

```bash
git clone https://github.com/goosepacket/ot-protocol-analyzer
cd ot-protocol-analyzer
pip install -e .          # or just run: python -m otpa ...
```

Python 3.9+ and nothing else.

## Use

```bash
# analyse a capture, write all report formats into report/
otpa analyze capture.pcap --out report/

# richer vendor names: download the IEEE OUI list (oui.csv) and pass it in
otpa analyze capture.pcap --out report/ --oui oui.csv

# CI / gate use: exit non-zero if anything medium or worse is found
otpa analyze capture.pcap --out report/ --fail-on medium

# generate the synthetic demo capture shipped with the repo
otpa sample demo.pcap
```

Outputs written to the `--out` directory:

| File | Contents |
|---|---|
| `report.html` | Self-contained, styled report (findings, assets, matrix) — open in a browser |
| `report.md` | The same, in Markdown — drops straight into an assessment write-up |
| `report.json` | Everything, structured — for your own tooling |
| `assets.csv`, `flows.csv`, `findings.csv` | Flat tables for Excel / a SIEM / a GRC tool |

A rendered example is in [`docs/example-report/`](docs/example-report/) (from [`samples/demo-substation.pcap`](samples/)).

## What it understands

**OT / ICS protocols** — with the operation and its security relevance, not just the port:

- **Modbus/TCP** (502) — function names; writes, diagnostics (restart / listen-only = high), device-ID reads
- **DNP3** (20000) — function codes; cold/warm restart, stop application, direct-operate, disable-unsolicited
- **IEC 60870-5-104** (2404) — I/S/U frames, STARTDT/STOPDT, type IDs, control commands, reset-process, clock-sync
- **S7comm** (ISO-on-TCP 102) — read/write var, PLC **STOP**, program up/download, PI services; MMS on the same port is distinguished
- **PROFINET** (0x8892) — cyclic RT, alarms, and **DCP** with station-name extraction (DCP **Set** = high)
- **IEC 61850 GOOSE** (0x88B8) — control-block reference, stNum/sqNum, simulation flag, publisher MAC
- **IEC 61850 Sampled Values** (0x88BA) — stream ID
- **EtherNet/IP** (44818 / 2222) — encapsulation commands, ListIdentity discovery

**Infrastructure & IT protocols that shouldn't be in clear text** — SNMP v1/v2c (default community detection), Telnet, FTP, TFTP, HTTP, MQTT (plain 1883, credentials in CONNECT), OPC UA (SecurityPolicy#None), BACnet/IP, LLDP (used to enrich the inventory), and ARP (duplicate-IP / spoofing detection).

**Captures** — classic `.pcap` (µs and ns, both byte orders) and `.pcapng`; Ethernet II with 802.1Q / Q-in-Q VLAN tags.

## What it does *not* do

Being honest about scope matters more in OT than anywhere else:

- It does not reassemble TCP streams, so a message split across segments may be partly read. Findings are indicators to confirm, not court evidence.
- It does not decrypt anything, and it does not fully decode every field of every protocol — it decodes enough to identify the asset, the role and the operation.
- The built-in vendor (OUI) table is a small, confident set of industrial vendors; use `--oui oui.csv` for the full IEEE list.
- It has no idea what *your* normal is. A "Modbus write" is only suspicious relative to your baseline — the tool surfaces it, you judge it.

## How findings map to IEC 62443

The findings line up with the foundational requirements, which is usually how they end up in a report:

- Clear-text management (Telnet/FTP/HTTP/SNMPv1) → **FR1** identification & authentication, **FR4** data confidentiality
- Unexpected writes / control / PLC-stop / restart → **FR2** use control
- GOOSE / ARP spoofing indicators → **FR3** system integrity
- The communication matrix itself → the evidence base for **FR5** restricted data flow (zones & conduits)

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

CI runs the suite on Python 3.9–3.12 on every push (see `.github/workflows/ci.yml`).

## License

MIT — see [LICENSE](LICENSE).
