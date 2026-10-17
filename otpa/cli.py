"""Command line: otpa analyze capture.pcap --out report/"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze
from .report import markdown, write_all


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="otpa", description="Passive OT/ICS protocol analyser for PCAP/PCAPNG captures.")
    ap.add_argument("--version", action="version", version=f"otpa {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyse a capture and write reports")
    a.add_argument("pcap")
    a.add_argument("--out", default="otpa-report", help="output directory (default: otpa-report)")
    a.add_argument("--oui", help="IEEE OUI CSV (oui.csv) for full vendor lookup")
    a.add_argument("--fail-on", choices=["high", "medium", "low"], help="exit 2 if a finding of this severity or worse exists")
    a.add_argument("--quiet", action="store_true")
    s = sub.add_parser("sample", help="write a synthetic demo capture")
    s.add_argument("path", nargs="?", default="sample.pcap")
    args = ap.parse_args(argv)

    if args.cmd == "sample":
        from .sample import build
        build(args.path)
        print(f"wrote {args.path}")
        return 0

    res = analyze(args.pcap, args.oui)
    paths = write_all(res, args.out)
    if not args.quiet:
        s = res["summary"]
        print(f"{s['packets']} packets, {s['assets']} assets, {s['flows']} flows, findings: {s['findings'] or 'none'}")
        for f in res["findings"][:10]:
            print(f"  [{f['severity'].upper():6}] {f['title']}  ({f['source']} -> {f['target']})")
        print("reports:", ", ".join(paths))
    if args.fail_on:
        order = ["high", "medium", "low"]
        bad = order[: order.index(args.fail_on) + 1]
        if any(f["severity"] in bad for f in res["findings"]):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
