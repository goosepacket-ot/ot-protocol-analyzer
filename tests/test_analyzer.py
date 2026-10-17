import os
import tempfile

import pytest

from otpa.analyzer import Analyzer, analyze, load_oui_csv
from otpa.pcap import read_packets
from otpa.report import html_report, markdown, write_all
from otpa.sample import build


@pytest.fixture(scope="module")
def result():
    d = tempfile.mkdtemp()
    pcap = os.path.join(d, "demo.pcap")
    build(pcap)
    return analyze(pcap)


def test_sample_is_readable():
    d = tempfile.mkdtemp()
    pcap = os.path.join(d, "demo.pcap")
    n = build(pcap)
    pkts = list(read_packets(pcap))
    assert n == len(pkts) > 0
    assert all(p.src_mac for p in pkts)


def test_assets_and_vendors(result):
    by_ip = {a["ip"]: a for a in result["assets"] if a["ip"]}
    assert "Schneider Electric" in by_ip["10.10.20.11"]["vendor"]
    assert "Rockwell" in by_ip["10.10.20.41"]["vendor"]
    assert by_ip["10.10.1.2"]["name"] == "SUB-A-SW01"          # LLDP name folded into the L3 asset
    assert "Hirschmann" in by_ip["10.10.1.2"]["vendor"]


def test_protocols_detected(result):
    protos = result["summary"]["protocols"]
    for p in ("Modbus/TCP", "IEC 60870-5-104", "EtherNet/IP", "SNMP", "Telnet", "MQTT", "LLDP"):
        assert p in protos, p


def test_findings_present(result):
    titles = {f["title"] for f in result["findings"]}
    assert any("default community" in t for t in titles)
    assert any("Telnet" in t for t in titles)
    assert any("MQTT" in t for t in titles)
    assert any("Modbus write" in t for t in titles)
    assert any("IEC 104 control" in t for t in titles)


def test_findings_sorted_by_severity(result):
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sevs = [order[f["severity"]] for f in result["findings"]]
    assert sevs == sorted(sevs)


def test_modbus_write_direction(result):
    writes = [f for f in result["findings"] if "Modbus write" in f["title"]]
    assert writes and writes[0]["source"] == "10.10.10.10" and writes[0]["target"] == "10.10.20.11"


def test_reports_written(result):
    d = tempfile.mkdtemp()
    paths = write_all(result, d)
    assert {os.path.basename(p) for p in paths} == {
        "report.json", "report.md", "report.html", "assets.csv", "flows.csv", "findings.csv"}
    for p in paths:
        assert os.path.getsize(p) > 0
    md = markdown(result)
    assert "# OT traffic assessment" in md and "Asset inventory" in md
    assert "<!doctype html>" in html_report(result).lower()


def test_malformed_input_does_not_crash():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "junk.pcap")
    # valid classic pcap header, then a truncated/garbage record
    import struct
    with open(p, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 0, 0, 8, 8) + b"\xff" * 8)
    assert analyze(p)["summary"]["packets"] >= 0


def test_oui_csv_loading():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "oui.csv")
    with open(p, "w") as f:
        f.write("Registry,Assignment,Organization Name,Organization Address\n")
        f.write("MA-L,AABBCC,Example Vendor Inc,Somewhere\n")
    table = load_oui_csv(p)
    assert table["aa:bb:cc"] == "Example Vendor Inc"
