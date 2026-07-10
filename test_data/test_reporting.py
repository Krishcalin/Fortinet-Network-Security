"""
Tests for the reporting/UX additions (2026-07): TTY-aware colour gating,
per-framework compliance scorecard, enriched JSON, full findings CSV.

Run:  python -m pytest test_data/test_reporting.py -v
"""
import csv
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fortinet_scanner as fs  # noqa: E402
from fortinet_offline_scanner import OfflineFortinetScanner  # noqa: E402

CONF = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")


def test_set_color_disable_blanks_ansi():
    sc = fs.FortinetScanner(host="x", token="y")
    sc.set_color(False)
    assert sc.RESET == "" and sc.BOLD == ""
    assert all(v == "" for v in sc.SEVERITY_COLOR.values())


def test_set_color_enable_restores_ansi():
    sc = fs.FortinetScanner(host="x", token="y")
    sc.set_color(False)
    sc.set_color(True)
    assert "\033[" in sc.RESET
    assert sc.SEVERITY_COLOR["CRITICAL"].startswith("\033[")


def test_compliance_scorecard_counts_distinct_controls():
    sc = fs.FortinetScanner(host="x", token="y")
    sc.findings = [
        fs.Finding(rule_id="FORTIOS-ADMIN-002", name="a", category="Admin Access",
                   severity="MEDIUM", file_path="fw", line_num=None, line_content="",
                   description="", recommendation="", cwe="CWE-1"),
        fs.Finding(rule_id="FORTIOS-ADMIN-003", name="b", category="Admin Access",
                   severity="HIGH", file_path="fw", line_num=None, line_content="",
                   description="", recommendation="", cwe="CWE-1"),
    ]
    card = sc.compliance_scorecard()
    assert set(card) == {"CIS", "PCI-DSS", "NIST", "SOC2", "HIPAA"}
    assert card["CIS"]["failing_controls"] >= 2          # 2.1.2 and 2.1.3
    assert card["CIS"]["worst_severity"] == "HIGH"       # HIGH outranks MEDIUM
    assert card["CIS"]["findings"] == 2


def test_enriched_json(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    p = str(tmp_path / "r.json")
    sc.save_json(p)
    d = json.load(open(p))
    assert d["schema_version"] == 2
    assert isinstance(d["risk_score"], int)
    assert "compliance_scorecard" in d and "tier_summary" in d
    assert d["prioritization"]
    # every finding carries a priority block when the engine is available
    assert all("priority" in f for f in d["findings"])
    pr = d["findings"][0]["priority"]
    assert set(pr) >= {"tier", "score", "kev", "epss", "internet_reachable"}


def test_findings_csv(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    p = str(tmp_path / "f.csv")
    sc.save_findings_csv(p)
    rows = list(csv.reader(open(p, newline="", encoding="utf-8")))
    header = rows[0]
    assert header[:6] == ["Rule ID", "Severity", "Tier", "Priority Score", "KEV", "EPSS"]
    assert "Compliance" in header and "Remediation CLI" in header
    assert len(rows) - 1 == len(sc.findings)
    # rows are severity-ordered (CRITICAL first)
    assert rows[1][1] == "CRITICAL"


def test_summary_only_runs_without_error(capsys):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    sc.set_color(False)
    sc.print_summary_only()
    out = capsys.readouterr().out
    assert "Compliance Scorecard" in out
    assert "Remediation Queue" in out or "P1" in out
    # the full per-finding dump header must NOT appear
    assert "Detailed Findings" not in out
