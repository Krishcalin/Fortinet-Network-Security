"""
Tests for the scored compliance-benchmark profile (benchmark_score / --framework).

Run:  python -m pytest test_data/test_benchmark.py -v
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


def _finding(rule_id, severity="HIGH"):
    return fs.Finding(rule_id=rule_id, name=rule_id, category="c", severity=severity,
                      file_path="fw", line_num=None, line_content="",
                      description="", recommendation="", cwe="CWE-1")


def _scanner(findings):
    sc = fs.FortinetScanner(host="x", token="y")
    sc.findings = findings
    return sc


def test_all_clean_scores_100():
    # no findings -> every mapped control passes
    bm = _scanner([]).benchmark_score("cis")
    assert bm["failed"] == 0
    assert bm["passed"] == bm["total_controls"] > 0
    assert bm["score_pct"] == 100


def test_one_failing_control():
    # FORTIOS-ADMIN-002 maps to CIS 2.1.2 -> exactly that control fails
    bm = _scanner([_finding("FORTIOS-ADMIN-002")]).benchmark_score("cis")
    failing = [c for c in bm["controls"] if c["status"] == "FAIL"]
    assert [c["control"] for c in failing] == ["2.1.2"]
    assert bm["failed"] == 1 and bm["passed"] == bm["total_controls"] - 1
    assert failing[0]["findings"] == ["FORTIOS-ADMIN-002"]
    assert failing[0]["worst_severity"] == "HIGH"


def test_pass_fail_partition_is_total():
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    for fw in ("cis", "pci", "nist", "soc2", "hipaa"):
        bm = sc.benchmark_score(fw)
        n_pass = sum(1 for c in bm["controls"] if c["status"] == "PASS")
        n_fail = sum(1 for c in bm["controls"] if c["status"] == "FAIL")
        assert n_pass + n_fail == bm["total_controls"] == len(bm["controls"])
        assert n_pass == bm["passed"] and n_fail == bm["failed"]
        assert 0 <= bm["score_pct"] <= 100
        # section rollups sum to the control totals
        assert sum(s["total"] for s in bm["sections"].values()) == bm["total_controls"]
        assert sum(s["passed"] for s in bm["sections"].values()) == bm["passed"]


def test_natural_section_order():
    bm = OfflineFortinetScanner(CONF, verbose=False)
    bm.scan()
    cis = list(bm.benchmark_score("cis")["sections"].keys())
    # numeric sections must be in numeric order (10 after 2, not before)
    nums = [int(s) for s in cis if s.isdigit()]
    assert nums == sorted(nums)


def test_severity_filter_does_not_inflate_score():
    """A --severity display filter must not change the benchmark (uses the full set)."""
    a = OfflineFortinetScanner(CONF, verbose=False); a.scan()
    score_full = a.benchmark_score("cis")["score_pct"]
    b = OfflineFortinetScanner(CONF, verbose=False); b.scan()
    b.filter_severity("CRITICAL")   # drop everything below CRITICAL from display
    score_filtered = b.benchmark_score("cis")["score_pct"]
    assert score_full == score_filtered


def test_unknown_framework_raises():
    with pytest.raises(ValueError):
        _scanner([]).benchmark_score("iso27001")


def test_save_benchmark_csv_and_json(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    csv_p = str(tmp_path / "b.csv")
    json_p = str(tmp_path / "b.json")
    sc.save_benchmark(csv_p, "cis")
    sc.save_benchmark(json_p, "cis")
    rows = list(csv.reader(open(csv_p, newline="", encoding="utf-8")))
    assert rows[0] == ["Framework", "Section", "Control", "Status", "Worst Severity", "Findings"]
    assert len(rows) - 1 == sc.benchmark_score("cis")["total_controls"]
    doc = json.load(open(json_p))
    assert doc["framework"] == "CIS" and "sections" in doc and doc["controls"]
