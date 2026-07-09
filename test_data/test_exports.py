"""
Tests for the machine-ingestible exports (SARIF 2.1.0, OCSF) and the
remediation / rollback CLI script generator.

Run:  python -m pytest test_data/test_exports.py -v
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fortinet_export as fx  # noqa: E402
import fortinet_scanner as fs  # noqa: E402
from fortinet_offline_scanner import OfflineFortinetScanner  # noqa: E402

CONF = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")


def _finding(**kw):
    base = dict(rule_id="FORTIOS-ADMIN-001", name="n", category="Admin Access",
                severity="HIGH", file_path="fw", line_num=None, line_content="lc",
                description="d", recommendation="r", cwe="CWE-319")
    base.update(kw)
    return fs.Finding(**base)


# ── SARIF ────────────────────────────────────────────────────────────────────

def test_sarif_structure_and_levels():
    findings = [
        _finding(rule_id="A-1", severity="CRITICAL"),
        _finding(rule_id="A-2", severity="MEDIUM"),
        _finding(rule_id="A-3", severity="LOW"),
    ]
    doc = fx.build_sarif(findings, tool_version="4.0.0", artifact_uri="fw.conf")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "FortiGate Security Scanner"
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 3
    level = {r["ruleId"]: r["level"] for r in run["results"]}
    assert level["A-1"] == "error" and level["A-2"] == "warning" and level["A-3"] == "note"
    # every result carries a location + stable fingerprint
    for r in run["results"]:
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "fw.conf"
        assert r["partialFingerprints"]["fortigateFindingHash"]


def test_sarif_dedupes_rules():
    findings = [_finding(rule_id="DUP"), _finding(rule_id="DUP")]
    doc = fx.build_sarif(findings)
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_enrichment_from_prio():
    f = _finding(rule_id="FORTIOS-CVE-002", cve="CVE-2024-21762", severity="CRITICAL")
    prio = {id(f): {"tier": "P1", "priority_score": 100, "kev": True, "epss": 0.83}}
    doc = fx.build_sarif([f], prio_by_id=prio)
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["priority_tier"] == "P1" and props["kev"] is True and props["cve"] == "CVE-2024-21762"
    # cve rule gets an NVD helpUri
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "nvd.nist.gov" in rule.get("helpUri", "")


# ── OCSF ─────────────────────────────────────────────────────────────────────

def test_ocsf_events():
    f = _finding(severity="CRITICAL", cve="CVE-2024-21762")
    prio = {id(f): {"tier": "P1", "priority_score": 100, "kev": True, "epss": 0.83}}
    events = fx.build_ocsf([f], meta={"hostname": "fw", "epoch": 123}, prio_by_id=prio)
    assert len(events) == 1
    e = events[0]
    assert e["class_uid"] == 2003 and e["category_uid"] == 2
    assert e["severity_id"] == 5  # CRITICAL
    assert e["finding_info"]["uid"] == "FORTIOS-ADMIN-001"
    assert e["unmapped"]["kev"] is True and e["unmapped"]["cve"] == "CVE-2024-21762"
    assert e["time"] == 123


def test_ocsf_severity_ids_in_range():
    findings = [_finding(severity=s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
    for e in fx.build_ocsf(findings):
        assert 1 <= e["severity_id"] <= 5


# ── save_sarif / save_ocsf on a real scan ────────────────────────────────────

def test_save_sarif_ocsf_end_to_end(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    sarif_p = str(tmp_path / "r.sarif")
    ocsf_p = str(tmp_path / "r.ocsf.json")
    sc.save_sarif(sarif_p)
    sc.save_ocsf(ocsf_p)
    doc = json.load(open(sarif_p))
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]
    events = json.load(open(ocsf_p))
    assert events and all(e["class_uid"] == 2003 for e in events)


# ── remediation / rollback script ────────────────────────────────────────────

def test_fix_script_generation(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    fix_p = str(tmp_path / "fix.conf")
    roll_p = str(tmp_path / "rollback.conf")
    sc.save_remediation_script(fix_p, roll_p, tier_max="P4")
    fix = open(fix_p).read()
    roll = open(roll_p).read()
    # runnable non-disruptive config fixes appear uncommented
    assert "set admin-https-redirect enable" in fix
    # a disruptive firmware upgrade is present but commented out
    assert "DISRUPTIVE" in fix
    # rollback script is produced with content
    assert roll.strip() and "rollback" in roll.lower()


def test_fix_script_disruptive_classifier():
    # negation-aware: "Non-disruptive ... no reboot" must NOT be disruptive even
    # though it mentions sessions being dropped / re-authenticating
    assert fs.FortinetScanner._is_disruptive(
        "Non-disruptive to data-plane traffic and no reboot. Sessions re-authenticate.") is False
    assert fs.FortinetScanner._is_disruptive(
        "A firmware upgrade REBOOTS the device and briefly interrupts all traffic.") is True
    assert fs.FortinetScanner._is_disruptive("") is False


def test_fix_script_tier_filter(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    p1 = str(tmp_path / "p1.conf")
    p4 = str(tmp_path / "p4.conf")
    sc.save_remediation_script(p1, tier_max="P1")
    sc.save_remediation_script(p4, tier_max="P4")
    # P4 (all tiers) must include at least as many finding blocks as P1
    n_p1 = open(p1).read().count("# ---- [")
    n_p4 = open(p4).read().count("# ---- [")
    assert n_p4 >= n_p1 > 0
