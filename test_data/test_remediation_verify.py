"""
Tests for the remediation-verification loop (remediation_verify.py) + the
verify_fixes_report wiring.

Run:  python -m pytest test_data/test_remediation_verify.py -v
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import remediation_verify as rv  # noqa: E402
import fortinet_scanner as fs  # noqa: E402
from fortinet_offline_scanner import OfflineFortinetScanner  # noqa: E402

CONF = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")


def _f(rid, sev, ev, name="finding", **kw):
    return fs.Finding(rule_id=rid, name=name, category="c", severity=sev, file_path="fw",
                      line_num=1, line_content=ev, description="d", recommendation="r", **kw)


def test_classifies_all_four_states():
    prior = [_f("A-1", "HIGH", "x").to_dict(),
             _f("A-2", "CRITICAL", "admintimeout=30").to_dict(),
             _f("A-3", "MEDIUM", "old").to_dict()]
    current = [_f("A-2", "CRITICAL", "admintimeout=30"),  # persisting
               _f("A-3", "MEDIUM", "new"),                 # changed
               _f("B-9", "HIGH", "boom")]                  # regression ; A-1 remediated
    rep = rv.build_verification(prior, current, host="fw|S1")
    by = {i["rule_id"]: i["status"] for i in rep["items"]}
    assert by["A-1"] == "REMEDIATED"
    assert by["A-2"] == "PERSISTING"
    assert by["A-3"] == "CHANGED"
    assert [r["rule_id"] for r in rep["regressions"]] == ["B-9"]
    s = rep["summary"]
    assert s["total_prior"] == 3 and s["remediated"] == 1 and s["remediation_rate_pct"] == 33
    assert s["clean"] is False  # A-2 CRITICAL persists + B-9 HIGH regression


def test_pseudo_and_info_excluded():
    prior = [_f("FORTIOS-DRIFT-SUMMARY", "INFO", "z").to_dict(),
             _f("FORTIOS-RULEBASE-SCORE", "INFO", "z").to_dict(),
             _f("MITRE-SUMMARY-SCORE", "LOW", "z").to_dict(),
             _f("Z-1", "LOW", "keep").to_dict(),
             _f("Z-2", "INFO", "drop").to_dict()]
    rep = rv.build_verification(prior, [], host="h")
    ids = {i["rule_id"] for i in rep["items"]}
    assert ids == {"Z-1"}  # summaries/score + INFO all excluded


def test_cosmetic_value_change_is_changed_not_remediated():
    # a rule that fires once (singleton fingerprint = rule_id): value change => CHANGED,
    # never remediated+regression (stable identity, evidence-independent matching).
    prior = [_f("FORTIOS-ADMIN-002", "MEDIUM", "admintimeout=30").to_dict()]
    current = [_f("FORTIOS-ADMIN-002", "MEDIUM", "admintimeout=20")]
    rep = rv.build_verification(prior, current, host="h")
    assert len(rep["items"]) == 1 and not rep["regressions"]
    assert rep["items"][0]["status"] == "CHANGED"
    assert rep["items"][0]["before"] == "admintimeout=30"
    assert rep["items"][0]["after"] == "admintimeout=20"


def test_entity_keeps_instances_distinct():
    # two policy instances of one rule: remediating one leaves the other persisting
    prior = [_f("FORTIOS-POLICY-001", "HIGH", "policy=Allow-All (ID 7)").to_dict(),
             _f("FORTIOS-POLICY-001", "HIGH", "policy=Wide-Open (ID 9)").to_dict()]
    current = [_f("FORTIOS-POLICY-001", "HIGH", "policy=Wide-Open (ID 9)")]
    rep = rv.build_verification(prior, current, host="h")
    st = sorted(i["status"] for i in rep["items"])
    assert st == ["PERSISTING", "REMEDIATED"] and not rep["regressions"]


def test_clean_when_all_crit_high_remediated_no_new():
    # remaining findings are all remediated or low-sev persisting; no crit/high open, no regressions
    prior = [_f("H-1", "HIGH", "a").to_dict(), _f("L-1", "LOW", "b").to_dict()]
    current = [_f("L-1", "LOW", "b")]  # H-1 remediated, L-1 persists (LOW)
    rep = rv.build_verification(prior, current, host="h")
    assert rep["summary"]["clean"] is True   # no CRITICAL/HIGH left open, no new crit/high
    assert rep["summary"]["remediated"] == 1


def test_empty_prior_is_clean_100pct():
    rep = rv.build_verification([], [_f("X", "HIGH", "e")], host="h")
    # nothing was targeted -> 100% remediated of zero; but a HIGH regression -> not clean
    assert rep["summary"]["total_prior"] == 0 and rep["summary"]["remediation_rate_pct"] == 100
    assert rep["summary"]["regressions"] == 1 and rep["summary"]["clean"] is False


def test_kb_verify_command_attached():
    from remediation_kb import RemediationKB
    kb = RemediationKB()
    prior = [_f("FORTIOS-ADMIN-002", "MEDIUM", "admintimeout=30").to_dict()]
    rep = rv.build_verification(prior, [_f("FORTIOS-ADMIN-002", "MEDIUM", "admintimeout=30")], kb=kb, host="h")
    # persisting finding carries a KB verify command (if the KB has one for this rule)
    it = rep["items"][0]
    assert it["status"] == "PERSISTING"
    assert isinstance(it["verify_cmd"], str)


def test_render_text_and_html():
    prior = [_f("A-1", "HIGH", "x").to_dict(), _f("A-2", "CRITICAL", "y").to_dict()]
    rep = rv.build_verification(prior, [_f("A-2", "CRITICAL", "y")], host="h")
    txt = rv.render_text(rep, baseline_label="prev.json")
    assert "Remediation Verification" in txt and "%" in txt
    html = rv.render_html(rep, baseline_label="prev.json")
    assert "<table" in html and "ACTION REQUIRED" in html


# ── end-to-end on a real offline scan ────────────────────────────────────────

def test_verify_fixes_report_end_to_end(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    prior = str(tmp_path / "prior.json")
    sc.save_json(prior)
    # re-scan the SAME config: nothing fixed -> everything persists -> not clean (criticals) -> exit 2
    sc2 = OfflineFortinetScanner(CONF, verbose=False)
    sc2.scan()
    html = str(tmp_path / "v.html")
    js = str(tmp_path / "v.json")
    code = sc2.verify_fixes_report(prior, html_path=html, json_path=js)
    assert code == 2                      # unremediated criticals persist
    doc = json.load(open(js, encoding="utf-8"))
    assert doc["summary"]["remediated"] == 0
    assert doc["summary"]["persisting"] + doc["summary"]["changed"] == doc["summary"]["total_prior"]
    assert doc["summary"]["regressions"] == 0
    assert os.path.getsize(html) > 0


def test_verify_fixes_missing_prior_returns_2(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    assert sc.verify_fixes_report(str(tmp_path / "nope.json")) == 2


def test_severity_filtered_prior_no_false_regressions():
    # Regression (adversarial review HIGH): a prior report produced with --severity HIGH
    # contains only HIGH+; the current FULL scan's pre-existing MEDIUM/LOW findings must
    # NOT be reported as regressions (they were there before, just filtered out), and must
    # not flip clean / exit-2 gate a CI window that introduced nothing.
    prior = [_f("H-1", "HIGH", "a").to_dict(), _f("C-1", "CRITICAL", "b").to_dict()]  # floor = HIGH
    current = [_f("H-1", "HIGH", "a"), _f("C-1", "CRITICAL", "b"),   # persisting
               _f("M-9", "MEDIUM", "pre-existing"), _f("L-9", "LOW", "pre-existing")]
    rep = rv.build_verification(prior, current, host="h")
    assert rep["regressions"] == []              # MEDIUM/LOW below prior floor -> not regressions
    # (H-1/C-1 persist unchanged, so they remain unresolved crit/high -> not clean; the point
    #  of the fix is that the MEDIUM/LOW did not fabricate NEW regressions.)
    assert rep["summary"]["unresolved_critical_high"] == 2 and rep["summary"]["clean"] is False


def test_genuine_high_regression_still_flagged_under_high_floor():
    # A prior with only HIGH+ (floor HIGH): a NEW HIGH finding IS a real regression.
    prior = [_f("H-1", "HIGH", "a").to_dict()]
    current = [_f("H-1", "HIGH", "a"), _f("H-NEW", "HIGH", "boom")]
    rep = rv.build_verification(prior, current, host="h")
    assert [r["rule_id"] for r in rep["regressions"]] == ["H-NEW"]


def test_rulebase002_instances_get_distinct_fingerprints():
    # Regression (adversarial review LOW): the RULEBASE-002 line_content must key on the
    # policy id, not the quoted action, so distinct redundant policies stay distinct.
    from posture import finding_entity
    lc5 = "policy 5 (A) is covered by earlier policy 1 (B); same action=accept"
    lc7 = "policy 7 (C) is covered by earlier policy 1 (B); same action=accept"
    e5 = finding_entity("FORTIOS-RULEBASE-002", lc5)
    e7 = finding_entity("FORTIOS-RULEBASE-002", lc7)
    assert e5 == "policy:5" and e7 == "policy:7" and e5 != e7
