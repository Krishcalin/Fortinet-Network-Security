"""
Tests for the SOAR / ticketing exporters (Jira, ServiceNow, Splunk SOAR,
generic CloudEvents webhook) in fortinet_export.py, plus the save_* wiring.

Run:  python -m pytest test_data/test_soar_export.py -v
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fortinet_export as fx  # noqa: E402
import fortinet_scanner as fs  # noqa: E402
from fortinet_offline_scanner import OfflineFortinetScanner  # noqa: E402
from posture import finding_entity, PostureDelta  # noqa: E402

CONF = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")


def _finding(**kw):
    base = dict(rule_id="FORTIOS-SSLVPN-001", name="SSL-VPN web mode enabled",
                category="SSL VPN", severity="CRITICAL", file_path="fgt-hq-01",
                line_num=1423, line_content="set web-mode enable",
                description="SSL-VPN web mode is enabled.", recommendation="Disable web mode.",
                cwe="CWE-787", cve="CVE-2024-21762")
    base.update(kw)
    return fs.Finding(**base)


def _prio(f, tier="P1", **kw):
    d = {"rule_id": f.rule_id, "severity": f.severity, "tier": tier, "tier_label": "Fix Now",
         "priority_score": 92, "kev": True, "kev_date": "2024-02-09", "epss": 0.94,
         "epss_pct": 0.999, "internet_reachable": True, "ransomware": True,
         "rationale": "r", "factors": []}
    d.update(kw)
    return {id(f): d}


def _rec(f, tier="P2", status="open", resolved_at=None):
    """A slim posture rec matching a Finding's fingerprint (so keys align)."""
    rec = {"rule_id": f.rule_id, "entity": finding_entity(f.rule_id, f.line_content),
           "severity": f.severity, "name": f.name, "tier": tier,
           "first_seen": "2026-07-01T00:00:00", "last_seen": "2026-07-10T00:00:00",
           "status": status, "kev": False}
    if resolved_at:
        rec["resolved_at"] = resolved_at
    return rec


# ── dedup key: stable, host-scoped, evidence-independent ─────────────────────

def test_dedup_key_stable_and_host_scoped():
    f = _finding()
    k1 = fx._dedup_key("fgt-hq-01", f)
    k2 = fx._dedup_key("fgt-hq-01", _finding())  # same logical finding, new object
    assert k1 == k2 and len(k1) == 16
    # different device -> different ticket (no cross-device collapse)
    assert fx._dedup_key("fgt-dr-02", f) != k1


def test_dedup_key_ignores_volatile_evidence():
    # a cosmetic value change (evidence differs) must be the SAME ticket
    a = _finding(rule_id="FORTIOS-ADMIN-002", line_content="admintimeout=30", cve=None)
    b = _finding(rule_id="FORTIOS-ADMIN-002", line_content="admintimeout=20", cve=None)
    assert fx._dedup_key("h", a) == fx._dedup_key("h", b)


def test_dedup_key_from_rec_matches_live_key():
    # the anti-leak invariant: a resolved rec's key equals the open finding's key
    f = _finding(rule_id="FORTIOS-POLICY-001", line_content='policy=Allow-All (ID 7)', cve=None)
    assert fx._dedup_key_from_rec("h", _rec(f)) == fx._dedup_key("h", f)


# ── min-tier filtering ───────────────────────────────────────────────────────

def test_min_tier_filters_on_prioritizer_tier():
    hi = _finding(rule_id="A-1")
    lo = _finding(rule_id="B-2", severity="LOW", cve=None)
    prio = {**_prio(hi, tier="P1"), **_prio(lo, tier="P4")}
    doc = fx.build_webhook([hi, lo], host="h", prio_by_id=prio, min_tier="P2")
    rids = {i["body"]["data"]["rule_id"] for i in doc["items"]}
    assert rids == {"A-1"}  # P4 dropped


def test_min_tier_falls_back_to_severity_without_prioritizer():
    crit = _finding(rule_id="A-1", severity="CRITICAL", cve=None)
    info = _finding(rule_id="B-2", severity="INFO", cve=None)
    doc = fx.build_jira([crit, info], host="h", min_tier="P1")  # no prio_by_id
    keys = [i["body"]["fields"]["summary"] for i in doc["items"]]
    assert len(keys) == 1 and "A-1" in keys[0]  # only CRITICAL->P1 survives


# ── Jira ─────────────────────────────────────────────────────────────────────

def test_jira_v3_adf_and_labels():
    f = _finding()
    doc = fx.build_jira([f], host="fgt-hq-01", prio_by_id=_prio(f), project_key="NET")
    body = doc["items"][0]["body"]
    fields = body["fields"]
    assert fields["project"]["key"] == "NET" and fields["issuetype"]["name"] == "Bug"
    # ADF description with type:text on every leaf
    desc = fields["description"]
    assert desc["type"] == "doc" and desc["version"] == 1
    for block in desc["content"]:
        for leaf in block.get("content", []):
            if leaf.get("type") == "text":
                assert "text" in leaf
    # labels are space-free and carry the fingerprint + severity
    key = doc["items"][0]["dedup_key"]
    assert f"fw-fp-{key}" in fields["labels"]
    assert all(" " not in l for l in fields["labels"])
    assert "sev-critical" in fields["labels"]
    # tier P1 -> Highest
    assert fields["priority"] == {"name": "Highest", "id": "1"}
    # entity property carries the machine-readable key
    prop = body["properties"][0]
    assert prop["key"] == "fwFinding" and prop["value"]["fingerprint"] == key


def test_jira_v2_plain_string_description():
    f = _finding()
    doc = fx.build_jira([f], host="h", api_version=2)
    desc = doc["items"][0]["body"]["fields"]["description"]
    assert isinstance(desc, str) and "Risk" in desc


def test_jira_no_priority_when_disabled():
    f = _finding()
    doc = fx.build_jira([f], host="h", set_priority=False)
    assert "priority" not in doc["items"][0]["body"]["fields"]


# ── ServiceNow ───────────────────────────────────────────────────────────────

def test_servicenow_urgency_impact_no_priority():
    f = _finding()
    doc = fx.build_servicenow([f], host="h", prio_by_id=_prio(f, tier="P1"))
    body = doc["items"][0]["body"]
    assert body["urgency"] == "1" and body["impact"] == "1"
    assert "priority" not in body  # OOB data lookup derives it; never send it
    assert body["correlation_id"] == f"fwscan:{doc['items'][0]['dedup_key']}"
    assert body["correlation_display"] == "FortiGate Security Scanner"
    assert len(body["short_description"]) <= 160
    assert len(body["description"]) <= 4000


def test_servicenow_correlation_id_under_100_chars():
    f = _finding()
    cid = fx.build_servicenow([f], host="h")["items"][0]["body"]["correlation_id"]
    assert len(cid) <= 100


# ── Splunk SOAR ──────────────────────────────────────────────────────────────

def test_splunk_container_and_artifact_sdi():
    f = _finding()
    doc = fx.build_splunk_soar([f], host="h", prio_by_id=_prio(f))
    c = doc["items"][0]["body"]
    key = doc["items"][0]["dedup_key"]
    assert c["source_data_identifier"] == f"fwscan:{key}"
    assert c["severity"] == "high" and c["severity"].islower()
    art = c["artifacts"][0]
    assert art["source_data_identifier"] == f"fwscan:{key}:1"
    assert "container_id" not in art  # implied for embedded artifacts
    assert art["cef"]["cs1"] == "FORTIOS-SSLVPN-001"


def test_splunk_severity_is_lowercase_shipped_name():
    for sev, want in [("CRITICAL", "high"), ("HIGH", "high"), ("MEDIUM", "medium"),
                      ("LOW", "low"), ("INFO", "low")]:
        f = _finding(rule_id="X", severity=sev, cve=None)
        c = fx.build_splunk_soar([f], host="h")["items"][0]["body"]
        assert c["severity"] == want


# ── Webhook (CloudEvents) ────────────────────────────────────────────────────

def test_webhook_cloudevents_shape():
    f = _finding()
    doc = fx.build_webhook([f], host="fgt-hq-01", prio_by_id=_prio(f),
                           now_iso="2026-07-10T09:20:00", tool_version="4.0.0")
    ce = doc["items"][0]["body"]
    assert ce["specversion"] == "1.0"
    key = doc["items"][0]["dedup_key"]
    # record identity is data.dedup_key / subject, NOT the per-emission id
    assert ce["subject"] == key and ce["data"]["dedup_key"] == key
    assert ce["id"].startswith(key + "-") and ce["id"] != key
    assert ce["type"] == "com.krishcalin.fortinet.finding.new"
    d = ce["data"]
    assert d["priority"]["tier"] == "P1" and d["priority"]["sla"] == "24-72h"
    # epss is a probability in [0,1], distinct from percentile
    assert 0.0 <= d["threat"]["epss"] <= 1.0 and d["threat"]["epss_percentile"] == 0.999
    assert d["threat"]["kev"] is True
    assert d["vulnerability"]["cve"] == "CVE-2024-21762"
    # remediation is populated even with no KB (finding-derived fallback)
    assert d["remediation"]["summary"] and d["remediation"]["steps"]


# ── lifecycle from a posture delta (the anti-leak contract) ──────────────────

def test_lifecycle_new_carried_reopened_resolved():
    new_f = _finding(rule_id="A-1")
    carried_f = _finding(rule_id="B-2", cve=None)
    reopened_f = _finding(rule_id="C-3", cve=None)
    resolved_f = _finding(rule_id="D-4", cve=None)  # absent from live findings
    live = [new_f, carried_f, reopened_f]

    delta = PostureDelta()
    delta.host = "h"
    delta.new = [_rec(new_f)]
    delta.carried = [_rec(carried_f)]
    delta.reopened = [_rec(reopened_f)]
    delta.resolved = [_rec(resolved_f, status="resolved", resolved_at="2026-07-10T00:00:00")]

    doc = fx.build_webhook(live, host="h", delta=delta)
    by_key = {i["dedup_key"]: i["op"] for i in doc["items"]}
    assert by_key[fx._dedup_key("h", new_f)] == "create"
    assert by_key[fx._dedup_key("h", carried_f)] == "update"
    assert by_key[fx._dedup_key("h", reopened_f)] == "reopen"
    # the resolved finding is NOT in `live` yet MUST appear as a closure, and its
    # key MUST equal the key its open ticket had (else the ticket leaks forever)
    resolved_key = fx._dedup_key("h", resolved_f)
    assert by_key.get(resolved_key) == "resolve"
    closure = next(i for i in doc["items"] if i["dedup_key"] == resolved_key)
    assert closure["body"]["data"]["event"] == "resolved"


def test_resolved_closures_across_all_targets():
    resolved_f = _finding(rule_id="D-4", cve=None)
    delta = PostureDelta()
    delta.host = "h"
    delta.resolved = [_rec(resolved_f, status="resolved", resolved_at="2026-07-10T00:00:00")]
    for builder in (fx.build_jira, fx.build_servicenow, fx.build_splunk_soar, fx.build_webhook):
        doc = builder([], host="h", delta=delta)  # no live findings, only a closure
        assert len(doc["items"]) == 1 and doc["items"][0]["op"] == "resolve"
        assert doc["items"][0]["dedup_key"] == fx._dedup_key("h", resolved_f)


def test_upsert_when_no_delta():
    f = _finding()
    doc = fx.build_servicenow([f], host="h")  # no delta
    assert doc["items"][0]["op"] == "upsert"


def test_resolved_closure_uses_severity_fallback_tier():
    # Regression: when the prioritizer was unavailable, a rec's stored tier is ""
    # A stricter --soar-min-tier must still CLOSE the ticket it would have OPENED
    # (the create side falls back to severity-derived tier; the close side must too,
    # or the ticket leaks forever).
    crit = _finding(rule_id="A-1", severity="CRITICAL", cve=None)  # severity -> P1
    # rec with empty tier (degraded mode) but CRITICAL severity
    rec = {"rule_id": "A-1", "entity": finding_entity("A-1", crit.line_content),
           "severity": "CRITICAL", "name": crit.name, "tier": "",
           "first_seen": "2026-07-01T00:00:00", "last_seen": "2026-07-10T00:00:00",
           "status": "resolved", "resolved_at": "2026-07-10T00:00:00", "kev": False}
    delta = PostureDelta()
    delta.host = "h"
    delta.resolved = [rec]
    # min_tier P2 (stricter than P4): the CRITICAL finding would have been ticketed
    # (P1 <= P2), so its closure MUST also be emitted.
    doc = fx.build_jira([], host="h", delta=delta, min_tier="P2")
    assert len(doc["items"]) == 1 and doc["items"][0]["op"] == "resolve"
    assert doc["items"][0]["dedup_key"] == fx._dedup_key("h", crit)


# ── save_* wiring on a real offline scan ─────────────────────────────────────

def test_save_soar_end_to_end(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    for name, saver in [("jira", sc.save_jira), ("sn", sc.save_servicenow),
                        ("soar", sc.save_splunk_soar), ("wh", sc.save_webhook)]:
        p = str(tmp_path / f"{name}.json")
        saver(p)
        doc = json.load(open(p, encoding="utf-8"))
        assert doc["items"] and doc["meta"]["host"]
        assert all(i["dedup_key"] and i["op"] for i in doc["items"])


def test_save_soar_min_tier_reduces(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    all_p, p2_p = str(tmp_path / "all.json"), str(tmp_path / "p2.json")
    sc.save_webhook(all_p, min_tier="P4")
    sc.save_webhook(p2_p, min_tier="P2")
    n_all = len(json.load(open(all_p))["items"])
    n_p2 = len(json.load(open(p2_p))["items"])
    assert n_all >= n_p2 > 0
