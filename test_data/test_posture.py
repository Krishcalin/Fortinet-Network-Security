"""
Tests for the Continuous Posture State: stable finding identity, the file-based
history store (new/carried/resolved/reopened), risk-acceptance exceptions with
fail-open, SLA aging, newly-weaponized detection, and trend snapshots. Also a
regression that config-drift matching no longer flips on volatile values.

Run:  python -m pytest test_data/test_posture.py -v
"""
import json
import os
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from posture import (  # noqa: E402
    PostureStore, Exceptions, finding_fingerprint, finding_entity, TIER_SLA_DAYS,
)


def F(rid, sev="HIGH", lc="", name="n", cve=None):
    return {"rule_id": rid, "severity": sev, "line_content": lc, "name": name, "cve": cve}


def P(rid, tier, kev=False, lc=""):
    return {"rule_id": rid, "tier": tier, "kev": kev, "line_content": lc}


# ----------------------------------------------------- stable identity ------

def test_fingerprint_ignores_volatile_values():
    a = finding_fingerprint(F("FORTIOS-ADMIN-002", lc="admintimeout=30 minutes"))
    b = finding_fingerprint(F("FORTIOS-ADMIN-002", lc="admintimeout=20 minutes"))
    assert a == b == "FORTIOS-ADMIN-002"


def test_entity_extraction():
    assert finding_entity("X", "policy 5 (p5): srcintf=WAN") == "policy:5"
    assert finding_entity("X", "interface=port1, allowaccess=http https") == "iface:port1"
    assert finding_entity("X", 'orphaned address object "SRV-OLD"') == "name:SRV-OLD"
    assert finding_entity("X", "admintimeout=30 minutes") == ""   # singleton


def test_entity_matches_real_scanner_formats():
    """Regression: the entity extractor must match the formats the scanner ACTUALLY
    emits — `policy=Name (ID n)`, single-quoted object names, and object key=name —
    or per-instance findings collapse into one fingerprint and hide live findings."""
    assert finding_entity("FORTIOS-POLICY-002", "policy=Legacy (ID 10), src=all, dst=all") == "policy:10"
    assert finding_entity("FORTIOS-AUTH-001", "LDAP 'DC1' secure=disable, port=389") == "name:DC1"
    assert finding_entity("FORTIOS-AUTH-002", "RADIUS 'ISE' secret length < 16 chars") == "name:ISE"
    assert finding_entity("FORTIOS-CERT-001", "certificate=Fortinet_Factory, CN=support") == "certificate:Fortinet_Factory"
    assert finding_entity("X", "admin=admin, accprofile=super_admin") == "admin:admin"


def test_per_instance_findings_do_not_collapse():
    """Two policies / two LDAP servers must get DISTINCT fingerprints."""
    p10 = finding_fingerprint(F("FORTIOS-POLICY-002", lc="policy=A (ID 10), src=all"))
    p20 = finding_fingerprint(F("FORTIOS-POLICY-002", lc="policy=B (ID 20), src=all"))
    assert p10 != p20 and p10 == "FORTIOS-POLICY-002|policy:10"
    dc1 = finding_fingerprint(F("FORTIOS-AUTH-001", lc="LDAP 'DC1' secure=disable"))
    dc2 = finding_fingerprint(F("FORTIOS-AUTH-001", lc="LDAP 'DC2' secure=disable"))
    assert dc1 != dc2


def test_fingerprint_distinguishes_entities():
    a = finding_fingerprint(F("FORTIOS-EXPOSURE-002", lc="policy 5 (a): svc SSH"))
    b = finding_fingerprint(F("FORTIOS-EXPOSURE-002", lc="policy 7 (b): svc RDP"))
    assert a != b and a == "FORTIOS-EXPOSURE-002|policy:5"


# ------------------------------------------------------- lifecycle ----------

def _store(tmp_path):
    return PostureStore(str(tmp_path / "hist.json"))


def test_first_scan_all_new(tmp_path):
    s = _store(tmp_path)
    d = s.update("fw", [F("A"), F("B")], [P("A", "P1"), P("B", "P2")],
                 now=datetime(2026, 7, 1), risk_score=35)
    assert len(d.new) == 2 and not d.carried and not d.resolved
    assert d.prev_date is None and d.risk_delta is None


def test_carried_and_resolved(tmp_path):
    p = str(tmp_path / "h.json")
    PostureStore(p).update("fw", [F("A"), F("B")], now=datetime(2026, 7, 1)) or None
    s = PostureStore(p)
    s.update("fw", [F("A"), F("B")], now=datetime(2026, 7, 1))
    s.save()
    s2 = PostureStore(p)
    d = s2.update("fw", [F("A")], now=datetime(2026, 7, 2))   # B disappeared
    assert [r["rule_id"] for r in d.resolved] == ["B"]
    assert len(d.carried) == 1 and not d.new


def test_reopened_restarts_clock(tmp_path):
    p = str(tmp_path / "h.json")
    s = PostureStore(p); s.update("fw", [F("A")], [P("A", "P1")], now=datetime(2026, 7, 1)); s.save()
    s = PostureStore(p); s.update("fw", [], now=datetime(2026, 7, 2)); s.save()   # A resolved
    s = PostureStore(p)
    d = s.update("fw", [F("A")], [P("A", "P1")], now=datetime(2026, 7, 10))       # A back
    assert len(d.reopened) == 1 and not d.new
    # first_seen restarted at reopen -> not an ancient SLA breach
    assert not d.sla_breaches


def test_value_change_is_carried_not_churned(tmp_path):
    p = str(tmp_path / "h.json")
    s = PostureStore(p)
    s.update("fw", [F("FORTIOS-ADMIN-002", lc="admintimeout=30 minutes")], now=datetime(2026, 7, 1))
    s.save()
    s = PostureStore(p)
    d = s.update("fw", [F("FORTIOS-ADMIN-002", lc="admintimeout=20 minutes")], now=datetime(2026, 7, 2))
    assert len(d.carried) == 1 and not d.new and not d.resolved


# ------------------------------------------------------- exceptions ---------

def test_exception_accepts_finding(tmp_path):
    s = _store(tmp_path)
    exc = Exceptions([{"host": "fw", "rule_id": "A", "reason": "x", "approver": "y", "expires": "2030-01-01"}])
    d = s.update("fw", [F("A"), F("B")], exceptions=exc, now=datetime(2026, 7, 1))
    assert d.open_accepted == 1 and d.open_active == 1
    assert d.accepted[0]["rec"]["rule_id"] == "A"


def test_expired_exception_fails_open(tmp_path):
    s = _store(tmp_path)
    exc = Exceptions([{"host": "fw", "rule_id": "A", "expires": "2020-01-01"}])
    d = s.update("fw", [F("A")], exceptions=exc, now=datetime(2026, 7, 1))
    assert d.open_active == 1 and d.open_accepted == 0
    assert any(e["rule_id"] == "A" for e in d.expired_exceptions)


def test_exception_host_wildcard_and_entity_scope(tmp_path):
    s = _store(tmp_path)
    exc = Exceptions([
        {"host": "*", "rule_id": "G", "expires": "2030-01-01"},                 # any host
        {"host": "fw", "rule_id": "E", "entity": "policy:5", "expires": "2030-01-01"},  # entity-scoped
    ])
    d = s.update("fw", [F("G"), F("E", lc="policy 5 (a)"), F("E", lc="policy 9 (b)")],
                 exceptions=exc, now=datetime(2026, 7, 1))
    accepted = {a["rec"]["rule_id"] + "|" + a["rec"].get("entity", "") for a in d.accepted}
    assert "G|" in accepted and "E|policy:5" in accepted
    assert "E|policy:9" not in accepted   # entity-scoped exception does not cover policy 9


def test_malformed_exception_fails_open(tmp_path):
    """A present-but-unparseable `expires` must NOT permanently suppress — it
    fails open (finding stays active) and is flagged as expired."""
    s = _store(tmp_path)
    exc = Exceptions(["not a dict", {"host": "fw", "rule_id": "A", "expires": "garbage-date", "reason": "x"}])
    d = s.update("fw", [F("A")], exceptions=exc, now=datetime(2026, 7, 1))
    assert d.open_active == 1 and d.open_accepted == 0        # not suppressed
    assert any(e["rule_id"] == "A" for e in d.expired_exceptions)


def test_exception_without_expiry_suppresses(tmp_path):
    """An exception with no expires key is a standing acceptance (suppresses)."""
    s = _store(tmp_path)
    exc = Exceptions([{"host": "fw", "rule_id": "A", "reason": "permanent compensating control"}])
    d = s.update("fw", [F("A")], exceptions=exc, now=datetime(2026, 7, 1))
    assert d.open_accepted == 1


# ---------------------------------------------------------- SLA -------------

def test_sla_breach_by_tier(tmp_path):
    p = str(tmp_path / "h.json")
    s = PostureStore(p)
    s.update("fw", [F("A"), F("B")], [P("A", "P1"), P("B", "P3")], now=datetime(2026, 7, 1))
    s.save()
    s = PostureStore(p)
    # +5 days: P1 window 3 -> breach; P3 window 30 -> fine
    d = s.update("fw", [F("A"), F("B")], [P("A", "P1"), P("B", "P3")], now=datetime(2026, 7, 6))
    breached = {b["rec"]["rule_id"] for b in d.sla_breaches}
    assert breached == {"A"}
    assert d.sla_breaches[0]["age_days"] == 5 and d.sla_breaches[0]["window"] == TIER_SLA_DAYS["P1"]


def test_accepted_excluded_from_sla(tmp_path):
    p = str(tmp_path / "h.json")
    s = PostureStore(p)
    s.update("fw", [F("A")], [P("A", "P1")], now=datetime(2026, 7, 1)); s.save()
    s = PostureStore(p)
    exc = Exceptions([{"host": "fw", "rule_id": "A", "expires": "2030-01-01"}])
    d = s.update("fw", [F("A")], [P("A", "P1")], exceptions=exc, now=datetime(2026, 7, 20))
    assert not d.sla_breaches   # accepted risk is not an SLA breach


# ------------------------------------------------- newly weaponized ---------

class _PR:
    """Mimics risk_prioritizer.PriorityResult: tier/kev on the object, the actual
    finding on `.finding` (what production passes to update_posture)."""
    def __init__(self, finding, tier, kev=False):
        self.finding, self.tier, self.kev = finding, tier, kev


def test_priority_overlay_unwraps_wrapped_finding(tmp_path):
    """Regression (#8): update() must unwrap PriorityResult.finding before
    fingerprinting, or tier/kev attach to nothing and SLA never fires."""
    p = str(tmp_path / "h.json")
    fin = [F("A"), F("B")]
    pr = [_PR(F("A"), "P1"), _PR(F("B"), "P3")]   # wrapped, like production
    s = PostureStore(p); s.update("fw", fin, pr, now=datetime(2026, 7, 1)); s.save()
    s = PostureStore(p)
    d = s.update("fw", fin, pr, now=datetime(2026, 7, 6))  # +5d: P1 (window 3) breaches
    assert {b["rec"]["rule_id"] for b in d.sla_breaches} == {"A"}   # proves overlay attached


def test_accepted_finding_excluded_from_new(tmp_path):
    """Regression (#6): a NEW finding covered by an exception is accepted, not
    reported as new (that is the nagging we remove)."""
    s = _store(tmp_path)
    exc = Exceptions([{"host": "fw", "rule_id": "A", "expires": "2030-01-01"}])
    d = s.update("fw", [F("A"), F("B")], exceptions=exc, now=datetime(2026, 7, 1))
    assert {r["rule_id"] for r in d.new} == {"B"}   # A accepted, not "new"
    assert d.open_accepted == 1


def test_sla_boundary_uses_full_timedelta(tmp_path):
    """Regression (#4): a P1 finding breaches at exactly its window (>=), not a
    day late."""
    p = str(tmp_path / "h.json")
    s = PostureStore(p); s.update("fw", [F("A")], [_PR(F("A"), "P1")], now=datetime(2026, 7, 1, 9)); s.save()
    s = PostureStore(p)
    d = s.update("fw", [F("A")], [_PR(F("A"), "P1")], now=datetime(2026, 7, 4, 9))  # exactly 3 days
    assert len(d.sla_breaches) == 1


def test_kev_sticky_no_reweaponize_on_missing_enrichment(tmp_path):
    """Regression (#5): a scan with missing enrichment must not clear a known KEV
    flag and re-fire weaponization."""
    p = str(tmp_path / "h.json")
    s = PostureStore(p); s.update("fw", [F("C", cve="c")], [_PR(F("C"), "P2", kev=True)], now=datetime(2026, 7, 1)); s.save()
    s = PostureStore(p); s.update("fw", [F("C", cve="c")], priorities=None, now=datetime(2026, 7, 2)); s.save()  # no enrichment
    s = PostureStore(p)
    d = s.update("fw", [F("C", cve="c")], [_PR(F("C"), "P2", kev=True)], now=datetime(2026, 7, 3))
    assert not d.newly_weaponized   # already known-KEV; must not re-fire


def test_newly_weaponized_on_kev_flip(tmp_path):
    p = str(tmp_path / "h.json")
    s = PostureStore(p)
    s.update("fw", [F("CVE-x", cve="c")], [P("CVE-x", "P2", kev=False)], now=datetime(2026, 7, 1)); s.save()
    s = PostureStore(p)
    d = s.update("fw", [F("CVE-x", cve="c")], [P("CVE-x", "P2", kev=True)], now=datetime(2026, 7, 8))
    assert [r["rule_id"] for r in d.newly_weaponized] == ["CVE-x"]
    # not weaponized again on the next scan (already flagged)
    s.save(); s = PostureStore(p)
    d2 = s.update("fw", [F("CVE-x", cve="c")], [P("CVE-x", "P2", kev=True)], now=datetime(2026, 7, 9))
    assert not d2.newly_weaponized


# ---------------------------------------------------------- trend -----------

def test_trend_and_risk_delta(tmp_path):
    p = str(tmp_path / "h.json")
    s = PostureStore(p)
    s.update("fw", [F("A")], now=datetime(2026, 7, 1), risk_score=40); s.save()
    s = PostureStore(p)
    d = s.update("fw", [F("A"), F("B")], now=datetime(2026, 7, 2), risk_score=55)
    assert d.prev_risk_score == 40 and d.risk_score == 55 and d.risk_delta == 15
    assert len(s.trend("fw")) == 2


# ---------------------------------------------------- store robustness -------

def test_corrupt_store_fails_open(tmp_path):
    p = tmp_path / "h.json"
    p.write_text("{not valid json", encoding="utf-8")
    s = PostureStore(str(p))   # must not crash
    d = s.update("fw", [F("A")], now=datetime(2026, 7, 1))
    assert len(d.new) == 1


def test_store_roundtrip(tmp_path):
    p = str(tmp_path / "h.json")
    s = PostureStore(p); s.update("fw", [F("A")], now=datetime(2026, 7, 1)); s.save()
    doc = json.loads(open(p, encoding="utf-8").read())
    assert doc["schema"].startswith("fortinet-posture")
    assert "fw" in doc["devices"] and "FORTIOS-ADMIN" not in doc["devices"]  # keyed by host


# ---------------------------------------------- drift refactor regression ----

def test_drift_uses_stable_fingerprint(tmp_path):
    """apply_drift must not report a finding as resolved+new merely because a
    volatile value in line_content changed."""
    from fortinet_scanner import FortinetScanner, Finding

    class _S(FortinetScanner):
        def __init__(self):
            self.findings = []
            self.host = "fw"
            self._sys_info = {"hostname": "fw"}
            self.verbose = False

    base = {
        "generated": "2026-07-01T00:00:00",
        "findings": [{"rule_id": "FORTIOS-ADMIN-002", "file_path": "fw",
                      "line_content": "admintimeout=30 minutes", "severity": "MEDIUM",
                      "name": "idle timeout"}],
    }
    bp = tmp_path / "base.json"
    bp.write_text(json.dumps(base), encoding="utf-8")
    s = _S()
    s.findings = [Finding("FORTIOS-ADMIN-002", "idle timeout", "Admin Access", "MEDIUM",
                          "fw", None, "admintimeout=20 minutes", "d", "r")]
    s.apply_drift(str(bp))
    summ = [f for f in s.findings if f.rule_id == "FORTIOS-DRIFT-SUMMARY"][0]
    assert "new=0" in summ.line_content and "resolved=0" in summ.line_content
