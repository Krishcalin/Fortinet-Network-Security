"""
Tests for the Risk-Prioritization Engine (severity x exploitability x exposure
-> P1-P4 fix-first tiers), the bundled threat-intel snapshot, and the report
integration.

Run:  python -m pytest test_data/test_risk_prioritizer.py -v
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_prioritizer import (  # noqa: E402
    RiskPrioritizer, ThreatIntel, TIER_META, TIER_THRESHOLDS, by_finding,
    DEFAULT_INTEL_PATH,
)


class FakeFinding:
    """Minimal stand-in for a scanner Finding (object with attributes)."""

    def __init__(self, rule_id, severity, category, cve=None, name=None):
        self.rule_id = rule_id
        self.severity = severity
        self.category = category
        self.cve = cve
        self.name = name or rule_id
        self.file_path = "FW-TEST"


def _intel():
    return ThreatIntel()


def _rp():
    return RiskPrioritizer(_intel())


# --------------------------------------------------------------- snapshot ---

def test_bundled_snapshot_loads_and_has_kev():
    intel = _intel()
    assert intel.available
    assert len(intel.cves) == 75
    assert intel.kev_count == 19
    # meta counts must match the actual cves map (guards against drift)
    assert intel.meta.get("cve_count") == len(intel.cves)
    assert intel.meta.get("kev_count") == intel.kev_count


def test_known_kev_cve_flagged():
    intel = _intel()
    e = intel.get("CVE-2022-40684")
    assert e["kev"] is True
    assert e["kev_date"]
    assert e["epss"] > 0.9  # famous, near-certain exploitation


def test_non_kev_cve_not_flagged():
    intel = _intel()
    e = intel.get("CVE-2024-26008")
    assert e is not None
    assert e["kev"] is False


def test_get_is_case_insensitive_and_none_safe():
    intel = _intel()
    assert intel.get("cve-2022-40684") is not None
    assert intel.get(None) is None
    assert intel.get("CVE-0000-0000") is None


# ----------------------------------------------------------- exposure ctx ---

def test_exposure_context_wide_open():
    findings = [FakeFinding("FORTIOS-EXPOSURE-001", "CRITICAL", "Attack Surface")]
    ctx = RiskPrioritizer.exposure_context(findings)
    assert ctx["data"] == "WIDE_OPEN"
    assert ctx["mgmt"] is False


def test_exposure_context_exposed_only():
    findings = [FakeFinding("FORTIOS-EXPOSURE-002", "HIGH", "Attack Surface")]
    ctx = RiskPrioritizer.exposure_context(findings)
    assert ctx["data"] == "EXPOSED"


def test_exposure_context_mgmt():
    findings = [FakeFinding("MITRE-T1595-001", "CRITICAL", "MITRE ATT&CK Resilience")]
    ctx = RiskPrioritizer.exposure_context(findings)
    assert ctx["mgmt"] is True
    assert ctx["data"] == "NONE"


def test_exposure_context_none():
    findings = [FakeFinding("FORTIOS-ADMIN-003", "MEDIUM", "Admin Access")]
    ctx = RiskPrioritizer.exposure_context(findings)
    assert ctx == {"data": "NONE", "mgmt": False}


# -------------------------------------------------------------- scoring -----

def test_kev_critical_exposed_is_p1():
    rp = _rp()
    f = FakeFinding("FORTIOS-CVE-001", "CRITICAL", "Known CVEs", cve="CVE-2022-40684")
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False})
    assert r.tier == "P1"
    assert r.score == 100
    assert r.kev is True
    assert r.reachable is True


def test_kev_never_below_p2_floor():
    """A known-exploited but low-EPSS chained bug with no exposure still floors at P2."""
    rp = _rp()
    f = FakeFinding("FORTIOS-CVE-030", "MEDIUM", "Known CVEs", cve="CVE-2025-24472")
    r = rp.assess(f, {"data": "NONE", "mgmt": False})
    assert r.kev is True
    assert r.tier in ("P1", "P2")
    assert r.tier != "P3" and r.tier != "P4"


def test_low_internal_finding_is_p4():
    rp = _rp()
    f = FakeFinding("FORTIOS-BACKUP-001", "LOW", "Backup & DR")
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False})
    assert r.tier == "P4"
    assert r.reachable is False  # backup is not a perimeter category


def test_admin_finding_ignores_data_plane_exposure():
    """A weak admin-password finding must NOT get a bonus from a wide-open DATA
    policy — only from management-plane exposure."""
    rp = _rp()
    f = FakeFinding("FORTIOS-ADMIN-003", "MEDIUM", "Admin Access")
    r_data = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False})
    assert r_data.reachable is False
    assert r_data.score == 15  # base MEDIUM only
    r_mgmt = rp.assess(f, {"data": "NONE", "mgmt": True})
    assert r_mgmt.reachable is True
    assert r_mgmt.score > 15


def test_cve_takes_stronger_plane():
    """A FortiOS CVE is service- or management-reachable; it takes whichever
    plane is exposed."""
    rp = _rp()
    f = FakeFinding("FORTIOS-CVE-055", "CRITICAL", "Known CVEs", cve="CVE-2024-55591")
    r = rp.assess(f, {"data": "NONE", "mgmt": True})
    assert r.reachable is True  # picked up mgmt exposure


def test_non_cve_finding_has_no_epss_or_kev():
    rp = _rp()
    f = FakeFinding("FORTIOS-LOG-002", "HIGH", "Logging & Monitoring")
    r = rp.assess(f, {"data": "NONE", "mgmt": False})
    assert r.kev is False
    assert r.epss is None


def test_score_is_capped_at_100():
    rp = _rp()
    f = FakeFinding("FORTIOS-CVE-001", "CRITICAL", "Known CVEs", cve="CVE-2022-40684")
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": True})
    assert r.score <= 100


def test_factors_sum_relates_to_score():
    rp = _rp()
    f = FakeFinding("FORTIOS-CVE-002", "CRITICAL", "Known CVEs", cve="CVE-2023-25610")
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False})
    total = sum(fc["points"] for fc in r.factors)
    assert r.score == min(100, total)
    # every factor carries a human-readable label + detail
    for fc in r.factors:
        assert fc["label"] and isinstance(fc["points"], int)


# ----------------------------------------------------------- collection -----

def test_prioritize_orders_fix_first():
    rp = _rp()
    findings = [
        FakeFinding("FORTIOS-BACKUP-001", "LOW", "Backup & DR"),
        FakeFinding("FORTIOS-CVE-001", "CRITICAL", "Known CVEs", cve="CVE-2022-40684"),
        FakeFinding("FORTIOS-EXPOSURE-001", "CRITICAL", "Attack Surface"),
        FakeFinding("FORTIOS-LOG-002", "HIGH", "Logging & Monitoring"),
    ]
    results = rp.prioritize(findings)
    tiers = [r.tier for r in results]
    # sorted ascending by tier rank (P1 first)
    ranks = [{"P1": 0, "P2": 1, "P3": 2, "P4": 3}[t] for t in tiers]
    assert ranks == sorted(ranks)
    assert results[0].finding.rule_id == "FORTIOS-CVE-001"  # KEV crit exposed, score 100


def test_tier_counts_sum_to_total():
    rp = _rp()
    findings = [
        FakeFinding("FORTIOS-CVE-001", "CRITICAL", "Known CVEs", cve="CVE-2022-40684"),
        FakeFinding("FORTIOS-ADMIN-003", "MEDIUM", "Admin Access"),
        FakeFinding("FORTIOS-BACKUP-001", "LOW", "Backup & DR"),
    ]
    results = rp.prioritize(findings)
    counts = rp.tier_counts(results)
    assert sum(counts.values()) == len(findings)


def test_by_finding_map():
    rp = _rp()
    findings = [FakeFinding("FORTIOS-CVE-001", "CRITICAL", "Known CVEs", cve="CVE-2022-40684")]
    results = rp.prioritize(findings)
    m = by_finding(results)
    assert m[id(findings[0])].tier == "P1"


def test_works_on_dict_findings():
    """Prioritizer must accept plain dicts (report/JSON round-trip), not just objects."""
    rp = _rp()
    findings = [
        {"rule_id": "FORTIOS-CVE-001", "severity": "CRITICAL",
         "category": "Known CVEs", "cve": "CVE-2022-40684", "name": "x", "file_path": "fw"},
    ]
    results = rp.prioritize(findings)
    assert results[0].tier == "P1"
    assert results[0].to_dict()["kev"] is True


def test_missing_intel_degrades_gracefully(tmp_path):
    """No snapshot file -> engine still ranks by severity + reachability."""
    intel = ThreatIntel(path=str(tmp_path / "nope.json"))
    assert not intel.available
    rp = RiskPrioritizer(intel)
    f = FakeFinding("FORTIOS-CVE-001", "CRITICAL", "Known CVEs", cve="CVE-2022-40684")
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False})
    assert r.kev is False          # no intel -> no KEV boost
    assert r.tier in ("P1", "P2")  # still critical + exposed


# ----------------------------------------------------------- integration ---

def test_scanner_prioritize_and_html(tmp_path):
    """End-to-end: the scanner exposes prioritize() and the HTML report renders
    the priority section without error."""
    from fortinet_scanner import FortinetScanner, Finding

    class _S(FortinetScanner):
        def __init__(self):
            self.findings = []
            self.host = "fw"
            self._sys_info = {"hostname": "fw", "version": "7.2.0"}
            self.verbose = False

    s = _S()
    s.findings = [
        Finding("FORTIOS-CVE-001", "Auth bypass", "Known CVEs", "CRITICAL",
                "fw", None, "FortiOS 7.2.0 < 7.2.9", "d", "r", cve="CVE-2022-40684"),
        Finding("FORTIOS-EXPOSURE-001", "Inbound ALL", "Attack Surface", "CRITICAL",
                "fw", None, "policy 1", "d", "r"),
        Finding("FORTIOS-BACKUP-001", "No backup", "Backup & DR", "LOW",
                "fw", None, "", "d", "r"),
    ]
    results = s.prioritize()
    assert results and results[0].tier == "P1"

    out = tmp_path / "r.html"
    s.save_html(str(out))
    html = out.read_text(encoding="utf-8")
    assert "Risk-Prioritized Remediation Queue" in html
    assert "pbadge p1" in html
    assert "Top" in html and "fix first" in html


# ------------------------------------------------ review-hardening regressions ---

def test_exposure_context_is_case_insensitive():
    """Regression: mixed-case severities (common in JSON exports from other tools)
    must still be recognized as exposure signals."""
    findings = [{"rule_id": "FORTIOS-EXPOSURE-001", "severity": "Critical",
                 "category": "Attack Surface"}]
    ctx = RiskPrioritizer.exposure_context(findings)
    assert ctx["data"] == "WIDE_OPEN"
    # end-to-end: a mixed-case wide-open critical must reach P1 (not silently P2)
    rp = _rp()
    findings2 = [
        {"rule_id": "FORTIOS-EXPOSURE-001", "severity": "Critical", "category": "Attack Surface"},
        {"rule_id": "FORTIOS-SSLVPN-002", "severity": "Critical", "category": "SSL VPN"},
    ]
    results = rp.prioritize(findings2)
    assert all(r.tier == "P1" and r.reachable for r in results)


def test_mgmt_exposure_does_not_outrank_data_wide_open():
    """Regression: a management-only exposure must not score a data-plane CVE
    HIGHER than a genuinely wide-open data path (mgmt graded at EXPOSED, not WIDE_OPEN)."""
    rp = _rp()
    cve = FakeFinding("FORTIOS-CVE-070", "CRITICAL", "Known CVEs", cve="CVE-2023-33308")  # not KEV, ~0 EPSS
    mgmt_only = rp.assess(cve, {"data": "NONE", "mgmt": True})
    data_open = rp.assess(cve, {"data": "WIDE_OPEN", "mgmt": False})
    assert mgmt_only.score <= data_open.score
    # mgmt is graded at the EXPOSED level (+14), not WIDE_OPEN (+20)
    assert mgmt_only.score == 50 + 14


def test_reachability_uses_context_findings_not_filtered_set():
    """Regression: reachability is derived from the full context set, so a
    severity-filtered finding list still gets the exposure bonus."""
    rp = _rp()
    # 'displayed' list is only the CRITICAL CVE; the exposure signal (a HIGH
    # http-on-WAN finding) lives only in the full context set.
    cve = FakeFinding("FORTIOS-CVE-070", "CRITICAL", "Known CVEs", cve="CVE-2023-33308")
    exposure = FakeFinding("MITRE-T1557-001", "HIGH", "MITRE ATT&CK Resilience")
    full = [cve, exposure]
    filtered = [cve]
    with_ctx = rp.prioritize(filtered, context_findings=full)
    without_ctx = rp.prioritize(filtered)
    assert with_ctx[0].reachable is True
    assert without_ctx[0].reachable is False
    assert with_ctx[0].score > without_ctx[0].score


def test_refresh_survives_malformed_upstream(monkeypatch):
    """Regression: a null/non-dict EPSS or KEV payload must be skipped, not crash
    the whole refresh."""
    import io
    import urllib.request
    import risk_prioritizer as rpmod

    payloads = {
        "epss": b'{"status":"OK","data":null}',                 # data is null
        "kev": b'{"title":"KEV","vulnerabilities":[null,"x"]}',  # rows non-dict
    }

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.close()

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        body = payloads["epss"] if "first.org" in url else payloads["kev"]
        return _Resp(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    out = tmp_path_factory_file()
    meta = rpmod.refresh_threat_intel(["CVE-2022-40684", "CVE-2024-21762"], path=out)
    # It completed without raising; every requested CVE is present with safe defaults.
    assert meta["cve_count"] == 2
    assert meta["kev_count"] == 0  # KEV rows were malformed -> nobody flagged
    import json as _json
    doc = _json.load(open(out, encoding="utf-8"))
    assert doc["cves"]["CVE-2022-40684"]["epss"] == 0.0
    os.remove(out)


def tmp_path_factory_file():
    import tempfile
    fd, path = tempfile.mkstemp(suffix="_ti.json")
    os.close(fd)
    return path


# ------------------------------------------------ intel freshness / sneakernet ---

def test_snapshot_staleness():
    from datetime import date
    import risk_prioritizer as rpmod
    intel = ThreatIntel()
    # bundled snapshot: age relative to a fixed future date
    snap = intel.snapshot_date
    assert snap and snap != "unknown"
    y, m, d = (int(x) for x in snap.split("-"))
    fresh_ref = date(y, m, d)
    assert intel.age_days(fresh_ref) == 0
    assert intel.is_stale(45, fresh_ref) is False
    late = date(y + 1, m, d)
    assert intel.age_days(late) >= 365
    assert intel.is_stale(45, late) is True


def test_staleness_handles_bad_date(tmp_path):
    import json
    p = tmp_path / "ti.json"
    p.write_text(json.dumps({"meta": {"snapshot_date": "not-a-date"},
                             "cves": {"CVE-1": {"epss": 0.1, "kev": False}}}), encoding="utf-8")
    intel = ThreatIntel(path=str(p))
    assert intel.age_days() is None
    assert intel.is_stale() is False


def test_export_import_roundtrip(tmp_path):
    import json
    import risk_prioritizer as rpmod
    dest = tmp_path / "bundle.json"
    meta = rpmod.export_intel(str(dest))
    assert meta.get("cve_count", 0) >= 1
    # import it into a fresh location and confirm it loads
    installed = tmp_path / "installed.json"
    rpmod.import_intel(str(dest), dest=str(installed))
    ti = ThreatIntel(path=str(installed))
    assert ti.available and len(ti.cves) == len(ThreatIntel().cves)


def test_import_refuses_garbage(tmp_path):
    import json
    import risk_prioritizer as rpmod
    bad = tmp_path / "bad.json"
    bad.write_text('{"not":"intel"}', encoding="utf-8")
    dest = tmp_path / "dest.json"
    with pytest.raises(ValueError):
        rpmod.import_intel(str(bad), dest=str(dest))
    assert not dest.exists()  # nothing written on refusal


def test_ransomware_flag_surfaced():
    intel = ThreatIntel()
    # CVE-2022-40684 is KEV + ransomware-linked in the bundled snapshot
    entry = intel.get("CVE-2022-40684")
    if entry and entry.get("ransomware"):
        rp = _rp()

        class _F:
            rule_id = "FORTIOS-CVE-011"; severity = "CRITICAL"; category = "Known CVEs"
            cve = "CVE-2022-40684"; name = "x"; file_path = "fw"
        r = rp.assess(_F(), {"data": "NONE", "mgmt": False})
        assert r.ransomware is True
        assert "ransomware" in r.rationale.lower()
        assert r.to_dict()["ransomware"] is True


def test_import_refuses_nondict_meta_and_preserves_good_snapshot(tmp_path):
    """Regression: a present-but-non-dict meta must be refused BEFORE writing, so a
    good snapshot is never clobbered by an invalid file."""
    import json
    import risk_prioritizer as rpmod
    good = tmp_path / "active.json"
    rpmod.export_intel(str(good))  # a valid snapshot at dest
    before = good.read_text(encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"meta": [1, 2, 3],
                               "cves": {"CVE-1": {"epss": 0.1, "kev": True}}}), encoding="utf-8")
    with pytest.raises(ValueError):
        rpmod.import_intel(str(bad), dest=str(good))
    assert good.read_text(encoding="utf-8") == before  # good snapshot untouched


def test_import_refuses_partly_malformed_cves(tmp_path):
    """Regression: validation must inspect ALL entries, not just the first."""
    import json
    import risk_prioritizer as rpmod
    bad = tmp_path / "partial.json"
    bad.write_text(json.dumps({"meta": {"snapshot_date": "2026-01-01"},
                               "cves": {"CVE-A": {"epss": 0.1, "kev": True},
                                        "CVE-B": "garbage",
                                        "CVE-C": {"kev": True}}}), encoding="utf-8")
    dest = tmp_path / "dest.json"
    with pytest.raises(ValueError):
        rpmod.import_intel(str(bad), dest=str(dest))
    assert not dest.exists()


def test_import_recomputes_counts(tmp_path):
    """Regression: reported cve_count/kev_count come from the actual entries, not a
    (possibly stale/tampered) meta value."""
    import json
    import risk_prioritizer as rpmod
    src = tmp_path / "src.json"
    src.write_text(json.dumps({"meta": {"snapshot_date": "2026-01-01", "cve_count": 500, "kev_count": 99},
                               "cves": {"CVE-A": {"epss": 0.1, "kev": True},
                                        "CVE-B": {"epss": 0.2, "kev": False}}}), encoding="utf-8")
    dest = tmp_path / "dest.json"
    meta = rpmod.import_intel(str(src), dest=str(dest))
    assert meta["cve_count"] == 2 and meta["kev_count"] == 1


def test_load_coerces_nondict_meta(tmp_path):
    """Regression: ThreatIntel._load must not keep a non-dict meta (would crash
    snapshot_date/age_days)."""
    import json
    p = tmp_path / "ti.json"
    p.write_text(json.dumps({"meta": [1, 2], "cves": {"CVE-1": {"epss": 0.1, "kev": True}}}), encoding="utf-8")
    ti = ThreatIntel(path=str(p))
    assert ti.meta == {} and ti.available
    assert ti.snapshot_date == "unknown" and ti.age_days() is None  # no crash


def test_tier_meta_covers_all_tiers():
    assert set(TIER_META) == {"P1", "P2", "P3", "P4"}
    for t, m in TIER_META.items():
        assert m["label"] and m["window"] and m["blurb"]


def test_thresholds_monotonic():
    thr = [t for t, _ in TIER_THRESHOLDS]
    assert thr == sorted(thr, reverse=True)
