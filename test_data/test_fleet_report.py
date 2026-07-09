"""
Tests for the Fleet Analysis Console: record building, hostname-first de-dup with
collision surfacing, worst-device ranking, prevalence campaigns with
reachability gating, systemic findings, and JSON/HTML/PDF rendering.

Run:  python -m pytest test_data/test_fleet_report.py -v
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fleet_report import FleetReport, build_record, record_from_json, risk_score  # noqa: E402


def _finding(rule_id, severity, name="x", category="Cat", cve=None):
    return {"rule_id": rule_id, "severity": severity, "name": name,
            "category": category, "cve": cve, "file_path": "fw", "line_content": ""}


def _priority(rule_id, tier, reachable=False, kev=False, ransomware=False):
    return {"rule_id": rule_id, "tier": tier, "internet_reachable": reachable,
            "kev": kev, "ransomware": ransomware}


def _device(hostname, findings, priorities=None, version="7.2.5", model="FGT60F",
            serial="OFFLINE-CONFIG", source=None):
    meta = {"hostname": hostname, "version": version, "model": model, "serial": serial}
    return build_record(meta, findings, priorities, source=source or hostname)


# ----------------------------------------------------------- record ---------

def test_risk_score_matches_formula():
    assert risk_score({"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}) == 25 + 10 + 4 + 1
    assert risk_score({"CRITICAL": 10}) == 100  # capped


def test_build_record_counts_and_tiers():
    r = _device("fw1",
                [_finding("A", "CRITICAL"), _finding("B", "HIGH"), _finding("C", "HIGH")],
                [_priority("A", "P1"), _priority("B", "P2"), _priority("C", "P3")])
    assert r["counts"]["CRITICAL"] == 1 and r["counts"]["HIGH"] == 2
    assert r["tiers"]["P1"] == 1 and r["tiers"]["P2"] == 1 and r["tiers"]["P3"] == 1
    assert r["risk_score"] == 25 + 10 + 10


# ------------------------------------------------------------- dedup --------

def test_hostname_collision_disambiguated_and_surfaced():
    f = [_finding("A", "HIGH")]
    fleet = FleetReport([_device("dup", f, source="a.conf"),
                         _device("dup", f, source="b.conf"),
                         _device("unique", f, source="c.conf")])
    ids = [r["device_id"] for r in fleet.records]
    assert len(set(ids)) == 3                 # all disambiguated
    assert len(fleet.agg["collisions"]) == 1  # one collision surfaced
    assert fleet.agg["device_count"] == 3     # count not inflated/collapsed


def test_real_serials_are_not_collided():
    f = [_finding("A", "HIGH")]
    fleet = FleetReport([_device("same", f, serial="FGT-AAA", source="a"),
                         _device("same", f, serial="FGT-BBB", source="b")])
    assert len(fleet.agg["collisions"]) == 0  # distinct real serials -> distinct devices


# --------------------------------------------------- worst-device ranking ---

def test_worst_device_ranking_order():
    low = _device("low", [_finding("A", "LOW")])
    high = _device("high", [_finding("A", "CRITICAL"), _finding("B", "CRITICAL")])
    mid = _device("mid", [_finding("A", "HIGH")])
    fleet = FleetReport([low, mid, high])
    order = [r["hostname"] for r in fleet.agg["worst_devices"]]
    assert order == ["high", "mid", "low"]


# ---------------------------------------------------------- campaigns -------

def test_campaign_prevalence_and_dedup_per_device():
    # rule A on all 3 devices (once each even if it fires twice on one)
    d1 = _device("d1", [_finding("A", "HIGH"), _finding("A", "HIGH"), _finding("B", "MEDIUM")])
    d2 = _device("d2", [_finding("A", "HIGH")])
    d3 = _device("d3", [_finding("A", "HIGH")])
    fleet = FleetReport([d1, d2, d3])
    camp = {c["rule_id"]: c for c in fleet.agg["campaigns"]}
    assert camp["A"]["device_count"] == 3   # counted once per device despite 2x on d1
    assert camp["B"]["device_count"] == 1


def test_campaign_reachability_gating():
    """A CVE campaign reports how many devices it is internet-reachable on."""
    fin = [_finding("FORTIOS-CVE-002", "CRITICAL", cve="CVE-2024-21762")]
    d1 = _device("d1", fin, [_priority("FORTIOS-CVE-002", "P1", reachable=True, kev=True)])
    d2 = _device("d2", fin, [_priority("FORTIOS-CVE-002", "P2", reachable=False, kev=True)])
    d3 = _device("d3", fin, [_priority("FORTIOS-CVE-002", "P1", reachable=True, kev=True)])
    fleet = FleetReport([d1, d2, d3])
    c = {x["rule_id"]: x for x in fleet.agg["campaigns"]}["FORTIOS-CVE-002"]
    assert c["device_count"] == 3
    assert c["reachable"] == 2   # only d1 and d3 are reachable
    assert c["kev"] is True


def test_campaign_ranked_by_coverage_then_severity():
    # broad medium beats narrow high on coverage
    devs = [_device(f"d{i}", [_finding("BROAD", "MEDIUM")]) for i in range(4)]
    devs[0]["findings"].append(_finding("NARROW", "CRITICAL"))
    devs[0] = build_record({"hostname": "d0", "version": "7.2", "model": "m", "serial": "OFFLINE-CONFIG"},
                           [_finding("BROAD", "MEDIUM"), _finding("NARROW", "CRITICAL")])
    fleet = FleetReport(devs)
    top = fleet.agg["campaigns"][0]
    assert top["rule_id"] == "BROAD" and top["device_count"] == 4


# --------------------------------------------------------- systemic ---------

def test_systemic_findings_threshold():
    # present on all 4 -> systemic; present on 1 -> not
    devs = [_device(f"d{i}", [_finding("EVERY", "HIGH")]) for i in range(4)]
    devs[0] = build_record({"hostname": "d0", "version": "7", "model": "m", "serial": "OFFLINE-CONFIG"},
                           [_finding("EVERY", "HIGH"), _finding("RARE", "HIGH")])
    fleet = FleetReport(devs, systemic_frac=0.75)
    sysrules = {c["rule_id"] for c in fleet.agg["systemic"]}
    assert "EVERY" in sysrules and "RARE" not in sysrules


# ------------------------------------------------------- json ingest --------

def test_record_from_json_report():
    doc = {
        "system_info": {"hostname": "fw-json", "version": "v7.4.4", "model": "FGT100F", "serial": "S1"},
        "findings": [_finding("A", "CRITICAL"), _finding("B", "HIGH")],
        "priorities": [_priority("A", "P1", reachable=True), _priority("B", "P3")],
    }
    r = record_from_json(doc, source="fw-json.json")
    assert r["hostname"] == "fw-json" and r["version"] == "7.4.4"
    assert r["counts"]["CRITICAL"] == 1 and r["tiers"]["P1"] == 1


def test_json_without_priorities_degrades():
    doc = {"system_info": {"hostname": "fw"}, "findings": [_finding("A", "HIGH")]}
    r = record_from_json(doc)
    assert r["tiers"] == {"P1": 0, "P2": 0, "P3": 0, "P4": 0}  # no overlay -> zero tiers
    fleet = FleetReport([r])
    assert fleet.agg["campaigns"][0]["reachable"] == 0


# --------------------------------------------------------- rendering --------

def test_fleet_renders_json_html_pdf(tmp_path):
    fin = [_finding("FORTIOS-ADMIN-003", "HIGH", name="Weak admin password"),
           _finding("FORTIOS-CVE-002", "CRITICAL", cve="CVE-2024-21762")]
    pr = [_priority("FORTIOS-ADMIN-003", "P2"), _priority("FORTIOS-CVE-002", "P1", reachable=True, kev=True)]
    fleet = FleetReport([_device("a", fin, pr, source="a.conf"),
                         _device("b", fin, pr, source="b.conf")])
    j, h, p = tmp_path / "f.json", tmp_path / "f.html", tmp_path / "f.pdf"
    fleet.save_json(str(j)); fleet.save_html(str(h)); fleet.save_pdf(str(p))
    doc = json.loads(j.read_text(encoding="utf-8"))
    assert doc["device_count"] == 2 and doc["campaigns"]
    html = h.read_text(encoding="utf-8")
    assert "Fleet Analysis" in html and "Remediation Campaigns" in html
    assert p.read_bytes()[:5] == b"%PDF-"


def test_empty_fleet_is_safe():
    fleet = FleetReport([])
    assert fleet.agg["device_count"] == 0
    assert fleet.agg["risk_max"] == 0 and fleet.agg["campaigns"] == []


# ------------------------------------------------ review-round regressions ---

def test_info_findings_excluded_for_consistent_aggregation():
    """INFO findings are dropped so --conf-dir (unfiltered) and --fleet-inputs
    (default-severity exports drop INFO) aggregate the same device identically."""
    r = build_record({"hostname": "fw"}, [_finding("A", "HIGH"), _finding("S", "INFO")],
                     [_priority("A", "P3"), _priority("S", "P4")])
    # _priority has no 'severity'; add it to exercise the priority INFO filter
    r2 = build_record({"hostname": "fw2"},
                      [_finding("A", "HIGH"), _finding("S", "INFO")],
                      [{"rule_id": "A", "tier": "P3", "severity": "HIGH", "internet_reachable": False},
                       {"rule_id": "S", "tier": "P4", "severity": "INFO", "internet_reachable": False}])
    assert r["counts"]["INFO"] == 0 and r["counts"]["HIGH"] == 1
    assert r2["tiers"]["P4"] == 0  # the INFO priority was dropped
    assert {c["rule_id"] for c in FleetReport([r]).agg["campaigns"]} == {"A"}


def test_systemic_threshold_no_float_overshoot():
    """ceil(round(frac*n)) must not drop a rule exactly on the boundary
    (0.14*50 == 7.0000...1 would wrongly ceil to 8)."""
    devs = [_device(f"d{i}", [_finding("EDGE", "HIGH")]) for i in range(7)]
    devs += [_device(f"c{i}", [_finding("OTHER", "LOW")]) for i in range(43)]
    fleet = FleetReport(devs, systemic_frac=0.14)   # threshold should be 7, not 8
    assert "EDGE" in {c["rule_id"] for c in fleet.agg["systemic"]}


def test_to_dict_campaign_merge_no_union_operator():
    """to_dict() must build campaign dicts without the 3.9+ `dict | dict` operator."""
    fleet = FleetReport([_device("a", [_finding("A", "HIGH")], [_priority("A", "P2")])])
    d = fleet.to_dict()
    assert d["campaigns"][0]["rule_id"] == "A"
    assert "fix_cli" in d["campaigns"][0] and "fix" not in d["campaigns"][0]


# ---- offline-scanner fleet ingestion helpers ----

def test_record_from_conf_skips_non_fortigate(tmp_path):
    from fortinet_offline_scanner import _record_from_conf
    good = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")
    garbage = tmp_path / "garbage.conf"
    garbage.write_text("this is not a fortigate backup\n", encoding="utf-8")
    assert _record_from_conf(str(garbage)) is None          # phantom device skipped
    assert _record_from_conf(good) is not None               # real backup kept


def test_fleet_inputs_dedup_realpath(tmp_path):
    import json as _json
    from fortinet_offline_scanner import _records_from_json_inputs
    doc = {"system_info": {"hostname": "fw-x", "serial": "OFFLINE-CONFIG", "version": "v7.2.5"},
           "findings": [_finding("A", "HIGH")]}
    p = tmp_path / "fw.json"
    p.write_text(_json.dumps(doc), encoding="utf-8")
    # same file twice (explicit) + via directory -> should load once
    recs = _records_from_json_inputs([str(p), str(p), str(tmp_path)])
    assert len(recs) == 1
