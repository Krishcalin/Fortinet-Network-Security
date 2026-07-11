"""
Tests for the compliance attestation pack (attestation.py) + save_attestation wiring.

Covers: canonical-JSON reproducibility, per-record + Merkle tamper localization,
SHA-256 / HMAC seal verification, risk-acceptance fail-open, anti-overclaim
(denominator + scope), OSCAL projection legality/link-resolution, and the
end-to-end save/verify path.

Run:  python -m pytest test_data/test_attestation.py -v
"""
import copy
import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import attestation as A  # noqa: E402
import fortinet_scanner as fs  # noqa: E402
from fortinet_offline_scanner import OfflineFortinetScanner  # noqa: E402
from posture import Exceptions  # noqa: E402

CONF = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")
FIXED = datetime(2026, 7, 10, 14, 0, 0, tzinfo=timezone.utc)


def _finding(rule_id, sev, controls, line="set x", **kw):
    f = fs.Finding(rule_id=rule_id, name=f"{rule_id} finding", category="Test",
                   severity=sev, file_path="fw", line_num=10, line_content=line,
                   description="d", recommendation="r", cwe=kw.get("cwe", "CWE-1"),
                   cve=kw.get("cve"))
    f.compliance = {"PCI-DSS": list(controls)}
    return f


def _bm(controls):
    """Synthetic benchmark_score output. controls = [(id, status)]."""
    out = []
    for cid, status in controls:
        out.append({"control": cid, "section": cid.split(".")[0], "status": status,
                    "findings": [], "worst_severity": None})
    return {"framework": "PCI-DSS", "total_controls": len(controls),
            "passed": sum(1 for _, s in controls if s == "PASS"),
            "failed": sum(1 for _, s in controls if s == "FAIL"),
            "score_pct": 0, "sections": {}, "controls": out}


def _build(findings, bm, host="fw|SER1", exceptions=None, coverage_meta=None, **kw):
    return A.build_attestation(
        findings, benchmarks={"PCI-DSS": bm}, host=host,
        device={"hostname": "fw", "model": "FGT60F", "serial": "SER1", "firmware": "v7.4.4"},
        tool_version="4.0.0", collection_dt=FIXED, report_dt=FIXED,
        exceptions=exceptions, coverage_meta=coverage_meta, **kw)


# ── reproducibility ──────────────────────────────────────────────────────────

def test_reproducible_root_and_body():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    bm = _bm([("1.2.1", "FAIL"), ("2.2.2", "PASS")])
    b1 = A.seal_attestation(_build([f], bm))
    b2 = A.seal_attestation(_build([_finding("A-1", "HIGH", ["1.2.1"])], bm))
    assert b1["body"]["manifest"]["merkle_root"] == b2["body"]["manifest"]["merkle_root"]
    assert A.canonical_bytes(b1["body"]) == A.canonical_bytes(b2["body"])
    assert b1["seal"]["value"] == b2["seal"]["value"]


def test_body_is_float_free():
    f = _finding("A-1", "HIGH", ["1.2.1"], cve="CVE-2024-21762")
    body = _build([f], _bm([("1.2.1", "FAIL")]))["body"]

    def walk(o):
        if isinstance(o, float):
            raise AssertionError(f"float in attestation body: {o!r}")
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(body)


# ── tamper localization ──────────────────────────────────────────────────────

def test_tamper_localized_to_record():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    b = A.seal_attestation(_build([f], _bm([("1.2.1", "FAIL"), ("2.2.2", "PASS")])))
    assert A.verify_attestation(b)["ok"]
    t = copy.deepcopy(b)
    t["body"]["results"][0]["controls"][0]["observations"][0]["evidence"] = "HACKED"
    res = A.verify_attestation(t)
    assert not res["ok"]
    assert any("record digest mismatch" in p for p in res["problems"])
    assert any("merkle_root mismatch" in p for p in res["problems"])


def test_reorder_and_delete_detected():
    fs_ = [_finding("A-1", "HIGH", ["1.2.1"]), _finding("B-2", "LOW", ["3.3.3"])]
    b = A.seal_attestation(_build(fs_, _bm([("1.2.1", "FAIL"), ("3.3.3", "FAIL")])))
    ctrls = b["body"]["results"][0]["controls"]
    t = copy.deepcopy(b)
    t["body"]["results"][0]["controls"] = list(reversed(ctrls))
    # reorder alone does not change the id-sorted record set, so the SEAL still
    # covers the same body?  No: body bytes changed (list order) -> seal invalid.
    assert not A.verify_attestation(t)["ok"]
    t2 = copy.deepcopy(b)
    del t2["body"]["results"][0]["controls"][0]
    assert not A.verify_attestation(t2)["ok"]


# ── seal ─────────────────────────────────────────────────────────────────────

def test_sha256_and_hmac_seal():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    u = _build([f], _bm([("1.2.1", "FAIL")]))
    plain = A.seal_attestation(u)
    assert plain["seal"]["alg"] == "SHA-256" and A.verify_attestation(plain)["ok"]
    keyed = A.seal_attestation(u, key=b"s3cret", key_id="k2026")
    assert keyed["seal"]["alg"] == "HMAC-SHA256" and keyed["seal"]["key_id"] == "k2026"
    assert A.verify_attestation(keyed, key=b"s3cret")["ok"]
    assert not A.verify_attestation(keyed, key=b"wrong")["ok"]
    # HMAC present but no key -> cannot verify
    assert not A.verify_attestation(keyed, key=None)["ok"]
    # never claims to be a signature
    assert "not a digital signature" in plain["seal"]["note"].lower()


def test_one_byte_body_edit_breaks_hmac():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    keyed = A.seal_attestation(_build([f], _bm([("1.2.1", "FAIL")])), key=b"k")
    t = copy.deepcopy(keyed)
    t["body"]["attestation"]["run_mode"] += "X"
    assert not A.verify_attestation(t, key=b"k")["ok"]


def test_seal_downgrade_forgery_is_rejected():
    # Regression (adversarial review HIGH): an attacker without the HMAC key edits the
    # body, recomputes the PUBLIC manifest/Merkle root, and swaps in a keyless SHA-256
    # seal. Verifying WITH the real key must reject the downgrade (not silently accept).
    f = _finding("A-1", "HIGH", ["1.2.1"])
    keyed = A.seal_attestation(_build([f], _bm([("1.2.1", "FAIL"), ("2.2.2", "PASS")])), key=b"realkey")
    forged = copy.deepcopy(keyed)
    # flip a FAIL control to PASS and drop its evidence
    c = next(x for x in forged["body"]["results"][0]["controls"] if x["control"] == "1.2.1")
    c["status"] = "PASS"
    c["observations"] = []
    # recompute the in-body manifest with the public API (no key needed)
    forged["body"]["manifest"] = A.build_manifest(A._attestation_records(forged["body"]))
    # downgrade: replace the HMAC seal with a keyless SHA-256 digest over the tampered body
    forged["seal"] = {"alg": "SHA-256", "value": A.sha256_hex(A.canonical_bytes(forged["body"])),
                      "computed_over": "canonical_bytes(body)", "note": "x"}
    res = A.verify_attestation(forged, key=b"realkey")
    assert not res["ok"]
    assert any("downgrade" in p for p in res["problems"])


def test_verify_survives_malformed_bundle():
    for bad in ({}, {"body": 1, "seal": {}}, {"body": {"results": [1, {"controls": [{}]}]}, "seal": {}}):
        res = A.verify_attestation(bad)
        assert res["ok"] is False and res["problems"]  # reports, never raises


def test_info_finding_does_not_block_risk_acceptance():
    # Regression (adversarial review MEDIUM): benchmark_score fails 1.2.1 on the HIGH
    # finding; an INFO finding also references 1.2.1 but is not a benchmark 'fail'. With
    # the HIGH finding accepted, the control must become RISK_ACCEPTED — the un-accepted
    # INFO finding must not keep it FAIL.
    hi = _finding("R-HI", "HIGH", ["1.2.1"], line="high")
    info = _finding("R-INFO", "INFO", ["1.2.1"], line="info")
    exc = Exceptions([{"host": "fw|SER1", "rule_id": "R-HI", "reason": "x",
                       "approver": "y", "expires": "2099-01-01"}])
    body = _build([hi, info], _bm([("1.2.1", "FAIL")]), exceptions=exc)["body"]
    c = _ctrl(body, "1.2.1")
    assert c["status"] == "RISK_ACCEPTED"
    # INFO finding is not carried as evidence either
    assert all(o["rule_id"] != "R-INFO" for o in c["observations"])


def test_oscal_deadline_is_tz_qualified():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    exc = Exceptions([{"host": "fw|SER1", "rule_id": "A-1", "reason": "x",
                       "approver": "y", "expires": "2026-12-31"}])
    body = _build([f], _bm([("1.2.1", "FAIL")]), exceptions=exc)["body"]
    risks = A.to_oscal(body)["assessment-results"]["results"][0]["risks"]
    assert risks and risks[0]["deadline"].endswith("+00:00")


# ── risk-acceptance fail-open ────────────────────────────────────────────────

def _ctrl(body, control):
    return next(c for c in body["results"][0]["controls"] if c["control"] == control)


def test_active_exception_marks_risk_accepted():
    f = _finding("FORTIOS-ADMIN-001", "HIGH", ["1.2.1"])
    exc = Exceptions([{"host": "fw|SER1", "rule_id": "FORTIOS-ADMIN-001",
                       "reason": "OOB only", "approver": "A. Rivera", "expires": "2099-01-01"}])
    body = _build([f], _bm([("1.2.1", "FAIL")]), exceptions=exc)["body"]
    assert _ctrl(body, "1.2.1")["status"] == "RISK_ACCEPTED"
    assert body["risk_acceptances"] and body["risk_acceptances"][0]["approver"] == "A. Rivera"


def test_expired_exception_fails_open():
    f = _finding("FORTIOS-ADMIN-001", "HIGH", ["1.2.1"])
    exc = Exceptions([{"host": "fw|SER1", "rule_id": "FORTIOS-ADMIN-001",
                       "reason": "stale", "approver": "x", "expires": "2000-01-01"}])
    body = _build([f], _bm([("1.2.1", "FAIL")]), exceptions=exc)["body"]
    c = _ctrl(body, "1.2.1")
    assert c["status"] == "FAIL" and c.get("exception_expired") is True
    assert not body["risk_acceptances"]


def test_partial_acceptance_stays_fail():
    # a control failed by TWO findings; only one accepted -> control stays FAIL
    f1 = _finding("R-1", "HIGH", ["1.2.1"], line="a")
    f2 = _finding("R-2", "HIGH", ["1.2.1"], line="b")
    exc = Exceptions([{"host": "fw|SER1", "rule_id": "R-1", "reason": "x",
                       "approver": "y", "expires": "2099-01-01"}])
    body = _build([f1, f2], _bm([("1.2.1", "FAIL")]), exceptions=exc)["body"]
    assert _ctrl(body, "1.2.1")["status"] == "FAIL"


# ── anti-overclaim ───────────────────────────────────────────────────────────

def test_pass_rate_denominator_is_evaluated_controls():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    body = _build([f], _bm([("1.2.1", "FAIL"), ("2.2.2", "PASS"), ("3.3.3", "PASS")]))["body"]
    cov = body["coverage"][0]
    assert cov["controls_evaluated"] == 3
    assert cov["pass_rate_of_evaluated"] == "67"  # 2/3
    # no fabricated framework-% unless a total is supplied
    assert "coverage_percent_of_framework" not in cov


def test_coverage_percent_only_when_total_known():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    body = _build([f], _bm([("1.2.1", "FAIL")]),
                  coverage_meta={"PCI-DSS": {"version": "4.0.1", "total": 100}})["body"]
    cov = body["coverage"][0]
    assert cov["controls_total_in_framework"] == 100
    assert cov["coverage_percent_of_framework"] == "1.0"  # 1/100


def test_disclaimer_never_claims_compliance():
    body = _build([_finding("A-1", "HIGH", ["1.2.1"])], _bm([("1.2.1", "FAIL")]))["body"]
    d = body["attestation"]["disclaimer"].lower()
    assert "not an attestation of compliance" in d
    assert "compliant" not in d.replace("not an attestation of compliance", "")


# ── OSCAL projection ─────────────────────────────────────────────────────────

def test_oscal_legality_and_no_dangling_links():
    f = _finding("FORTIOS-ADMIN-001", "HIGH", ["1.2.1"])
    exc = Exceptions([{"host": "fw|SER1", "rule_id": "FORTIOS-ADMIN-001", "reason": "x",
                       "approver": "y", "expires": "2099-01-01"}])
    body = _build([f, _finding("A-2", "LOW", ["2.2.2"])],
                  _bm([("1.2.1", "FAIL"), ("2.2.2", "FAIL"), ("3.3.3", "PASS")]),
                  exceptions=exc)["body"]
    ar = A.to_oscal(body)["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    result = ar["results"][0]
    obs_uuids = {o["uuid"] for o in result["observations"]}
    risk_uuids = {r["uuid"] for r in result["risks"]}
    for fnd in result["findings"]:
        assert fnd["target"]["status"]["state"] in ("satisfied", "not-satisfied")
        assert fnd["target"]["status"]["reason"] in ("pass", "fail", "other")
        for ro in fnd.get("related-observations", []):
            assert ro["observation-uuid"] in obs_uuids
        for rr in fnd.get("related-risks", []):
            assert rr["risk-uuid"] in risk_uuids
    # timestamps carry a timezone offset
    assert result["start"].endswith("+00:00")
    for r in result["risks"]:
        assert r["status"] == "deviation-approved"


def test_oscal_uuid_stable_across_runs():
    f = _finding("A-1", "HIGH", ["1.2.1"])
    o1 = A.to_oscal(_build([f], _bm([("1.2.1", "FAIL")]))["body"])
    o2 = A.to_oscal(_build([_finding("A-1", "HIGH", ["1.2.1"])], _bm([("1.2.1", "FAIL")]))["body"])
    assert o1["assessment-results"]["uuid"] == o2["assessment-results"]["uuid"]


# ── end-to-end on a real offline scan ────────────────────────────────────────

def test_save_and_verify_end_to_end(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    p = str(tmp_path / "att.json")
    hp = str(tmp_path / "att.html")
    op = str(tmp_path / "att.oscal.json")
    sc.save_attestation(p, html_path=hp, oscal_path=op, org="Phalanx Cyber")
    bundle = json.load(open(p, encoding="utf-8"))
    assert A.verify_attestation(bundle)["ok"]
    assert bundle["body"]["manifest"]["record_count"] > 0
    assert bundle["body"]["attestation"]["source_artifact"]["sha256"]  # config hashed
    assert os.path.getsize(hp) > 0
    oscal = json.load(open(op, encoding="utf-8"))
    assert oscal["assessment-results"]["results"][0]["findings"]


def test_severity_filter_does_not_change_attestation(tmp_path):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    full = str(tmp_path / "full.json")
    sc.save_attestation(full)
    # apply a high display filter, then re-attest: must be identical (uses _all_findings)
    sc.filter_severity("CRITICAL")
    filt = str(tmp_path / "filt.json")
    sc.save_attestation(filt)
    a = json.load(open(full))["body"]["manifest"]["merkle_root"]
    b = json.load(open(filt))["body"]["manifest"]["merkle_root"]
    assert a == b


def test_keyed_seal_end_to_end(tmp_path, monkeypatch):
    sc = OfflineFortinetScanner(CONF, verbose=False)
    sc.scan()
    monkeypatch.setenv("FORTI_ATTEST_KEY", "super-secret-2026")
    p = str(tmp_path / "att.json")
    sc.save_attestation(p, key_spec="env:FORTI_ATTEST_KEY")
    bundle = json.load(open(p, encoding="utf-8"))
    assert bundle["seal"]["alg"] == "HMAC-SHA256"
    assert A.verify_attestation(bundle, key=b"super-secret-2026")["ok"]
    assert not A.verify_attestation(bundle, key=b"nope")["ok"]
