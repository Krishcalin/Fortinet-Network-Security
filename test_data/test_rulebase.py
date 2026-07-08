"""
Tests for the rule-base analysis engine, Policy Control Index, rule-usage and
object-hygiene checks (FireMon-style policy hygiene).

Run:  python -m pytest test_data/test_rulebase.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fortinet_scanner import FortinetScanner  # noqa: E402


class StubScanner(FortinetScanner):
    """A FortinetScanner whose _api_get is fed from in-memory dicts."""

    def __init__(self, data=None, monitor=None):
        self.findings = []
        self.host = "test"
        self._sys_info = {}
        self._data = data or {}
        self._monitor = monitor or {}

    def _api_get(self, path, monitor=False):
        return (self._monitor if monitor else self._data).get(path)


def _pol(pid, action="accept", status="enable", srcintf="any", dstintf="any",
         srcaddr="all", dstaddr="all", service="ALL", **extra):
    def lst(v):
        return [{"name": n} for n in (v if isinstance(v, (list, tuple)) else [v])]
    p = {"policyid": pid, "name": f"p{pid}", "action": action, "status": status,
         "srcintf": lst(srcintf), "dstintf": lst(dstintf),
         "srcaddr": lst(srcaddr), "dstaddr": lst(dstaddr), "service": lst(service)}
    p.update(extra)
    return p


def _ids(findings):
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------- rule-base ---

def test_redundant_duplicate_rule():
    pols = [
        _pol(1, srcaddr="all", dstaddr="all", service="ALL"),          # broad accept
        _pol(2, srcintf="lan", dstintf="wan", srcaddr="h1", dstaddr="s1", service="HTTPS"),  # covered, same action
    ]
    s = StubScanner({"firewall/policy": pols})
    s._check_rulebase()
    assert "FORTIOS-RULEBASE-002" in _ids(s.findings)


def test_shadowed_accept_over_deny_is_high():
    pols = [
        _pol(1, action="accept", srcaddr="all", dstaddr="all", service="ALL"),
        _pol(2, action="deny", srcintf="lan", dstintf="wan", srcaddr="h1", dstaddr="s1", service="HTTPS"),
    ]
    s = StubScanner({"firewall/policy": pols})
    s._check_rulebase()
    shadow = [f for f in s.findings if f.rule_id == "FORTIOS-RULEBASE-001"]
    assert shadow, "expected a shadowed-rule finding"
    assert shadow[0].severity == "HIGH"  # accept shadowing a deny hides a block


def test_specific_rules_not_flagged():
    # Two non-overlapping specific rules: no shadow/redundancy.
    pols = [
        _pol(1, srcintf="lan", dstintf="wan", srcaddr="h1", dstaddr="s1", service="HTTPS",
             logtraffic="all", **{"av-profile": "default"}),
        _pol(2, srcintf="lan", dstintf="dmz", srcaddr="h2", dstaddr="s2", service="SSH",
             logtraffic="all", **{"ips-sensor": "default"}),
    ]
    s = StubScanner({"firewall/policy": pols})
    s._check_rulebase()
    assert "FORTIOS-RULEBASE-001" not in _ids(s.findings)
    assert "FORTIOS-RULEBASE-002" not in _ids(s.findings)


def test_policy_control_index_emitted_and_scored():
    # One fully-permissive, unlogged, unprotected accept => low grade.
    s = StubScanner({"firewall/policy": [_pol(1)]})
    s._check_rulebase()
    score = [f for f in s.findings if f.rule_id == "FORTIOS-RULEBASE-SCORE"]
    assert score, "Policy Control Index finding must always be emitted when policies exist"
    assert "grade F" in score[0].name  # 100 -35 -20 -20 = 25
    assert score[0].severity == "HIGH"


def test_clean_rulebase_scores_high():
    # Specific, logged, protected accept => grade A.
    s = StubScanner({"firewall/policy": [
        _pol(1, srcintf="lan", dstintf="wan", srcaddr="h1", dstaddr="s1", service="HTTPS",
             logtraffic="all", **{"av-profile": "default", "ips-sensor": "default"})]})
    s._check_rulebase()
    score = [f for f in s.findings if f.rule_id == "FORTIOS-RULEBASE-SCORE"][0]
    assert "grade A" in score.name
    assert score.severity == "INFO"


def test_negated_rules_skipped():
    # A negated policy must not be treated as covering/covered (subset logic invalid).
    pols = [
        _pol(1, srcaddr="all", dstaddr="all", service="ALL", **{"srcaddr-negate": "enable"}),
        _pol(2, srcintf="lan", dstintf="wan", srcaddr="h1", dstaddr="s1", service="HTTPS"),
    ]
    s = StubScanner({"firewall/policy": pols})
    s._check_rulebase()
    assert "FORTIOS-RULEBASE-001" not in _ids(s.findings)
    assert "FORTIOS-RULEBASE-002" not in _ids(s.findings)


# ---------------------------------------------------------------- usage -------

def test_rule_usage_flags_dormant_only():
    data = {"firewall/policy": [_pol(1, name="busy"), _pol(2, name="dormant")]}
    monitor = {"firewall/policy": [
        {"policyid": 1, "bytes": 12345, "packets": 100},
        {"policyid": 2, "bytes": 0, "packets": 0, "hit_count": 0},
    ]}
    s = StubScanner(data, monitor)
    s._check_rule_usage()
    ids = _ids(s.findings)
    assert "FORTIOS-USAGE-001" in ids
    assert "FORTIOS-USAGE-SUMMARY" in ids
    dormant = [f for f in s.findings if f.rule_id == "FORTIOS-USAGE-001"]
    assert len(dormant) == 1 and "policy 2" in dormant[0].line_content


def test_rule_usage_offline_noop():
    # No monitor data (offline) => no findings.
    s = StubScanner({"firewall/policy": [_pol(1)]}, monitor={})
    s._check_rule_usage()
    assert s.findings == []


# --------------------------------------------------------------- objects ------

def test_object_hygiene_unused_addresses_services_profiles():
    data = {
        "firewall/policy": [_pol(1, srcaddr="lan-net", dstaddr="web", service="HTTPS",
                                 **{"av-profile": "default"})],
        "firewall/address": [{"name": "lan-net"}, {"name": "web"}, {"name": "all"},
                             {"name": "orphan1"}, {"name": "orphan2"}, {"name": "orphan3"}],
        "firewall.service/custom": [{"name": "HTTPS"}, {"name": "dead1"}, {"name": "dead2"}, {"name": "dead3"}],
        "antivirus/profile": [{"name": "default"}, {"name": "u1"}, {"name": "u2"}, {"name": "u3"}],
    }
    s = StubScanner(data)
    s._check_object_hygiene()
    ids = _ids(s.findings)
    assert "FORTIOS-OBJECT-001" in ids   # unused addresses
    assert "FORTIOS-OBJECT-002" in ids   # unused services
    assert "FORTIOS-OBJECT-003" in ids   # unused profiles


def test_object_hygiene_group_membership_counts_as_used():
    # An address used only via a referenced group must NOT be flagged unused.
    data = {
        "firewall/policy": [_pol(1, srcaddr="grp", dstaddr="web", service="HTTPS")],
        "firewall/addrgrp": [{"name": "grp", "member": [{"name": "m1"}, {"name": "m2"}]}],
        "firewall/address": [{"name": "web"}, {"name": "m1"}, {"name": "m2"}, {"name": "all"}],
    }
    s = StubScanner(data)
    s._check_object_hygiene()
    # m1/m2 are used via the group; only 0 orphans => no OBJECT-001 (needs >=3)
    assert "FORTIOS-OBJECT-001" not in _ids(s.findings)


# --------------------------------------------------------------- exposure ----

def _idata(policies):
    return {"system/interface": [{"name": "wan1", "role": "wan"}, {"name": "lan", "role": "lan"}],
            "firewall/policy": policies}


def test_exposure_ssh_from_internet_is_critical():
    s = StubScanner(_idata([_pol(1, srcintf="wan1", srcaddr="all", dstaddr="srv", service="SSH")]))
    s._check_exposure()
    e2 = [f for f in s.findings if f.rule_id == "FORTIOS-EXPOSURE-002"]
    assert e2 and e2[0].severity == "CRITICAL"


def test_exposure_restricted_rdp_is_high():
    s = StubScanner(_idata([_pol(1, srcintf="wan1", srcaddr="trusted", dstaddr="srv", service="RDP")]))
    s._check_exposure()
    e2 = [f for f in s.findings if f.rule_id == "FORTIOS-EXPOSURE-002"]
    assert e2 and e2[0].severity == "HIGH"


def test_exposure_any_to_all_and_summary():
    s = StubScanner(_idata([_pol(1, srcintf="wan1", srcaddr="all", service="ALL")]))
    s._check_exposure()
    ids = _ids(s.findings)
    assert "FORTIOS-EXPOSURE-001" in ids
    assert "FORTIOS-EXPOSURE-SUMMARY" in ids


def test_exposure_outbound_and_web_not_flagged():
    s = StubScanner(_idata([
        _pol(1, srcintf="lan", dstintf="wan1", srcaddr="all", service="SSH"),  # outbound
        _pol(2, srcintf="wan1", srcaddr="all", service="HTTPS"),               # web = legit public
    ]))
    s._check_exposure()
    assert "FORTIOS-EXPOSURE-002" not in _ids(s.findings)


# ----------------------------------------------------------------- drift ------

def _finding(rid, sev, name, lc="x"):
    from fortinet_scanner import Finding
    return Finding(rule_id=rid, name=name, category="c", severity=sev, file_path="h",
                   line_num=None, line_content=lc, description="", recommendation="")


def _write_baseline(tmp_path, findings, summary):
    import json as _json
    doc = {"generated": "2026-01-01T00:00:00", "summary": summary,
           "findings": [{"rule_id": f[0], "file_path": "h", "line_content": f[3] if len(f) > 3 else "x",
                         "severity": f[1], "name": f[2]} for f in findings]}
    p = tmp_path / "baseline.json"
    p.write_text(_json.dumps(doc), encoding="utf-8")
    return str(p)


def test_drift_detects_new_and_resolved(tmp_path):
    base = _write_baseline(tmp_path, [("R-OLD", "CRITICAL", "old")], {"CRITICAL": 1})
    s = StubScanner({})
    s.findings = [_finding("R-NEW", "HIGH", "new one")]
    s.apply_drift(base)
    drift = [f for f in s.findings if f.rule_id == "FORTIOS-DRIFT-SUMMARY"][0]
    assert "new=1" in drift.line_content and "resolved=1" in drift.line_content
    assert drift.severity == "HIGH"  # a new HIGH is a regression


def test_drift_identical_is_zero(tmp_path):
    base = _write_baseline(tmp_path, [("R-1", "LOW", "f1")], {"LOW": 1})
    s = StubScanner({})
    s.findings = [_finding("R-1", "LOW", "f1")]
    s.apply_drift(base)
    drift = [f for f in s.findings if f.rule_id == "FORTIOS-DRIFT-SUMMARY"][0]
    assert "new=0" in drift.line_content and "resolved=0" in drift.line_content
    assert drift.severity == "INFO"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
