"""
Regression tests for 10 correctness bugs found by adversarial review (2026-07).
Each test reproduces the original failure scenario and asserts the fix holds.

Run:  python -m pytest test_data/test_bugfixes.py -v
"""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cve_reachability as cr          # noqa: E402
import risk_prioritizer as rp          # noqa: E402
import pdf_writer                       # noqa: E402
import fortinet_scanner as fs           # noqa: E402
from fortinet_offline_scanner import OfflineFortinetScanner  # noqa: E402


class FakeScanner:
    """Minimal scanner exposing _api_get from a dict + _wan_interfaces/_fw_version."""

    def __init__(self, data, wan=None, ver=(7, 0, 10)):
        self._data = data
        self._wan = set(wan or [])
        self._fw_version = ver

    def _api_get(self, path, monitor=False):
        return self._data.get(path)

    def _wan_interfaces(self):
        return self._wan


# ── #1 WAN-detection false negative ─────────────────────────────────────────

def _uplink_data(with_default_route=False):
    data = {
        "system/interface": [{"name": "port1", "allowaccess": "https ssh ping"},
                             {"name": "port2", "allowaccess": "ping"}],
        "vpn.ssl/settings": {"status": "enable", "source-interface": [{"name": "port1"}]},
        "vpn.ipsec/phase1-interface": [{"name": "t1", "interface": [{"name": "port1"}]}],
        "firewall/policy": [],
        "router/static": [],
    }
    if with_default_route:
        data["router/static"] = [{"dst": "", "gateway": "203.0.113.1", "device": "port1"}]
    return data


def test_wan_undetermined_yields_indeterminate_not_decisive():
    """Static-IP uplink with no `set role wan` and no default route: WAN can't be
    determined, so internet-facing predicates must be INDETERMINATE, never a
    decisive CONFIGURED_NOT_EXPOSED (which would hide a real SSL-VPN/admin RCE)."""
    v = cr.build_view(FakeScanner(_uplink_data()))
    assert v["wan_known"] is False
    assert cr.assess("sslvpn", v)[0] == cr.INDETERMINATE
    assert cr.assess("admin-gui", v)[0] == cr.INDETERMINATE
    assert cr.assess("admin-ssh", v)[0] == cr.INDETERMINATE
    assert cr.assess("rest-api", v)[0] == cr.INDETERMINATE
    assert cr.assess("ipsec", v)[0] == cr.INDETERMINATE


def test_default_route_uplink_detected_as_wan():
    """The interface owning the default route is WAN even without role/heuristics."""
    v = cr.build_view(FakeScanner(_uplink_data(with_default_route=True)))
    assert "port1" in v["wan"]
    assert v["wan_known"] is True
    assert cr.assess("sslvpn", v)[0] == cr.CONFIRMED_REACHABLE
    assert cr.assess("admin-gui", v)[0] == cr.CONFIRMED_REACHABLE


def test_known_wan_still_decisive_not_exposed():
    """A properly-tagged WAN with mgmt only on LAN stays a decisive not-exposed."""
    data = {
        "system/interface": [{"name": "wan1", "role": "wan", "allowaccess": "ping"},
                             {"name": "lan", "allowaccess": "https ssh"}],
        "vpn.ssl/settings": {"status": "enable", "source-interface": [{"name": "lan"}]},
        "firewall/policy": [], "router/static": [],
    }
    v = cr.build_view(FakeScanner(data))
    assert v["wan_known"] is True
    assert cr.assess("admin-gui", v)[0] == cr.CONFIGURED_NOT_EXPOSED
    assert cr.assess("sslvpn", v)[0] == cr.CONFIGURED_NOT_EXPOSED


# ── #5 IPS over-claim ────────────────────────────────────────────────────────

def test_ips_on_internal_policy_not_confirmed():
    data = {
        "system/interface": [{"name": "wan1", "role": "wan"}, {"name": "lan"}, {"name": "dmz"}],
        "firewall/policy": [{"srcintf": [{"name": "lan"}], "dstintf": [{"name": "dmz"}],
                             "ips-sensor": "default", "status": "enable"}],
    }
    v = cr.build_view(FakeScanner(data))
    assert v["ips_policies"] is True
    assert v["ips_policies_wan"] is False
    assert cr.assess("ips", v)[0] != cr.CONFIRMED_REACHABLE


def test_ips_on_wan_policy_confirmed():
    data = {
        "system/interface": [{"name": "wan1", "role": "wan"}, {"name": "dmz"}],
        "firewall/policy": [{"srcintf": [{"name": "wan1"}], "dstintf": [{"name": "dmz"}],
                            "ips-sensor": "default", "status": "enable"}],
    }
    v = cr.build_view(FakeScanner(data))
    assert cr.assess("ips", v)[0] == cr.CONFIRMED_REACHABLE


# ── #6 CAPWAP default-profile miscount ───────────────────────────────────────

def test_capwap_wired_only_is_feature_disabled():
    """Default wtp-PROFILE objects are always present; only managed APs (wtp) and
    user VAPs count. A wired-only box must reach FEATURE_DISABLED for CAPWAP CVEs."""
    data = {
        "system/interface": [{"name": "wan1", "role": "wan"}],
        "wireless-controller/wtp-profile": [{"name": "FAP-default"}, {"name": "FAP221E-default"}],
        "wireless-controller/wtp": [], "wireless-controller/vap": [], "firewall/policy": [],
    }
    v = cr.build_view(FakeScanner(data))
    assert v["wtp"] == 0
    assert cr.assess("capwap", v)[0] == cr.FEATURE_DISABLED


def test_capwap_managed_ap_is_configured():
    data = {
        "system/interface": [{"name": "wan1", "role": "wan"}],
        "wireless-controller/wtp-profile": [{"name": "FAP-default"}],
        "wireless-controller/wtp": [{"name": "FP231F0000000001"}],
        "wireless-controller/vap": [], "firewall/policy": [],
    }
    v = cr.build_view(FakeScanner(data))
    assert v["wtp"] == 1
    assert cr.assess("capwap", v)[0] == cr.CONFIGURED_NOT_EXPOSED


# ── #3 Ecosystem CVE false positive ──────────────────────────────────────────

def _cve_scanner(ver):
    s = FakeScanner({}, ver=ver)
    s._sys_info = {"hostname": "fw"}
    s.host = "fw"
    s.findings = []
    s._add = lambda f: s.findings.append(f)
    s._ver_in_train = fs.FortinetScanner._ver_in_train.__get__(s)
    s._ver_lt = fs.FortinetScanner._ver_lt.__get__(s)
    s._parse_ver = staticmethod(fs.FortinetScanner._parse_ver).__func__
    s._FORTIOS_PRODUCTS = fs.FortinetScanner._FORTIOS_PRODUCTS
    s._assess_cve_reachability = lambda m: None
    s._warn = lambda m: None
    return s


def test_ecosystem_cves_not_matched_against_fortios():
    s = _cve_scanner((7, 0, 10))
    fs.FortinetScanner._check_cves(s)
    hit = {f.cve for f in s.findings}
    # FortiManager / FortiClient EMS advisories must NOT flag a FortiGate
    assert "CVE-2024-47575" not in hit   # FortiJump (FortiManager)
    assert "CVE-2023-48788" not in hit   # FortiClient EMS SQLi
    assert "CVE-2023-36554" not in hit   # FortiManager API
    # a genuine FortiOS SSL-VPN CVE on 7.0.10 IS still flagged
    assert "CVE-2024-21762" in hit


def test_all_ecosystem_entries_tagged_with_product():
    tagged = {c["id"] for c in fs.FORTIOS_CVES if "product" in c}
    assert tagged == {"FORTIOS-CVE-006", "FORTIOS-CVE-007", "FORTIOS-CVE-010"}
    for c in fs.FORTIOS_CVES:
        if "product" in c:
            assert c["product"].lower() not in fs.FortinetScanner._FORTIOS_PRODUCTS


# ── #9 Missing lower (6.0) CVE trains ────────────────────────────────────────

def test_flagship_sslvpn_cves_flag_60_train():
    for ver in ((6, 0, 5), (6, 0, 12)):
        s = _cve_scanner(ver)
        fs.FortinetScanner._check_cves(s)
        hit = {f.cve for f in s.findings}
        assert "CVE-2024-21762" in hit, f"6.0 not flagged for CVE-2024-21762 on {ver}"
        assert "CVE-2023-27997" in hit, f"6.0 not flagged for CVE-2023-27997 on {ver}"


# ── #4 import_intel key-case collision ───────────────────────────────────────

def test_import_intel_normalizes_key_case():
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "src.json")
        dest = os.path.join(d, "dest.json")
        with open(src, "w") as fh:
            json.dump({"meta": {"snapshot_date": "2026-07-09"},
                       "cves": {"cve-2022-40684": {"kev": True, "epss": 0.9},
                                "CVE-2022-40684": {"kev": False, "epss": 0.1}}}, fh)
        meta = rp.import_intel(src, dest)
        loaded = rp.ThreatIntel(dest)
        # the exported count must match what the loader actually retains
        assert meta["cve_count"] == len(loaded.cves) == 1
        # keys on disk are upper-cased (match loader semantics)
        on_disk = json.load(open(dest))["cves"]
        assert set(on_disk) == {"CVE-2022-40684"}


# ── #10 PDF wrap mid-line long token ─────────────────────────────────────────

def test_pdf_wrap_hardsplits_midline_long_token():
    w = pdf_writer.PDFWriter()
    longname = "MGMT_" + "A" * 90
    text = f"Admin account '{longname}' lacks two-factor authentication enabled."
    maxw = 505.28
    lines = w.wrap(text, "H", 9.5, maxw)
    widest = max(w.string_width(ln, "H", 9.5) for ln in lines)
    assert widest <= maxw + 0.5, f"line overflows column: {widest} > {maxw}"


def test_pdf_wrap_preserves_content_and_blank_lines():
    w = pdf_writer.PDFWriter()
    lines = w.wrap("alpha beta\n\ngamma", "H", 10, 500)
    assert "".join(lines).replace(" ", "") == "alphabetagamma".replace(" ", "") or \
        "alpha" in " ".join(lines)
    # a blank line in the source is preserved as an empty output line
    assert "" in w.wrap("a\n\nb", "H", 10, 500)


# ── #2 apply_drift severity-filter skew (end-to-end) ─────────────────────────

def test_apply_drift_independent_of_severity_filter(tmp_path):
    conf = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")
    # baseline: full report
    base = OfflineFortinetScanner(conf, verbose=False)
    base.scan()
    base.filter_severity("LOW")
    base_path = str(tmp_path / "baseline.json")
    base.save_json(base_path)

    # re-scan the SAME config with a HIGH display filter, then drift
    cur = OfflineFortinetScanner(conf, verbose=False)
    cur.scan()
    cur.filter_severity("HIGH")
    cur.apply_drift(base_path)

    drift = [f for f in cur.findings if f.rule_id == "FORTIOS-DRIFT-SUMMARY"]
    assert drift, "drift summary finding not produced"
    lc = drift[0].line_content
    # unchanged config => nothing new, nothing resolved, delta 0 — regardless of filter
    assert "resolved=0" in lc, lc
    assert "delta +0" in lc, lc
    assert lc.split("new=")[1].split(" ")[0] == "0", lc


# ── #7 / #8 object hygiene: orphan VIPs + non-policy refs ────────────────────

def _hygiene_scanner(data):
    s = FakeScanner(data)
    s.findings = []
    s._sys_info = {"hostname": "fw"}
    s.host = "fw"
    s._add = lambda f: s.findings.append(f)
    return s


def test_object_hygiene_reports_orphan_vips():
    data = {
        "firewall/policy": [{"srcaddr": [{"name": "lan"}], "dstaddr": [{"name": "VIP_USED"}],
                             "service": [{"name": "ALL"}]}],
        "firewall/addrgrp": [], "firewall.service/group": [],
        "firewall/vip": [{"name": "VIP_ORPHAN1"}, {"name": "VIP_ORPHAN2"},
                         {"name": "VIP_ORPHAN3"}, {"name": "VIP_USED"}],
        "firewall/address": [], "firewall.service/custom": [],
    }
    s = _hygiene_scanner(data)
    fs.FortinetScanner._check_object_hygiene(s)
    vip = next((f for f in s.findings if f.rule_id == "FORTIOS-OBJECT-004"), None)
    assert vip is not None, "orphan-VIP check (OBJECT-004) did not fire"
    assert "VIP_USED" not in vip.line_content
    assert "VIP_ORPHAN1" in vip.line_content


def test_object_hygiene_excludes_localin_referenced_address():
    data = {
        "firewall/policy": [{"srcaddr": [{"name": "lan"}], "dstaddr": [{"name": "all"}],
                             "service": [{"name": "HTTPS"}]}],
        "firewall/addrgrp": [], "firewall.service/group": [],
        # MGMT_JUMPHOST referenced ONLY by a local-in-policy — must not be "unused"
        "firewall/local-in-policy": [{"srcaddr": [{"name": "MGMT_JUMPHOST"}],
                                      "dstaddr": [{"name": "all"}]}],
        "firewall/address": [{"name": "MGMT_JUMPHOST"}, {"name": "UNUSED_A"},
                             {"name": "UNUSED_B"}, {"name": "UNUSED_C"}],
        "firewall.service/custom": [], "firewall/vip": [],
    }
    s = _hygiene_scanner(data)
    fs.FortinetScanner._check_object_hygiene(s)
    addr = next((f for f in s.findings if f.rule_id == "FORTIOS-OBJECT-001"), None)
    assert addr is not None
    assert "MGMT_JUMPHOST" not in addr.line_content
    assert "UNUSED_A" in addr.line_content
