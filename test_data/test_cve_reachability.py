"""
Tests for the CVE reachability-gating engine (cve_reachability.py) and its
integration with the Risk-Prioritization Engine: a CVE whose vulnerable feature
is disabled / not internet-facing is DOWNRANKED (never suppressed), with the
CISA-KEV floor intact.

Run:  python -m pytest test_data/test_cve_reachability.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cve_reachability as cr  # noqa: E402
from risk_prioritizer import RiskPrioritizer, ThreatIntel  # noqa: E402
import fortinet_scanner as fs  # noqa: E402


def _view(**kw):
    base = dict(fw_version=(7, 4, 4), wan={"wan1"}, wan_access=set(), all_access=set(),
                sslvpn_status="", sslvpn_present=False, sslvpn_srcintf=set(), ipsec_count=0,
                ipsec_wan=False, fmg=False, wtp=0, radius=0, tacacs=0, ldap=0, fsso=0,
                ips_policies=False, dnsfilter_policies=False, proxy_on=False,
                captive_portal=False, ha_mode="")
    base.update(kw)
    return base


class F:
    def __init__(self, rid, sev, cat, cve=None):
        self.rule_id, self.severity, self.category, self.cve = rid, sev, cat, cve
        self.name, self.file_path = rid, "fw"


# ----------------------------------------------------------- predicates -----

def test_sslvpn_disabled():
    v = cr.assess("sslvpn", _view(sslvpn_present=True, sslvpn_status="disable"))
    assert v[0] == cr.FEATURE_DISABLED


def test_sslvpn_enabled_wan():
    v = cr.assess("sslvpn", _view(sslvpn_present=True, sslvpn_status="enable"))
    assert v[0] == cr.CONFIRMED_REACHABLE


def test_sslvpn_enabled_internal_only():
    v = cr.assess("sslvpn", _view(sslvpn_present=True, sslvpn_status="enable", sslvpn_srcintf={"lan"}))
    assert v[0] == cr.CONFIGURED_NOT_EXPOSED


def test_sslvpn_absent_block_is_indeterminate():
    assert cr.assess("sslvpn", _view())[0] == cr.INDETERMINATE


# ---- review regression: SSL-VPN `status` toggle only exists from 7.4.1 ----

def test_sslvpn_no_status_pre_741_is_reachable_not_disabled():
    """On <7.4.1 there is no `set status` field; a configured block = SSL-VPN in use.
    Absent status must NOT be read as FEATURE_DISABLED (that hid flagship CVEs)."""
    v = _view(fw_version=(7, 0, 12), sslvpn_present=True, sslvpn_status="")  # no status key
    assert cr.assess("sslvpn", v)[0] == cr.CONFIRMED_REACHABLE


def test_sslvpn_no_status_741plus_is_disabled_by_default():
    """On >=7.4.1 the default is disable; an enabled box carries `set status enable`,
    so an absent status means disabled-by-default."""
    v = _view(fw_version=(7, 4, 4), sslvpn_present=True, sslvpn_status="")
    assert cr.assess("sslvpn", v)[0] == cr.FEATURE_DISABLED


def test_sslvpn_explicit_disable_always_disabled():
    for ver in ((7, 0, 12), (7, 4, 4)):
        v = _view(fw_version=ver, sslvpn_present=True, sslvpn_status="disable")
        assert cr.assess("sslvpn", v)[0] == cr.FEATURE_DISABLED


def test_sslvpn_multiwan_source_interface_string_split():
    """Offline parser space-joins multi-value source-interface into one string;
    _names must split it so a dual-WAN SSL-VPN is CONFIRMED, not CONFIGURED."""
    assert cr._names("wan1 wan2") == {"wan1", "wan2"}
    v = _view(sslvpn_present=True, sslvpn_status="enable",
              sslvpn_srcintf={"wan1", "wan2"}, wan={"wan1", "wan2"})
    assert cr.assess("sslvpn", v)[0] == cr.CONFIRMED_REACHABLE


def test_proxy_vdom_global_inspection_mode():
    assert cr.assess("proxy", _view(proxy_on=True))[0] == cr.CONFIGURED_NOT_EXPOSED
    assert cr.assess("proxy", _view(proxy_on=False))[0] == cr.FEATURE_DISABLED


def test_tacacs_predicate():
    assert cr.assess("tacacs", _view(tacacs=1))[0] == cr.CONFIGURED_NOT_EXPOSED
    assert cr.assess("tacacs", _view())[0] == cr.FEATURE_DISABLED


def test_admin_gui_wan_vs_internal():
    assert cr.assess("admin-gui", _view(wan_access={"https"}))[0] == cr.CONFIRMED_REACHABLE
    assert cr.assess("admin-gui", _view())[0] == cr.CONFIGURED_NOT_EXPOSED


def test_fgfm_states():
    assert cr.assess("fgfm", _view(wan_access={"fgfm"}))[0] == cr.CONFIRMED_REACHABLE
    assert cr.assess("fgfm", _view(fmg=True))[0] == cr.CONFIGURED_NOT_EXPOSED
    assert cr.assess("fgfm", _view())[0] == cr.FEATURE_DISABLED


def test_ipsec_states():
    assert cr.assess("ipsec", _view())[0] == cr.FEATURE_DISABLED
    assert cr.assess("ipsec", _view(ipsec_count=2, ipsec_wan=True))[0] == cr.CONFIRMED_REACHABLE
    assert cr.assess("ipsec", _view(ipsec_count=2))[0] == cr.CONFIGURED_NOT_EXPOSED


def test_ecosystem_always_indeterminate():
    assert cr.assess("ecosystem", _view(wan_access={"https"}))[0] == cr.INDETERMINATE


def test_unknown_component_indeterminate():
    assert cr.assess("no-such-component", _view())[0] == cr.INDETERMINATE
    assert cr.assess(None, _view())[0] == cr.INDETERMINATE


def test_every_predicate_returns_evidence():
    for comp in cr.PREDICATES:
        verdict, evidence = cr.assess(comp, _view())
        assert verdict in (cr.CONFIRMED_REACHABLE, cr.CONFIGURED_NOT_EXPOSED,
                           cr.FEATURE_DISABLED, cr.INDETERMINATE)
        assert isinstance(evidence, str)


# --------------------------------------------------- component-map sanity ----

def test_component_map_ids_exist_and_components_known():
    valid = set(cr.PREDICATES)
    cve_ids = {c["id"] for c in fs.FORTIOS_CVES}
    for rule_id, comp in fs.CVE_COMPONENTS.items():
        assert rule_id in cve_ids, f"{rule_id} not a real CVE id"
        assert comp in valid, f"{comp} has no predicate"


def test_ecosystem_cves_tagged_ecosystem():
    # FortiManager / FortiClient EMS entries must be 'ecosystem' -> INDETERMINATE
    for rid in ("FORTIOS-CVE-006", "FORTIOS-CVE-007", "FORTIOS-CVE-010"):
        assert fs.CVE_COMPONENTS[rid] == "ecosystem"


def test_nvd_corrected_component_tags():
    """Review + NVD corrections: CVE-2024-35279 is CAPWAP (not fgfm), CVE-2025-22252
    is TACACS+ (not radius), CVE-2024-26010 has no NVD-named component (untagged)."""
    assert fs.CVE_COMPONENTS["FORTIOS-CVE-027"] == "capwap"
    assert fs.CVE_COMPONENTS["FORTIOS-CVE-029"] == "tacacs"
    assert "FORTIOS-CVE-020" not in fs.CVE_COMPONENTS  # INDETERMINATE by omission


def test_unknown_verdict_falls_back_to_plane():
    """An unrecognized verdict string must fall back to the plane heuristic, never
    silently swallow the exposure bonus."""
    rp = _rp()
    f = F("FORTIOS-CVE-999", "CRITICAL", "Known CVEs", "CVE-2099-9999")
    reach = {"CVE-2099-9999": {"verdict": "SOMETHING_NEW", "evidence": "x", "component": "y"}}
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False}, reach)
    assert r.reachable is True and r.tier == "P1"


# --------------------------------------------------------- gating scoring ----

def _rp():
    return RiskPrioritizer(ThreatIntel())


def test_kev_critical_feature_disabled_capped_at_p2():
    rp = _rp()
    f = F("FORTIOS-CVE-002", "CRITICAL", "Known CVEs", "CVE-2024-21762")  # SSL-VPN, KEV, high EPSS
    reach = {"CVE-2024-21762": {"verdict": cr.FEATURE_DISABLED,
                                "evidence": "vpn.ssl settings status=disable", "component": "sslvpn"}}
    r = rp.assess(f, {"data": "NONE", "mgmt": False}, reach)
    assert r.tier == "P2"            # capped out of P1, but KEV floor keeps it visible
    assert "disabled" in r.rationale.lower()


def test_kev_critical_confirmed_reachable_is_p1():
    rp = _rp()
    f = F("FORTIOS-CVE-002", "CRITICAL", "Known CVEs", "CVE-2024-21762")
    reach = {"CVE-2024-21762": {"verdict": cr.CONFIRMED_REACHABLE,
                                "evidence": "SSL-VPN enabled internet-facing", "component": "sslvpn"}}
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False}, reach)
    assert r.tier == "P1"
    assert r.reachable is True


def test_non_kev_critical_disabled_capped_at_p3():
    rp = _rp()
    f = F("FORTIOS-CVE-070", "CRITICAL", "Known CVEs", "CVE-2023-33308")  # not KEV
    reach = {"CVE-2023-33308": {"verdict": cr.FEATURE_DISABLED, "evidence": "no proxy policies", "component": "proxy"}}
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False}, reach)
    assert r.tier in ("P3", "P4")


def test_configured_not_exposed_no_bonus_no_cap():
    rp = _rp()
    f = F("FORTIOS-CVE-070", "CRITICAL", "Known CVEs", "CVE-2023-33308")
    reach = {"CVE-2023-33308": {"verdict": cr.CONFIGURED_NOT_EXPOSED, "evidence": "proxy internal", "component": "proxy"}}
    r = rp.assess(f, {"data": "NONE", "mgmt": False}, reach)
    assert r.reachable is False
    assert r.score == 50  # base CRITICAL only, no exposure bonus, no penalty


def test_indeterminate_falls_back_to_plane_logic():
    rp = _rp()
    f = F("FORTIOS-CVE-070", "CRITICAL", "Known CVEs", "CVE-2023-33308")
    reach = {"CVE-2023-33308": {"verdict": cr.INDETERMINATE, "evidence": "", "component": "x"}}
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False}, reach)
    assert r.reachable is True     # plane logic applies when verdict is indeterminate
    assert r.tier == "P1"


def test_no_reachability_map_is_unchanged():
    """Without a reachability map, behaviour is exactly as before (plane-based)."""
    rp = _rp()
    f = F("FORTIOS-CVE-002", "CRITICAL", "Known CVEs", "CVE-2024-21762")
    r = rp.assess(f, {"data": "WIDE_OPEN", "mgmt": False}, None)
    assert r.tier == "P1"


# ------------------------------------------------ scanner integration -------

def test_offline_scan_populates_reachability():
    from fortinet_offline_scanner import OfflineFortinetScanner
    conf = os.path.join(os.path.dirname(__file__), "sample_insecure.conf")
    s = OfflineFortinetScanner(conf)
    s.scan()
    rc = getattr(s, "_cve_reachability", {})
    assert rc, "reachability map should be populated after a scan with CVE matches"
    verdicts = {v["verdict"] for v in rc.values()}
    assert verdicts & {cr.CONFIRMED_REACHABLE, cr.FEATURE_DISABLED, cr.CONFIGURED_NOT_EXPOSED}
    # every entry carries a component + (usually) an evidence string
    for cve, info in rc.items():
        assert "verdict" in info and "component" in info
