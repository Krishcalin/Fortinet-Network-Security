"""
Tests for the coverage added in 2026-07: 5 legacy KEV CVEs, 4 config checks
(CERT-012, ADMIN-025, SSLVPN-015/-017) and 3 MITRE techniques (T1505/T1602/T1552).

Run:  python -m pytest test_data/test_new_checks.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fortinet_scanner as fs  # noqa: E402


class Bag:
    """Scanner stub: _api_get from a dict, collects findings."""

    def __init__(self, data):
        self._d = data
        self.findings = []
        self._sys_info = {"hostname": "fw"}
        self.host = "fw"

    def _api_get(self, path, monitor=False):
        return self._d.get(path)

    def _add(self, f):
        self.findings.append(f)


def _ids(bag):
    return {f.rule_id for f in bag.findings}


# ── config checks ────────────────────────────────────────────────────────────

def test_cert012_default_admin_cert():
    b = Bag({"system/global": {"admin-server-cert": "Fortinet_Factory"}})
    fs.FortinetScanner._check_admin_access(b)
    assert "FORTIOS-CERT-012" in _ids(b)


def test_cert012_not_fired_with_real_cert():
    b = Bag({"system/global": {"admin-server-cert": "MyCorp-CA"}})
    fs.FortinetScanner._check_admin_access(b)
    assert "FORTIOS-CERT-012" not in _ids(b)


def test_cert012_not_fired_when_key_absent():
    # key not present in config -> can't assert factory default -> no finding
    b = Bag({"system/global": {}})
    fs.FortinetScanner._check_admin_access(b)
    assert "FORTIOS-CERT-012" not in _ids(b)


def test_admin025_maintainer_enabled():
    b = Bag({"system/global": {"admin-maintainer": "enable"}})
    fs.FortinetScanner._check_admin_access(b)
    assert "FORTIOS-ADMIN-025" in _ids(b)
    b2 = Bag({"system/global": {"admin-maintainer": "disable"}})
    fs.FortinetScanner._check_admin_access(b2)
    assert "FORTIOS-ADMIN-025" not in _ids(b2)


def test_sslvpn015_unrestricted_source():
    b = Bag({"vpn.ssl/settings": {"status": "enable", "source-interface": [{"name": "wan1"}],
                                  "source-address": [{"name": "all"}]}})
    fs.FortinetScanner._check_ssl_vpn(b)
    assert "FORTIOS-SSLVPN-015" in _ids(b)


def test_sslvpn015_restricted_source_ok():
    b = Bag({"vpn.ssl/settings": {"status": "enable", "source-interface": [{"name": "wan1"}],
                                  "source-address": [{"name": "CorpNets"}], "algorithm": "high"}})
    fs.FortinetScanner._check_ssl_vpn(b)
    assert "FORTIOS-SSLVPN-015" not in _ids(b)


def test_sslvpn_checks_gated_on_binding():
    # No source-interface => SSL-VPN not bound => the two new checks must not fire
    b = Bag({"vpn.ssl/settings": {"status": "enable"}})
    fs.FortinetScanner._check_ssl_vpn(b)
    assert "FORTIOS-SSLVPN-015" not in _ids(b)
    assert "FORTIOS-SSLVPN-017" not in _ids(b)


def test_sslvpn017_algorithm_not_high():
    b = Bag({"vpn.ssl/settings": {"status": "enable", "source-interface": [{"name": "wan1"}],
                                  "source-address": [{"name": "CorpNets"}], "algorithm": "default"}})
    fs.FortinetScanner._check_ssl_vpn(b)
    assert "FORTIOS-SSLVPN-017" in _ids(b)


# ── new MITRE techniques ─────────────────────────────────────────────────────

def _mitre_bag(**over):
    data = {
        "system/interface": [{"name": "wan1", "role": "wan"}, {"name": "lan", "role": "lan"}],
        "firewall/policy": [], "system.snmp/community": [], "system/global": {},
    }
    data.update(over)
    return Bag(data)


def test_mitre_t1505_inbound_without_ips_av():
    b = _mitre_bag(**{"firewall/policy": [
        {"srcintf": [{"name": "wan1"}], "dstintf": [{"name": "lan"}], "status": "enable"}]})
    fs.FortinetScanner._check_mitre_attack_resilience(b)
    assert "MITRE-T1505-001" in _ids(b)


def test_mitre_t1505_protected_inbound_ok():
    b = _mitre_bag(**{"firewall/policy": [
        {"srcintf": [{"name": "wan1"}], "dstintf": [{"name": "lan"}], "status": "enable",
         "ips-sensor": "default", "av-profile": "default"}]})
    fs.FortinetScanner._check_mitre_attack_resilience(b)
    assert "MITRE-T1505-001" not in _ids(b)


def test_mitre_t1602_default_community_high():
    b = _mitre_bag(**{"system.snmp/community": [{"name": "public", "query-v1-status": "enable"}]})
    fs.FortinetScanner._check_mitre_attack_resilience(b)
    hit = next((f for f in b.findings if f.rule_id == "MITRE-T1602-001"), None)
    assert hit is not None and hit.severity == "HIGH"


def test_mitre_t1552_pde_disabled():
    b = _mitre_bag(**{"system/global": {"private-data-encryption": "disable"}})
    fs.FortinetScanner._check_mitre_attack_resilience(b)
    hit = next((f for f in b.findings if f.rule_id == "MITRE-T1552-001"), None)
    assert hit is not None and hit.cve == "CVE-2019-6693"


def test_mitre_summary_total_is_34():
    b = _mitre_bag(**{"system/global": {"private-data-encryption": "disable"}})
    fs.FortinetScanner._check_mitre_attack_resilience(b)
    summary = next((f for f in b.findings if f.rule_id.startswith("MITRE-SUMMARY")), None)
    assert summary is not None and "/34" in summary.line_content


# ── legacy KEV CVEs on old firmware ──────────────────────────────────────────

@pytest.mark.parametrize("cve", [
    "CVE-2018-13379", "CVE-2018-13382", "CVE-2018-13383", "CVE-2019-6693", "CVE-2021-44168",
])
def test_legacy_kev_cve_present_in_dataset(cve):
    assert any(c["cve"] == cve for c in fs.FORTIOS_CVES)


def test_cve_component_map_only_references_real_cves():
    ids = {c["id"] for c in fs.FORTIOS_CVES}
    assert set(fs.CVE_COMPONENTS) <= ids
