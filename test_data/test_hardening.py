"""
Tests for the 2026-07 hardening check-pack: ADMIN-026 (IPv6 trusted hosts),
SSLVPN-016 (web mode), SYS-019 (weak SSH algos), NET-019 (local-in-policy),
NET-020 (GeoIP). Includes the two edge cases the adversarial verify pass found:
SSLVPN-016 must not fire when SSL-VPN is status=disable, and NET-020 must fire
when the firewall/address section is absent.

Run:  python -m pytest test_data/test_hardening.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fortinet_scanner as fs  # noqa: E402
from fortinet_offline_scanner import OfflineFortinetScanner  # noqa: E402

HEADER = "#config-version=FGT60F-7.4.4-FW-build2571-240101:opmode=0\n"


class Bag:
    """Scanner stub bound to real methods, _api_get from a dict."""

    def __init__(self, data, ver=(7, 4, 4)):
        self._d = data
        self.findings = []
        self._sys_info = {"hostname": "fw"}
        self.host = "fw"
        self._fw_version = ver

    def _api_get(self, path, monitor=False):
        return self._d.get(path)

    def _add(self, f):
        self.findings.append(f)

    def _wan_interfaces(self):
        return self._d.get("_wan", set())

    def _ver_lt(self, v):
        return fs.FortinetScanner._ver_lt(self, v)

    @staticmethod
    def _parse_ver(x):
        return fs.FortinetScanner._parse_ver(x)


def _ids(b):
    return {f.rule_id for f in b.findings}


def _run_conf(tmp_path, body, grep=None):
    conf = tmp_path / "t.conf"
    conf.write_text(HEADER + body)
    sc = OfflineFortinetScanner(str(conf), verbose=False)
    sc.scan()
    return {f.rule_id for f in sc.findings}


# ── ADMIN-026 ────────────────────────────────────────────────────────────────

def _admin_bag(data):
    b = Bag(data)
    b._ipv6_admin_exposure = fs.FortinetScanner._ipv6_admin_exposure.__get__(b)
    return b


def test_admin026_fires_when_v6_exposed_and_v4_locked():
    b = _admin_bag({
        "system/admin": [{"name": "a1", "trusthost1": "10.0.0.0 255.255.255.0"}],
        "system/interface": [{"name": "wan1", "role": "wan", "ipv6": {"ip6-allowaccess": "https ssh"}}],
        "_wan": {"wan1"}, "system/global": {},
    })
    fs.FortinetScanner._check_admin_access(b)
    hit = next((f for f in b.findings if f.rule_id == "FORTIOS-ADMIN-026"), None)
    assert hit is not None and hit.severity == "HIGH"   # exposing iface is WAN


def test_admin026_medium_when_v6_exposed_on_internal():
    b = _admin_bag({
        "system/admin": [{"name": "a1", "trusthost1": "10.0.0.0 255.255.255.0"}],
        "system/interface": [{"name": "lan", "role": "lan", "ipv6": {"ip6-allowaccess": "https"}}],
        "_wan": set(), "system/global": {},
    })
    fs.FortinetScanner._check_admin_access(b)
    hit = next((f for f in b.findings if f.rule_id == "FORTIOS-ADMIN-026"), None)
    assert hit is not None and hit.severity == "MEDIUM"


def test_admin026_no_fire_when_v6_not_exposed():
    b = _admin_bag({
        "system/admin": [{"name": "a1", "trusthost1": "10.0.0.0 255.255.255.0"}],
        "system/interface": [{"name": "wan1", "role": "wan", "ipv6": {"ip6-allowaccess": "ping"}}],
        "_wan": {"wan1"}, "system/global": {},
    })
    fs.FortinetScanner._check_admin_access(b)
    assert "FORTIOS-ADMIN-026" not in _ids(b)


def test_admin026_no_fire_when_v6_trusthost_set():
    b = _admin_bag({
        "system/admin": [{"name": "a1", "trusthost1": "10.0.0.0 255.255.255.0",
                          "ip6-trusthost1": "2001:db8::/64"}],
        "system/interface": [{"name": "wan1", "role": "wan", "ipv6": {"ip6-allowaccess": "https ssh"}}],
        "_wan": {"wan1"}, "system/global": {},
    })
    fs.FortinetScanner._check_admin_access(b)
    assert "FORTIOS-ADMIN-026" not in _ids(b)


def test_admin026_no_double_report_with_admin006():
    # no IPv4 trusted hosts -> ADMIN-006 territory; ADMIN-026 must stay silent
    b = _admin_bag({
        "system/admin": [{"name": "a1"}],
        "system/interface": [{"name": "wan1", "role": "wan", "ipv6": {"ip6-allowaccess": "https ssh"}}],
        "_wan": {"wan1"}, "system/global": {},
    })
    fs.FortinetScanner._check_admin_access(b)
    ids = _ids(b)
    assert "FORTIOS-ADMIN-006" in ids and "FORTIOS-ADMIN-026" not in ids


def test_admin026_parses_nested_ipv6_from_conf(tmp_path):
    body = """\
config system interface
    edit "wan1"
        set role wan
        set allowaccess https ssh
        config ipv6
            set ip6-allowaccess https ssh
        end
    next
end
config system admin
    edit "admin1"
        set trusthost1 "10.0.0.0 255.255.255.0"
    next
end
"""
    assert "FORTIOS-ADMIN-026" in _run_conf(tmp_path, body)


# ── SSLVPN-016 (+ the verify-pass FP fix) ────────────────────────────────────

def _ssl_bag(settings, portals):
    return Bag({"vpn.ssl/settings": settings, "vpn.ssl.web/portal": portals})


def test_sslvpn016_fires_when_enabled_and_web_mode():
    b = _ssl_bag({"status": "enable", "source-interface": [{"name": "wan1"}],
                  "source-address": [{"name": "g"}], "algorithm": "high"},
                 [{"name": "p", "web-mode": "enable", "host-check": "enable"}])
    fs.FortinetScanner._check_ssl_vpn(b)
    assert "FORTIOS-SSLVPN-016" in _ids(b)


def test_sslvpn016_no_fire_when_status_disable():
    # verify-pass FP: source-interface residue but SSL-VPN administratively off
    b = _ssl_bag({"status": "disable", "source-interface": [{"name": "wan1"}]},
                 [{"name": "p", "web-mode": "enable"}])
    fs.FortinetScanner._check_ssl_vpn(b)
    assert "FORTIOS-SSLVPN-016" not in _ids(b)
    # the shared gate also protects SSLVPN-015/017
    assert "FORTIOS-SSLVPN-015" not in _ids(b) and "FORTIOS-SSLVPN-017" not in _ids(b)


def test_sslvpn016_no_fire_tunnel_only():
    b = _ssl_bag({"status": "enable", "source-interface": [{"name": "wan1"}],
                  "source-address": [{"name": "g"}], "algorithm": "high"},
                 [{"name": "p", "web-mode": "disable"}])
    fs.FortinetScanner._check_ssl_vpn(b)
    assert "FORTIOS-SSLVPN-016" not in _ids(b)


# ── SYS-019 (weak SSH algorithms + substring traps) ──────────────────────────

def _adv(glb, ver=(7, 4, 4)):
    b = Bag({"system/global": glb, "system/dns": {}, "firewall/policy": [], "system/interface": []}, ver=ver)
    fs.FortinetScanner._check_advanced_hardening(b)
    return _ids(b)


@pytest.mark.parametrize("glb", [
    {"ssh-enc-algo": "aes256-cbc aes256-ctr"},
    {"ssh-kex-algo": "diffie-hellman-group14-sha1"},
    {"ssh-mac-algo": "hmac-md5 hmac-sha2-256"},
    {"ssh-enc-algo": "3des-cbc"},
])
def test_sys019_fires_on_weak(glb):
    assert "FORTIOS-SYS-019" in _adv(glb)


@pytest.mark.parametrize("glb", [
    {},                                                            # absent = strong default
    {"ssh-kex-algo": "diffie-hellman-group14-sha256 curve25519-sha256@libssh.org"},  # -sha256 not -sha1
    {"ssh-mac-algo": "hmac-sha2-256 hmac-sha2-512"},              # not hmac-sha1
    {"ssh-enc-algo": "aes256-gcm@openssh.com aes256-ctr"},        # gcm/ctr, no cbc
])
def test_sys019_no_fp_on_strong(glb):
    assert "FORTIOS-SYS-019" not in _adv(glb)


def test_sys019_legacy_gated_off_on_modern_train():
    # legacy boolean knob present but on 7.6 -> must be gated off by _ver_lt(7.0.2)
    assert "FORTIOS-SYS-019" not in _adv({"ssh-cbc-cipher": "enable"}, ver=(7, 6, 1))
    # on 6.4 without strong-crypto it fires
    assert "FORTIOS-SYS-019" in _adv({"ssh-cbc-cipher": "enable"}, ver=(6, 4, 5))
    # ...unless strong-crypto neutralizes it
    assert "FORTIOS-SYS-019" not in _adv({"ssh-cbc-cipher": "enable", "strong-crypto": "enable"}, ver=(6, 4, 5))


# ── NET-019 / NET-020 ────────────────────────────────────────────────────────

def _net(data):
    b = Bag(data)
    b._mgmt_exposure = fs.FortinetScanner._mgmt_exposure.__get__(b)
    b._d.setdefault("firewall/DoS-policy", [{"policyid": 1, "anomaly": []}])
    fs.FortinetScanner._check_network(b)
    return _ids(b)


def test_net019_fires_mgmt_on_wan_no_localin():
    ids = _net({"system/interface": [{"name": "wan1", "role": "wan", "allowaccess": "https ssh ping"}],
                "_wan": {"wan1"}, "vpn.ssl/settings": {}, "firewall/local-in-policy": []})
    assert "FORTIOS-NET-019" in ids


def test_net019_no_fire_internal():
    ids = _net({"system/interface": [{"name": "lan", "allowaccess": "https ssh"}],
                "_wan": set(), "vpn.ssl/settings": {}, "firewall/local-in-policy": []})
    assert "FORTIOS-NET-019" not in ids


def test_net019_disabled_localin_still_fires():
    ids = _net({"system/interface": [{"name": "wan1", "role": "wan", "allowaccess": "https ssh"}],
                "_wan": {"wan1"}, "vpn.ssl/settings": {},
                "firewall/local-in-policy": [{"policyid": 1, "status": "disable", "srcaddr": [{"name": "x"}]}]})
    assert "FORTIOS-NET-019" in ids   # no *enabled* local-in-policy


def test_net020_fires_localin_without_geo():
    ids = _net({"system/interface": [{"name": "wan1", "role": "wan", "allowaccess": "https ssh"}],
                "_wan": {"wan1"}, "vpn.ssl/settings": {},
                "firewall/local-in-policy": [{"policyid": 1, "srcaddr": [{"name": "MGMT"}], "action": "accept"}],
                "firewall/address": [{"name": "MGMT"}], "firewall/addrgrp": []})
    assert "FORTIOS-NET-020" in ids and "FORTIOS-NET-019" not in ids


def test_net020_no_fire_when_geo_referenced():
    ids = _net({"system/interface": [{"name": "wan1", "role": "wan", "allowaccess": "https ssh"}],
                "_wan": {"wan1"}, "vpn.ssl/settings": {},
                "firewall/local-in-policy": [{"policyid": 1, "srcaddr": [{"name": "GEO"}], "action": "accept"}],
                "firewall/address": [{"name": "GEO", "type": "geography", "country": "US"}], "firewall/addrgrp": []})
    assert "FORTIOS-NET-020" not in ids


def test_net020_geo_nested_in_group_suppresses():
    ids = _net({"system/interface": [{"name": "wan1", "role": "wan", "allowaccess": "https ssh"}],
                "_wan": {"wan1"}, "vpn.ssl/settings": {},
                "firewall/local-in-policy": [{"policyid": 1, "srcaddr": [{"name": "OuterGrp"}], "action": "accept"}],
                "firewall/address": [{"name": "GEO", "type": "geography", "country": "US"}],
                "firewall/addrgrp": [{"name": "OuterGrp", "member": [{"name": "InnerGrp"}]},
                                     {"name": "InnerGrp", "member": [{"name": "GEO"}]}]})
    assert "FORTIOS-NET-020" not in ids


def test_net020_fires_when_address_section_absent(tmp_path):
    # verify-pass FN: exposed + enabled local-in-policy + NO firewall/address section
    body = """\
config system interface
    edit "port1"
        set role wan
        set allowaccess ping https ssh
    next
end
config vpn ssl settings
    set status enable
    set source-interface "port1"
end
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
    next
end
"""
    assert "FORTIOS-NET-020" in _run_conf(tmp_path, body)
