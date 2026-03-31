#!/usr/bin/env python3
"""
Test runner for Fortinet FortiOS Security Scanner.

Mocks the FortiOS REST API responses with intentionally insecure
configuration data to validate that the scanner detects findings
across all 18 check categories.
"""

import json
import os
import sys

# Add parent directory so we can import the scanner
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fortinet_scanner import FortinetScanner, Finding

# ============================================================================
#  MOCK API DATA — Intentionally insecure to trigger maximum findings
# ============================================================================

MOCK_SYSTEM_STATUS = {
    "version": "v7.0.10",       # Vulnerable to CVE-2024-55591 (fixed in 7.0.17)
    "hostname": "FGT-TEST-LAB",
    "model_name": "FortiGate-60F",
    "model": "FGT60F",
    "serial": "FGT60FTK21000001",
    "build": 1234,
}

MOCK_API_RESPONSES = {
    # ── System Global (triggers: HTTP admin, long idle timeout, weak pwd policy,
    #    no pre/post-login banner, no strong-crypto, no lockout, weak TLS,
    #    tcp-session-without-syn, IPv6 w/o policies, LLDP, FIPS, SCP, timers, SSH grace)
    "system/global": {
        "admin-https-redirect": "disable",
        "admin-sport": 443,
        "admin-http-port": 80,
        "admintimeout": 30,
        "pre-login-banner": "disable",
        "post-login-banner": "disable",
        "strong-crypto": "disable",
        "admin-lockout-threshold": 0,
        "admin-lockout-duration": 60,
        "admin-https-ssl-versions": "tlsv1-0 tlsv1-1 tlsv1-2",
        "tcp-session-without-syn": "enable",
        "gui-ipv6": "enable",
        "lldp-reception": "enable",
        "fips-cc": "disable",
        "admin-scp": "disable",
        "tcp-halfopen-timer": 120,
        "tcp-halfclose-timer": 600,
        "admin-ssh-grace-time": 300,
        "revision-backup-on-logout": "disable",
        "cfg-save": "automatic",
        "auto-install-config": "enable",
        "revision-image-auto-backup": "disable",
        "admin-restrict-local": "disable",
    },

    # ── Password Policy (triggers: weak length, no uppercase/lowercase/number/special,
    #    no expiry, reuse allowed)
    "system/password-policy": {
        "minimum-length": 6,
        "min-upper-case-letter": 0,
        "min-lower-case-letter": 0,
        "min-number": 0,
        "min-non-alphanumeric": 0,
        "expire-day": 0,
        "reuse-password": "enable",
    },

    # ── Admin Accounts (triggers: default admin, no MFA, no trusted hosts,
    #    super_admin profile, too many super_admins, guest auth)
    "system/admin": [
        {
            "name": "admin",
            "two-factor": "disable",
            "trusthost1": "0.0.0.0 0.0.0.0",
            "accprofile": "super_admin",
            "status": "enable",
            "guest-auth": "disable",
            "password-expire": "",
        },
        {
            "name": "backup-admin",
            "two-factor": "disable",
            "trusthost1": "0.0.0.0 0.0.0.0",
            "accprofile": "super_admin",
            "status": "enable",
            "guest-auth": "enable",
            "password-expire": "",
        },
        {
            "name": "api-readonly",
            "two-factor": "disable",
            "trusthost1": "0.0.0.0 0.0.0.0",
            "accprofile": "super_admin",
            "status": "enable",
            "guest-auth": "disable",
            "password-expire": "",
        },
    ],

    # ── API Users (triggers: no trusted hosts, super_admin profile, no docs)
    "system/api-user": [
        {
            "name": "automation-token",
            "trusthost": [],
            "accprofile": "super_admin",
            "cors-allow-origin": "*",
            "comments": "",
            "schedule": "",
        },
        {
            "name": "monitoring-token",
            "trusthost": [],
            "accprofile": "prof_admin",
            "cors-allow-origin": "",
            "comments": "",
            "schedule": "",
        },
    ],

    # ── System Settings (triggers: SIP helper, ECMP, multicast, subnet overlap,
    #    no central NAT, unnamed policy, etc.)
    "system/settings": {
        "sip-helper": "enable",
        "ecmp-max-paths": 32,
        "multicast-forward": "enable",
        "allow-subnet-overlap": "enable",
        "central-nat": "disable",
        "gui-allow-unnamed-policy": "enable",
        "gui-default-policy-columns": "",
    },

    # ── Interfaces (triggers: HTTP/Telnet on interfaces, mgmt on WAN, ping on WAN,
    #    DHCP relay on WAN, src-check disabled, DNS override disabled)
    "system/interface": [
        {
            "name": "wan1",
            "type": "physical",
            "role": "wan",
            "allowaccess": "https ssh http telnet ping snmp fgfm",
            "dhcp-relay-service": "enable",
            "dns-server-override": "disable",
            "src-check": "disable",
            "speed": "auto",
        },
        {
            "name": "dmz",
            "type": "physical",
            "role": "dmz",
            "allowaccess": "http ping",
            "dhcp-relay-service": "disable",
            "dns-server-override": "enable",
            "src-check": "disable",
            "speed": "1000full",
        },
        {
            "name": "lan",
            "type": "physical",
            "role": "lan",
            "allowaccess": "https ssh ping",
            "dhcp-relay-service": "disable",
            "dns-server-override": "enable",
            "src-check": "enable",
            "speed": "auto",
        },
        {
            "name": "ha-mgmt",
            "type": "loopback",
            "role": "undefined",
            "allowaccess": "ping",
            "dhcp-relay-service": "disable",
            "dns-server-override": "enable",
            "src-check": "enable",
            "speed": "auto",
        },
    ],

    # ── Firewall Policies (triggers: disabled policy, any-to-any, no logging,
    #    no UTM, no SSL inspection, unnamed policy, all services, no egress filter)
    "firewall/policy": [
        {
            "policyid": 1,
            "name": "Allow-All-Internet",
            "action": "accept",
            "status": "enable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "disable",
            "schedule": "always",
        },
        {
            "policyid": 2,
            "name": "DMZ-Access",
            "action": "accept",
            "status": "enable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "DMZ-Servers"}],
            "service": [{"name": "HTTP"}, {"name": "HTTPS"}],
            "srcintf": [{"name": "wan1"}],
            "dstintf": [{"name": "dmz"}],
            "logtraffic": "disable",
        },
        {
            "policyid": 3,
            "name": "",
            "action": "accept",
            "status": "enable",
            "srcaddr": [{"name": "LAN-Subnet"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "",
        },
        {
            "policyid": 4,
            "name": "Old-Test-Policy",
            "action": "accept",
            "status": "disable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "disable",
        },
        {
            "policyid": 5,
            "name": "Deny-Block",
            "action": "deny",
            "status": "enable",
            "srcaddr": [{"name": "Bad-IPs"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "wan1"}],
            "dstintf": [{"name": "lan"}],
            "logtraffic": "disable",
        },
        {
            "policyid": 6,
            "name": "Old-Disabled-1",
            "action": "accept",
            "status": "disable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "disable",
        },
        {
            "policyid": 7,
            "name": "Old-Disabled-2",
            "action": "accept",
            "status": "disable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "disable",
        },
        {
            "policyid": 8,
            "name": "Old-Disabled-3",
            "action": "accept",
            "status": "disable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "disable",
        },
        {
            "policyid": 9,
            "name": "Old-Disabled-4",
            "action": "accept",
            "status": "disable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "disable",
        },
        {
            "policyid": 10,
            "name": "Old-Disabled-5",
            "action": "accept",
            "status": "disable",
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "logtraffic": "disable",
        },
    ],

    # ── VIPs (triggers: no port forwarding)
    "firewall/vip": [
        {
            "name": "WebServer-VIP",
            "type": "static-nat",
            "extip": "203.0.113.10",
            "mappedip": [{"range": "10.0.1.10"}],
            "portforward": "disable",
        },
    ],

    # ── IPv6 policies (empty => triggers finding when gui-ipv6=enable)
    "firewall/policy6": [],

    # ── SSL VPN Settings (triggers: weak TLS, default port, long idle, high login attempts,
    #    no tunnel IP pool, no DNS, DTLS disabled, no banned cipher, compression)
    "vpn.ssl/settings": {
        "status": "enable",
        "ssl-min-proto-ver": "tlsv1-0",
        "port": 443,
        "idle-timeout": 3600,
        "login-attempt-limit": 10,
        "tunnel-connect-without-reauth": "enable",
        "tunnel-ip-pools": [],
        "dns-server1": "",
        "dns-server2": "",
        "dtls-tunnel": "disable",
        "banned-cipher": "",
        "http-compression": "enable",
        "reqclientcert": "disable",
    },

    # ── SSL VPN Portals (triggers: split tunnelling, no host check, FTP access,
    #    no concurrent login limit, web-mode)
    "vpn.ssl.web/portal": [
        {
            "name": "full-access",
            "split-tunneling": "enable",
            "web-mode": "enable",
            "host-check": "disable",
            "allow-user-access": "web ftp smb",
            "limit-user-logins": "disable",
            "ip-pools": [],
            "tunnel-mode": "",
        },
        {
            "name": "guest-portal",
            "split-tunneling": "enable",
            "web-mode": "disable",
            "host-check": "disable",
            "allow-user-access": "web",
            "limit-user-logins": "disable",
            "ip-pools": [],
            "tunnel-mode": "",
        },
    ],

    # ── VPN User Groups (triggers: VPN group without MFA)
    "user/group": [
        {
            "name": "VPN-Users",
            "member": [{"name": "user1"}, {"name": "user2"}, {"name": "user3"}],
            "match": [],
        },
        {
            "name": "SSL-Remote-Workers",
            "member": [{"name": "remote1"}, {"name": "remote2"}],
            "match": [],
        },
    ],

    # ── IPsec Phase 1 (triggers: aggressive mode, weak encryption, weak hash,
    #    weak DH, no DPD, IKEv1, long keylife, PSK auth)
    "vpn.ipsec/phase1-interface": [
        {
            "name": "Site-B-Tunnel",
            "mode": "aggressive",
            "proposal": "des-md5 3des-md5",
            "dhgrp": "1 2",
            "dpd": "disable",
            "ike-version": "1",
            "keylife": 172800,
            "authmethod": "psk",
        },
        {
            "name": "Cloud-VPN",
            "mode": "main",
            "proposal": "aes128-sha1 3des-sha256",
            "dhgrp": "5 14",
            "dpd": "on-demand",
            "ike-version": "1",
            "keylife": 28800,
            "authmethod": "psk",
        },
    ],

    # ── IPsec Phase 2 (triggers: PFS disabled, weak encryption, long keylife,
    #    replay disabled)
    "vpn.ipsec/phase2-interface": [
        {
            "name": "Site-B-P2",
            "pfs": "disable",
            "proposal": "des-md5",
            "keylifeseconds": 86400,
            "replay": "disable",
        },
        {
            "name": "Cloud-VPN-P2",
            "pfs": "disable",
            "proposal": "3des-sha256",
            "keylifeseconds": 50000,
            "replay": "enable",
        },
    ],

    # ── Antivirus Profiles (triggers: HTTP not in block mode, no outbreak prevention,
    #    no sandbox/analytics)
    "antivirus/profile": [
        {
            "name": "default",
            "http": {"av-scan": "monitor", "options": "scan"},
            "outbreak-prevention": "disable",
            "ftgd-analytics": "disable",
            "analytics-max-upload": 0,
            "feature-set": "",
        },
    ],

    # ── IPS Sensors (triggers: all entries monitor/pass, IP exemptions)
    "ips/sensor": [
        {
            "name": "default-ips",
            "entries": [
                {"action": "pass", "exempt-ip": []},
                {"action": "monitor", "exempt-ip": [{"dst-ip": "10.0.0.0/8"}]},
            ],
        },
    ],

    # ── Web Filter Profiles (triggers: no safe search, no category filters)
    "webfilter/profile": [
        {
            "name": "basic-filter",
            "web": {"safe-search": "disable"},
            "ftgd-wf": {"filters": []},
        },
    ],

    # ── Application Control (triggers: high-risk categories allowed)
    "application/list": [
        {
            "name": "app-default",
            "entries": [
                {
                    "category": [{"id": 2}, {"id": 15}, {"id": 25}],
                    "action": "pass",
                },
            ],
        },
    ],

    # ── DLP Sensors (triggers: log-only mode)
    "dlp/sensor": [
        {
            "name": "basic-dlp",
            "filter": [
                {"action": "log-only"},
                {"action": "allow"},
            ],
        },
    ],

    # ── DNS Filter (triggers: botnet blocking disabled, no FTGD filters)
    "dnsfilter/profile": [
        {
            "name": "dns-default",
            "block-botnet": "disable",
            "sdns-domain-log": "disable",
            "ftgd-dns": {"filters": []},
        },
    ],

    # ── SSL/SSH Inspection Profiles (triggers: no deep inspection, allows invalid certs)
    "firewall/ssl-ssh-profile": [
        {
            "name": "custom-ssl-profile",
            "ssl": {"inspect-all": "certificate-inspection", "invalid-server-cert": "allow"},
            "https": {"status": "enable"},
        },
    ],

    # ── Email Filter (empty => triggers finding)
    "emailfilter/profile": [],

    # ── File Filter (triggers: no rules)
    "file-filter/profile": [
        {"name": "file-default", "rules": []},
    ],

    # ── ICAP (triggers: no preview mode)
    "icap/profile": [
        {"name": "icap-server", "preview": "disable"},
    ],

    # ── FortiAnalyzer (triggers: not enabled)
    "log.fortianalyzer/setting": {
        "status": "disable",
        "enc-algorithm": "default",
        "reliable": "disable",
    },

    # ── Syslog (triggers: not enabled)
    "log.syslogd/setting": {
        "status": "disable",
        "mode": "udp",
        "server": "",
    },

    # ── Syslog2 (secondary, disabled)
    "log.syslogd2/setting": {
        "status": "disable",
    },

    # ── Log Settings (triggers: overwrite, no implicit deny log, no local-in logging)
    "log/setting": {
        "diskfull": "overwrite",
        "fwpolicy-implicit-log": "disable",
        "local-in-allow": "disable",
        "local-in-deny-unicast": "disable",
        "log-mode": "udp",
    },

    # ── Event Filter (triggers: system/VPN/user event logging disabled)
    "log/eventfilter": {
        "event": "disable",
        "vpn": "disable",
        "user": "disable",
    },

    # ── Alert Email (triggers: no alert email configured)
    "alertemail/setting": {
        "username": "",
        "mailto1": "",
    },

    # ── Automation Triggers (empty => triggers finding)
    "system/automation-trigger": [],

    # ── HA Configuration (triggers: standalone mode)
    "system/ha": {
        "mode": "a-p",
        "authentication": "disable",
        "session-pickup": "disable",
        "encryption": "disable",
        "hbdev": "",
        "monitor": "",
        "override": "enable",
    },

    # ── HA Peers (triggers: firmware mismatch)
    "system/ha-peer": [
        {"serial": "FGT60FTK21000001", "version": "v7.0.10", "sw_version": "v7.0.10"},
        {"serial": "FGT60FTK21000002", "version": "v7.0.8", "sw_version": "v7.0.8"},
    ],

    # ── Certificates (triggers: factory cert, expired cert, expiring cert, weak key,
    #    self-signed, wildcard, SHA-1 sig)
    "vpn.certificate/local": [
        {
            "name": "Fortinet_Factory_Self-Sign",
            "common-name": "Fortinet_Factory",
            "issuer": "Fortinet_Factory",
            "subject": "Fortinet_Factory",
            "key-size": 1024,
            "signature-algorithm": "sha1WithRSAEncryption",
            "expiry": "2020-01-01 00:00:00",
            "source": "self",
        },
        {
            "name": "corp-wildcard",
            "common-name": "*.corp.example.com",
            "issuer": "DigiCert CA",
            "subject": "*.corp.example.com",
            "key-size": 2048,
            "signature-algorithm": "sha256WithRSAEncryption",
            "expiry": "2026-04-15 00:00:00",
            "source": "import",
        },
        {
            "name": "internal-ca",
            "common-name": "internal-ca.local",
            "issuer": "internal-ca.local",
            "subject": "internal-ca.local",
            "key-size": 4096,
            "signature-algorithm": "sha256WithRSAEncryption",
            "expiry": "2030-12-31 23:59:59",
            "source": "self-signed",
        },
    ],

    # ── CRL / OCSP (empty => triggers no revocation checking)
    "vpn.certificate/crl": [],
    "vpn.certificate/ocsp-server": [],

    # ── DoS Policies (triggers: high thresholds for SYN/UDP/ICMP flood)
    "firewall/DoS-policy": [
        {
            "policyid": 1,
            "anomaly": [
                {"name": "syn_flood", "status": "enable", "threshold": 50000},
                {"name": "udp_flood", "status": "enable", "threshold": 50000},
                {"name": "icmp_flood", "status": "enable", "threshold": 5000},
            ],
        },
    ],

    # ── BGP (triggers: neighbour without authentication)
    "router/bgp": {
        "neighbor": [
            {"ip": "10.0.0.1", "password": ""},
            {"ip": "10.0.0.2", "password": ""},
        ],
    },

    # ── OSPF (triggers: interface without authentication)
    "router/ospf": {
        "area": [{"id": "0.0.0.0"}],
        "ospf-interface": [
            {"name": "lan-ospf", "authentication": "none"},
            {"name": "dmz-ospf", "authentication": ""},
        ],
    },

    # ── SNMP Communities (triggers: default community, SNMPv1 enabled)
    "system.snmp/community": [
        {
            "id": 1,
            "name": "public",
            "query-v1-status": "enable",
            "query-v2c-status": "enable",
        },
        {
            "id": 2,
            "name": "private",
            "query-v1-status": "disable",
            "query-v2c-status": "enable",
        },
    ],

    # ── SNMPv3 Users (triggers: no auth/no priv)
    "system.snmp/user": [
        {"name": "monitor-user", "security-level": "no-auth-no-priv"},
    ],

    # ── NTP (triggers: no authentication)
    "system/ntp": {
        "authentication": "disable",
        "ntpserver": [{"server": "pool.ntp.org"}],
    },

    # ── ZTNA Access Proxy (triggers: no API gateway, no client cert)
    "firewall/access-proxy": [
        {
            "name": "ztna-proxy-1",
            "api-gateway": [],
            "client-cert": "disable",
        },
    ],

    # ── SD-WAN (triggers: enabled without health checks, no SLA rules)
    "system/sdwan": {
        "status": "enable",
        "health-check": [],
        "service": [],
    },

    # ── FortiGuard License Status (triggers: expired services, outdated sigs)
    "license/status": {
        "antivirus": {
            "status": "expired",
            "expires": "2025-01-15",
            "last_update": "2025-01-01 00:00:00",
        },
        "ips": {
            "status": "licensed",
            "expires": "2026-04-10",
            "last_update": "2025-12-01 00:00:00",
        },
        "webfilter": {
            "status": "disabled",
            "expires": "",
            "last_update": "",
        },
        "app-ctrl": {
            "status": "licensed",
            "expires": "2026-12-31",
            "last_update": "2026-02-15 00:00:00",
        },
    },

    # ── FortiGuard Connection (triggers: not connected)
    "system/fortiguard-service-status": {
        "connected": "disconnected",
        "service_connection_status": "disconnected",
    },

    # ── Auto Update Schedule (triggers: disabled)
    "system/autoupdate/schedule": {
        "status": "disable",
    },

    # ── Wireless WTP Profiles (triggers: CAPWAP cleartext)
    "wireless-controller/wtp-profile": [
        {"name": "default-wtp", "dtls-policy": "clear-text"},
    ],

    # ── Wireless VAPs (triggers: weak security, guest without isolation,
    #    internal SSID broadcast, no max clients, no PMF, 802.11r FT-over-DS)
    "wireless-controller/vap": [
        {
            "name": "Corp-Internal-WiFi",
            "security": "wpa-personal",
            "intra-vap-privacy": "disable",
            "broadcast-ssid": "enable",
            "max-clients": 0,
            "pmf": "disable",
            "fast-roaming": "enable",
            "ft-over-ds": "enable",
        },
        {
            "name": "Guest-WiFi",
            "security": "open",
            "intra-vap-privacy": "disable",
            "broadcast-ssid": "enable",
            "max-clients": 0,
            "pmf": "disable",
            "fast-roaming": "disable",
            "ft-over-ds": "disable",
        },
    ],

    # ── WIDS Profile (triggers: rogue AP scanning disabled)
    "wireless-controller/wids-profile": [
        {"name": "default-wids", "ap-scan": "disable"},
    ],

    # ── Central Management (triggers: no FortiManager)
    "system/central-management": {
        "mode": "normal",
        "fmg": "",
    },

    # ── Auto Update Schedule (for backup check)
    "system.autoupdate/schedule": {
        "status": "disable",
    },

    # ── LDAP Servers (triggers: no TLS, no server identity check)
    "user/ldap": [
        {
            "name": "corp-ad",
            "secure": "starttls",
            "port": 389,
            "server-identity-check": "disable",
        },
        {
            "name": "legacy-ldap",
            "secure": "disable",
            "port": 389,
            "server-identity-check": "disable",
        },
    ],

    # ── RADIUS Servers (triggers: short secret, long timeout)
    "user/radius": [
        {
            "name": "radius-primary",
            "secret": "short",
            "timeout": 60,
        },
        {
            "name": "radius-secondary",
            "secret": "alsoShort",
            "timeout": 5,
        },
    ],

    # ── SAML (empty => triggers no SSO finding)
    "user/saml": [],

    # ── FSSO (empty => triggers no SSO finding)
    "user/fsso": [],

    # ── Local Users (triggers: no MFA)
    "user/local": [
        {"name": "local-admin", "two-factor": "disable", "status": "enable"},
        {"name": "local-user1", "two-factor": "disable", "status": "enable"},
    ],

    # ── DNS Settings (triggers: cleartext DNS)
    "system/dns": {
        "protocol": "cleartext",
    },

    # ── System Certificate (monitor fallback — won't be called if local exists)
    "system/certificate": [],
}


# ============================================================================
#  MONKEY-PATCH & RUN
# ============================================================================

def mock_api_get(self, path: str, monitor: bool = False) -> dict | list | None:
    """Return mock data from our test dictionary."""
    data = MOCK_API_RESPONSES.get(path)
    if data is None:
        return None
    # Simulate the API returning {"results": <data>}
    # The scanner calls data.get("results", data) on the response, but our
    # mock bypasses requests entirely and returns the inner data directly.
    return data


def mock_get_system_status(self) -> bool:
    """Inject mock system status."""
    self._sys_info = MOCK_SYSTEM_STATUS
    ver_str = MOCK_SYSTEM_STATUS.get("version", "").lstrip("v")
    self._fw_version = self._parse_ver(ver_str)
    return True


def main():
    test_dir = os.path.dirname(os.path.abspath(__file__))

    # Monkey-patch the scanner to use mock data
    FortinetScanner._api_get = mock_api_get
    FortinetScanner._get_system_status = mock_get_system_status

    # Create scanner instance (host/token don't matter since API is mocked)
    scanner = FortinetScanner(
        host="10.0.0.1",
        token="mock-test-token",
        verify_ssl=False,
        timeout=30,
        verbose=True,
    )

    # Run the scan
    scanner.scan()

    # Print report
    scanner.print_report()

    # Save JSON report
    json_path = os.path.join(test_dir, "fortinet_report.json")
    scanner.save_json(json_path)

    # Save HTML report
    html_path = os.path.join(test_dir, "fortinet_report.html")
    scanner.save_html(html_path)

    # Print summary
    counts = scanner.summary()
    print("\n" + "=" * 60)
    print("  TEST RESULTS SUMMARY")
    print("=" * 60)
    total = sum(counts.values())
    print(f"  Total findings: {total}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = counts.get(sev, 0)
        print(f"    {sev:10s}: {count}")
    print("=" * 60)

    # Count categories
    categories = {}
    for f in scanner.findings:
        categories[f.category] = categories.get(f.category, 0) + 1
    print("\n  Findings by Category:")
    print("  " + "-" * 50)
    for cat in sorted(categories.keys()):
        print(f"    {cat:35s}: {categories[cat]}")
    print("  " + "-" * 50)
    print(f"\n  Reports saved:")
    print(f"    JSON: {json_path}")
    print(f"    HTML: {html_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
