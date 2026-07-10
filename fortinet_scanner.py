#!/usr/bin/env python3
"""
Fortinet FortiGate / FortiOS Network Security Scanner v4.0.0

A comprehensive live-API security scanner for Fortinet FortiGate NGFW
appliances.  Connects via the FortiOS REST API (/api/v2/cmdb/...) and
audits firewall policies, admin access, VPN configuration, security
profiles, logging, HA, certificates, ZTNA, and known CVEs.

Supported targets:
  FortiGate NGFW (FortiOS 6.x / 7.x)
  FortiGate-VM (cloud and on-prem)
  FortiWiFi appliances running FortiOS

Usage:
  python fortinet_scanner.py 10.1.1.1 --token <API-TOKEN>
  python fortinet_scanner.py fw.corp.local --token <TOKEN> --json report.json --html report.html
  python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --severity HIGH --verbose
"""

from __future__ import annotations

import argparse
import html as _html
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "4.0.0"

# ---------------------------------------------------------------------------
# requests / urllib3 (only required for live API mode — imported lazily so
# the offline scanner can run on a minimal Python install without them)
# ---------------------------------------------------------------------------
_requests = None
try:
    import urllib3 as _urllib3
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    _urllib3 = None


def _ensure_requests():
    """Import the ``requests`` library on demand. Live API mode only."""
    global _requests
    if _requests is None:
        try:
            import requests as _req  # noqa: PLC0415
        except ImportError:
            print(
                "[!] 'requests' library is required for live API scanning: pip install requests",
                file=sys.stderr,
            )
            sys.exit(1)
        _requests = _req
    return _requests

# ========================================================================== #
#  KNOWN FortiOS CVEs                                                         #
# ========================================================================== #

FORTIOS_CVES: list[dict] = [
    {
        "id": "FORTIOS-CVE-001", "cve": "CVE-2024-55591", "severity": "CRITICAL",
        "name": "Authentication bypass via Node.js websocket module",
        "affected": [
            {"train": "7.0", "fixed": "7.0.17"},
        ],
        "description": "An authentication bypass using an alternate path (CWE-288) in FortiOS allows a remote unauthenticated attacker to gain super-admin privileges via crafted requests to the Node.js websocket module. Actively exploited in the wild since November 2024.",
        "recommendation": "Upgrade to FortiOS 7.0.17 or later. Restrict management interface access to trusted IPs. Disable HTTP/HTTPS admin access on WAN interfaces.",
        "cwe": "CWE-288",
    },
    {
        "id": "FORTIOS-CVE-002", "cve": "CVE-2024-21762", "severity": "CRITICAL",
        "name": "SSL VPN out-of-bounds write (RCE)",
        "affected": [
            {"train": "7.4", "fixed": "7.4.3"},
            {"train": "7.2", "fixed": "7.2.7"},
            {"train": "7.0", "fixed": "7.0.14"},
            {"train": "6.4", "fixed": "6.4.15"},
            {"train": "6.2", "fixed": "6.2.16"},
            # 6.0 is affected per FG-IR-24-015 but EOL with no fixed build —
            # sentinel flags every 6.0.x ("migrate to a fixed release").
            {"train": "6.0", "fixed": "6.0.999"},
        ],
        "description": "An out-of-bounds write vulnerability in FortiOS SSL VPN (sslvpnd) allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests. Added to CISA Known Exploited Vulnerabilities (KEV) catalogue.",
        "recommendation": "Upgrade to the fixed version for your branch. If immediate patching is not possible, disable SSL VPN as a workaround.",
        "cwe": "CWE-787",
    },
    {
        "id": "FORTIOS-CVE-003", "cve": "CVE-2024-23113", "severity": "CRITICAL",
        "name": "Format string vulnerability in fgfmd daemon",
        "affected": [
            {"train": "7.4", "fixed": "7.4.3"},
            {"train": "7.2", "fixed": "7.2.7"},
            {"train": "7.0", "fixed": "7.0.14"},
        ],
        "description": "A format string vulnerability (CWE-134) in the FortiOS fgfmd daemon allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.",
        "recommendation": "Upgrade to the fixed version. Restrict access to the FGFM port (tcp/541) to trusted FortiManager IPs only.",
        "cwe": "CWE-134",
    },
    {
        "id": "FORTIOS-CVE-004", "cve": "CVE-2023-27997", "severity": "CRITICAL",
        "name": "SSL VPN heap buffer overflow (xortigate)",
        "affected": [
            {"train": "7.2", "fixed": "7.2.5"},
            {"train": "7.0", "fixed": "7.0.12"},
            {"train": "6.4", "fixed": "6.4.13"},
            {"train": "6.2", "fixed": "6.2.15"},
            # 6.0 is affected per FG-IR-23-097 but EOL with no fixed build.
            {"train": "6.0", "fixed": "6.0.999"},
        ],
        "description": "A heap-based buffer overflow vulnerability in FortiOS SSL VPN allows a remote attacker to execute arbitrary code via specially crafted requests. Publicly known as 'xortigate'.",
        "recommendation": "Upgrade to the fixed version for your branch. Disable SSL VPN if not required.",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-005", "cve": "CVE-2022-42475", "severity": "CRITICAL",
        "name": "SSL VPN heap overflow with persistent backdoor",
        "affected": [
            {"train": "7.2", "fixed": "7.2.3"},
            {"train": "7.0", "fixed": "7.0.9"},
            {"train": "6.4", "fixed": "6.4.11"},
            {"train": "6.2", "fixed": "6.2.12"},
        ],
        "description": "A heap-based buffer overflow in FortiOS sslvpnd allows a remote unauthenticated attacker to achieve RCE. Threat actors have been observed creating symbolic links in the SSL VPN language folder to maintain persistent read-only access even after patching.",
        "recommendation": "Upgrade to the fixed version AND check for symlink persistence in /data/etc/ssl/vhosts/*/language/. Reset the device if backdoors are found.",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-006", "cve": "CVE-2024-47575", "severity": "CRITICAL",
        "name": "FortiManager missing authentication (FortiJump)",
        "product": "FortiManager",  # NOT FortiOS — skipped for FortiGate firmware matching
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.8"},
            {"train": "7.0", "fixed": "7.0.13"},
        ],
        "description": "A missing authentication for critical function vulnerability (CWE-306) in FortiManager fgfmsd daemon allows a remote unauthenticated attacker to execute arbitrary code via specially crafted requests. Known as 'FortiJump'.",
        "recommendation": "Upgrade FortiManager to the fixed version. Restrict FGFM access to known FortiGate IP addresses.",
        "cwe": "CWE-306",
    },
    {
        "id": "FORTIOS-CVE-007", "cve": "CVE-2023-48788", "severity": "CRITICAL",
        "name": "FortiClient EMS SQL injection",
        "product": "FortiClient EMS",  # NOT FortiOS — skipped for FortiGate firmware matching
        "affected": [
            {"train": "7.2", "fixed": "7.2.3"},
            {"train": "7.0", "fixed": "7.0.11"},
        ],
        "description": "An SQL injection vulnerability in FortiClient EMS allows an unauthenticated attacker to execute commands via specially crafted requests to the DAS component.",
        "recommendation": "Upgrade FortiClient EMS to the fixed version.",
        "cwe": "CWE-89",
    },
    {
        "id": "FORTIOS-CVE-008", "cve": "CVE-2021-26109", "severity": "CRITICAL",
        "name": "SSL-VPN memory allocator integer overflow (heap RCE)",
        "affected": [
            {"train": "7.0", "fixed": "7.0.1"},
            {"train": "6.4", "fixed": "6.4.6"},
            {"train": "6.2", "fixed": "6.2.10"},
            {"train": "6.0", "fixed": "6.0.13"},
        ],
        "description": "An integer overflow in the SSL-VPN memory allocator lets an unauthenticated attacker corrupt heap control data via crafted requests to the SSL-VPN service, leading to potential remote code execution.",
        "recommendation": "Upgrade to FortiOS 7.0.1 / 6.4.6 / 6.2.10 / 6.0.13 or later. If SSL-VPN is not required, disable it; otherwise restrict SSL-VPN portal access to trusted sources.",
        "cwe": "CWE-190",
    },
    {
        "id": "FORTIOS-CVE-009", "cve": "CVE-2023-50176", "severity": "HIGH",
        "name": "SSL VPN session hijacking",
        "affected": [
            {"train": "7.4", "fixed": "7.4.2"},
            {"train": "7.2", "fixed": "7.2.7"},
            {"train": "7.0", "fixed": "7.0.13"},
        ],
        "description": "A session fixation vulnerability in FortiOS SSL VPN allows an attacker to hijack user sessions via phishing.",
        "recommendation": "Upgrade to the fixed version. Enable MFA for all SSL VPN users.",
        "cwe": "CWE-384",
    },
    {
        "id": "FORTIOS-CVE-010", "cve": "CVE-2023-36554", "severity": "HIGH",
        "name": "FortiManager API remote code execution",
        "product": "FortiManager",  # NOT FortiOS — skipped for FortiGate firmware matching
        "affected": [
            {"train": "7.4", "fixed": "7.4.1"},
            {"train": "7.2", "fixed": "7.2.5"},
        ],
        "description": "An improper access control vulnerability in FortiManager API allows a remote authenticated attacker to execute arbitrary code.",
        "recommendation": "Upgrade FortiManager. Restrict API access to trusted admin networks.",
        "cwe": "CWE-284",
    },
    {
        "id": "FORTIOS-CVE-011", "cve": "CVE-2022-40684", "severity": "CRITICAL",
        "name": "Authentication bypass via crafted HTTP request",
        "affected": [
            {"train": "7.2", "fixed": "7.2.2"},
            {"train": "7.0", "fixed": "7.0.7"},
        ],
        "description": "An authentication bypass using alternate path or channel in FortiOS allows an unauthenticated attacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.",
        "recommendation": "Upgrade to the fixed version. Immediately restrict admin interface access.",
        "cwe": "CWE-288",
    },
    {
        "id": "FORTIOS-CVE-012", "cve": "CVE-2022-41328", "severity": "HIGH",
        "name": "Path traversal allowing code execution",
        "affected": [
            {"train": "7.2", "fixed": "7.2.4"},
            {"train": "7.0", "fixed": "7.0.10"},
            {"train": "6.4", "fixed": "6.4.12"},
        ],
        "description": "A path traversal vulnerability in FortiOS allows a privileged attacker to read and write arbitrary files via crafted CLI commands.",
        "recommendation": "Upgrade to the fixed version. Audit admin account access.",
        "cwe": "CWE-22",
    },
    {
        "id": "FORTIOS-CVE-013", "cve": "CVE-2023-25610", "severity": "CRITICAL",
        "name": "Buffer underwrite in administrative interface",
        "affected": [
            {"train": "7.2", "fixed": "7.2.4"},
            {"train": "7.0", "fixed": "7.0.10"},
            {"train": "6.4", "fixed": "6.4.12"},
            {"train": "6.2", "fixed": "6.2.13"},
        ],
        "description": "A buffer underwrite vulnerability in the FortiOS administrative interface allows a remote unauthenticated attacker to execute arbitrary code via specifically crafted requests.",
        "recommendation": "Upgrade to the fixed version. Restrict admin interface access to internal management networks.",
        "cwe": "CWE-124",
    },
    {
        "id": "FORTIOS-CVE-014", "cve": "CVE-2020-12812", "severity": "HIGH",
        "name": "SSL VPN improper authentication",
        "affected": [
            {"train": "6.4", "fixed": "6.4.1"},
            {"train": "6.2", "fixed": "6.2.4"},
        ],
        "description": "An improper authentication vulnerability in FortiOS SSL VPN allows a user to log in without being prompted for the second factor of authentication (FortiToken) if they change the case of their username.",
        "recommendation": "Upgrade to the fixed version. Enforce case-sensitive username matching.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-015", "cve": "CVE-2019-5591", "severity": "HIGH",
        "name": "Default configuration vulnerability — LDAP server identity not verified",
        "affected": [
            {"train": "6.2", "fixed": "6.2.4"},
        ],
        "description": "A default configuration vulnerability in FortiOS may allow an unauthenticated attacker on the same subnet to intercept LDAP traffic by impersonating the LDAP server.",
        "recommendation": "Enable server identity verification for all LDAP connections.",
        "cwe": "CWE-295",
    },
    {
        "id": "FORTIOS-CVE-016", "cve": "CVE-2025-22254", "severity": "HIGH",
        "name": "GUI websocket module improper privilege management",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.10"},
        ],
        "description": "An improper privilege management vulnerability in the FortiOS GUI websocket module allows an authenticated attacker to escalate privileges.",
        "recommendation": "Upgrade to the fixed version. Restrict GUI access to trusted networks.",
        "cwe": "CWE-269",
    },
    {
        "id": "FORTIOS-CVE-017", "cve": "CVE-2025-25250", "severity": "MEDIUM",
        "name": "SSL VPN sensitive information disclosure",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.10"},
            {"train": "7.0", "fixed": "7.0.17"},
        ],
        "description": "A sensitive information disclosure vulnerability in FortiOS SSL VPN may expose session or configuration data.",
        "recommendation": "Upgrade to the fixed version.",
        "cwe": "CWE-200",
    },
    {
        "id": "FORTIOS-CVE-018", "cve": "CVE-2023-44249", "severity": "HIGH",
        "name": "Access control vulnerability in FortiOS REST API",
        "affected": [
            {"train": "7.4", "fixed": "7.4.1"},
            {"train": "7.2", "fixed": "7.2.6"},
            {"train": "7.0", "fixed": "7.0.13"},
        ],
        "description": "An improper access control vulnerability in FortiOS allows an authenticated attacker to access resources beyond their intended permissions via crafted API requests.",
        "recommendation": "Upgrade to the fixed version. Review API user permissions.",
        "cwe": "CWE-284",
    },
    {
        "id": "FORTIOS-CVE-019", "cve": "CVE-2023-42789", "severity": "CRITICAL",
        "name": "Captive portal buffer overflow",
        "affected": [
            {"train": "7.4", "fixed": "7.4.1"},
            {"train": "7.2", "fixed": "7.2.6"},
            {"train": "7.0", "fixed": "7.0.13"},
        ],
        "description": "A heap-based buffer overflow in the FortiOS captive portal may allow an attacker with access to the captive portal to execute arbitrary code via specially crafted HTTP requests.",
        "recommendation": "Upgrade to the fixed version. Restrict captive portal access.",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-020", "cve": "CVE-2024-26010", "severity": "HIGH",
        "name": "Stack-based buffer overflow via crafted packets",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.8"},
            {"train": "7.0", "fixed": "7.0.15"},
            {"train": "6.4", "fixed": "6.4.16"},
            {"train": "6.2", "fixed": "6.2.17"},
        ],
        "description": "A stack-based buffer overflow in FortiOS (and FortiProxy/FortiPAM/FortiWeb/FortiSwitchManager) allows an attacker to execute unauthorized code or commands via specially crafted packets (FG-IR-24-015).",
        "recommendation": "Upgrade to the fixed version.",
        "cwe": "CWE-121",
    },
    # ── 2025 CVEs ───────────────────────────────────────────────────────
    {
        "id": "FORTIOS-CVE-021", "cve": "CVE-2024-48884", "severity": "HIGH",
        "name": "Path traversal in FortiOS httpd — file read",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.10"},
            {"train": "7.0", "fixed": "7.0.16"},
        ],
        "description": "A path traversal vulnerability in FortiOS httpd allows a remote authenticated attacker with read-only admin privileges to read arbitrary files on the device.",
        "recommendation": "Upgrade to FortiOS 7.4.5, 7.2.10, or 7.0.16. Restrict admin access to trusted IPs.",
        "cwe": "CWE-22",
    },
    {
        "id": "FORTIOS-CVE-022", "cve": "CVE-2024-48886", "severity": "HIGH",
        "name": "SSL VPN authentication bypass via cookie manipulation",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.10"},
        ],
        "description": "An authentication bypass in FortiOS SSL VPN allows a remote attacker to bypass authentication via crafted cookie values, gaining unauthorized VPN access.",
        "recommendation": "Upgrade to FortiOS 7.4.5 or 7.2.10. Monitor SSL VPN auth logs for anomalies.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-023", "cve": "CVE-2025-24472", "severity": "CRITICAL",
        "name": "CSF proxy authentication bypass — super-admin",
        "affected": [
            {"train": "7.0", "fixed": "7.0.17"},
        ],
        "description": "An authentication bypass in FortiOS CSF proxy allows a remote unauthenticated attacker to gain super-admin privileges via crafted CSF proxy requests. Related to CVE-2024-55591, actively exploited.",
        "recommendation": "Upgrade to FortiOS 7.0.17+. Disable HTTP/HTTPS management on WAN interfaces. Restrict management to trusted IPs.",
        "cwe": "CWE-288",
    },
    {
        "id": "FORTIOS-CVE-024", "cve": "CVE-2024-46666", "severity": "MEDIUM",
        "name": "Resource consumption via crafted HTTP/S requests",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.9"},
            {"train": "7.0", "fixed": "7.0.16"},
        ],
        "description": "Uncontrolled resource consumption in FortiOS allows a remote unauthenticated attacker to cause denial of service via crafted HTTP/S requests consuming excessive memory.",
        "recommendation": "Upgrade to the fixed version. Implement rate limiting on management interfaces.",
        "cwe": "CWE-400",
    },
    {
        "id": "FORTIOS-CVE-025", "cve": "CVE-2024-46668", "severity": "HIGH",
        "name": "httpd memory exhaustion via large request bodies",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.9"},
        ],
        "description": "A resource allocation vulnerability in FortiOS httpd allows a remote unauthenticated attacker to cause memory exhaustion and denial of service by sending large HTTP request bodies.",
        "recommendation": "Upgrade to FortiOS 7.4.4 or 7.2.9. Configure request size limits on upstream WAF/LB.",
        "cwe": "CWE-770",
    },
    {
        "id": "FORTIOS-CVE-026", "cve": "CVE-2024-50563", "severity": "HIGH",
        "name": "Weak authentication in FGFM protocol",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.10"},
            {"train": "7.0", "fixed": "7.0.16"},
        ],
        "description": "Weak authentication in the FGFM (FortiGate-FortiManager) protocol allows an attacker with network access to forge communications between FortiGate and FortiManager.",
        "recommendation": "Upgrade to fixed version. Restrict FGFM port (541) access. Use certificate-based FortiManager auth.",
        "cwe": "CWE-1390",
    },
    {
        "id": "FORTIOS-CVE-027", "cve": "CVE-2024-35279", "severity": "CRITICAL",
        "name": "Stack-based buffer overflow via CAPWAP control — RCE",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.9"},
        ],
        "description": "A stack-based buffer overflow in FortiOS allows a remote unauthenticated attacker to execute arbitrary code or commands via crafted UDP packets through the CAPWAP control, when the fabric service is running on the exposed interface (FG-IR-24-160).",
        "recommendation": "Upgrade to FortiOS 7.4.5 or 7.2.9. Restrict CAPWAP (UDP 5246) and disable the fabric/CAPWAP service on internet-facing interfaces.",
        "cwe": "CWE-121",
    },
    {
        "id": "FORTIOS-CVE-028", "cve": "CVE-2024-33510", "severity": "MEDIUM",
        "name": "SSL VPN improper access control — cross-user",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.9"},
            {"train": "7.0", "fixed": "7.0.15"},
        ],
        "description": "Improper access control in FortiOS SSL VPN web portal allows an authenticated attacker to access bookmarks and resources of other SSL VPN users.",
        "recommendation": "Upgrade to fixed version. Review SSL VPN portal access controls and user group assignments.",
        "cwe": "CWE-284",
    },
    {
        "id": "FORTIOS-CVE-029", "cve": "CVE-2025-22252", "severity": "CRITICAL",
        "name": "TACACS+ authentication bypass (missing authentication)",
        "affected": [
            {"train": "7.6", "fixed": "7.6.1"},
            {"train": "7.4", "fixed": "7.4.7"},
        ],
        "description": "Missing authentication for a critical function in FortiOS (and FortiProxy/FortiSwitchManager) devices configured to use TACACS+ with ASCII authentication allows an attacker who knows an existing admin account to bypass authentication and access the device as a valid admin (FG-IR-24-472).",
        "recommendation": "Upgrade to FortiOS 7.4.7 or 7.6.1. If using TACACS+ for administrator authentication, avoid ASCII authentication and prefer PAP/CHAP/MSCHAP where supported.",
        "cwe": "CWE-306",
    },
    {
        "id": "FORTIOS-CVE-030", "cve": "CVE-2024-40591", "severity": "HIGH",
        "name": "Authenticated admin privilege escalation",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
            {"train": "7.2", "fixed": "7.2.10"},
            {"train": "7.0", "fixed": "7.0.16"},
        ],
        "description": "Improper privilege management in FortiOS allows an authenticated administrator with limited privileges to escalate to super-admin via crafted configuration changes.",
        "recommendation": "Upgrade to fixed version. Review admin accounts for least-privilege. Monitor config change logs.",
        "cwe": "CWE-269",
    },
    # ─────────────────────────────────────────────────────────────────────────
    #  Batch 2: comprehensive PSIRT sweep (2023-2026), CVE-031 .. CVE-066
    #  Sourced from FortiGuard PSIRT advisories pages 1-7 (FortiOS filter).
    #  Fixed version derived as (max-affected-version + 1 patch) per the
    #  Fortinet release convention; verified against several known CVEs.
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "FORTIOS-CVE-031", "cve": "CVE-2026-24858", "severity": "CRITICAL",
        "name": "Administrative FortiCloud SSO authentication bypass",
        "affected": [
            {"train": "7.6", "fixed": "7.6.6"},
        ],
        "description": "An authentication bypass in the FortiCloud SSO login flow on FortiOS allows a remote attacker to gain administrative access to the FortiGate via crafted SSO requests.",
        "recommendation": "Upgrade to FortiOS 7.6.6 or later. If FortiCloud SSO is not required, disable it on the admin login profile.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-032", "cve": "CVE-2025-59718", "severity": "CRITICAL",
        "name": "FortiCloud SSO login authentication bypass (multi-product)",
        "affected": [
            {"train": "7.6", "fixed": "7.6.4"},
            {"train": "7.4", "fixed": "7.4.9"},
        ],
        "description": "A missing or improper authentication step in the FortiCloud SSO login handler allows an unauthenticated attacker to obtain a valid admin session against multiple Fortinet products including FortiOS.",
        "recommendation": "Upgrade FortiOS to 7.6.4 / 7.4.9 or later. Restrict admin login interfaces to management networks.",
        "cwe": "CWE-288",
    },
    {
        "id": "FORTIOS-CVE-033", "cve": "CVE-2026-22153", "severity": "HIGH",
        "name": "LDAP authentication bypass in Agentless VPN and FSSO",
        "affected": [
            {"train": "7.6", "fixed": "7.6.5"},
        ],
        "description": "An authentication bypass in the LDAP path used by FortiOS Agentless VPN and Fortinet Single Sign-On (FSSO) allows an attacker to authenticate as a valid user without supplying valid credentials.",
        "recommendation": "Upgrade FortiOS to 7.6.5 or later. Audit LDAP authentication logs for unexplained successful logins.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-034", "cve": "CVE-2025-58325", "severity": "HIGH",
        "name": "Restricted CLI command bypass",
        "affected": [
            {"train": "7.6", "fixed": "7.6.1"},
            {"train": "7.4", "fixed": "7.4.6"},
        ],
        "description": "A restricted shell escape allows an admin with a limited-CLI profile (prof_admin / read-only) to execute commands outside their permitted command set, leading to privilege escalation.",
        "recommendation": "Upgrade to fixed version. Review accprofile assignments for least-privilege.",
        "cwe": "CWE-184",
    },
    {
        "id": "FORTIOS-CVE-035", "cve": "CVE-2025-53844", "severity": "HIGH",
        "name": "Out-of-bounds access in CAPWAP daemon",
        "affected": [
            {"train": "7.6", "fixed": "7.6.4"},
            {"train": "7.4", "fixed": "7.4.9"},
            {"train": "7.2", "fixed": "7.2.11"},
        ],
        "description": "An out-of-bounds memory access in the CAPWAP daemon used to manage FortiAP access points allows a network-adjacent attacker to crash the daemon or potentially execute code.",
        "recommendation": "Upgrade to fixed version. If FortiAPs are not deployed, disable the CAPWAP listener.",
        "cwe": "CWE-125",
    },
    {
        "id": "FORTIOS-CVE-036", "cve": "CVE-2025-25249", "severity": "HIGH",
        "name": "Heap-based buffer overflow in cw_acd daemon (CAPWAP)",
        "affected": [
            {"train": "7.6", "fixed": "7.6.4"},
            {"train": "7.4", "fixed": "7.4.9"},
        ],
        "description": "A heap-based buffer overflow in the cw_acd CAPWAP control daemon allows a remote unauthenticated attacker on the management/wireless segment to execute arbitrary code or crash the daemon.",
        "recommendation": "Upgrade to fixed version. Restrict CAPWAP (UDP/5246, UDP/5247) to trusted AP networks only.",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-037", "cve": "CVE-2024-46670", "severity": "HIGH",
        "name": "Out-of-bounds read in IPsec IKE handler",
        "affected": [
            {"train": "7.6", "fixed": "7.6.1"},
            {"train": "7.4", "fixed": "7.4.5"},
        ],
        "description": "An out-of-bounds read in the IPsec IKE message handler can be triggered by a malformed IKE packet, leading to information disclosure or daemon crash.",
        "recommendation": "Upgrade to fixed version. Restrict IPsec peer IPs in phase-1 configuration where possible.",
        "cwe": "CWE-125",
    },
    {
        "id": "FORTIOS-CVE-038", "cve": "CVE-2024-45324", "severity": "HIGH",
        "name": "Multiple format string vulnerabilities",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
        ],
        "description": "Multiple format string flaws across FortiOS components allow an authenticated attacker to execute arbitrary code or trigger memory disclosure via crafted CLI input.",
        "recommendation": "Upgrade to FortiOS 7.4.5 or later.",
        "cwe": "CWE-134",
    },
    {
        "id": "FORTIOS-CVE-039", "cve": "CVE-2024-26013", "severity": "HIGH",
        "name": "FGFM connection lacks certificate name verification",
        "affected": [
            {"train": "7.4", "fixed": "7.4.5"},
        ],
        "description": "The FortiGate Federated Management (FGFM) channel between the FortiGate and FortiManager does not properly verify the certificate name, allowing a MitM attacker on the management network to intercept or modify management traffic.",
        "recommendation": "Upgrade to FortiOS 7.4.5. Use IPsec or dedicated out-of-band management for FGFM where possible.",
        "cwe": "CWE-295",
    },
    {
        "id": "FORTIOS-CVE-040", "cve": "CVE-2024-26009", "severity": "HIGH",
        "name": "Weak authentication in FGFM protocol (FortiOS 6.4)",
        "affected": [
            {"train": "6.4", "fixed": "6.4.16"},
        ],
        "description": "A weak-authentication flaw in the FGFM protocol on FortiOS 6.4 lets an attacker who can reach the management port impersonate FortiManager and push configuration changes.",
        "recommendation": "Upgrade to FortiOS 6.4.16 or migrate to 7.x. Restrict FGFM (TCP/541) to trusted FortiManager IPs.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-041", "cve": "CVE-2024-23110", "severity": "HIGH",
        "name": "Multiple buffer overflows in 'diag npu' CLI command",
        "affected": [
            {"train": "7.4", "fixed": "7.4.3"},
            {"train": "7.2", "fixed": "7.2.7"},
        ],
        "description": "Multiple stack-based buffer overflows in the 'diag npu' diagnostic CLI commands allow an authenticated admin to execute arbitrary code with elevated privileges.",
        "recommendation": "Upgrade to fixed version. Restrict CLI access to trusted admins.",
        "cwe": "CWE-120",
    },
    {
        "id": "FORTIOS-CVE-042", "cve": "CVE-2024-23112", "severity": "HIGH",
        "name": "Authorization bypass via SSL VPN bookmarks",
        "affected": [
            {"train": "7.4", "fixed": "7.4.2"},
            {"train": "7.2", "fixed": "7.2.7"},
        ],
        "description": "An IDOR-style authorization bypass in the SSL VPN bookmark mechanism allows an authenticated SSL VPN user to access another user's bookmarks (and the resources they reference).",
        "recommendation": "Upgrade to fixed version. Audit SSL VPN bookmarks for sensitive internal targets.",
        "cwe": "CWE-639",
    },
    {
        "id": "FORTIOS-CVE-043", "cve": "CVE-2023-44250", "severity": "HIGH",
        "name": "Improper authorization for HA requests",
        "affected": [
            {"train": "7.4", "fixed": "7.4.2"},
            {"train": "7.2", "fixed": "7.2.6"},
        ],
        "description": "Improper authorization on HA cluster requests allows a low-privileged admin on one HA peer to perform operations that should require super-admin privileges, by routing the request through the HA channel.",
        "recommendation": "Upgrade to fixed version. Restrict HA heartbeat/sync interfaces to dedicated, isolated VLANs.",
        "cwe": "CWE-285",
    },
    {
        "id": "FORTIOS-CVE-044", "cve": "CVE-2023-41677", "severity": "HIGH",
        "name": "Administrator cookie leakage",
        "affected": [
            {"train": "7.4", "fixed": "7.4.2"},
            {"train": "7.2", "fixed": "7.2.7"},
        ],
        "description": "An admin authentication cookie may be exposed to other services or written to logs, allowing an attacker with limited access to hijack an active admin session.",
        "recommendation": "Upgrade to fixed version. Rotate admin sessions and review audit logs for unexpected admin activity.",
        "cwe": "CWE-1004",
    },
    {
        "id": "FORTIOS-CVE-045", "cve": "CVE-2023-41678", "severity": "HIGH",
        "name": "Double-free in cache management (FortiOS 7.0)",
        "affected": [
            {"train": "7.0", "fixed": "7.0.6"},
        ],
        "description": "A double-free condition in the FortiOS 7.0 cache management code allows a remote attacker to crash the system or potentially achieve code execution.",
        "recommendation": "Upgrade to FortiOS 7.0.6 or later.",
        "cwe": "CWE-415",
    },
    {
        "id": "FORTIOS-CVE-046", "cve": "CVE-2023-36639", "severity": "HIGH",
        "name": "Format string vulnerability in HTTPSd",
        "affected": [
            {"train": "7.4", "fixed": "7.4.1"},
            {"train": "7.2", "fixed": "7.2.5"},
        ],
        "description": "A format string flaw in the HTTPSd web administration daemon allows an authenticated attacker to crash the daemon or execute arbitrary code.",
        "recommendation": "Upgrade to fixed version. Restrict admin HTTPS access to trusted networks.",
        "cwe": "CWE-134",
    },
    {
        "id": "FORTIOS-CVE-047", "cve": "CVE-2025-68686", "severity": "MEDIUM",
        "name": "SSL-VPN symlink persistence patch bypass",
        "affected": [
            {"train": "7.6", "fixed": "7.6.2"},
            {"train": "7.4", "fixed": "7.4.7"},
        ],
        "description": "A patch bypass for the SSL-VPN symlink persistence technique (originally seen with CVE-2022-42475) lets an attacker who previously planted a symlink under /data/etc/ssl/vhosts/*/language/ retain read-only access to portal files after patching.",
        "recommendation": "Upgrade to fixed version AND audit /data/etc/ssl/vhosts/*/language/ for unexpected symlinks. Reset affected devices.",
        "cwe": "CWE-59",
    },
    {
        "id": "FORTIOS-CVE-048", "cve": "CVE-2025-67862", "severity": "MEDIUM",
        "name": "Restricted CLI escape via embedded Lua",
        "affected": [
            {"train": "7.6", "fixed": "7.6.4"},
            {"train": "7.4", "fixed": "7.4.9"},
            {"train": "7.2", "fixed": "7.2.11"},
            {"train": "7.0", "fixed": "7.0.17"},
            {"train": "6.4", "fixed": "6.4.16"},
        ],
        "description": "An admin restricted to a limited CLI profile can break out via the embedded Lua scripting engine, executing arbitrary system commands.",
        "recommendation": "Upgrade to fixed version. Disable Lua scripting for restricted admins.",
        "cwe": "CWE-78",
    },
    {
        "id": "FORTIOS-CVE-049", "cve": "CVE-2025-57740", "severity": "MEDIUM",
        "name": "Authenticated heap overflow in SSL-VPN bookmarks",
        "affected": [
            {"train": "7.6", "fixed": "7.6.3"},
            {"train": "7.4", "fixed": "7.4.8"},
        ],
        "description": "An authenticated SSL-VPN user can trigger a heap overflow in the bookmark handler, leading to denial of service or potential code execution in the SSL-VPN daemon.",
        "recommendation": "Upgrade to fixed version. Disable SSL-VPN bookmarks if not in use.",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-050", "cve": "CVE-2025-55018", "severity": "MEDIUM",
        "name": "HTTP request smuggling in admin interface",
        "affected": [
            {"train": "7.6", "fixed": "7.6.1"},
            {"train": "7.4", "fixed": "7.4.10"},
        ],
        "description": "An HTTP request smuggling vulnerability in the FortiOS web admin / SSL-VPN front-end allows an unauthenticated attacker to bypass front-end security controls or pivot through the proxy layer.",
        "recommendation": "Upgrade to fixed version. Front the admin interface with a WAF that normalises Content-Length / Transfer-Encoding.",
        "cwe": "CWE-444",
    },
    {
        "id": "FORTIOS-CVE-051", "cve": "CVE-2025-58413", "severity": "MEDIUM",
        "name": "Stack buffer overflow in CAPWAP daemon",
        "affected": [
            {"train": "7.6", "fixed": "7.6.4"},
            {"train": "7.4", "fixed": "7.4.9"},
        ],
        "description": "A stack-based buffer overflow in the CAPWAP daemon can be triggered by a malformed CAPWAP message and may lead to daemon crash or code execution.",
        "recommendation": "Upgrade to fixed version. Restrict CAPWAP ports to trusted AP segments.",
        "cwe": "CWE-121",
    },
    {
        "id": "FORTIOS-CVE-052", "cve": "CVE-2025-64157", "severity": "MEDIUM",
        "name": "Format string vulnerability in CAPWAP fast-failover mode",
        "affected": [
            {"train": "7.6", "fixed": "7.6.5"},
        ],
        "description": "A format string flaw in CAPWAP fast-failover handling allows an attacker on the AP/wireless control segment to crash the daemon or potentially execute code.",
        "recommendation": "Upgrade to FortiOS 7.6.5 or later.",
        "cwe": "CWE-134",
    },
    {
        "id": "FORTIOS-CVE-053", "cve": "CVE-2025-53847", "severity": "MEDIUM",
        "name": "Missing authentication for critical function in CAPWAP daemon",
        "affected": [
            {"train": "7.6", "fixed": "7.6.4"},
            {"train": "7.4", "fixed": "7.4.9"},
        ],
        "description": "A critical CAPWAP control function lacks authentication checks, letting a network-adjacent attacker invoke management operations on FortiAP-connected devices.",
        "recommendation": "Upgrade to fixed version. Segment AP networks from user / guest networks.",
        "cwe": "CWE-306",
    },
    {
        "id": "FORTIOS-CVE-054", "cve": "CVE-2025-54821", "severity": "MEDIUM",
        "name": "Trusted hosts bypass via SSH",
        "affected": [
            {"train": "7.6", "fixed": "7.6.4"},
            {"train": "7.4", "fixed": "7.4.12"},
        ],
        "description": "Under specific SSH configurations, the FortiOS trusted-hosts ACL is not enforced for SSH admin logins, letting an attacker connect from an untrusted source IP.",
        "recommendation": "Upgrade to fixed version. Restrict the SSH admin port via firewall policy as an additional control.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-055", "cve": "CVE-2025-61624", "severity": "MEDIUM",
        "name": "Path traversal in CLI",
        "affected": [
            {"train": "7.6", "fixed": "7.6.5"},
        ],
        "description": "A path traversal flaw in a FortiOS CLI command allows an authenticated admin to read or write files outside the intended directory, leading to privilege escalation or config tampering.",
        "recommendation": "Upgrade to FortiOS 7.6.5 or later.",
        "cwe": "CWE-22",
    },
    {
        "id": "FORTIOS-CVE-056", "cve": "CVE-2025-24471", "severity": "MEDIUM",
        "name": "eap-cert-auth bypass via revoked certificate",
        "affected": [
            {"train": "7.6", "fixed": "7.6.2"},
            {"train": "7.4", "fixed": "7.4.8"},
        ],
        "description": "The EAP certificate authentication path does not properly check certificate revocation, allowing a user with a revoked client certificate to still authenticate to 802.1X / Wi-Fi.",
        "recommendation": "Upgrade to fixed version. Verify OCSP/CRL configuration on the user certificate profile.",
        "cwe": "CWE-295",
    },
    {
        "id": "FORTIOS-CVE-057", "cve": "CVE-2025-22258", "severity": "MEDIUM",
        "name": "Heap buffer overflow in WebSocket handler",
        "affected": [
            {"train": "7.6", "fixed": "7.6.3"},
            {"train": "7.4", "fixed": "7.4.7"},
        ],
        "description": "A heap buffer overflow in the FortiOS WebSocket handler can be triggered by an authenticated user via crafted WebSocket frames, leading to potential code execution.",
        "recommendation": "Upgrade to fixed version. Disable unused WebSocket-based admin / SSL-VPN features.",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-058", "cve": "CVE-2024-55599", "severity": "MEDIUM",
        "name": "DNS filter bypass via DNS type 65 (HTTPS) records",
        "affected": [
            {"train": "7.6", "fixed": "7.6.1"},
            {"train": "7.4", "fixed": "7.4.8"},
        ],
        "description": "The DNS filter does not inspect DNS type 65 (HTTPS) resource records, allowing a client to resolve domains that should be blocked by web/DNS filtering policy.",
        "recommendation": "Upgrade to fixed version. Use additional egress filtering on DoH/DoT endpoints.",
        "cwe": "CWE-693",
    },
    {
        "id": "FORTIOS-CVE-059", "cve": "CVE-2024-50571", "severity": "MEDIUM",
        "name": "Heap overflow in fgfmsd",
        "affected": [
            {"train": "7.6", "fixed": "7.6.3"},
            {"train": "7.4", "fixed": "7.4.7"},
        ],
        "description": "A heap overflow in the fgfmsd (Fortinet Federated Management Server Daemon) can be triggered by a crafted FGFM message, potentially leading to remote code execution on the management plane.",
        "recommendation": "Upgrade to fixed version. Restrict FGFM (TCP/541) to trusted FortiManager IPs only.",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-060", "cve": "CVE-2024-50562", "severity": "MEDIUM",
        "name": "Insufficient session expiration on SSL-VPN cookie",
        "affected": [
            {"train": "7.6", "fixed": "7.6.1"},
            {"train": "7.4", "fixed": "7.4.8"},
        ],
        "description": "The SSL-VPN session cookie remains valid beyond the intended idle/absolute timeout, allowing a captured cookie to be reused after the user has logically logged out.",
        "recommendation": "Upgrade to fixed version. Tighten SSL-VPN idle-timeout and force-logout on auth failure.",
        "cwe": "CWE-613",
    },
    {
        "id": "FORTIOS-CVE-061", "cve": "CVE-2024-36505", "severity": "MEDIUM",
        "name": "Real-time file system integrity write-protection bypass",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.8"},
        ],
        "description": "The real-time file system integrity checker can be bypassed, allowing an authenticated attacker with shell access to modify protected system files without triggering integrity alerts.",
        "recommendation": "Upgrade to fixed version. Forward integrity logs to FortiAnalyzer / SIEM and alert on unexpected file modifications.",
        "cwe": "CWE-693",
    },
    {
        "id": "FORTIOS-CVE-062", "cve": "CVE-2024-26011", "severity": "MEDIUM",
        "name": "Improper authentication in fgfmd",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.8"},
        ],
        "description": "An improper authentication flaw in fgfmd allows an attacker with network access to the FGFM port to send commands that should require an authenticated FortiManager session.",
        "recommendation": "Upgrade to fixed version. Restrict FGFM (TCP/541) to trusted FortiManager IPs only.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-063", "cve": "CVE-2024-26008", "severity": "MEDIUM",
        "name": "Unauthenticated reset of FGFM connection",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.8"},
        ],
        "description": "An unauthenticated attacker who can reach the FGFM port can repeatedly reset the FGFM connection, causing management plane denial of service against FortiManager.",
        "recommendation": "Upgrade to fixed version. Restrict FGFM port to trusted FortiManager IPs.",
        "cwe": "CWE-306",
    },
    {
        "id": "FORTIOS-CVE-064", "cve": "CVE-2024-3596", "severity": "MEDIUM",
        "name": "RADIUS protocol weakness — Blast-RADIUS",
        "affected": [
            {"train": "7.6", "fixed": "7.6.1"},
            {"train": "7.4", "fixed": "7.4.6"},
        ],
        "description": "Implementation of RFC 2865 is vulnerable to the 'Blast-RADIUS' MD5 chosen-prefix collision attack, allowing a MitM on the FortiGate↔RADIUS path to forge Access-Accept responses.",
        "recommendation": "Upgrade to fixed version. Run RADIUS over IPsec or RadSec (TLS) where possible.",
        "cwe": "CWE-924",
    },
    {
        "id": "FORTIOS-CVE-065", "cve": "CVE-2023-46720", "severity": "MEDIUM",
        "name": "Stack buffer overflow on Bluetooth write feature",
        "affected": [
            {"train": "7.4", "fixed": "7.4.4"},
            {"train": "7.2", "fixed": "7.2.8"},
        ],
        "description": "A stack-based buffer overflow in the Bluetooth write helper used by FortiAP provisioning can be triggered by an attacker with physical proximity, causing a crash or code execution.",
        "recommendation": "Upgrade to fixed version. Disable Bluetooth provisioning on FortiAPs in production.",
        "cwe": "CWE-121",
    },
    {
        "id": "FORTIOS-CVE-066", "cve": "CVE-2023-46714", "severity": "MEDIUM",
        "name": "Buffer overflow in administrative interface",
        "affected": [
            {"train": "7.4", "fixed": "7.4.2"},
            {"train": "7.2", "fixed": "7.2.8"},
        ],
        "description": "A buffer overflow in the FortiOS administrative interface allows an authenticated admin to crash the management daemon or potentially execute code with elevated privileges.",
        "recommendation": "Upgrade to fixed version. Restrict admin interface to trusted networks.",
        "cwe": "CWE-120",
    },
    {
        "id": "FORTIOS-CVE-067", "cve": "CVE-2025-62439", "severity": "MEDIUM",
        "name": "FSSO policy source-verification bypass",
        "affected": [
            {"train": "7.6", "fixed": "7.6.5"},
            {"train": "7.4", "fixed": "7.4.10"},
            {"train": "7.2", "fixed": "7.2.14"},
            {"train": "7.0", "fixed": "7.0.20"},
        ],
        "description": "An improper verification of the source of a communication channel in FortiOS lets an authenticated user who knows the FSSO policy configuration reach protected network resources via crafted requests, bypassing the intended source checks.",
        "recommendation": "Upgrade to FortiOS 7.6.5 / 7.4.10 / 7.2.14 / 7.0.20 or later. Review FSSO-based firewall policies and constrain them with additional source-address and identity restrictions.",
        "cwe": "CWE-940",
    },
    {
        "id": "FORTIOS-CVE-068", "cve": "CVE-2022-35843", "severity": "CRITICAL",
        "name": "SSH login authentication bypass via crafted RADIUS response",
        "affected": [
            {"train": "7.2", "fixed": "7.2.2"},
            {"train": "7.0", "fixed": "7.0.8"},
            {"train": "6.4", "fixed": "6.4.10"},
            {"train": "6.2", "fixed": "6.2.13"},
            {"train": "6.0", "fixed": "6.0.16"},
        ],
        "description": "Improper handling of assumed-immutable data in the SSH login path lets a remote unauthenticated attacker bypass authentication when the RADIUS server can be induced to return a crafted Access-Challenge response.",
        "recommendation": "Upgrade to FortiOS 7.2.2 / 7.0.8 / 6.4.10 / 6.2.13 / 6.0.16 or later. Harden the FortiGate-to-RADIUS path (RadSec/IPsec) and restrict SSH administrative access to trusted networks.",
        "cwe": "CWE-287",
    },
    {
        "id": "FORTIOS-CVE-069", "cve": "CVE-2023-28001", "severity": "CRITICAL",
        "name": "REST API session reuse of deleted users",
        "affected": [
            {"train": "7.2", "fixed": "7.2.5"},
            {"train": "7.0", "fixed": "7.0.13"},
        ],
        "description": "Insufficient session expiration lets an attacker execute unauthorized commands via the REST API by reusing the session token of a deleted administrator/user.",
        "recommendation": "Upgrade to FortiOS 7.2.5 / 7.0.13 or later. Rotate REST API tokens and review active API admin sessions after deleting any account.",
        "cwe": "CWE-613",
    },
    {
        "id": "FORTIOS-CVE-070", "cve": "CVE-2023-33308", "severity": "CRITICAL",
        "name": "Stack overflow in proxy-mode policies with deep inspection",
        "affected": [
            {"train": "7.2", "fixed": "7.2.4"},
            {"train": "7.0", "fixed": "7.0.11"},
        ],
        "description": "A stack-based buffer overflow reachable through proxy-mode firewall/proxy policies with deep or full SSL inspection lets a remote unauthenticated attacker execute arbitrary code via crafted packets.",
        "recommendation": "Upgrade to FortiOS 7.2.4 / 7.0.11 or later. As an interim workaround, disable deep/full inspection on proxy-mode policies or switch the affected policies to flow mode.",
        "cwe": "CWE-787",
    },
    # ---- Legacy CISA-KEV SSL-VPN / integrity CVEs (2018-2021) --------------- #
    # These predate the list's original 2019 start but are all CISA-KEV-listed and
    # still found on unpatched/EOL FortiGates. Legacy trains (5.x/6.0) — the train
    # matcher evaluates each {train,fixed} independently, so no engine change needed.
    {
        "id": "FORTIOS-CVE-071", "cve": "CVE-2018-13379", "severity": "CRITICAL",
        "name": "SSL VPN pre-auth path traversal (system-file / credential disclosure)",
        "affected": [
            {"train": "6.0", "fixed": "6.0.5"},
            {"train": "5.6", "fixed": "5.6.8"},
            {"train": "5.4", "fixed": "5.4.13"},
        ],
        "description": "A path traversal (CWE-22) in the FortiOS SSL VPN web portal lets an unauthenticated attacker download system files, including the sslvpn_websession file containing plaintext usernames and passwords, via crafted HTTP requests. One of the most widely exploited FortiGate CVEs; CISA-KEV listed and repeatedly used to seed ransomware intrusions.",
        "recommendation": "Upgrade to FortiOS 6.0.5 / 5.6.8 / 5.4.13 or later (these trains are EOL — migrate to a supported release). Assume credential compromise: reset ALL local and VPN account passwords and rotate secrets, since leaked credentials remain valid after patching.",
        "cwe": "CWE-22",
    },
    {
        "id": "FORTIOS-CVE-072", "cve": "CVE-2018-13382", "severity": "HIGH",
        "name": "SSL VPN improper authorization — portal password reset ('magic backdoor')",
        "affected": [
            {"train": "6.0", "fixed": "6.0.5"},
            {"train": "5.6", "fixed": "5.6.9"},
            {"train": "5.4", "fixed": "5.4.11"},
        ],
        "description": "An improper authorization vulnerability (CWE-285) in the FortiOS SSL VPN web portal lets an unauthenticated attacker change the password of an SSL-VPN web portal user via specially crafted requests. CISA-KEV listed.",
        "recommendation": "Upgrade to FortiOS 6.0.5 / 5.6.9 / 5.4.11 or later. Reset SSL-VPN portal user passwords and enable MFA for all VPN users.",
        "cwe": "CWE-285",
    },
    {
        "id": "FORTIOS-CVE-073", "cve": "CVE-2018-13383", "severity": "MEDIUM",
        "name": "SSL VPN web portal heap overflow (href proxying)",
        "affected": [
            {"train": "6.0", "fixed": "6.0.5"},
            {"train": "5.6", "fixed": "5.6.11"},
            {"train": "5.4", "fixed": "5.4.13"},
            {"train": "5.2", "fixed": "5.2.15"},
        ],
        "description": "A heap buffer overflow (CWE-122) in the FortiOS SSL VPN web portal, triggered when proxying a crafted web page's href, can terminate the SSL-VPN service and potentially execute code on the client-processing path. CISA-KEV listed.",
        "recommendation": "Upgrade to FortiOS 6.0.5 / 5.6.11 / 5.4.13 / 5.2.15 or later (EOL trains — migrate to a supported release).",
        "cwe": "CWE-122",
    },
    {
        "id": "FORTIOS-CVE-074", "cve": "CVE-2019-6693", "severity": "MEDIUM",
        "name": "Hard-coded cryptographic key encrypts sensitive config-backup data",
        "affected": [
            {"train": "6.2", "fixed": "6.2.1"},
            {"train": "6.0", "fixed": "6.0.7"},
            {"train": "5.6", "fixed": "5.6.11"},
        ],
        "description": "FortiOS uses a hard-coded cryptographic key (CWE-321) to cipher sensitive data (private keys, LDAP/RADIUS binds, VPN PSKs) in the configuration backup. Anyone who obtains a backup file can decrypt those secrets offline with the shared key. CISA-KEV listed. Reachability is not determinable from the config (data-at-rest), so this is treated as INDETERMINATE by the risk engine.",
        "recommendation": "Upgrade to FortiOS 6.2.1 / 6.0.7 / 5.6.11 or later and enable per-device private-data-encryption (config system global / set private-data-encryption enable) so backups are keyed to a device-specific passphrase.",
        "cwe": "CWE-321",
    },
    {
        "id": "FORTIOS-CVE-075", "cve": "CVE-2021-44168", "severity": "HIGH",
        "name": "Download of code without integrity check via 'execute restore src-vis'",
        "affected": [
            {"train": "7.0", "fixed": "7.0.3"},
            {"train": "6.4", "fixed": "6.4.8"},
            {"train": "6.2", "fixed": "6.2.10"},
            {"train": "6.0", "fixed": "6.0.14"},
        ],
        "description": "A download-of-code-without-integrity-check (CWE-494) in the FortiOS 'execute restore src-vis' command lets an authenticated attacker execute arbitrary code by supplying a crafted file from a remote server. CISA-KEV listed.",
        "recommendation": "Upgrade to FortiOS 7.0.3 / 6.4.8 / 6.2.10 / 6.0.14 or later. Restrict administrative CLI access to trusted management hosts.",
        "cwe": "CWE-494",
    },
]

# ========================================================================== #
#  CVE -> vulnerable-component map (for reachability-aware prioritization)     #
# ========================================================================== #
# Maps each tracked CVE to the FortiOS subsystem whose feature must be enabled/
# reachable for the bug to matter. cve_reachability.py turns this + the parsed
# config into a per-CVE verdict that DOWNRANKS (never suppresses) findings whose
# feature is disabled or not internet-facing. Assignments are deliberately
# CONSERVATIVE: a CVE is only tagged when the component is clear from the
# advisory; ambiguous CVEs (e.g. 038/045/057/061) are intentionally omitted and
# therefore treated as INDETERMINATE (no priority change). Ecosystem CVEs
# (FortiManager/FortiClient EMS) are tagged 'ecosystem' -> always INDETERMINATE,
# since a FortiGate .conf cannot prove another product's reachability.
CVE_COMPONENTS: dict[str, str] = {
    "FORTIOS-CVE-001": "admin-gui",       # jsconsole websocket auth bypass (admin iface)
    "FORTIOS-CVE-002": "sslvpn",
    "FORTIOS-CVE-003": "fgfm",            # fgfmd
    "FORTIOS-CVE-004": "sslvpn",
    "FORTIOS-CVE-005": "sslvpn",
    "FORTIOS-CVE-006": "ecosystem",       # FortiManager (FortiJump)
    "FORTIOS-CVE-007": "ecosystem",       # FortiClient EMS
    "FORTIOS-CVE-008": "sslvpn",
    "FORTIOS-CVE-009": "sslvpn",
    "FORTIOS-CVE-010": "ecosystem",       # FortiManager API
    "FORTIOS-CVE-011": "admin-gui",       # auth bypass via crafted HTTP (admin iface)
    "FORTIOS-CVE-012": "admin-auth",      # path traversal, admin-side
    "FORTIOS-CVE-013": "admin-gui",       # administrative interface
    "FORTIOS-CVE-014": "sslvpn",
    "FORTIOS-CVE-015": "ldap",            # LDAP server identity not verified
    "FORTIOS-CVE-016": "admin-gui",       # GUI websocket module
    "FORTIOS-CVE-017": "sslvpn",
    "FORTIOS-CVE-018": "rest-api",
    "FORTIOS-CVE-019": "captive-portal",
    # CVE-020 (CVE-2024-26010): NVD describes only "specially crafted packets"
    # with no named component -> left untagged (INDETERMINATE), not guessed.
    "FORTIOS-CVE-021": "admin-gui",       # httpd path traversal
    "FORTIOS-CVE-022": "sslvpn",
    "FORTIOS-CVE-023": "admin-gui",       # CSF proxy auth bypass (over admin iface)
    "FORTIOS-CVE-024": "admin-gui",       # crafted HTTP/S DoS
    "FORTIOS-CVE-025": "admin-gui",       # httpd memory exhaustion
    "FORTIOS-CVE-026": "fgfm",
    "FORTIOS-CVE-027": "capwap",          # CVE-2024-35279: crafted UDP via CAPWAP control (NVD)
    "FORTIOS-CVE-028": "sslvpn",
    "FORTIOS-CVE-029": "tacacs",          # CVE-2025-22252: TACACS+ auth bypass (NVD)
    "FORTIOS-CVE-030": "admin-auth",      # authenticated admin privesc
    "FORTIOS-CVE-031": "forticloud-sso",
    "FORTIOS-CVE-032": "forticloud-sso",
    "FORTIOS-CVE-033": "ldap",            # LDAP bypass (agentless VPN + FSSO)
    "FORTIOS-CVE-034": "admin-auth",      # restricted CLI bypass
    "FORTIOS-CVE-035": "capwap",
    "FORTIOS-CVE-036": "capwap",          # cw_acd
    "FORTIOS-CVE-037": "ipsec",           # IKE handler
    # 038 (multiple format strings) — ambiguous surface -> INDETERMINATE
    "FORTIOS-CVE-039": "fgfm",
    "FORTIOS-CVE-040": "fgfm",
    "FORTIOS-CVE-041": "admin-auth",      # diag npu CLI
    "FORTIOS-CVE-042": "sslvpn",          # SSL VPN bookmarks
    "FORTIOS-CVE-043": "ha",
    "FORTIOS-CVE-044": "admin-gui",       # admin cookie leakage
    # 045 (double-free in cache mgmt) — unclear surface -> INDETERMINATE
    "FORTIOS-CVE-046": "admin-gui",       # HTTPSd format string
    "FORTIOS-CVE-047": "sslvpn",          # SSL-VPN symlink persistence
    "FORTIOS-CVE-048": "admin-auth",      # restricted CLI Lua escape
    "FORTIOS-CVE-049": "sslvpn",          # SSL-VPN bookmarks (authenticated)
    "FORTIOS-CVE-050": "admin-gui",       # HTTP request smuggling (admin iface)
    "FORTIOS-CVE-051": "capwap",
    "FORTIOS-CVE-052": "capwap",
    "FORTIOS-CVE-053": "capwap",
    "FORTIOS-CVE-054": "admin-ssh",       # trusted hosts bypass via SSH
    "FORTIOS-CVE-055": "admin-auth",      # path traversal in CLI
    "FORTIOS-CVE-056": "ipsec",           # eap-cert-auth
    # 057 (websocket handler heap overflow) — ambiguous (GUI vs SSL-VPN) -> INDETERMINATE
    "FORTIOS-CVE-058": "dnsfilter",
    "FORTIOS-CVE-059": "fgfm",            # fgfmsd
    "FORTIOS-CVE-060": "sslvpn",          # SSL-VPN cookie
    # 061 (filesystem integrity write-protection) — local -> INDETERMINATE
    "FORTIOS-CVE-062": "fgfm",
    "FORTIOS-CVE-063": "fgfm",
    "FORTIOS-CVE-064": "radius",          # Blast-RADIUS
    "FORTIOS-CVE-065": "bluetooth",
    "FORTIOS-CVE-066": "admin-gui",       # administrative interface
    "FORTIOS-CVE-067": "fsso",
    "FORTIOS-CVE-068": "admin-ssh",       # SSH login bypass via RADIUS
    "FORTIOS-CVE-069": "rest-api",
    "FORTIOS-CVE-070": "proxy",           # proxy-mode policies
    "FORTIOS-CVE-071": "sslvpn",          # CVE-2018-13379 pre-auth path traversal
    "FORTIOS-CVE-072": "sslvpn",          # CVE-2018-13382 portal password reset
    "FORTIOS-CVE-073": "sslvpn",          # CVE-2018-13383 web-portal heap overflow
    # CVE-074 (CVE-2019-6693, hard-coded backup key) is data-at-rest, not network-
    # reachable -> intentionally untagged so it stays INDETERMINATE.
    "FORTIOS-CVE-075": "admin-auth",      # CVE-2021-44168 execute restore (authenticated CLI)
}

# ========================================================================== #
#  WEAK CRYPTO CONSTANTS                                                      #
# ========================================================================== #

WEAK_CIPHERS = {"des", "3des", "rc4", "null", "rc2", "idea", "seed", "aria128"}
WEAK_HASHES = {"md5", "md5-96"}
WEAK_DH_GROUPS = {"1", "2", "5"}
WEAK_TLS = {"sslv3", "tlsv1.0", "tlsv1-0", "tlsv1.1", "tlsv1-1", "tls1.0", "tls1.1", "tls-1.0", "tls-1.1"}

# ========================================================================== #
#  COMPLIANCE FRAMEWORK MAPPING                                               #
# ========================================================================== #
# Maps rule ID prefixes to compliance control references.
# Each finding can reference multiple frameworks.

COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    # ── CIS FortiGate Benchmark ─────────────────────────────────────────
    "FORTIOS-ADMIN-001": {"CIS": ["2.1.1"], "PCI-DSS": ["2.2.2", "8.2.1"], "NIST": ["AC-17", "SC-8"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(d)"]},
    "FORTIOS-ADMIN-002": {"CIS": ["2.1.2"], "PCI-DSS": ["8.1.8"], "NIST": ["AC-11"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(2)(iii)"]},
    "FORTIOS-ADMIN-003": {"CIS": ["2.1.3"], "PCI-DSS": ["8.2.3"], "NIST": ["IA-5"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(d)"]},
    "FORTIOS-ADMIN-004": {"CIS": ["2.1.4"], "PCI-DSS": ["8.3.1"], "NIST": ["IA-2(1)"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(d)"]},
    "FORTIOS-ADMIN-005": {"CIS": ["2.1.5"], "PCI-DSS": ["8.3.1"], "NIST": ["IA-2(1)"], "SOC2": ["CC6.1"]},
    "FORTIOS-ADMIN-006": {"CIS": ["2.1.6"], "PCI-DSS": ["7.1.1"], "NIST": ["AC-6"], "SOC2": ["CC6.3"]},
    "FORTIOS-ADMIN-007": {"CIS": ["2.1.7"], "PCI-DSS": ["2.2.2"], "NIST": ["AC-3"], "SOC2": ["CC6.1"]},
    "FORTIOS-ADMIN-008": {"CIS": ["2.1.8"], "PCI-DSS": ["7.1.2"], "NIST": ["AC-6(1)"], "SOC2": ["CC6.3"]},
    # New hardening checks (2026-07)
    "FORTIOS-ADMIN-025": {"CIS": ["2.1.9"], "NIST": ["AC-6", "PE-3"], "SOC2": ["CC6.1"]},
    "FORTIOS-ADMIN-026": {"CIS": ["2.1.6"], "PCI-DSS": ["1.3", "7.2"], "NIST": ["AC-3", "SC-7"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(1)"]},
    "FORTIOS-CERT-012":  {"CIS": ["8.1.3"], "PCI-DSS": ["4.2.1"], "NIST": ["SC-17", "SC-23"], "SOC2": ["CC6.7"]},
    "FORTIOS-SSLVPN-015": {"CIS": ["5.1.4"], "PCI-DSS": ["1.3"], "NIST": ["AC-3", "SC-7"], "SOC2": ["CC6.6"]},
    "FORTIOS-SSLVPN-016": {"CIS": ["5.1.6"], "PCI-DSS": ["2.2.2"], "NIST": ["CM-7", "SC-7"], "SOC2": ["CC6.6"]},
    "FORTIOS-SSLVPN-017": {"CIS": ["5.1.5"], "PCI-DSS": ["4.2.1"], "NIST": ["SC-8", "SC-13"], "SOC2": ["CC6.7"]},
    "FORTIOS-SYS-019":   {"CIS": ["3.1.7"], "PCI-DSS": ["2.2.7", "4.2.1"], "NIST": ["SC-8", "SC-13"], "SOC2": ["CC6.7"], "HIPAA": ["164.312(e)(1)"]},
    "FORTIOS-NET-019":   {"CIS": ["9.1.4"], "PCI-DSS": ["1.3"], "NIST": ["SC-7", "AC-17"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(a)(1)"]},
    "FORTIOS-NET-020":   {"CIS": ["9.1.5"], "PCI-DSS": ["1.3"], "NIST": ["SC-7", "AC-17"], "SOC2": ["CC6.6"]},
    "FORTIOS-SYS-001":   {"CIS": ["3.1.1"], "PCI-DSS": ["2.2.4"], "NIST": ["SC-13"], "SOC2": ["CC6.1"]},
    "FORTIOS-SYS-002":   {"CIS": ["3.1.2"], "PCI-DSS": ["2.2.4"], "NIST": ["SC-13"]},
    "FORTIOS-SYS-003":   {"CIS": ["3.1.3"], "PCI-DSS": ["2.2.2"], "NIST": ["AC-8"], "SOC2": ["CC6.1"]},
    "FORTIOS-SYS-004":   {"CIS": ["3.1.4"], "PCI-DSS": ["2.2.2"], "NIST": ["AC-8"]},
    "FORTIOS-SYS-005":   {"CIS": ["3.1.5"], "PCI-DSS": ["8.1.6"], "NIST": ["AC-7"], "HIPAA": ["164.312(a)(2)(i)"]},
    "FORTIOS-SYS-018":   {"CIS": ["3.1.6"], "PCI-DSS": ["3.5.1", "8.3.2"], "NIST": ["SC-28", "SC-12"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(2)(iv)"]},
    # Rule-base analysis / policy hygiene (family-prefix matches, FireMon-style)
    "FORTIOS-RULEBASE":  {"CIS": ["4.1"], "PCI-DSS": ["1.1.7", "1.2.1"], "NIST": ["AC-4", "CM-7"], "SOC2": ["CC6.6"]},
    "FORTIOS-USAGE":     {"PCI-DSS": ["1.1.7"], "NIST": ["AC-4", "CM-7"], "SOC2": ["CC6.6"]},
    "FORTIOS-OBJECT":    {"PCI-DSS": ["1.1.7"], "NIST": ["CM-7"], "SOC2": ["CC6.6"]},
    "FORTIOS-EXPOSURE":  {"CIS": ["4.1"], "PCI-DSS": ["1.2.1", "1.3"], "NIST": ["SC-7", "AC-17"], "SOC2": ["CC6.6"]},
    "FORTIOS-DRIFT":     {"PCI-DSS": ["1.1.7", "11.5"], "NIST": ["CM-3", "CM-6", "SI-7"], "SOC2": ["CC7.1"]},
    "FORTIOS-POLICY-001": {"CIS": ["4.1.1"], "PCI-DSS": ["1.2.1"], "NIST": ["AC-4"], "SOC2": ["CC6.6"]},
    "FORTIOS-POLICY-002": {"CIS": ["4.1.2"], "PCI-DSS": ["1.2.1"], "NIST": ["AC-4", "SC-7"], "SOC2": ["CC6.6"]},
    "FORTIOS-POLICY-003": {"CIS": ["4.1.3"], "PCI-DSS": ["1.1.7"], "NIST": ["AU-3"], "SOC2": ["CC7.2"]},
    "FORTIOS-POLICY-004": {"CIS": ["4.1.4"], "PCI-DSS": ["1.2.1"], "NIST": ["SC-7"], "SOC2": ["CC6.6"]},
    "FORTIOS-SSLVPN-001": {"CIS": ["5.1.1"], "PCI-DSS": ["4.1"], "NIST": ["SC-8"], "SOC2": ["CC6.7"], "HIPAA": ["164.312(e)(1)"]},
    "FORTIOS-SSLVPN-002": {"CIS": ["5.1.2"], "PCI-DSS": ["4.1"], "NIST": ["SC-8", "SC-13"]},
    "FORTIOS-SSLVPN-003": {"CIS": ["5.1.3"], "PCI-DSS": ["8.3.1"], "NIST": ["IA-2"], "HIPAA": ["164.312(d)"]},
    "FORTIOS-IPSEC-001":  {"CIS": ["5.2.1"], "PCI-DSS": ["4.1"], "NIST": ["SC-8", "SC-13"], "SOC2": ["CC6.7"]},
    "FORTIOS-IPSEC-002":  {"CIS": ["5.2.2"], "PCI-DSS": ["4.1"], "NIST": ["SC-12"]},
    "FORTIOS-IPSEC-003":  {"CIS": ["5.2.3"], "PCI-DSS": ["4.1"], "NIST": ["SC-13"]},
    "FORTIOS-LOG-001":    {"CIS": ["6.1.1"], "PCI-DSS": ["10.1", "10.2"], "NIST": ["AU-2", "AU-3"], "SOC2": ["CC7.2"], "HIPAA": ["164.312(b)"]},
    "FORTIOS-LOG-002":    {"CIS": ["6.1.2"], "PCI-DSS": ["10.5.3"], "NIST": ["AU-9"], "SOC2": ["CC7.2"]},
    "FORTIOS-LOG-003":    {"CIS": ["6.1.3"], "PCI-DSS": ["10.2"], "NIST": ["AU-12"], "SOC2": ["CC7.2"]},
    "FORTIOS-LOG-004":    {"CIS": ["6.1.4"], "PCI-DSS": ["10.5.1"], "NIST": ["AU-9"]},
    "FORTIOS-HA-001":     {"CIS": ["7.1.1"], "PCI-DSS": ["12.10.1"], "NIST": ["CP-7", "CP-9"], "SOC2": ["CC7.5"]},
    "FORTIOS-CERT-001":   {"CIS": ["8.1.1"], "PCI-DSS": ["4.1"], "NIST": ["SC-17"], "SOC2": ["CC6.7"]},
    "FORTIOS-CERT-002":   {"CIS": ["8.1.2"], "PCI-DSS": ["4.1"], "NIST": ["SC-17"]},
    "FORTIOS-NET-001":    {"CIS": ["9.1.1"], "PCI-DSS": ["11.4"], "NIST": ["SC-5"], "SOC2": ["CC6.6"]},
    "FORTIOS-NET-002":    {"CIS": ["9.1.2"], "PCI-DSS": ["2.2.2"], "NIST": ["CM-7"]},
    "FORTIOS-NET-003":    {"CIS": ["9.1.3"], "PCI-DSS": ["2.2.2", "10.6"], "NIST": ["AU-8"], "SOC2": ["CC7.2"]},
    "FORTIOS-UPDATE-001": {"CIS": ["10.1.1"], "PCI-DSS": ["6.2"], "NIST": ["SI-2", "SI-3"], "SOC2": ["CC7.1"]},
    "FORTIOS-UPDATE-002": {"CIS": ["10.1.2"], "PCI-DSS": ["6.2"], "NIST": ["SI-2"]},
    "FORTIOS-WIRELESS-001": {"CIS": ["11.1.1"], "PCI-DSS": ["4.1.1"], "NIST": ["SC-8", "AC-18"]},
    "FORTIOS-WIRELESS-002": {"CIS": ["11.1.2"], "PCI-DSS": ["11.1"], "NIST": ["AC-18"]},
    "FORTIOS-BACKUP-001": {"CIS": ["12.1.1"], "PCI-DSS": ["12.10.1"], "NIST": ["CP-9"], "SOC2": ["CC7.5"]},
    "FORTIOS-AUTH-001":   {"CIS": ["13.1.1"], "PCI-DSS": ["8.3.1"], "NIST": ["IA-2(1)"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(d)"]},
    "FORTIOS-AUTH-002":   {"CIS": ["13.1.2"], "PCI-DSS": ["8.2.1"], "NIST": ["IA-5(1)"], "SOC2": ["CC6.1"]},
    "FORTIOS-ZTNA-001":   {"CIS": ["14.1.1"], "PCI-DSS": ["1.2.1"], "NIST": ["AC-4", "SC-7"]},
    "FORTIOS-PROFILE-001": {"CIS": ["4.2.1"], "PCI-DSS": ["5.1", "5.2"], "NIST": ["SI-3"], "SOC2": ["CC6.8"]},
    "FORTIOS-PROFILE-002": {"CIS": ["4.2.2"], "PCI-DSS": ["11.4"], "NIST": ["SI-4"]},
    "FORTIOS-PROFILE-003": {"CIS": ["4.2.3"], "PCI-DSS": ["1.2.1"], "NIST": ["SC-7"]},
    # CVE rules map to patch management controls
    "FORTIOS-CVE":         {"PCI-DSS": ["6.2"], "NIST": ["SI-2", "RA-5"], "SOC2": ["CC7.1"], "HIPAA": ["164.308(a)(5)(ii)(B)"]},
    # MITRE ATT&CK resilience rules
    "MITRE-T1190":  {"CIS": ["4.2.2"], "PCI-DSS": ["6.5", "11.4"], "NIST": ["SI-4", "SC-7"]},
    "MITRE-T1566":  {"CIS": ["4.2.1", "4.2.3"], "PCI-DSS": ["5.1", "5.2"], "NIST": ["SI-3", "SI-8"]},
    "MITRE-T1133":  {"CIS": ["5.1.3"], "PCI-DSS": ["8.3.1"], "NIST": ["AC-17", "IA-2"]},
    "MITRE-T1059":  {"CIS": ["4.2.4"], "PCI-DSS": ["1.2.1"], "NIST": ["CM-7", "SC-7"]},
    "MITRE-T1203":  {"CIS": ["4.2.5"], "PCI-DSS": ["6.5", "11.4"], "NIST": ["SI-4", "SC-8"]},
    "MITRE-T1078":  {"CIS": ["2.1.4"], "PCI-DSS": ["8.3.1"], "NIST": ["IA-2(1)", "AC-6"]},
    "MITRE-T1071":  {"CIS": ["4.2.6"], "PCI-DSS": ["1.2.1"], "NIST": ["SC-7", "SI-4"]},
    "MITRE-T1027":  {"CIS": ["4.2.1"], "PCI-DSS": ["5.1"], "NIST": ["SI-3"]},
    "MITRE-T1562":  {"CIS": ["6.1.1", "6.1.2"], "PCI-DSS": ["10.1", "10.5"], "NIST": ["AU-2", "AU-9"], "HIPAA": ["164.312(b)"]},
    "MITRE-T1110":  {"CIS": ["3.1.5"], "PCI-DSS": ["8.1.6"], "NIST": ["AC-7", "IA-5"]},
    "MITRE-T1557":  {"CIS": ["2.1.1"], "PCI-DSS": ["4.1"], "NIST": ["SC-8", "SC-23"]},
    "MITRE-T1021":  {"CIS": ["4.1.2"], "PCI-DSS": ["1.2.1"], "NIST": ["AC-4", "SC-7"]},
    "MITRE-T1048":  {"CIS": ["4.2.7"], "PCI-DSS": ["1.3.4"], "NIST": ["SC-7", "AC-4"]},
    "MITRE-T1041":  {"CIS": ["4.2.6"], "PCI-DSS": ["1.2.1"], "NIST": ["SI-4", "SC-7"]},
    "MITRE-T1573":  {"CIS": ["4.2.5"], "PCI-DSS": ["4.1"], "NIST": ["SC-8", "SI-4"]},
    "MITRE-T1090":  {"CIS": ["4.2.4"], "PCI-DSS": ["1.2.1"], "NIST": ["SC-7"]},
    "MITRE-T1498":  {"CIS": ["9.1.1"], "PCI-DSS": ["11.4"], "NIST": ["SC-5"]},
    "MITRE-T1486":  {"CIS": ["4.2.1"], "PCI-DSS": ["5.1"], "NIST": ["SI-3", "CP-9"]},
    "MITRE-T1595":  {"CIS": ["2.1.7"], "PCI-DSS": ["1.2.1"], "NIST": ["AC-17", "SC-7"]},
    "MITRE-T1572":  {"CIS": ["4.2.6"], "PCI-DSS": ["1.2.1"], "NIST": ["SC-7", "SI-4"]},
    "MITRE-T1571":  {"CIS": ["4.2.4"], "PCI-DSS": ["1.2.1"], "NIST": ["SC-7", "CM-7"]},
    "MITRE-T1189":  {"CIS": ["4.2.3"], "PCI-DSS": ["5.1"], "NIST": ["SI-3", "SC-7"]},
    "MITRE-T1105":  {"CIS": ["4.2.1"], "PCI-DSS": ["5.1", "5.2"], "NIST": ["SI-3"]},
    "MITRE-T1046":  {"CIS": ["9.1.1"], "PCI-DSS": ["11.4"], "NIST": ["SI-4", "SC-7"]},
    "MITRE-T1210":  {"CIS": ["4.2.2"], "PCI-DSS": ["6.5", "11.4"], "NIST": ["SI-4", "SI-2"]},
    "MITRE-T1219":  {"CIS": ["4.2.4"], "PCI-DSS": ["1.2.1"], "NIST": ["CM-7", "SC-7"]},
    "MITRE-T1568":  {"CIS": ["4.2.6"], "PCI-DSS": ["1.2.1"], "NIST": ["SI-4"]},
    "MITRE-T1102":  {"CIS": ["4.2.5"], "PCI-DSS": ["1.2.1"], "NIST": ["SC-7", "SI-4"]},
    "MITRE-T1567":  {"CIS": ["4.2.7"], "PCI-DSS": ["1.3.4"], "NIST": ["SC-7", "AC-4"]},
    "MITRE-T1499":  {"CIS": ["9.1.1"], "PCI-DSS": ["11.4"], "NIST": ["SC-5", "SI-4"]},
    "MITRE-T1496":  {"CIS": ["4.2.4"], "PCI-DSS": ["1.2.1"], "NIST": ["CM-7"]},
    "MITRE-T1505":  {"CIS": ["4.2.2"], "PCI-DSS": ["6.5", "11.4"], "NIST": ["SI-3", "SI-4"]},
    "MITRE-T1602":  {"CIS": ["9.1.3"], "PCI-DSS": ["2.2.2"], "NIST": ["SC-8", "AC-3"]},
    "MITRE-T1552":  {"CIS": ["3.1.6"], "PCI-DSS": ["3.5.1", "8.3.2"], "NIST": ["SC-28", "IA-5"]},
}

# ── Remediation CLI commands (FortiOS config) per rule ──────────────────
REMEDIATION_COMMANDS: dict[str, str] = {
    "FORTIOS-ADMIN-001": "config system global\n  set admin-https-redirect enable\nend",
    "FORTIOS-ADMIN-002": "config system global\n  set admintimeout 5\nend",
    "FORTIOS-ADMIN-003": "config system password-policy\n  set minimum-length 12\n  set min-upper-case-letter 1\n  set min-lower-case-letter 1\n  set min-number 1\n  set min-non-alphanumeric 1\nend",
    "FORTIOS-ADMIN-004": "config system admin\n  edit <admin-name>\n    set two-factor fortitoken\n  next\nend",
    "FORTIOS-ADMIN-005": "config system admin\n  edit <admin-name>\n    set two-factor fortitoken\n  next\nend",
    "FORTIOS-ADMIN-006": "config system admin\n  edit <admin-name>\n    set trusthost1 <trusted-network/mask>\n  next\nend",
    "FORTIOS-ADMIN-007": "config system interface\n  edit <wan-interface>\n    set allowaccess ping https ssh\n    unset allowaccess http\n  next\nend",
    "FORTIOS-ADMIN-008": "config system admin\n  edit <admin-name>\n    set accprofile <least-privilege-profile>\n  next\nend",
    "FORTIOS-ADMIN-025": "config system global\n  set admin-maintainer disable\nend",
    "FORTIOS-ADMIN-026": "config system admin\n  edit <admin-name>\n    set ip6-trusthost1 <ipv6-mgmt-prefix>\n  next\nend",
    "FORTIOS-CERT-012":  "config system global\n  set admin-server-cert \"<your-ca-issued-cert>\"\nend",
    "FORTIOS-SSLVPN-015": "config vpn ssl settings\n  set source-address \"<trusted-address-group>\"\nend",
    "FORTIOS-SSLVPN-016": "config vpn ssl web portal\n  edit <portal>\n    set web-mode disable\n    set tunnel-mode enable\n  next\nend",
    "FORTIOS-SSLVPN-017": "config vpn ssl settings\n  set algorithm high\nend",
    "FORTIOS-SYS-019":   "config system global\n  set strong-crypto enable\n  set ssh-enc-algo aes256-ctr aes256-gcm@openssh.com\n  set ssh-kex-algo diffie-hellman-group14-sha256 curve25519-sha256@libssh.org\n  set ssh-mac-algo hmac-sha2-256 hmac-sha2-512\nend",
    "FORTIOS-NET-019":   "config firewall local-in-policy\n  edit 1\n    set intf <wan>\n    set srcaddr <MGMT-TRUSTED>\n    set dstaddr all\n    set service HTTPS SSH\n    set action accept\n  next\nend",
    "FORTIOS-NET-020":   "config firewall address\n  edit Geo-Allow\n    set type geography\n    set country <CC>\n  end",
    "FORTIOS-ADMIN-013": "config system password-policy\n  set min-upper-case-letter 1\nend",
    "FORTIOS-ADMIN-014": "config system password-policy\n  set min-lower-case-letter 1\nend",
    "FORTIOS-ADMIN-015": "config system password-policy\n  set min-number 1\nend",
    "FORTIOS-SYS-001":   "config system global\n  set strong-crypto enable\nend",
    "FORTIOS-SYS-002":   "config system global\n  set fds-statistics disable\nend",
    "FORTIOS-SYS-003":   "config system global\n  set pre-login-banner enable\nend",
    "FORTIOS-SYS-004":   "config system global\n  set post-login-banner enable\nend",
    "FORTIOS-SYS-005":   "config system global\n  set admin-lockout-threshold 3\n  set admin-lockout-duration 300\nend",
    "FORTIOS-POLICY-002": "config firewall policy\n  edit <policy-id>\n    set srcaddr <specific-address>\n    set dstaddr <specific-address>\n    set service <specific-service>\n  next\nend",
    "FORTIOS-POLICY-003": "config firewall policy\n  edit <policy-id>\n    set logtraffic all\n  next\nend",
    "FORTIOS-SSLVPN-001": "config vpn ssl settings\n  set sslv3 disable\n  set tlsv1-0 disable\n  set tlsv1-1 disable\n  set tlsv1-2 enable\n  set tlsv1-3 enable\nend",
    "FORTIOS-SSLVPN-003": "config vpn ssl settings\n  set reqclientcert enable\nend",
    "FORTIOS-IPSEC-001":  "config vpn ipsec phase1-interface\n  edit <vpn-name>\n    set proposal aes256-sha256 aes256gcm-prfsha384\n  next\nend",
    "FORTIOS-IPSEC-002":  "config vpn ipsec phase1-interface\n  edit <vpn-name>\n    set dhgrp 14 20 21\n  next\nend",
    "FORTIOS-LOG-001":    "config log fortianalyzer setting\n  set status enable\n  set server <FAZ-IP>\nend",
    "FORTIOS-LOG-002":    "config log syslogd setting\n  set status enable\n  set server <syslog-IP>\nend",
    "FORTIOS-LOG-003":    "config log setting\n  set fwpolicy-implicit-log enable\nend",
    "FORTIOS-LOG-004":    "config log fortianalyzer setting\n  set enc-algorithm high\nend",
    "FORTIOS-HA-001":     "config system ha\n  set mode a-p\n  set group-name <ha-group>\n  set password <ha-password>\nend",
    "FORTIOS-NET-001":    "config firewall DoS-policy\n  edit 1\n    set status enable\n    set interface <wan-interface>\n  next\nend",
    "FORTIOS-NET-003":    "config system ntp\n  set ntpsync enable\n  set type custom\n  config ntpserver\n    edit 1\n      set server <ntp-server>\n    next\n  end\nend",
    "FORTIOS-UPDATE-001": "Upgrade FortiOS firmware via System > Firmware. Download from https://support.fortinet.com",
    "FORTIOS-CERT-001":   "config vpn certificate local\n  Generate or import a CA-signed certificate to replace the default self-signed certificate.\nend",
    "FORTIOS-WIRELESS-001": "config wireless-controller vap\n  edit <ssid-name>\n    set security wpa2-only-enterprise\n  next\nend",
    "FORTIOS-BACKUP-001": "config system central-management\n  set type fortimanager\n  set fmg <fmg-ip>\nend",
    "FORTIOS-AUTH-001":   "config system admin\n  edit <admin-name>\n    set two-factor fortitoken\n  next\nend",
    "FORTIOS-AUTH-002":   "config user ldap\n  edit <ldap-server>\n    set secure ldaps\n    set server-identity-check enable\n  next\nend",
    "FORTIOS-ZTNA-001":   "config firewall access-proxy\n  edit <proxy-name>\n    set vip <virtual-IP>\n  next\nend",
    # Session management
    "FORTIOS-SYS-013":    "config system global\n  set tcp-halfclose-timer 120\n  set tcp-halfopen-timer 30\nend",
    "FORTIOS-SYS-014":    "config system global\n  set admin-scp enable\nend",
    "FORTIOS-SYS-015":    "config system global\n  set admin-ssh-grace-time 60\nend",
    # FIPS
    "FORTIOS-SYS-016":    "config system global\n  set fips-cc enable\nend\n# NOTE: Enabling FIPS mode requires reboot and restricts cipher suites.",
    "FORTIOS-SYS-018":    "config system global\n  set private-data-encryption enable\nend\n# Then set a device-unique key: config system global / set private-encryption-key <64-hex-key>",
    # Log retention
    "FORTIOS-LOG-017":    "config log setting\n  set log-file-size <size-MB>\nend\nAlternatively, configure FortiAnalyzer retention policies.",
    "FORTIOS-LOG-018":    "config log fortianalyzer setting\n  set enc-algorithm high\nend",
}

# ========================================================================== #
#  FINDING CLASS                                                              #
# ========================================================================== #

class Finding:
    """A single vulnerability finding with compliance mapping and remediation."""

    __slots__ = (
        "rule_id", "name", "category", "severity",
        "file_path", "line_num", "line_content",
        "description", "recommendation", "cwe", "cve",
        "compliance", "remediation_cmd",
    )

    def __init__(
        self,
        rule_id: str, name: str, category: str, severity: str,
        file_path: str, line_num: int | None, line_content: str,
        description: str, recommendation: str,
        cwe: str | None = None, cve: str | None = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = str(file_path)
        self.line_num = line_num
        self.line_content = (line_content.strip() if line_content else "")
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe
        self.cve = cve
        # Auto-resolve compliance mapping
        self.compliance: dict[str, list[str]] = self._resolve_compliance()
        # Auto-resolve remediation command
        self.remediation_cmd: str = REMEDIATION_COMMANDS.get(rule_id, "")

    def _resolve_compliance(self) -> dict[str, list[str]]:
        """Look up compliance framework references for this finding."""
        # Exact match first
        if self.rule_id in COMPLIANCE_MAP:
            return COMPLIANCE_MAP[self.rule_id]
        # Prefix match (e.g., FORTIOS-CVE-001 -> FORTIOS-CVE)
        prefix = self.rule_id.rsplit("-", 1)[0] if "-" in self.rule_id else self.rule_id
        if prefix in COMPLIANCE_MAP:
            return COMPLIANCE_MAP[prefix]
        return {}

    @property
    def compliance_str(self) -> str:
        """Format compliance references as a readable string."""
        if not self.compliance:
            return ""
        parts = []
        for framework, controls in sorted(self.compliance.items()):
            parts.append(f"{framework}: {', '.join(controls)}")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        d = {s: getattr(self, s) for s in self.__slots__ if s not in ("compliance", "remediation_cmd")}
        d["compliance"] = self.compliance
        d["remediation_cmd"] = self.remediation_cmd
        return d


# ========================================================================== #
#  REPORT MIXIN                                                               #
# ========================================================================== #

class _ReportMixin:
    """Shared reporting helpers."""

    SEVERITY_ORDER: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
    }
    SEVERITY_COLOR: dict[str, str] = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m",
        "MEDIUM": "\033[94m", "LOW": "\033[92m", "INFO": "\033[97m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    findings: list[Finding]

    def _add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def _vprint(self, msg: str) -> None:
        if getattr(self, "verbose", False):
            print(msg)

    def _warn(self, msg: str) -> None:
        if getattr(self, "verbose", False):
            print(f"  [!] {msg}", file=sys.stderr)

    # ---- terminal colour gating --------------------------------------------
    _NOCOLOR = {"CRITICAL": "", "HIGH": "", "MEDIUM": "", "LOW": "", "INFO": ""}

    def set_color(self, enabled: "bool | None" = None) -> None:
        """Enable/disable ANSI colour. ``None`` = auto-detect: colour only when
        stdout is a TTY, NO_COLOR is unset and TERM != dumb. This stops raw escape
        codes leaking into piped/redirected output and files."""
        if enabled is None:
            enabled = (sys.stdout.isatty() and "NO_COLOR" not in os.environ
                       and os.environ.get("TERM") != "dumb")
        if enabled:
            for attr in ("SEVERITY_COLOR", "RESET", "BOLD"):
                self.__dict__.pop(attr, None)  # fall back to coloured class defaults
        else:
            self.SEVERITY_COLOR = dict(self._NOCOLOR)
            self.RESET = ""
            self.BOLD = ""

    # ---- per-framework compliance scorecard --------------------------------
    _FRAMEWORKS = ("CIS", "PCI-DSS", "NIST", "SOC2", "HIPAA")

    def compliance_scorecard(self) -> dict:
        """Per-framework rollup: distinct failing controls, finding count and worst
        severity. An auditor's pass/fail-per-framework view (vs a raw finding list)."""
        acc = {fw: {"controls": set(), "findings": 0, "worst": None} for fw in self._FRAMEWORKS}
        for f in self.findings:
            comp = getattr(f, "compliance", {}) or {}
            for fw in self._FRAMEWORKS:
                controls = comp.get(fw) or []
                if not controls:
                    continue
                d = acc[fw]
                d["findings"] += 1
                d["controls"].update(controls)
                rank = self.SEVERITY_ORDER.get(f.severity, 4)
                if d["worst"] is None or rank < self.SEVERITY_ORDER.get(d["worst"], 4):
                    d["worst"] = f.severity
        return {fw: {"failing_controls": len(d["controls"]),
                     "failing_control_ids": sorted(d["controls"]),
                     "findings": d["findings"],
                     "worst_severity": d["worst"]}
                for fw, d in acc.items()}

    def print_compliance_scorecard(self) -> None:
        sc = self.compliance_scorecard()
        if not any(v["findings"] for v in sc.values()):
            return
        sep = "=" * 72
        print(f"\n{self.BOLD}{sep}")
        print("  Compliance Scorecard  (distinct failing controls per framework)")
        print(f"{sep}{self.RESET}")
        for fw in self._FRAMEWORKS:
            d = sc[fw]
            worst = d["worst_severity"] or "-"
            col = self.SEVERITY_COLOR.get(worst, "")
            print(f"    {fw:<9} {col}{d['failing_controls']:>3} failing control(s){self.RESET}"
                  f"   across {d['findings']} finding(s)   worst: {col}{worst}{self.RESET}")
        print()

    # ---- scored benchmark profile (pass/fail per mapped control) ------------
    # arg value -> COMPLIANCE_MAP framework key
    FRAMEWORK_KEYS = {"cis": "CIS", "pci": "PCI-DSS", "nist": "NIST",
                      "soc2": "SOC2", "hipaa": "HIPAA"}

    @staticmethod
    def _control_section(fw_key: str, control: str) -> str:
        """Group a control ID into its benchmark section (for per-section rollups)."""
        if fw_key == "NIST":
            return control.split("-")[0]        # AC-3 -> AC
        if fw_key == "HIPAA":
            return control.split("(")[0]         # 164.312(a)(2)(i) -> 164.312
        return control.split(".")[0]             # CIS 2.1.3 -> 2 ; PCI 8.3.1 -> 8 ; CC6.1 -> CC6

    def benchmark_score(self, framework: str) -> dict:
        """Score the device against a compliance framework: every control the tool
        maps (COMPLIANCE_MAP) is the denominator; a control FAILS if any reportable
        finding references it, else PASSES. Returns overall + per-section scores and
        a per-control breakdown. Denominator is the controls THIS TOOL evaluates —
        not the full external benchmark (stated in the output so it's not overclaimed)."""
        fw_key = self.FRAMEWORK_KEYS.get(str(framework).lower())
        if not fw_key:
            raise ValueError(f"unknown framework {framework!r}; choose from {sorted(self.FRAMEWORK_KEYS)}")

        universe: set = set()
        for mapping in COMPLIANCE_MAP.values():
            for c in (mapping.get(fw_key) or []):
                universe.add(c)

        # Evaluate against the full pre-filter set minus INFO, so a --severity display
        # filter cannot inflate the score (same rationale as the drift fix).
        full = getattr(self, "_all_findings", None) or self.findings
        info_rank = self.SEVERITY_ORDER.get("INFO", 4)
        reportable = [f for f in full if self.SEVERITY_ORDER.get(f.severity, 4) < info_rank]

        control_findings: dict = {}
        control_worst: dict = {}
        for f in reportable:
            for c in ((getattr(f, "compliance", {}) or {}).get(fw_key) or []):
                if c not in universe:
                    continue
                control_findings.setdefault(c, set()).add(f.rule_id)
                rank = self.SEVERITY_ORDER.get(f.severity, 4)
                if c not in control_worst or rank < self.SEVERITY_ORDER.get(control_worst[c], 4):
                    control_worst[c] = f.severity

        failed = set(control_findings)
        sections: dict = {}
        controls_out: list = []
        for c in sorted(universe):
            sec = self._control_section(fw_key, c)
            s = sections.setdefault(sec, {"total": 0, "failed": 0})
            s["total"] += 1
            is_fail = c in failed
            if is_fail:
                s["failed"] += 1
            controls_out.append({
                "control": c, "section": sec,
                "status": "FAIL" if is_fail else "PASS",
                "findings": sorted(control_findings.get(c, [])),
                "worst_severity": control_worst.get(c),
            })
        for s in sections.values():
            s["passed"] = s["total"] - s["failed"]
            s["score_pct"] = round(s["passed"] / s["total"] * 100) if s["total"] else 100

        total = len(universe)
        n_pass = total - len(failed)
        # natural section order: numeric sections (CIS/PCI) sort numerically, then
        # alpha sections (NIST/SOC2) lexically — so "10" doesn't sort before "2".
        def _sec_key(s: str):
            return (0, int(s)) if s.isdigit() else (1, s)
        return {
            "framework": fw_key,
            "total_controls": total,
            "passed": n_pass,
            "failed": len(failed),
            "score_pct": round(n_pass / total * 100) if total else 100,
            "sections": {k: sections[k] for k in sorted(sections, key=_sec_key)},
            "controls": controls_out,
        }

    def print_benchmark(self, framework: str) -> None:
        try:
            bm = self.benchmark_score(framework)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return
        sep = "=" * 72
        print(f"\n{self.BOLD}{sep}")
        print(f"  {bm['framework']} Benchmark Score — {bm['score_pct']}%  "
              f"({bm['passed']}/{bm['total_controls']} evaluated controls pass)")
        print(f"{sep}{self.RESET}")
        for sec, s in bm["sections"].items():
            band = "HIGH" if s["score_pct"] < 60 else ("MEDIUM" if s["score_pct"] < 85 else "LOW")
            col = self.SEVERITY_COLOR.get(band, "")
            bar = "#" * round(s["score_pct"] / 10) + "-" * (10 - round(s["score_pct"] / 10))
            print(f"    {sec:<10} {col}{s['score_pct']:>3}%{self.RESET} [{bar}]  {s['passed']}/{s['total']} pass")
        print(f"\n    Score = mapped controls that pass. Denominator is the {bm['total_controls']} "
              f"{bm['framework']} controls this tool evaluates, not the full benchmark.")
        print()

    def save_benchmark(self, output_path: str, framework: str) -> None:
        """Save the per-control benchmark. JSON by extension, else per-control CSV."""
        bm = self.benchmark_score(framework)
        if output_path.lower().endswith(".json"):
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(bm, fh, indent=2, ensure_ascii=False)
        else:
            import csv
            with open(output_path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["Framework", "Section", "Control", "Status", "Worst Severity", "Findings"])
                for c in bm["controls"]:
                    w.writerow([bm["framework"], c["section"], c["control"], c["status"],
                                c["worst_severity"] or "", "; ".join(c["findings"])])
        print(f"[+] {bm['framework']} benchmark ({bm['score_pct']}% · "
              f"{bm['passed']}/{bm['total_controls']} pass) saved to: {output_path}")

    def print_summary_only(self) -> None:
        """Compact console output: severity table + compliance scorecard + the
        risk-prioritized fix-first queue, skipping the full per-finding dump."""
        counts = self.summary()
        risk = self._risk_score(counts)
        sep = "=" * 72
        print(f"\n{self.BOLD}{sep}")
        print(f"  Scan Summary — aggregate risk score {risk}/100")
        print(f"{sep}{self.RESET}")
        for sev in self.SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c:
                col = self.SEVERITY_COLOR.get(sev, "")
                print(f"    {col}{sev:<10}{self.RESET} {c}")
        self.print_compliance_scorecard()
        self.print_priorities()

    def save_findings_csv(self, output_path: str) -> None:
        """Full findings CSV enriched with tier / KEV / EPSS / CVE / CWE / evidence
        — a complete, spreadsheet-friendly export (vs the compliance-only CSV)."""
        import csv
        prio = self._prio_by_id()
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["Rule ID", "Severity", "Tier", "Priority Score", "KEV", "EPSS",
                        "Category", "Name", "CVE", "CWE", "Compliance", "Evidence",
                        "Recommendation", "Remediation CLI"])
            order = self.SEVERITY_ORDER
            for f in sorted(self.findings, key=lambda x: (order.get(x.severity, 5), x.rule_id)):
                pr = prio.get(id(f), {})
                w.writerow([
                    f.rule_id, f.severity, pr.get("tier", ""), pr.get("priority_score", ""),
                    "yes" if pr.get("kev") else "", pr.get("epss", ""),
                    f.category, f.name, f.cve or "", f.cwe or "",
                    f.compliance_str, f.line_content or "",
                    f.recommendation, (f.remediation_cmd or "").replace("\n", " / "),
                ])
        print(f"[+] Findings CSV saved to: {output_path}")

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str) -> None:
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        # Preserve the full, unfiltered set so the risk prioritizer can still see
        # the attack-surface findings that signal internet-reachability even when
        # a high --severity threshold would otherwise drop them (reachability is a
        # property of the device, not a display concern).
        if not getattr(self, "_all_findings", None):
            self._all_findings = list(self.findings)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    @staticmethod
    def _risk_score(counts: dict) -> int:
        return min(100, counts.get("CRITICAL", 0) * 25 + counts.get("HIGH", 0) * 10
                   + counts.get("MEDIUM", 0) * 4 + counts.get("LOW", 0) * 1)

    def apply_drift(self, baseline_path: str) -> None:
        """Compare the current findings against a previous ``--json`` report and
        report what is NEW (regressions) vs RESOLVED, plus the posture delta.
        Prints a drift summary and adds a FORTIOS-DRIFT-SUMMARY finding so the
        change surfaces in every report format. Enables trend/continuous-compliance
        use (run on a schedule, diff each time)."""
        try:
            with open(baseline_path, encoding="utf-8") as fh:
                base = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"[!] Could not load baseline '{baseline_path}': {exc}", file=sys.stderr)
            return
        # Coerce defensively (a null/absent 'findings' must not crash) and exclude the
        # scanner's own synthetic drift finding from both sides, or it would always be
        # counted as "resolved" and skew the score on the next scheduled diff.
        raw = base.get("findings", []) if isinstance(base, dict) else []
        base_findings = [d for d in (raw if isinstance(raw, list) else [])
                         if isinstance(d, dict) and d.get("rule_id") != "FORTIOS-DRIFT-SUMMARY"]

        def sig_d(d):
            return (d.get("rule_id", ""), d.get("file_path", ""), d.get("line_content", ""))

        # Diff against the finding set as it would appear in a normal report, NOT the
        # --severity-filtered display set: a high --severity threshold must not make
        # below-threshold findings look "resolved" and collapse the score. Use the
        # full pre-filter set (_all_findings, captured by filter_severity) but exclude
        # INFO — it is never written to a --json baseline (default min severity is
        # LOW), so counting it would fabricate phantom "new" findings on every diff.
        full = getattr(self, "_all_findings", None) or self.findings
        _low = self.SEVERITY_ORDER.get("LOW", 3)
        current = [f for f in full
                   if f.rule_id != "FORTIOS-DRIFT-SUMMARY"
                   and self.SEVERITY_ORDER.get(f.severity, 4) <= _low]
        base_sigs = {sig_d(d): d for d in base_findings}
        cur_sigs = {(f.rule_id, f.file_path, f.line_content): f for f in current}
        new = [f for s, f in cur_sigs.items() if s not in base_sigs]
        resolved = [d for s, d in base_sigs.items() if s not in cur_sigs]
        new.sort(key=lambda f: self.SEVERITY_ORDER.get(f.severity, 4))
        new_crit = sum(1 for f in new if f.severity == "CRITICAL")
        new_high = sum(1 for f in new if f.severity == "HIGH")

        cur_counts: dict = {}
        for f in cur_sigs.values():
            cur_counts[f.severity] = cur_counts.get(f.severity, 0) + 1
        cur_score = self._risk_score(cur_counts)
        # Recompute the baseline score from its (drift-free) findings rather than trusting
        # base['summary'], which may be null or may have counted a prior drift finding.
        base_counts: dict = {}
        for d in base_findings:
            base_counts[d.get("severity", "")] = base_counts.get(d.get("severity", ""), 0) + 1
        base_score = self._risk_score(base_counts)
        delta = cur_score - base_score
        base_time = str(base.get("generated", "") if isinstance(base, dict) else "")[:19].replace("T", " ")

        sep = "=" * 60
        print(f"\n{self.BOLD}{sep}")
        print("  Configuration Drift vs baseline")
        print(f"  Baseline : {baseline_path}  ({base_time or 'unknown time'})")
        print(f"  New      : {len(new)}  (CRITICAL {new_crit}, HIGH {new_high})")
        print(f"  Resolved : {len(resolved)}")
        print(f"  Risk score: {base_score} -> {cur_score}  (delta {delta:+d})")
        print(f"{sep}{self.RESET}")
        for f in new[:15]:
            print(f"    {self.SEVERITY_COLOR.get(f.severity, '')}+ [{f.severity}]{self.RESET} {f.rule_id} — {f.name}")
        for d in resolved[:10]:
            print(f"    - [resolved] {d.get('rule_id', '')} — {d.get('name', '')}")
        print()

        sev = "HIGH" if (new_crit or new_high) else ("LOW" if new else "INFO")
        top = "; ".join(f"[{f.severity}] {f.rule_id} {f.name}" for f in new[:8])
        self._add(Finding(
            rule_id="FORTIOS-DRIFT-SUMMARY",
            name=f"Config drift: {len(new)} new, {len(resolved)} resolved vs baseline",
            category="Drift", severity=sev,
            file_path=self._sys_info.get("hostname", self.host), line_num=None,
            line_content=(f"new={len(new)} (crit={new_crit} high={new_high}) resolved={len(resolved)} "
                          f"risk_score {base_score}->{cur_score} (delta {delta:+d}) baseline={base_time}"),
            description=(f"Compared against the baseline scan from {base_time or 'a previous run'}: {len(new)} new finding(s) "
                         f"({new_crit} Critical, {new_high} High) appeared and {len(resolved)} were resolved. Aggregate risk "
                         f"score moved {base_score} -> {cur_score} (delta {delta:+d}). "
                         + (f"New/regressed: {top}." if top else "No new findings — posture held or improved.")),
            recommendation=("Investigate every new Critical/High finding as a potential regression or unauthorized change; "
                            "confirm resolved findings were fixed intentionally. Run this scan on a schedule and diff each run "
                            "to catch configuration drift early (continuous compliance)."),
            cwe="CWE-710",
        ))

    def print_report(self) -> None:
        sep = "=" * 72
        print(f"\n{self.BOLD}{sep}")
        print(f"  Fortinet FortiOS Security Scanner v{VERSION} — Report")
        print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        target = getattr(self, "host", "")
        if target:
            print(f"  Target: {target}")
        sys_info = getattr(self, "_sys_info", {})
        if sys_info:
            print(f"  Hostname: {sys_info.get('hostname', 'N/A')}")
            print(f"  Model: {sys_info.get('model_name', sys_info.get('model', 'N/A'))}")
            print(f"  FortiOS: {sys_info.get('version', 'N/A')}")
            print(f"  Serial: {sys_info.get('serial', 'N/A')}")
        print(f"  Total findings: {len(self.findings)}")
        print(f"{sep}{self.RESET}\n")

        if not self.findings:
            print(f"  {self.BOLD}No findings.{self.RESET}\n")
            return

        ordered = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )
        for f in ordered:
            sc = self.SEVERITY_COLOR.get(f.severity, "")
            sev = f"{sc}{self.BOLD}{f.severity:<8}{self.RESET}"
            print(f"  [{sev}] {self.BOLD}{f.rule_id}{self.RESET} — {f.name}")
            if f.file_path:
                print(f"           Target: {f.file_path}")
            if f.line_content:
                print(f"           Detail: {f.line_content[:140]}")
            ref = f.cwe or ""
            if f.cve:
                ref = f"{ref} | {f.cve}" if ref else f.cve
            if ref:
                print(f"              Ref: {ref}")
            comp = f.compliance_str
            if comp:
                print(f"       Compliance: {comp[:180]}")
            print(f"             Desc: {f.description[:180]}")
            print(f"              Fix: {f.recommendation[:180]}")
            if f.remediation_cmd:
                cmd_preview = f.remediation_cmd.replace("\n", " / ")[:120]
                print(f"          CLI Fix: {cmd_preview}")
            print()

        counts = self.summary()
        print(f"  {self.BOLD}Summary:{self.RESET}")
        for sev in self.SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c:
                sc = self.SEVERITY_COLOR.get(sev, "")
                print(f"    {sc}{sev:<10}{self.RESET} {c}")
        print()

    def save_json(self, output_path: str) -> None:
        sys_info = getattr(self, "_sys_info", {})
        finding_dicts = [f.to_dict() for f in self.findings]
        report = {
            "scanner": f"Fortinet FortiOS Security Scanner v{VERSION}",
            "schema_version": 2,
            "generated": datetime.now().isoformat(),
            "target": getattr(self, "host", ""),
            "system_info": sys_info,
            "total_findings": len(self.findings),
            "risk_score": self._risk_score(self.summary()),
            "summary": self.summary(),
            "compliance_scorecard": self.compliance_scorecard(),
            "findings": finding_dicts,
        }
        # Enrich with the risk-prioritization the HTML/PDF already show, so the
        # machine-readable format is not strictly poorer than the human reports.
        try:
            results = self.prioritize()
        except Exception:  # pragma: no cover - defensive
            results = []
        if results:
            by_id = {id(r.finding): r for r in results}
            for fd, f in zip(finding_dicts, self.findings):
                r = by_id.get(id(f))
                if r is not None:
                    fd["priority"] = {"tier": r.tier, "score": r.score,
                                      "kev": r.kev, "epss": r.epss,
                                      "internet_reachable": r.reachable}
            tier_summary: dict = {}
            for r in results:
                tier_summary[r.tier] = tier_summary.get(r.tier, 0) + 1
            report["tier_summary"] = tier_summary
            report["prioritization"] = [r.to_dict() for r in results]
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved to: {output_path}")

    # ---- Machine-ingestible exports (SARIF / OCSF) --------------------------

    def _prio_by_id(self) -> dict:
        """Map id(finding) -> PriorityResult.to_dict() for KEV/EPSS/tier
        enrichment of the export formats. Empty dict if the engine is unavailable."""
        try:
            return {id(r.finding): r.to_dict() for r in self.prioritize()}
        except Exception:  # pragma: no cover - defensive
            return {}

    def save_sarif(self, output_path: str) -> None:
        """Write a SARIF 2.1.0 log (GitHub code-scanning / CI ingestion)."""
        from fortinet_export import build_sarif
        doc = build_sarif(
            self.findings, tool_version=VERSION,
            artifact_uri=str(getattr(self, "host", "") or "fortigate-config"),
            prio_by_id=self._prio_by_id())
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
        print(f"[+] SARIF report saved to: {output_path}")

    def save_ocsf(self, output_path: str) -> None:
        """Write OCSF Compliance Finding events (SIEM ingestion)."""
        from fortinet_export import build_ocsf
        si = getattr(self, "_sys_info", {}) or {}
        meta = {
            "hostname": si.get("hostname", getattr(self, "host", "")),
            "version": si.get("version", ""),
            "epoch": int(datetime.now().timestamp() * 1000),
        }
        events = build_ocsf(self.findings, meta=meta, prio_by_id=self._prio_by_id())
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(events, fh, indent=2, ensure_ascii=False)
        print(f"[+] OCSF events saved to: {output_path} ({len(events)} event(s))")

    # ---- Remediation / rollback CLI script generation -----------------------

    # Only STRONG, data-plane-impacting signals mark a fix disruptive (so it is
    # commented out by default). Minor effects an impact note may mention — an admin
    # re-authenticating, a single GUI session dropping — must NOT gate the fix.
    _DISRUPTIVE_TOKENS = ("reboot", "failover", "outage", "power cycle", "downtime",
                          "interrupts all traffic", "interrupt all traffic",
                          "restart the device", "reboots the device", "drops all vpn",
                          "all tunnels", "service restart", "device restart")
    # Phrases that explicitly PROMISE the fix is safe — override the token match.
    _NONDISRUPTIVE_MARKERS = ("non-disruptive", "not disruptive", "no reboot",
                              "without reboot", "does not reboot", "no downtime",
                              "no outage", "no service interruption")

    @classmethod
    def _is_disruptive(cls, impact: str) -> bool:
        il = (impact or "").lower()
        if any(s in il for s in cls._NONDISRUPTIVE_MARKERS):
            return False
        return any(t in il for t in cls._DISRUPTIVE_TOKENS)

    def save_remediation_script(self, fix_path: str, rollback_path: "str | None" = None,
                                tier_max: str = "P4", force: bool = False) -> None:
        """Assemble a fix-first FortiOS CLI batch (and optional paired rollback
        batch) from the remediation KB. Fixes flagged disruptive (reboot / HA
        failover / VPN drop) are emitted COMMENTED OUT unless ``force=True``,
        mirroring the SAFE_MODE philosophy. Generation only — never executes."""
        from risk_prioritizer import TIER_RANK
        results = self.prioritize()
        kb = self._report_kb()
        if results:
            items = [(r.finding, r.tier, getattr(r, "score", ""), r.tier_rank) for r in results]
            max_rank = TIER_RANK.get(str(tier_max).upper(), 3)
            selected = [it for it in items if it[3] <= max_rank]
        else:
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            selected = [(f, "-", "", order.get(f.severity, 5))
                        for f in sorted(self.findings, key=lambda x: order.get(x.severity, 5))]

        si = getattr(self, "_sys_info", {}) or {}
        host = si.get("hostname", getattr(self, "host", ""))
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def _hdr(kind: str) -> list:
            lines = [
                "# " + "=" * 72,
                f"# FortiGate {kind} script — generated {stamp}",
                f"# Host: {host}   Tiers: P1..{str(tier_max).upper()}   Findings: {len(selected)}",
                "# Fix-first order (P1 = most urgent). REVIEW before pasting into the CLI.",
                "# Lines beginning with '#' are comments / manual steps (not executed).",
            ]
            if kind == "remediation" and not force:
                lines.append("# Disruptive fixes are commented out; re-run with force to include them.")
            lines += ["# " + "=" * 72, ""]
            return lines

        fix_lines = _hdr("remediation")
        roll_lines = _hdr("rollback")
        n_manual = n_disruptive = n_auto = 0

        for f, tier, score, _rank in selected:
            rid = getattr(f, "rule_id", "")
            sev = getattr(f, "severity", "")
            detail = kb.detail_for(f) if kb else {}
            cli = (detail.get("cli") or "").strip()
            rollback = (detail.get("rollback") or "").strip()
            verify = (detail.get("verify") or "").strip()
            impact = (detail.get("impact") or "").strip()
            disruptive = self._is_disruptive(impact)
            has_cli = bool(cli) and ("config" in cli or "set " in cli)

            fix_lines.append(f"# ---- [{tier}] {rid}  {sev}  score {score} ----")
            fix_lines.append(f"#   {getattr(f, 'name', '')}")
            if verify:
                fix_lines.append(f"#   verify: {verify.splitlines()[0][:160]}")
            if impact:
                fix_lines.append(f"#   impact: {impact.splitlines()[0][:160]}")

            if not has_cli:
                n_manual += 1
                rec = (getattr(f, "recommendation", "") or "").strip()
                fix_lines.append(f"#   MANUAL: {rec[:220]}")
            elif disruptive and not force:
                n_disruptive += 1
                fix_lines.append("#   !! DISRUPTIVE — commented out (re-run with force to include):")
                fix_lines.extend("#   " + ln for ln in cli.splitlines())
            else:
                n_auto += 1
                fix_lines.extend(cli.splitlines())
            fix_lines.append("")

            roll_lines.append(f"# ---- [{tier}] {rid}  {sev} ----")
            roll_lines.append(f"#   {getattr(f, 'name', '')}")
            if rollback and any(tok in rollback for tok in ("config ", "set ", "unset ", "\nend")):
                roll_lines.extend(rollback.splitlines())
            elif rollback:
                roll_lines.append(f"#   {rollback[:300]}")
            else:
                roll_lines.append("#   (no rollback recorded — reverse the change manually)")
            roll_lines.append("")

        with open(fix_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(fix_lines).rstrip() + "\n")
        print(f"[+] Remediation script saved to: {fix_path}  "
              f"({n_auto} runnable, {n_disruptive} disruptive-commented, {n_manual} manual)")
        if rollback_path:
            with open(rollback_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(roll_lines).rstrip() + "\n")
            print(f"[+] Rollback script saved to: {rollback_path}")

    def _report_kb(self):
        kb = getattr(self, "_kb_cache", None)
        if kb is None:
            try:
                from remediation_kb import RemediationKB
                kb = RemediationKB()
            except Exception:
                kb = None
            self._kb_cache = kb
        return kb

    def _report_meta(self) -> dict:
        si = getattr(self, "_sys_info", {}) or {}
        meta = {
            "host": getattr(self, "host", ""),
            "hostname": si.get("hostname", "N/A"),
            "model": si.get("model_name", si.get("model", "N/A")),
            "version": si.get("version", "N/A"),
            "serial": si.get("serial", "N/A"),
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity_filter": getattr(self, "_sev_filter", "ALL"),
        }
        try:
            from risk_prioritizer import ThreatIntel
            intel = getattr(self, "_intel_cache", None) or ThreatIntel()
            self._intel_cache = intel
            if intel.available:
                meta["intel_snapshot"] = intel.snapshot_date
                meta["intel_kev_count"] = intel.kev_count
                age = intel.age_days()
                if age is not None:
                    meta["intel_age_days"] = age
                    meta["intel_stale"] = intel.is_stale()
        except Exception:
            pass
        return meta

    def save_html(self, output_path: str) -> None:
        """Rich, self-contained HTML report with detailed per-finding remediation."""
        from fortinet_html import FortinetHTMLReport
        FortinetHTMLReport(self.findings, self._report_meta(), self._report_kb(),
                           self.prioritize()).generate(output_path)

    def save_pdf(self, output_path: str) -> None:
        """Paginated, print-ready PDF report (stdlib-only, no third-party deps)."""
        from fortinet_pdf import FortinetPDFReport
        FortinetPDFReport(self.findings, self._report_meta(), self._report_kb(),
                          self.prioritize()).generate(output_path)
        print(f"[+] PDF report saved to: {output_path}")

    # ---- Risk-Prioritization Engine -----------------------------------------

    def prioritize(self):
        """Rank findings into P1–P4 *fix-first* tiers by fusing base severity,
        real-world exploitability (CISA KEV membership + FIRST.org EPSS for CVE
        findings) and internet-reachability from the attack-surface analysis.
        Returns a list of ``PriorityResult`` ordered fix-first, or ``[]`` if the
        engine is unavailable. Cheap (O(n)); safe to call more than once."""
        try:
            from risk_prioritizer import RiskPrioritizer, ThreatIntel
            intel = getattr(self, "_intel_cache", None)
            if intel is None:
                intel = ThreatIntel()
                self._intel_cache = intel
            # Derive reachability from the full (pre-severity-filter) set if we
            # captured one, so a high --severity threshold can't strip the
            # attack-surface findings that signal internet exposure.
            context = getattr(self, "_all_findings", None) or self.findings
            return RiskPrioritizer(intel).prioritize(
                self.findings, context_findings=context,
                cve_reachability=getattr(self, "_cve_reachability", None))
        except Exception as exc:  # pragma: no cover - defensive
            self._warn(f"risk prioritization unavailable: {exc}")
            return []

    def print_priorities(self, top: int | None = None) -> None:
        """Print the fix-first work queue (top N, or the tier summary) to the console."""
        results = self.prioritize()
        if not results:
            return
        try:
            from risk_prioritizer import TIER_META
        except Exception:  # pragma: no cover - defensive (module unavailable)
            return
        counts: dict = {t: 0 for t in TIER_META}
        for r in results:
            counts[r.tier] = counts.get(r.tier, 0) + 1
        sep = "=" * 72
        print(f"\n{self.BOLD}{sep}")
        print("  Risk-Prioritized Remediation Queue  (severity × exploitability × exposure)")
        print(f"{sep}{self.RESET}")
        for t in ("P1", "P2", "P3", "P4"):
            m = TIER_META[t]
            print(f"    {self.BOLD}{t}{self.RESET} {m['label']:<20} {counts[t]:>3}   ({m['window']})")
        intel = getattr(self, "_intel_cache", None)
        if intel is not None and getattr(intel, "available", False):
            age = intel.age_days()
            age_str = f", {age}d old" if age is not None else ""
            print(f"    {self.SEVERITY_COLOR['INFO']}threat-intel snapshot {intel.snapshot_date}{age_str} · "
                  f"{intel.kev_count} KEV-listed CVE(s){self.RESET}")
            if intel.is_stale():
                print(f"    {self.SEVERITY_COLOR['HIGH']}{self.BOLD}[!] threat-intel snapshot is stale "
                      f"({age}d) — refresh with --refresh-intel (or --import-intel on air-gapped hosts){self.RESET}")
        n = top if top and top > 0 else 10
        shown = [r for r in results if r.tier in ("P1", "P2")][:n]
        if not shown:
            shown = results[:n]
        print(f"\n  {self.BOLD}Top {len(shown)} to fix first:{self.RESET}")
        for i, r in enumerate(shown, 1):
            f = r.finding
            sc = self.SEVERITY_COLOR.get(f.severity, "")
            tags = []
            if r.kev:
                tags.append("KEV")
            if getattr(r, "ransomware", False):
                tags.append("ransomware")
            if r.epss is not None and r.epss >= 0.10:
                tags.append(f"EPSS {r.epss*100:.0f}%")
            if r.reachable:
                tags.append("internet-exposed")
            tagstr = ("  [" + ", ".join(tags) + "]") if tags else ""
            print(f"    {i:>2}. {self.BOLD}{r.tier}{self.RESET} "
                  f"{sc}{f.severity:<8}{self.RESET} {f.rule_id}  {f.name[:60]}{tagstr}")
            print(f"        score {r.score}/100 · {f.file_path}")
        print()


# ========================================================================== #
#  FORTINET SCANNER                                                           #
# ========================================================================== #

class FortinetScanner(_ReportMixin):
    """Live security scanner for Fortinet FortiGate appliances via FortiOS REST API."""

    def __init__(
        self,
        host: str,
        token: str,
        verify_ssl: bool = False,
        timeout: int = 30,
        verbose: bool = False,
    ):
        self.host = host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = f"https://{self.host}"
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.verbose = verbose
        self.findings: list[Finding] = []
        self._sys_info: dict = {}
        self._fw_version: tuple[int, ...] = ()

    # ---- API helpers ----

    def _api_get(self, path: str, monitor: bool = False) -> dict | list | None:
        req = _ensure_requests()
        prefix = "monitor" if monitor else "cmdb"
        url = f"{self.host}/api/v2/{prefix}/{path}"
        self._vprint(f"  [api] GET {url}")
        try:
            resp = req.get(
                url,
                headers={"Authorization": f"Bearer {self.token}"},
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except req.exceptions.ConnectionError as exc:
            self._warn(f"Connection failed: {exc}")
            return None
        except req.exceptions.Timeout:
            self._warn(f"Timeout for {path}")
            return None
        except req.exceptions.RequestException as exc:
            self._warn(f"Request failed: {exc}")
            return None

        if resp.status_code == 401:
            self._warn("Authentication failed (401). Check your API token.")
            return None
        if resp.status_code == 403:
            self._warn(f"Access denied (403) for {path}")
            return None
        if resp.status_code == 404:
            self._warn(f"Endpoint not found (404): {path}")
            return None
        if resp.status_code != 200:
            self._warn(f"Unexpected {resp.status_code} for {path}")
            return None

        try:
            data = resp.json()
            return data.get("results", data)
        except (ValueError, AttributeError):
            self._warn(f"Non-JSON response from {path}")
            return None

    def _get_system_status(self) -> bool:
        data = self._api_get("system/status", monitor=True)
        if not data or not isinstance(data, dict):
            return False
        self._sys_info = data
        ver_str = data.get("version", "")
        # FortiOS version format: "v7.2.5" or "7.2.5"
        ver_str = ver_str.lstrip("v")
        self._fw_version = self._parse_ver(ver_str)
        return True

    # ---- version helpers ----

    @staticmethod
    def _parse_ver(s: str) -> tuple[int, ...]:
        parts = re.split(r"[.\-]", re.sub(r"[^0-9.]", "", s))
        try:
            return tuple(int(p) for p in parts if p)
        except ValueError:
            return ()

    def _ver_in_train(self, train: str) -> bool:
        """Check if current firmware is in the given major.minor train."""
        train_parts = self._parse_ver(train)
        if not train_parts or not self._fw_version:
            return False
        return self._fw_version[:len(train_parts)] == train_parts

    def _ver_lt(self, fixed: str) -> bool:
        """Check if current firmware is less than the fixed version."""
        fv = self._parse_ver(fixed)
        if not fv or not self._fw_version:
            return False
        length = max(len(self._fw_version), len(fv))
        a = self._fw_version + (0,) * (length - len(self._fw_version))
        b = fv + (0,) * (length - len(fv))
        return a < b

    # ---- main scan orchestrator ----

    def scan(self) -> None:
        print(f"[*] Fortinet FortiOS Security Scanner v{VERSION}")
        print(f"[*] Target: {self.host}")
        print("[*] Retrieving system status …")

        if not self._get_system_status():
            print("[!] Could not retrieve system status. Check connectivity and API token.", file=sys.stderr)
            sys.exit(1)

        ver = self._sys_info.get("version", "N/A")
        hostname = self._sys_info.get("hostname", "N/A")
        model = self._sys_info.get("model_name", self._sys_info.get("model", "N/A"))
        serial = self._sys_info.get("serial", "N/A")
        print(f"[*] Connected: {hostname} ({model}), FortiOS {ver}, S/N {serial}")
        print("[*] Running security checks …\n")

        checks = [
            ("Known CVEs",           self._check_cves),
            ("Admin Access",         self._check_admin_access),
            ("System Settings",      self._check_system_settings),
            ("Firewall Policies",    self._check_firewall_policies),
            ("Rule-Base Analysis",   self._check_rulebase),
            ("Rule Usage",           self._check_rule_usage),
            ("Object Hygiene",       self._check_object_hygiene),
            ("Attack Surface",       self._check_exposure),
            ("SSL VPN",              self._check_ssl_vpn),
            ("IPsec VPN",            self._check_ipsec_vpn),
            ("Security Profiles",    self._check_security_profiles),
            ("Logging & Monitoring", self._check_logging),
            ("High Availability",    self._check_ha),
            ("Certificates",         self._check_certificates),
            ("Network Hardening",    self._check_network),
            ("ZTNA / SASE",          self._check_ztna),
            ("FortiGuard & Updates", self._check_fortiguard),
            ("Wireless Security",    self._check_wireless),
            ("Backup & DR",          self._check_backup),
            ("Authentication",       self._check_authentication),
            ("Advanced Hardening",   self._check_advanced_hardening),
            ("MITRE ATT&CK Resilience", self._check_mitre_attack_resilience),
        ]

        for name, func in checks:
            self._vprint(f"  [check] {name}")
            try:
                func()
            except Exception as exc:
                self._warn(f"{name} check failed: {exc}")

        print(f"\n[*] Scan complete. {len(self.findings)} finding(s).")

    # ================================================================== #
    #  CHECK: Known CVEs                                                   #
    # ================================================================== #

    # Firmware this scanner actually audits. Ecosystem advisories (FortiManager,
    # FortiClient EMS, …) are tracked in FORTIOS_CVES for documentation but must NOT
    # be version-matched against FortiGate firmware — their train numbers overlap
    # FortiOS's, which would otherwise produce guaranteed false-positive CRITICALs.
    _FORTIOS_PRODUCTS = {"fortios", "fortigate"}

    def _check_cves(self) -> None:
        if not self._fw_version:
            return
        matched: list[dict] = []
        for cve_entry in FORTIOS_CVES:
            product = str(cve_entry.get("product", "FortiOS")).lower()
            if product not in self._FORTIOS_PRODUCTS:
                continue  # cross-product advisory — not this device's firmware
            for branch in cve_entry.get("affected", []):
                train = branch["train"]
                fixed = branch["fixed"]
                if self._ver_in_train(train) and self._ver_lt(fixed):
                    ver_str = ".".join(str(x) for x in self._fw_version)
                    self._add(Finding(
                        rule_id=cve_entry["id"],
                        name=cve_entry["name"],
                        category="Known CVEs",
                        severity=cve_entry["severity"],
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None,
                        line_content=f"FortiOS {ver_str} < {fixed} (train {train})",
                        description=cve_entry["description"],
                        recommendation=cve_entry["recommendation"],
                        cwe=cve_entry.get("cwe"),
                        cve=cve_entry["cve"],
                    ))
                    matched.append(cve_entry)
                    break  # One match per CVE is enough
        # Reachability gating: assess, from the config, whether each matched CVE's
        # vulnerable feature is actually enabled/internet-facing on this device.
        # The verdict feeds the Risk-Prioritization Engine (downrank, never suppress).
        if matched:
            self._assess_cve_reachability(matched)

    def _assess_cve_reachability(self, matched: list[dict]) -> None:
        """Populate ``self._cve_reachability`` = {cve: {verdict, evidence, component}}
        for the CVEs that version-matched. Best-effort and fully guarded — any
        failure just leaves the map empty (prioritizer falls back to severity)."""
        try:
            import cve_reachability
            comp = {e["id"]: CVE_COMPONENTS[e["id"]] for e in matched if e["id"] in CVE_COMPONENTS}
            id_to_cve = {e["id"]: e["cve"] for e in matched}
            self._cve_reachability = cve_reachability.assess_cves(self, comp, id_to_cve)
        except Exception as exc:  # pragma: no cover - defensive
            self._warn(f"CVE reachability assessment unavailable: {exc}")
            self._cve_reachability = {}

    # ================================================================== #
    #  CHECK: Admin Access                                                 #
    # ================================================================== #

    def _ipv6_admin_exposure(self) -> tuple:
        """(exposed, on_wan): is IPv6 admin login (https/http/ssh) enabled on any
        interface, and is any such interface a WAN interface? Gates ADMIN-026 so a
        pure-IPv4 device (no ip6-allowaccess management) is never flagged."""
        try:
            wan = self._wan_interfaces()
        except Exception:
            wan = set()
        exposed = on_wan = False
        for iface in (self._api_get("system/interface") or []):
            if not isinstance(iface, dict):
                continue
            v6 = iface.get("ipv6")
            if not isinstance(v6, dict):
                continue
            toks = set(str(v6.get("ip6-allowaccess", "")).lower().split())
            if toks & {"https", "http", "ssh"}:
                exposed = True
                if iface.get("name") in wan:
                    on_wan = True
        return exposed, on_wan

    def _check_admin_access(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        # System global settings
        glb = self._api_get("system/global")
        if isinstance(glb, list) and glb:
            glb = glb[0] if isinstance(glb[0], dict) else {}
        if not isinstance(glb, dict):
            glb = {}

        # HTTP admin enabled
        if glb.get("admin-https-redirect", "") != "enable" or glb.get("admin-sport", 443) == 80:
            admin_port = glb.get("admin-sport", "")
            if str(glb.get("admin-http-port", "")) and str(glb.get("admin-https-redirect", "")) != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-ADMIN-001", name="HTTP admin access may be enabled",
                    category="Admin Access", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"admin-https-redirect={glb.get('admin-https-redirect', 'N/A')}",
                    description="Administrative access via HTTP exposes credentials in cleartext.",
                    recommendation="Disable HTTP admin access. Use HTTPS only with admin-https-redirect enabled.",
                    cwe="CWE-319",
                ))

        # Admin idle timeout
        admintimeout = glb.get("admintimeout", 5)
        if isinstance(admintimeout, int) and admintimeout > 5:
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-002", name="Admin idle timeout exceeds 5 minutes",
                category="Admin Access", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"admintimeout={admintimeout} minutes",
                description=f"Admin idle timeout is set to {admintimeout} minutes. CIS recommends 5 minutes or less.",
                recommendation="Set admintimeout to 5 minutes: config system global / set admintimeout 5.",
                cwe="CWE-613",
            ))

        # Admin GUI HTTPS server certificate — default/self-signed = MITM + fingerprinting.
        # Only flag when admin-server-cert is explicitly present in config (absent means
        # the key wasn't in the .conf/API response, not necessarily the factory default).
        if "admin-server-cert" in glb:
            admin_cert = str(glb.get("admin-server-cert", "")).strip()
            if admin_cert.lower() in ("", "fortinet_factory", "self-sign"):
                self._add(Finding(
                    rule_id="FORTIOS-CERT-012", name="Admin GUI uses the default/self-signed server certificate",
                    category="Certificates", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"admin-server-cert={admin_cert or 'unset'}",
                    description="The admin GUI serves HTTPS with the shared Fortinet_Factory (or a self-signed) certificate. "
                                "Every FortiGate ships the same factory certificate, so admin HTTPS is trivially fingerprinted, "
                                "cannot be validated by a browser, and is susceptible to man-in-the-middle interception.",
                    recommendation="Install a CA-issued certificate and bind it to the admin GUI: config system global / set admin-server-cert <cert-name>.",
                    cwe="CWE-295",
                ))

        # Maintainer console password-recovery account (physical/console recovery vector).
        if str(glb.get("admin-maintainer", "enable")).lower() == "enable":
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-025", name="Maintainer console password-recovery account enabled",
                category="Admin Access", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="admin-maintainer=enable",
                description="The 'maintainer' account permits console-port password reset (user 'maintainer' + device serial number) — "
                            "a physical/console recovery and persistence vector. CIS recommends disabling it where physical access is "
                            "controlled, so a console-port attacker cannot reset the admin password.",
                recommendation="Ensure an alternate break-glass access method exists, then disable: config system global / set admin-maintainer disable.",
                cwe="CWE-1188",
            ))

        # ---- Password policy checks ----------------------------------------
        pwd_policy = self._api_get("system/password-policy")
        if isinstance(pwd_policy, list) and pwd_policy:
            pwd_policy = pwd_policy[0] if isinstance(pwd_policy[0], dict) else {}
        if not isinstance(pwd_policy, dict):
            pwd_policy = glb.get("admin-password-policy", {})
        if not isinstance(pwd_policy, dict):
            pwd_policy = {}

        # Minimum length
        min_len = pwd_policy.get("minimum-length", pwd_policy.get("min-length", 0))
        if isinstance(min_len, int) and min_len < 12:
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-003", name="Weak admin password policy — minimum length",
                category="Admin Access", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"minimum-length={min_len}",
                description=f"Admin password minimum length is {min_len}. Minimum 12 characters recommended.",
                recommendation="Set minimum password length to 12+: config system password-policy / set minimum-length 12.",
                cwe="CWE-521",
            ))

        # Uppercase requirement
        upper = pwd_policy.get("min-upper-case-letter", 0)
        if isinstance(upper, int) and upper < 1:
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-013", name="Password policy — no uppercase requirement",
                category="Admin Access", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"min-upper-case-letter={upper}",
                description="Password policy does not require uppercase letters, reducing password complexity.",
                recommendation="Set min-upper-case-letter to 1 or higher.",
                cwe="CWE-521",
            ))

        # Lowercase requirement
        lower = pwd_policy.get("min-lower-case-letter", 0)
        if isinstance(lower, int) and lower < 1:
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-014", name="Password policy — no lowercase requirement",
                category="Admin Access", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"min-lower-case-letter={lower}",
                description="Password policy does not require lowercase letters.",
                recommendation="Set min-lower-case-letter to 1 or higher.",
                cwe="CWE-521",
            ))

        # Number requirement
        num_req = pwd_policy.get("min-number", 0)
        if isinstance(num_req, int) and num_req < 1:
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-015", name="Password policy — no numeric digit requirement",
                category="Admin Access", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"min-number={num_req}",
                description="Password policy does not require numeric digits.",
                recommendation="Set min-number to 1 or higher.",
                cwe="CWE-521",
            ))

        # Special character requirement
        special = pwd_policy.get("min-non-alphanumeric", pwd_policy.get("min-special", 0))
        if isinstance(special, int) and special < 1:
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-016", name="Password policy — no special character requirement",
                category="Admin Access", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"min-non-alphanumeric={special}",
                description="Password policy does not require special characters (!@#$%^&*).",
                recommendation="Set min-non-alphanumeric to 1 or higher.",
                cwe="CWE-521",
            ))

        # Password expiry / max age
        expire_days = pwd_policy.get("expire-day", pwd_policy.get("expire", 0))
        if isinstance(expire_days, int) and expire_days == 0:
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-017", name="Password policy — no password expiry configured",
                category="Admin Access", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"expire-day={expire_days}",
                description="Admin passwords never expire. Long-lived passwords increase the risk of credential compromise.",
                recommendation="Set password expiry to 90 days: set expire-day 90.",
                cwe="CWE-262",
            ))

        # Password reuse prevention
        reuse = pwd_policy.get("reuse-password", "")
        if str(reuse).lower() == "enable":
            self._add(Finding(
                rule_id="FORTIOS-ADMIN-018", name="Password policy — password reuse allowed",
                category="Admin Access", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"reuse-password={reuse}",
                description="Password reuse is allowed. Admins can re-use old passwords, negating the benefit of password rotation.",
                recommendation="Disable password reuse: set reuse-password disable.",
                cwe="CWE-262",
            ))

        # Check admin accounts
        admins = self._api_get("system/admin")
        if isinstance(admins, list):
            ipv6_admin_exposed, ipv6_admin_on_wan = self._ipv6_admin_exposure()
            for admin in admins:
                aname = admin.get("name", "unknown")

                # Default admin account
                if aname == "admin":
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-004", name="Default 'admin' account exists",
                        category="Admin Access", severity="MEDIUM",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"admin={aname}",
                        description="The default 'admin' account is present. Rename it or create a separate admin account.",
                        recommendation="Create a new admin account with a non-default name and disable the default 'admin' account.",
                        cwe="CWE-1188",
                    ))

                # No MFA configured
                two_factor = admin.get("two-factor", "disable")
                if two_factor == "disable":
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-005", name="Admin account without MFA",
                        category="Admin Access", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"admin={aname}, two-factor=disable",
                        description=f"Admin account '{aname}' does not have two-factor authentication enabled.",
                        recommendation="Enable MFA for all admin accounts: set two-factor fortitoken / fortitoken-cloud.",
                        cwe="CWE-308",
                    ))

                # No trusted hosts
                trust_hosts = []
                for i in range(1, 11):
                    th = admin.get(f"trusthost{i}", "0.0.0.0 0.0.0.0")
                    if th and th != "0.0.0.0 0.0.0.0":
                        trust_hosts.append(th)
                if not trust_hosts:
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-006", name="Admin account without trusted host restriction",
                        category="Admin Access", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"admin={aname}, trustedhosts=none",
                        description=f"Admin account '{aname}' has no trusted host restrictions, allowing login from any IP.",
                        recommendation="Configure trusted hosts for each admin account to restrict management access.",
                        cwe="CWE-284",
                    ))
                # IPv6 trusted-host gap: only when IPv6 admin access is actually enabled
                # on the device AND this admin HAS IPv4 trusted hosts set (so it never
                # double-reports ADMIN-006). FortiOS filters trusted hosts per address
                # family, so an IPv4-only lockdown is bypassable over IPv6.
                elif ipv6_admin_exposed:
                    ipv6_trust = []
                    for i in range(1, 11):
                        th6 = str(admin.get(f"ip6-trusthost{i}", "::/0")).strip().lower()
                        if th6 and th6 not in ("::/0", "::", "0::/0", "::/0 ::"):
                            ipv6_trust.append(th6)
                    if not ipv6_trust:
                        self._add(Finding(
                            rule_id="FORTIOS-ADMIN-026",
                            name="Admin account without IPv6 trusted-host restriction",
                            category="Admin Access",
                            severity="HIGH" if ipv6_admin_on_wan else "MEDIUM",
                            file_path=_host, line_num=None,
                            line_content=f"admin={aname}, ipv4 trusted hosts set but ip6-trusthost1..10=::/0 (any IPv6)",
                            description=(f"Admin account '{aname}' restricts IPv4 login via trusted hosts but leaves every IPv6 "
                                         "trusted-host slot (ip6-trusthost1..10) at the default ::/0, allowing administrative login "
                                         "from ANY IPv6 source. IPv6 admin access (https/http/ssh) is enabled on this device, so the "
                                         "IPv4 trusted-host lockdown is bypassable over IPv6 — FortiOS applies trusted-host filtering "
                                         "per address family."),
                            recommendation=("Set ip6-trusthost1..10 to the specific IPv6 management prefixes for this admin, mirroring "
                                            "the IPv4 trusted hosts: config system admin / edit <name> / set ip6-trusthost1 <prefix>. "
                                            "Or remove IPv6 management from internet-facing interfaces (unset ip6-allowaccess)."),
                            cwe="CWE-284",
                        ))

                # Using default prof_admin (super_admin)
                profile = admin.get("accprofile", "")
                if profile in ("super_admin", "prof_admin"):
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-007", name="Admin using default super_admin profile",
                        category="Admin Access", severity="MEDIUM",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"admin={aname}, accprofile={profile}",
                        description=f"Admin '{aname}' uses the default super_admin profile with unrestricted access.",
                        recommendation="Create custom admin profiles with least-privilege permissions. Reserve super_admin for emergencies only.",
                        cwe="CWE-269",
                    ))

        # ---- Admin account advanced checks --------------------------------
        if isinstance(admins, list):
            # Count super_admin profiles
            super_admins = [a for a in admins if a.get("accprofile", "") in ("super_admin", "prof_admin")]
            if len(super_admins) > 2:
                self._add(Finding(
                    rule_id="FORTIOS-ADMIN-019", name="Too many super_admin accounts",
                    category="Admin Access", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"super_admin accounts={len(super_admins)}",
                    description=f"{len(super_admins)} admin accounts have super_admin privileges. Excessive privileged accounts increase risk.",
                    recommendation="Limit super_admin accounts to 2 (primary + break-glass). Use custom profiles for daily operations.",
                    cwe="CWE-269",
                ))

            # Check for disabled/inactive admin accounts
            for admin in admins:
                aname = admin.get("name", "unknown")
                admin_status = admin.get("status", "")
                # Wildcard admin (empty password hash or guest)
                guest_flag = admin.get("guest-auth", "")
                if str(guest_flag).lower() == "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-020", name="Admin account with guest auth enabled",
                        category="Admin Access", severity="CRITICAL",
                        file_path=_host, line_num=None,
                        line_content=f"admin={aname}, guest-auth=enable",
                        description=f"Admin account '{aname}' has guest authentication enabled, potentially allowing unauthenticated access.",
                        recommendation="Disable guest auth on admin accounts: set guest-auth disable.",
                        cwe="CWE-287",
                    ))

        # Check API users
        api_users = self._api_get("system/api-user")
        if isinstance(api_users, list):
            for api_user in api_users:
                uname = api_user.get("name", "unknown")

                # No trusted hosts for API user
                trusthosts = api_user.get("trusthost", [])
                if not trusthosts:
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-008", name="API user without trusted host restriction",
                        category="Admin Access", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"api-user={uname}, trusthost=none",
                        description=f"API user '{uname}' has no trusted host restrictions.",
                        recommendation="Configure trusted hosts for API users to restrict API access to known management IPs.",
                        cwe="CWE-284",
                    ))

                # API user with super_admin profile
                api_profile = api_user.get("accprofile", "")
                if api_profile in ("super_admin", "prof_admin"):
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-021", name="API user with super_admin profile",
                        category="Admin Access", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"api-user={uname}, accprofile={api_profile}",
                        description=f"API user '{uname}' has super_admin privileges. API tokens should have minimal permissions.",
                        recommendation="Create a custom read-only admin profile for API users.",
                        cwe="CWE-269",
                    ))

                # API token without CORS restriction
                cors_allow = api_user.get("cors-allow-origin", "")
                if cors_allow == "*" or cors_allow == "":
                    schedule = api_user.get("schedule", "")
                    # Check if API user has comments/description
                    comments = api_user.get("comments", "")
                    if not comments:
                        self._add(Finding(
                            rule_id="FORTIOS-ADMIN-022", name="API user without documentation",
                            category="Admin Access", severity="LOW",
                            file_path=_host, line_num=None,
                            line_content=f"api-user={uname}, comments=empty",
                            description=f"API user '{uname}' has no description/comments. Undocumented API tokens make audit and rotation difficult.",
                            recommendation="Add comments to document the purpose and owner of each API user.",
                            cwe="CWE-1078",
                        ))

    # ================================================================== #
    #  CHECK: System Settings                                              #
    # ================================================================== #

    def _check_system_settings(self) -> None:
        _host = self._sys_info.get("hostname", self.host)

        settings = self._api_get("system/settings")
        if isinstance(settings, list) and settings:
            settings = settings[0] if isinstance(settings[0], dict) else {}
        if not isinstance(settings, dict):
            settings = {}

        # ---- Analyse system/settings object --------------------------------
        if settings:
            # GUI allow default apps
            default_app = settings.get("gui-default-policy-columns", "")

            # Strict HTTP header validation
            sip_helper = settings.get("sip-helper", "")
            if str(sip_helper).lower() == "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-001", name="SIP ALG helper enabled",
                    category="System Settings", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"sip-helper=enable",
                    description="SIP Application Layer Gateway (ALG) helper is enabled. SIP ALG can introduce VoIP issues and bypass firewall policies.",
                    recommendation="Disable SIP helper unless required for NAT traversal: set sip-helper disable.",
                    cwe="CWE-284",
                ))

            # ECMP max paths
            ecmp = settings.get("ecmp-max-paths", 255)
            if isinstance(ecmp, int) and ecmp > 8:
                self._add(Finding(
                    rule_id="FORTIOS-SYS-002", name="ECMP max paths excessively high",
                    category="System Settings", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"ecmp-max-paths={ecmp}",
                    description=f"ECMP max paths is {ecmp}. Excessively high values can cause unpredictable routing.",
                    recommendation="Set ecmp-max-paths to a value appropriate for your network topology (typically 4-8).",
                    cwe="CWE-400",
                ))

            # Multicast forwarding
            multicast_fwd = settings.get("multicast-forward", "")
            if str(multicast_fwd).lower() == "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-003", name="Multicast forwarding enabled",
                    category="System Settings", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content="multicast-forward=enable",
                    description="Multicast forwarding is enabled. Unless required, it increases the attack surface.",
                    recommendation="Disable multicast forwarding if not required: set multicast-forward disable.",
                    cwe="CWE-284",
                ))

            # Allow subnet overlap
            subnet_overlap = settings.get("allow-subnet-overlap", "")
            if str(subnet_overlap).lower() == "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-004", name="Subnet overlap allowed",
                    category="System Settings", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content="allow-subnet-overlap=enable",
                    description="Subnet overlap is allowed, which can cause routing ambiguity and security policy bypass.",
                    recommendation="Disable subnet overlap: set allow-subnet-overlap disable.",
                    cwe="CWE-284",
                ))

            # Central NAT
            central_nat = settings.get("central-nat", "")
            if str(central_nat).lower() != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-005", name="Central NAT not enabled",
                    category="System Settings", severity="INFO",
                    file_path=_host, line_num=None,
                    line_content=f"central-nat={central_nat}",
                    description="Central NAT is not enabled. Per-policy NAT can be harder to audit and maintain consistently.",
                    recommendation="Consider enabling central NAT for easier management: set central-nat enable.",
                    cwe="CWE-1078",
                ))

            # GUI allow unnamed policies
            unnamed = settings.get("gui-allow-unnamed-policy", "")
            if str(unnamed).lower() == "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-006", name="Unnamed firewall policies allowed",
                    category="System Settings", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content="gui-allow-unnamed-policy=enable",
                    description="Unnamed policies are allowed. Unnamed policies make audit trails and change management difficult.",
                    recommendation="Require named policies: set gui-allow-unnamed-policy disable.",
                    cwe="CWE-1078",
                ))

        # ---- Global settings for password policy & admin -------------------
        glb = self._api_get("system/global")
        if isinstance(glb, list) and glb:
            glb = glb[0] if isinstance(glb[0], dict) else {}
        if isinstance(glb, dict):
            # Pre-login banner
            pre_login = glb.get("pre-login-banner", "")
            if str(pre_login).lower() != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-007", name="No pre-login banner configured",
                    category="System Settings", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"pre-login-banner={pre_login}",
                    description="No pre-login banner is displayed before admin authentication. Legal banners may be required for compliance.",
                    recommendation="Enable pre-login banner with an appropriate legal warning: set pre-login-banner enable.",
                    cwe="CWE-1078",
                ))

            # Post-login disclaimer
            post_login = glb.get("post-login-banner", "")
            if str(post_login).lower() != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-008", name="No post-login banner configured",
                    category="System Settings", severity="INFO",
                    file_path=_host, line_num=None,
                    line_content=f"post-login-banner={post_login}",
                    description="No post-login banner is displayed after admin authentication.",
                    recommendation="Enable post-login banner for compliance: set post-login-banner enable.",
                    cwe="CWE-1078",
                ))

            # Strong-crypto enforcement
            strong_crypto = glb.get("strong-crypto", "")
            if str(strong_crypto).lower() != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-009", name="Strong crypto not enforced globally",
                    category="System Settings", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"strong-crypto={strong_crypto}",
                    description="Strong crypto is not enforced. Weak ciphers (DES, 3DES, RC4) and protocols (SSLv3, TLSv1.0) may be used for admin and VPN sessions.",
                    recommendation="Enable strong-crypto globally: config system global / set strong-crypto enable.",
                    cwe="CWE-326",
                ))

            # Admin login lockout
            admin_lockout = glb.get("admin-lockout-threshold", 0)
            if isinstance(admin_lockout, int) and admin_lockout == 0:
                self._add(Finding(
                    rule_id="FORTIOS-SYS-010", name="Admin account lockout not configured",
                    category="System Settings", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"admin-lockout-threshold={admin_lockout}",
                    description="Admin account lockout is not configured. Unlimited failed login attempts enable brute-force attacks.",
                    recommendation="Set admin-lockout-threshold to 3-5 and admin-lockout-duration to 300+ seconds.",
                    cwe="CWE-307",
                ))

            admin_lockout_dur = glb.get("admin-lockout-duration", 60)
            if isinstance(admin_lockout_dur, int) and admin_lockout_dur < 300 and isinstance(admin_lockout, int) and admin_lockout > 0:
                self._add(Finding(
                    rule_id="FORTIOS-SYS-011", name="Admin lockout duration too short",
                    category="System Settings", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"admin-lockout-duration={admin_lockout_dur}s",
                    description=f"Admin lockout duration is only {admin_lockout_dur} seconds. Short lockouts are ineffective against sustained brute-force.",
                    recommendation="Set admin-lockout-duration to 300 seconds or more.",
                    cwe="CWE-307",
                ))

            # Admin HTTPS TLS version
            admin_tls = glb.get("admin-https-ssl-versions", "")
            if isinstance(admin_tls, str):
                admin_tls_lower = admin_tls.lower()
                for weak in ("tlsv1-0", "tlsv1.0", "sslv3", "tlsv1-1", "tlsv1.1"):
                    if weak in admin_tls_lower:
                        self._add(Finding(
                            rule_id="FORTIOS-SYS-012", name="Admin HTTPS allows weak TLS versions",
                            category="System Settings", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"admin-https-ssl-versions={admin_tls}",
                            description=f"Admin HTTPS interface allows deprecated TLS version ({weak}). These are vulnerable to POODLE, BEAST, and other attacks.",
                            recommendation="Restrict admin HTTPS to TLS 1.2+: set admin-https-ssl-versions tlsv1-2 tlsv1-3.",
                            cwe="CWE-326",
                        ))
                        break

            # Private-data (config secret) encryption — CVE-2026-25815
            pde = glb.get("private-data-encryption", "")
            if str(pde).lower() != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-SYS-018", name="Private-data encryption disabled (config secrets use a shared default key)",
                    category="System Settings", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"private-data-encryption={pde or 'disable'}",
                    description="private-data-encryption is disabled, so LDAP/RADIUS bind passwords, VPN pre-shared keys and other secrets stored in the configuration are encrypted with a key that is identical across all FortiGate installations. Anyone who obtains a configuration backup can decrypt the stored credentials (CVE-2026-25815, exploited in the wild since Dec 2025).",
                    recommendation="Enable a device-unique key: config system global / set private-data-encryption enable, then set private-encryption-key <64-hex-key>. Rotate any credentials that were stored in previously exported configs and treat all backups as secrets.",
                    cwe="CWE-1394",
                    cve="CVE-2026-25815",
                ))

        # ---- Check management interfaces -----------------------------------
        interfaces = self._api_get("system/interface")
        if isinstance(interfaces, list):
            for iface in interfaces:
                iface_name = iface.get("name", "unknown")
                iface_type = iface.get("type", "")
                allowaccess = iface.get("allowaccess", "")

                # Skip internal/loopback/HA interfaces
                if iface_type in ("loopback", "aggregate", "redundant"):
                    continue

                # Check for HTTP/Telnet on interfaces
                if isinstance(allowaccess, str):
                    access_list = [a.strip().lower() for a in allowaccess.split()]
                else:
                    access_list = []

                if "http" in access_list:
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-009", name="HTTP admin access on interface",
                        category="Admin Access", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"interface={iface_name}, allowaccess={allowaccess}",
                        description=f"Interface '{iface_name}' allows HTTP management access.",
                        recommendation="Remove HTTP from allowaccess. Use HTTPS only.",
                        cwe="CWE-319",
                    ))

                if "telnet" in access_list:
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-010", name="Telnet access on interface",
                        category="Admin Access", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"interface={iface_name}, allowaccess={allowaccess}",
                        description=f"Interface '{iface_name}' allows Telnet access (unencrypted).",
                        recommendation="Remove telnet from allowaccess. Use SSH only.",
                        cwe="CWE-319",
                    ))

                # PING on WAN interface
                role = iface.get("role", "")
                if role == "wan" and "ping" in access_list:
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-011", name="PING enabled on WAN interface",
                        category="Admin Access", severity="LOW",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"interface={iface_name}, role=wan, allowaccess includes ping",
                        description=f"WAN interface '{iface_name}' responds to ICMP ping, aiding reconnaissance.",
                        recommendation="Remove ping from WAN interface allowaccess unless required for monitoring.",
                        cwe="CWE-200",
                    ))

                # Management protocols on WAN
                wan_bad = {"https", "ssh", "snmp", "fgfm"} & set(access_list)
                if role == "wan" and wan_bad:
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-012", name="Management protocols on WAN interface",
                        category="Admin Access", severity="CRITICAL",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"interface={iface_name}, role=wan, mgmt_access={','.join(sorted(wan_bad))}",
                        description=f"WAN interface '{iface_name}' allows management protocols ({', '.join(sorted(wan_bad))}). This exposes the management plane to the internet.",
                        recommendation="Remove all management protocols from WAN interfaces. Use a dedicated management interface or VPN for admin access.",
                        cwe="CWE-284",
                    ))

    # ================================================================== #
    #  CHECK: Firewall Policies                                            #
    # ================================================================== #

    def _check_firewall_policies(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        policies = self._api_get("firewall/policy")
        if not isinstance(policies, list):
            return

        active_count = 0
        disabled_count = 0

        for pol in policies:
            pol_id = pol.get("policyid", "?")
            pol_name = pol.get("name", f"policy-{pol_id}")
            action = pol.get("action", "").lower()
            status = pol.get("status", "enable")

            # Disabled policies
            if status == "disable":
                disabled_count += 1
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-001", name="Disabled firewall policy",
                    category="Firewall Policies", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), status=disable",
                    description=f"Firewall policy '{pol_name}' (ID {pol_id}) is disabled. Disabled policies add clutter and may be accidentally re-enabled.",
                    recommendation="Remove disabled policies or document the reason for keeping them disabled.",
                    cwe="CWE-1078",
                ))
                continue

            active_count += 1

            # Unnamed policy
            if not pol.get("name") or pol.get("name", "").strip() == "":
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-007", name="Unnamed firewall policy",
                    category="Firewall Policies", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"policy ID {pol_id}, name=(empty)",
                    description=f"Firewall policy ID {pol_id} has no name. Unnamed policies are difficult to audit and troubleshoot.",
                    recommendation="Assign descriptive names to all firewall policies.",
                    cwe="CWE-1078",
                ))

            if action != "accept":
                # Check deny policies for logging
                logtraffic = pol.get("logtraffic", "")
                if logtraffic in ("disable", "") and action == "deny":
                    self._add(Finding(
                        rule_id="FORTIOS-POLICY-008", name="Deny policy without logging",
                        category="Firewall Policies", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"policy={pol_name} (ID {pol_id}), action=deny, logtraffic={logtraffic or 'disable'}",
                        description=f"Deny policy '{pol_name}' does not log blocked traffic. This hinders attack detection.",
                        recommendation="Enable logtraffic on deny policies to record blocked connection attempts.",
                        cwe="CWE-778",
                    ))
                continue

            # Source/dest checks
            srcaddr = pol.get("srcaddr", [])
            dstaddr = pol.get("dstaddr", [])
            service = pol.get("service", [])
            src_names = [a.get("name", "") for a in srcaddr] if isinstance(srcaddr, list) else []
            dst_names = [a.get("name", "") for a in dstaddr] if isinstance(dstaddr, list) else []
            svc_names = [s.get("name", "") for s in service] if isinstance(service, list) else []

            # Any-to-any
            if "all" in src_names and "all" in dst_names:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-002", name="Any-to-any allow policy",
                    category="Firewall Policies", severity="CRITICAL",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), src=all, dst=all",
                    description=f"Policy '{pol_name}' allows traffic from any source to any destination, bypassing segmentation.",
                    recommendation="Replace with specific source and destination address objects.",
                    cwe="CWE-284",
                ))

            # Source = all
            elif "all" in src_names:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-003", name="Allow policy with 'all' source",
                    category="Firewall Policies", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), srcaddr=all",
                    description=f"Policy '{pol_name}' allows traffic from any source address.",
                    recommendation="Restrict the source to specific address objects or groups.",
                    cwe="CWE-284",
                ))

            # Destination = all
            elif "all" in dst_names:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-009", name="Allow policy with 'all' destination",
                    category="Firewall Policies", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), dstaddr=all",
                    description=f"Policy '{pol_name}' allows traffic to any destination address.",
                    recommendation="Restrict the destination to specific address objects or groups.",
                    cwe="CWE-284",
                ))

            # Service = ALL
            if "ALL" in svc_names:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-004", name="Allow policy with ALL services",
                    category="Firewall Policies", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), service=ALL",
                    description=f"Policy '{pol_name}' allows all services/ports.",
                    recommendation="Restrict services to only those required.",
                    cwe="CWE-284",
                ))

            # No logging
            logtraffic = pol.get("logtraffic", "")
            if logtraffic in ("disable", ""):
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-005", name="No traffic logging on allow policy",
                    category="Firewall Policies", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), logtraffic={logtraffic or 'disable'}",
                    description=f"Policy '{pol_name}' does not log traffic, hindering forensic investigation.",
                    recommendation="Enable logtraffic=all or logtraffic=utm on all allow policies.",
                    cwe="CWE-778",
                ))

            # Missing UTM / security profiles
            utm_keys = ["av-profile", "webfilter-profile", "ips-sensor", "application-list",
                        "ssl-ssh-profile", "dlp-sensor", "dnsfilter-profile"]
            has_utm = any(pol.get(k) for k in utm_keys)

            if not has_utm:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-006", name="Allow policy without security profiles",
                    category="Firewall Policies", severity="CRITICAL",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), utm_profiles=none",
                    description=f"Policy '{pol_name}' allows traffic without any UTM security profiles (AV, IPS, WebFilter, AppControl).",
                    recommendation="Apply security profiles (antivirus, IPS, web filter, application control) to all allow policies.",
                    cwe="CWE-693",
                ))

            # No SSL inspection profile
            ssl_profile = pol.get("ssl-ssh-profile", "")
            if not ssl_profile:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-010", name="Allow policy without SSL inspection",
                    category="Firewall Policies", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"policy={pol_name} (ID {pol_id}), ssl-ssh-profile=none",
                    description=f"Policy '{pol_name}' has no SSL inspection profile. Encrypted threats may bypass security profiles.",
                    recommendation="Apply an ssl-ssh-profile to enable encrypted traffic inspection.",
                    cwe="CWE-693",
                ))

            # Schedule validation — permanent allow rules
            schedule = pol.get("schedule", "")
            if isinstance(schedule, str) and schedule.lower() in ("always", ""):
                # Only flag wide-open permanent rules
                if "all" in src_names or "all" in dst_names or "ALL" in svc_names:
                    self._add(Finding(
                        rule_id="FORTIOS-POLICY-011", name="Broad allow policy with permanent schedule",
                        category="Firewall Policies", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"policy={pol_name} (ID {pol_id}), schedule=always, broad rule",
                        description=f"Policy '{pol_name}' has a broad scope (all src/dst/svc) with an 'always' schedule, suggesting a temporary rule made permanent.",
                        recommendation="Review if this policy should have a time-limited schedule. Apply least-privilege addressing.",
                        cwe="CWE-284",
                    ))

        # Policy hygiene — too many disabled
        total = len(policies)
        if total > 0 and disabled_count > 0:
            ratio = disabled_count / total
            if ratio > 0.3 and disabled_count >= 5:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-012", name="High ratio of disabled policies",
                    category="Firewall Policies", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"disabled={disabled_count}/{total} ({ratio:.0%})",
                    description=f"{disabled_count} of {total} policies ({ratio:.0%}) are disabled. Excessive disabled policies indicate poor policy lifecycle management.",
                    recommendation="Review and remove disabled policies that are no longer needed.",
                    cwe="CWE-1078",
                ))

        # ---- NAT / VIP checks -----------------------------------------------
        vips = self._api_get("firewall/vip")
        if isinstance(vips, list):
            for vip in vips:
                vip_name = vip.get("name", "unknown")
                vip_type = vip.get("type", "")
                extip = vip.get("extip", "")
                mappedip = vip.get("mappedip", [])
                # VIP without policy
                portforward = vip.get("portforward", "")
                # VIP exposing all ports (no port restriction)
                if str(portforward).lower() != "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-POLICY-013", name="VIP without port forwarding restriction",
                        category="Firewall Policies", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"vip={vip_name}, portforward={portforward}",
                        description=f"VIP '{vip_name}' maps all ports from {extip} to the internal server. This exposes all services on the target.",
                        recommendation="Enable port forwarding and restrict to only required ports: set portforward enable.",
                        cwe="CWE-284",
                    ))

        # ---- Egress filtering check ----------------------------------------
        if isinstance(policies, list):
            has_egress_filter = False
            for pol in policies:
                if pol.get("status", "") == "disable":
                    continue
                srcintf = pol.get("srcintf", [])
                dstintf = pol.get("dstintf", [])
                src_names_e = [i.get("name", "") for i in srcintf] if isinstance(srcintf, list) else []
                dst_names_e = [i.get("name", "") for i in dstintf] if isinstance(dstintf, list) else []
                # Look for LAN→WAN deny rules (egress filtering)
                action = pol.get("action", "").lower()
                if action == "deny":
                    for si in src_names_e:
                        for di in dst_names_e:
                            if "lan" in si.lower() or "internal" in si.lower():
                                if "wan" in di.lower() or "external" in di.lower():
                                    has_egress_filter = True
            if not has_egress_filter and active_count > 3:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-014", name="No egress filtering policies detected",
                    category="Firewall Policies", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content="No LAN→WAN deny policies found",
                    description="No egress filtering (outbound deny) policies detected. Without egress filtering, compromised hosts can freely exfiltrate data.",
                    recommendation="Implement egress filtering policies to restrict outbound traffic to only necessary services.",
                    cwe="CWE-284",
                ))

    # ================================================================== #
    #  CHECK: Rule-Base Analysis (policy hygiene, FireMon-style)           #
    # ================================================================== #

    # Universal ("any"/"all") tokens per policy field.
    _RB_UNIVERSAL: dict[str, set] = {
        "srcintf": {"any"}, "dstintf": {"any"},
        "srcaddr": {"all"}, "dstaddr": {"all"},
        # NOTE: ALL_TCP / ALL_UDP are NOT universal — they are protocol-specific and
        # cannot cover a service on the other protocol (else a TCP-only rule would be
        # reported as shadowing a UDP deny). Only "ALL"/"ANY" match every service.
        "service": {"ALL", "ANY", "all"},
    }
    _RB_FIELDS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")
    _RB_UTM_KEYS = ("av-profile", "webfilter-profile", "ips-sensor", "application-list",
                    "ssl-ssh-profile", "dlp-sensor", "dnsfilter-profile",
                    "file-filter-profile", "emailfilter-profile")

    @classmethod
    def _rb_set(cls, pol: dict, field: str):
        """Set of object names for a policy field, or None if it is universal (any/all)."""
        vals = pol.get(field, [])
        if isinstance(vals, list):
            names = {v.get("name", "") for v in vals if isinstance(v, dict) and v.get("name")}
        elif isinstance(vals, str) and vals:
            names = {vals}
        else:
            names = set()
        if names & cls._RB_UNIVERSAL.get(field, set()):
            return None
        return names

    @staticmethod
    def _rb_covers(a, b) -> bool:
        """Does field-set a cover field-set b? None = universal covers anything."""
        if a is None:
            return True
        if b is None:
            return False
        return bool(b) and b.issubset(a)

    def _check_rulebase(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        policies = self._api_get("firewall/policy")
        if not isinstance(policies, list) or not policies:
            return

        def negated(p: dict) -> bool:
            return any(str(p.get(k, "")).lower() == "enable"
                       for k in ("srcaddr-negate", "dstaddr-negate", "service-negate"))

        # Precompute field sets for enabled policies (in evaluation order).
        enabled = []
        for p in policies:
            if str(p.get("status", "enable")).lower() == "disable":
                continue
            sets = {f: self._rb_set(p, f) for f in self._RB_FIELDS}
            enabled.append((p, sets, negated(p)))

        n = len(enabled)
        shadowed = redundant = 0

        if n > 2500:
            self._add(Finding(
                rule_id="FORTIOS-RULEBASE-INFO", name="Rule-base too large for full shadow analysis",
                category="Rule-Base Analysis", severity="INFO",
                file_path=_host, line_num=None,
                line_content=f"enabled policies={n} (>2500)",
                description=f"The rule-base has {n} enabled policies; pairwise shadow/redundancy analysis was skipped for performance.",
                recommendation="Consider consolidating policies, or run analysis per-VDOM / per interface-pair.",
                cwe="CWE-1120",
            ))
        else:
            # O(n^2) top-down coverage: policy B is dead if an earlier enabled policy A covers it.
            for i in range(n):
                pol_b, sets_b, neg_b = enabled[i]
                if neg_b:
                    continue
                pid_b = pol_b.get("policyid", "?")
                name_b = pol_b.get("name") or f"policy-{pid_b}"
                act_b = str(pol_b.get("action", "")).lower()
                for j in range(i):
                    pol_a, sets_a, neg_a = enabled[j]
                    if neg_a:
                        continue
                    if all(self._rb_covers(sets_a[f], sets_b[f]) for f in self._RB_FIELDS):
                        pid_a = pol_a.get("policyid", "?")
                        name_a = pol_a.get("name") or f"policy-{pid_a}"
                        act_a = str(pol_a.get("action", "")).lower()
                        if act_a == act_b:
                            redundant += 1
                            self._add(Finding(
                                rule_id="FORTIOS-RULEBASE-002",
                                name="Redundant / duplicate firewall policy",
                                category="Rule-Base Analysis", severity="LOW",
                                file_path=_host, line_num=None,
                                line_content=f"policy {pid_b} ({name_b}) is covered by earlier policy {pid_a} ({name_a}); same action '{act_b}'",
                                description=f"Policy {pid_b} '{name_b}' matches only traffic already matched by the earlier policy {pid_a} '{name_a}', which has the same action. It is redundant and never changes the outcome.",
                                recommendation=f"Remove policy {pid_b}, or merge its objects into policy {pid_a}. Fewer, clearer rules cut audit effort and misconfiguration risk.",
                                cwe="CWE-1164",
                            ))
                        else:
                            sev = "HIGH" if (act_a == "accept" and act_b == "deny") else "MEDIUM"
                            shadowed += 1
                            self._add(Finding(
                                rule_id="FORTIOS-RULEBASE-001",
                                name="Shadowed (dead) firewall policy",
                                category="Rule-Base Analysis", severity=sev,
                                file_path=_host, line_num=None,
                                line_content=f"policy {pid_b} ({name_b}, {act_b}) shadowed by earlier policy {pid_a} ({name_a}, {act_a})",
                                description=("Policy {b} '{nb}' (action {ab}) can never match: the earlier policy {a} '{na}' (action {aa}) already covers all of its traffic and is evaluated first. ".format(
                                                 b=pid_b, nb=name_b, ab=act_b, a=pid_a, na=name_a, aa=act_a)
                                             + ("Because the earlier rule ALLOWS the traffic this rule intends to DENY, traffic you believe is blocked is actually permitted."
                                                if sev == "HIGH" else "The intended traffic is silently handled by the earlier rule instead.")),
                                recommendation=f"Reorder or remove the shadowed policy {pid_b}. If its intent matters, move it above policy {pid_a} or narrow the scope of policy {pid_a}.",
                                cwe="CWE-561",
                            ))
                        break  # first covering rule is enough

        # ---- Policy Control Index (rule-base posture score) ----------------
        accept = [(p, s) for (p, s, neg) in enabled
                  if str(p.get("action", "")).lower() == "accept" and not neg]
        ta = len(accept)
        fully_perm = part_perm = logged = protected = 0
        for p, s in accept:
            univ = sum(1 for f in ("srcaddr", "dstaddr", "service") if s[f] is None)
            if univ >= 3:
                fully_perm += 1
            elif univ == 2:
                part_perm += 1
            if str(p.get("logtraffic", "")).lower() in ("all", "utm"):
                logged += 1
            # A bare ssl-ssh-profile of no-inspection/certificate-inspection is not real UTM.
            real_utm = any(p.get(k) for k in self._RB_UTM_KEYS if k != "ssl-ssh-profile")
            ssl_prof = str(p.get("ssl-ssh-profile", "")).lower()
            if real_utm or (ssl_prof and ssl_prof not in ("no-inspection", "certificate-inspection")):
                protected += 1
        disabled = sum(1 for p in policies if str(p.get("status", "enable")).lower() == "disable")

        score = 100.0
        if ta:
            score -= 35 * (fully_perm / ta)
            score -= 15 * (part_perm / ta)
            score -= 20 * (1 - logged / ta)
            score -= 20 * (1 - protected / ta)
        if n:
            score -= 25 * ((shadowed + redundant) / n)
        score = int(max(0, min(100, round(score))))
        grade = ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
                 else "D" if score >= 60 else "F")
        sev = ("INFO" if score >= 80 else "LOW" if score >= 70
               else "MEDIUM" if score >= 60 else "HIGH")
        self._add(Finding(
            rule_id="FORTIOS-RULEBASE-SCORE",
            name=f"Policy Control Index: {score}/100 (grade {grade})",
            category="Rule-Base Analysis", severity=sev,
            file_path=_host, line_num=None,
            line_content=(f"score={score}/100 grade={grade} | accept={ta} any-any-any={fully_perm} "
                          f"broad={part_perm} logged={logged}/{ta} protected={protected}/{ta} "
                          f"shadowed={shadowed} redundant={redundant} disabled={disabled}"),
            description=(f"The Policy Control Index summarises firewall rule-base hygiene on a 0-100 scale (higher is better) "
                         f"from rule permissiveness, logging and UTM coverage, and dead/redundant rules. This device scores "
                         f"{score}/100 (grade {grade}) across {ta} active allow rules: {fully_perm} fully permissive "
                         f"(any-any-any), {part_perm} broadly permissive, {logged}/{ta} with traffic logging, "
                         f"{protected}/{ta} with UTM profiles, {shadowed} shadowed and {redundant} redundant rules."),
            recommendation=("Raise the score by tightening any-any-any rules to specific address/service objects, enabling "
                            "logging and UTM security profiles on every allow rule, and removing shadowed/redundant rules. "
                            "Target grade A (score >= 90)."),
            cwe="CWE-1120",
        ))

    # ================================================================== #
    #  CHECK: Rule Usage (live-only — dormant-rule cleanup)               #
    # ================================================================== #

    def _check_rule_usage(self) -> None:
        """Flag firewall policies with no observed traffic (dormant rules), using
        the runtime hit counters from the monitor API. Live mode only — the
        offline .conf carries no runtime statistics, so this silently skips."""
        _host = self._sys_info.get("hostname", self.host)
        stats = self._api_get("firewall/policy", monitor=True)
        if not isinstance(stats, list) or not stats:
            return  # runtime stats unavailable (offline, or endpoint not present)

        pol_by_id: dict = {}
        policies = self._api_get("firewall/policy")
        if isinstance(policies, list):
            for p in policies:
                pol_by_id[str(p.get("policyid"))] = p

        dormant = 0
        for st in stats:
            pid = str(st.get("policyid", st.get("id", "")))
            pol = pol_by_id.get(pid, {})
            if str(pol.get("status", "enable")).lower() == "disable":
                continue
            action = str(pol.get("action", "")).lower()
            name = pol.get("name") or f"policy-{pid}"
            nbytes = st.get("bytes", 0) or 0
            npkts = st.get("packets", 0) or 0
            hits = st.get("hit_count")
            never_used = (nbytes == 0 and npkts == 0) and (hits in (0, None))
            if never_used and action == "accept":
                dormant += 1
                self._add(Finding(
                    rule_id="FORTIOS-USAGE-001",
                    name="Dormant firewall policy (no observed traffic)",
                    category="Rule Usage", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"policy {pid} ({name}): bytes={nbytes}, packets={npkts}, hit_count={hits}",
                    description=(f"Firewall policy {pid} '{name}' (accept) has matched no traffic since its counters were "
                                 "last reset. Dormant allow rules widen the attack surface with no business benefit and are "
                                 "prime cleanup / recertification candidates. (Account for device uptime and seasonal traffic "
                                 "before removing — a rule may simply not have been exercised yet.)"),
                    recommendation=(f"Verify policy {pid} is genuinely unused (check counter age vs device uptime), disable it "
                                    "for an observation window, then remove it if still unused. Track recertification with a "
                                    "policy-review workflow / FortiManager Policy Optimizer."),
                    cwe="CWE-1164",
                ))
        if dormant:
            self._add(Finding(
                rule_id="FORTIOS-USAGE-SUMMARY",
                name=f"{dormant} dormant allow policy(ies) identified for cleanup",
                category="Rule Usage", severity="INFO",
                file_path=_host, line_num=None,
                line_content=f"dormant_accept_policies={dormant}",
                description=f"{dormant} enabled allow policy(ies) show zero observed traffic and are candidates for recertification or removal.",
                recommendation="Run a rule-base cleanup: recertify or remove dormant rules to shrink the policy set and the attack surface.",
                cwe="CWE-1164",
            ))

    # ================================================================== #
    #  CHECK: Object Hygiene (orphaned addresses / services / profiles)   #
    # ================================================================== #

    def _check_object_hygiene(self) -> None:
        """Flag defined address / service objects and security profiles that are
        not referenced by any firewall policy — orphaned cleanup candidates."""
        _host = self._sys_info.get("hostname", self.host)
        policies = self._api_get("firewall/policy")
        if not isinstance(policies, list) or not policies:
            return

        # profile policy-field -> (endpoint, human name)
        prof_map = {
            "av-profile": ("antivirus/profile", "AntiVirus"),
            "webfilter-profile": ("webfilter/profile", "Web Filter"),
            "ips-sensor": ("ips/sensor", "IPS"),
            "application-list": ("application/list", "Application Control"),
            "dnsfilter-profile": ("dnsfilter/profile", "DNS Filter"),
            "dlp-sensor": ("dlp/sensor", "DLP"),
        }

        addr_refs: set = set()
        svc_refs: set = set()
        prof_refs: dict = {k: set() for k in prof_map}
        for p in policies:
            for fld in ("srcaddr", "dstaddr"):
                for o in (p.get(fld) or []):
                    if isinstance(o, dict) and o.get("name"):
                        addr_refs.add(o["name"])
            for o in (p.get("service") or []):
                if isinstance(o, dict) and o.get("name"):
                    svc_refs.add(o["name"])
            for pf in prof_map:
                v = p.get(pf)
                if isinstance(v, str) and v:
                    prof_refs[pf].add(v)

        # Expand group membership transitively to a fixpoint (a referenced group uses
        # its members, recursively — nested groups, any config/API ordering).
        def _expand(refs: set, groups) -> None:
            gmap = {g.get("name"): g for g in groups
                    if isinstance(g, dict) and g.get("name")}
            changed = True
            while changed:
                changed = False
                for gname in list(refs):
                    g = gmap.get(gname)
                    if not g:
                        continue
                    for m in (g.get("member") or []):
                        nm = m.get("name") if isinstance(m, dict) else None
                        if nm and nm not in refs:
                            refs.add(nm)
                            changed = True

        addrgrps = self._api_get("firewall/addrgrp")
        if isinstance(addrgrps, list):
            _expand(addr_refs, addrgrps)
        svcgrps = self._api_get("firewall.service/group")
        if isinstance(svcgrps, list):
            _expand(svc_refs, svcgrps)

        # Objects are also referenced OUTSIDE the firewall/policy table — most
        # commonly by local-in-policies (management/VPN source whitelists), DoS
        # policies and proxy policies. Fold those references in so an address used
        # only by, say, a local-in management whitelist is not falsely reported as
        # an unused cleanup candidate (which an admin could then delete in error).
        for endpoint in ("firewall/local-in-policy", "firewall/DoS-policy", "firewall/proxy-policy"):
            extra = self._api_get(endpoint)
            if not isinstance(extra, list):
                continue
            for p in extra:
                if not isinstance(p, dict):
                    continue
                for fld in ("srcaddr", "dstaddr"):
                    for o in (p.get(fld) or []):
                        if isinstance(o, dict) and o.get("name"):
                            addr_refs.add(o["name"])
                for o in (p.get("service") or []):
                    if isinstance(o, dict) and o.get("name"):
                        svc_refs.add(o["name"])

        # VIPs referenced as a destination are "used"; VIPs never referenced are orphaned.
        vips = self._api_get("firewall/vip")
        vip_objs = [v for v in vips if isinstance(v, dict)] if isinstance(vips, list) else []
        vip_names = {v.get("name") for v in vip_objs if v.get("name")}

        def _sample(names, k=8):
            names = sorted(n for n in names if n)
            return ", ".join(names[:k]) + (f", +{len(names) - k} more" if len(names) > k else "")

        # Orphaned VIPs: defined but never referenced as a policy destination (a used
        # VIP lands in addr_refs above). Exclude factory/default VIPs.
        orphan_vips = {v.get("name") for v in vip_objs
                       if v.get("name") and v["name"] not in addr_refs
                       and str(v.get("is-factory-setting", "")).lower() not in ("enable", "true")}
        if len(orphan_vips) >= 3:
            self._add(Finding(
                rule_id="FORTIOS-OBJECT-004", name=f"{len(orphan_vips)} unused VIP objects",
                category="Object Hygiene", severity="LOW",
                file_path=_host, line_num=None,
                line_content=f"unused VIPs ({len(orphan_vips)}): {_sample(orphan_vips)}",
                description=(f"{len(orphan_vips)} virtual IP (VIP) object(s) are defined but not referenced as a "
                             "destination by any firewall policy. Orphaned VIPs still carry a NAT/port-forward "
                             "definition, clutter the configuration, and can be accidentally reused in a new over-broad rule."),
                recommendation="Review and delete unused VIPs (config firewall vip / delete <name>). Confirm each is not referenced by a load-balance or DNAT policy first.",
                cwe="CWE-1164",
            ))

        # Unused address objects (excluding built-in system defaults used implicitly
        # by features rather than by firewall policies).
        default_addrs = {"all", "none", "SSLVPN_TUNNEL_ADDR", "SSLVPN_TUNNEL_IPv6_ADDR",
                         "FIREWALL_AUTH_PORTAL_ADDRESS", "FABRIC_DEVICE", "metadata"}
        addrs = self._api_get("firewall/address")
        if isinstance(addrs, list):
            unused = {a.get("name") for a in addrs
                      if a.get("name") and a["name"] not in addr_refs
                      and a["name"] not in default_addrs
                      and str(a.get("is-factory-setting", "")).lower() not in ("enable", "true")}
            if len(unused) >= 3:
                self._add(Finding(
                    rule_id="FORTIOS-OBJECT-001", name=f"{len(unused)} unused address objects",
                    category="Object Hygiene", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"unused address objects ({len(unused)}): {_sample(unused)}",
                    description=(f"{len(unused)} address object(s) are defined but not referenced by any firewall policy or "
                                 "used address group. Orphaned objects clutter the configuration, slow audits, and can be "
                                 "accidentally reused in a new over-broad rule."),
                    recommendation="Review and delete unused address objects (config firewall address / delete <name>). Confirm each is not referenced by VPN, routing, or other features first.",
                    cwe="CWE-1164",
                ))

        # Unused custom service objects
        svcs = self._api_get("firewall.service/custom")
        if isinstance(svcs, list):
            unused = {s.get("name") for s in svcs if s.get("name") and s["name"] not in svc_refs}
            if len(unused) >= 3:
                self._add(Finding(
                    rule_id="FORTIOS-OBJECT-002", name=f"{len(unused)} unused service objects",
                    category="Object Hygiene", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"unused custom services ({len(unused)}): {_sample(unused)}",
                    description=(f"{len(unused)} custom service object(s) are defined but not referenced by any firewall "
                                 "policy or service group. Unused services are cleanup candidates and reduce audit clarity."),
                    recommendation="Review and delete unused custom services (config firewall service custom / delete <name>).",
                    cwe="CWE-1164",
                ))

        # Unused security profiles (across profile types)
        unused_profiles: list = []
        for pf, (endpoint, label) in prof_map.items():
            objs = self._api_get(endpoint)
            if not isinstance(objs, list):
                continue
            for o in objs:
                nm = o.get("name")
                if nm and nm not in prof_refs[pf] and nm.lower() not in ("no-inspection", "custom-deep-inspection"):
                    unused_profiles.append(f"{label}:{nm}")
        if len(unused_profiles) >= 3:
            self._add(Finding(
                rule_id="FORTIOS-OBJECT-003", name=f"{len(unused_profiles)} unused security profiles",
                category="Object Hygiene", severity="LOW",
                file_path=_host, line_num=None,
                line_content=f"unused profiles ({len(unused_profiles)}): {_sample(unused_profiles)}",
                description=(f"{len(unused_profiles)} security profile(s) (AV / IPS / Web Filter / App Control / DNS / DLP) "
                             "are defined but not applied to any firewall policy. Unapplied profiles provide no protection and "
                             "obscure which controls are actually enforced."),
                recommendation="Either apply these profiles to the relevant allow policies, or delete them if superseded. Ensure every internet-facing allow rule carries the appropriate UTM profiles.",
                cwe="CWE-1164",
            ))

    # ================================================================== #
    #  CHECK: Exposure / Attack Surface (internet-reachable services)     #
    # ================================================================== #

    # Services that should essentially never be directly reachable from the internet.
    # Matched at word boundaries (see _risky_label) so e.g. "gRPC-API" is not flagged
    # as RPC and "NoSQL-Proxy" is not flagged as SQL.
    _EXPO_RISKY = {
        "ssh": "SSH", "telnet": "Telnet", "rdp": "RDP", "smb": "SMB",
        "samba": "SMB", "netbios": "NetBIOS", "cifs": "SMB", "mssql": "MS-SQL",
        "mysql": "MySQL", "sql": "SQL", "postgres": "PostgreSQL", "postgresql": "PostgreSQL",
        "mongo": "MongoDB", "mongodb": "MongoDB", "redis": "Redis", "vnc": "VNC",
        "ftp": "FTP", "tftp": "TFTP", "rlogin": "rlogin", "ldap": "LDAP",
        "winrm": "WinRM", "snmp": "SNMP", "rpc": "RPC", "elasticsearch": "Elasticsearch",
        "kibana": "Kibana", "docker": "Docker", "rexec": "rexec", "rsh": "rsh", "x11": "X11",
    }
    _EXPO_ALL_SVC = {"ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ANY"}

    @classmethod
    def _risky_label(cls, service_name: str):
        """Return the risk label if the service name contains a high-risk token as a
        whole word (delimiter-bounded), else None. Whole-word match avoids false
        positives like gRPC->RPC or NoSQL->SQL."""
        parts = {p for p in re.split(r"[^a-z0-9]+", service_name.lower()) if p}
        for tok, label in cls._EXPO_RISKY.items():
            if tok in parts:
                return label
        return None

    def _wan_interfaces(self) -> set:
        """Best-effort set of internet-facing interface names (role=wan, or a
        conventional WAN name when the role attribute is not set)."""
        names: set = set()
        ifaces = self._api_get("system/interface")
        if isinstance(ifaces, list):
            for i in ifaces:
                if not isinstance(i, dict):
                    continue
                nm = i.get("name", "")
                role = str(i.get("role", "")).lower()
                mode = str(i.get("mode", "")).lower()
                if role == "wan":
                    names.add(nm)
                elif role in ("", "undefined") and (
                        any(t in nm.lower() for t in ("wan", "internet", "outside", "ppp", "wwan"))
                        or mode in ("dhcp", "pppoe")):
                    # Best-effort: an interface obtaining its address via DHCP/PPPoE and
                    # with no LAN role is very likely an internet uplink (e.g. 'port1').
                    names.add(nm)
        return names

    def _check_exposure(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        policies = self._api_get("firewall/policy")
        if not isinstance(policies, list) or not policies:
            return
        wan = self._wan_interfaces()

        exposed = []       # (pid, name, src_all, svc_names)
        risky_count = 0
        all_svc_count = 0
        for pol in policies:
            if str(pol.get("status", "enable")).lower() == "disable":
                continue
            if str(pol.get("action", "")).lower() != "accept":
                continue
            srcintf = {i.get("name", "") for i in (pol.get("srcintf") or []) if isinstance(i, dict)}
            dstintf = {i.get("name", "") for i in (pol.get("dstintf") or []) if isinstance(i, dict)}
            # A policy is internet-inbound only if its source is the WAN/any AND it is
            # NOT purely egress (dstintf entirely within the WAN set). This excludes
            # ordinary outbound internet-access rules (any -> wan) and wan->wan transit.
            src_internet = ("any" in srcintf) or bool(srcintf & wan)
            egress_wan_only = bool(dstintf) and "any" not in dstintf and dstintf <= wan
            if not src_internet or egress_wan_only:
                continue
            src_names = {a.get("name", "") for a in (pol.get("srcaddr") or []) if isinstance(a, dict)}
            svc_names = [s.get("name", "") for s in (pol.get("service") or []) if isinstance(s, dict)]
            src_all = "all" in src_names
            pid = pol.get("policyid", "?")
            name = pol.get("name") or f"policy-{pid}"
            exposed.append((pid, name, src_all, svc_names))
            src_desc = "ANY internet source" if src_all else "a restricted external source"

            # Named high-risk services reachable from the internet (whole-word match).
            for sv in svc_names:
                if sv.upper() in self._EXPO_ALL_SVC:
                    continue  # handled by EXPOSURE-001 below
                label = self._risky_label(sv)
                if not label:
                    continue
                risky_count += 1
                sev = "CRITICAL" if src_all else "HIGH"
                self._add(Finding(
                    rule_id="FORTIOS-EXPOSURE-002",
                    name=f"High-risk service exposed to the internet: {label}",
                    category="Attack Surface", severity=sev,
                    file_path=_host, line_num=None,
                    line_content=f"policy {pid} ({name}): {src_desc} -> service {sv} via WAN",
                    description=(f"Inbound WAN policy {pid} '{name}' permits internet traffic to the high-risk service "
                                 f"'{sv}' ({label}) from {src_desc}. {label} is a common initial-access / lateral-movement "
                                 "target and should not be directly internet-facing."),
                    recommendation=(f"Remove '{sv}' from inbound WAN policy {pid}, or restrict srcaddr to specific trusted "
                                    "IP objects and require VPN/ZTNA for administrative access. Front web apps with a WAF and "
                                    "publish management only via VPN — never expose SSH/RDP/SMB/database ports to the internet."),
                    cwe="CWE-284",
                ))

            # Inbound policy permitting ALL services (any protocol) from the internet —
            # fires regardless of source; CRITICAL for any-source, HIGH for restricted.
            if any(s.upper() in self._EXPO_ALL_SVC for s in svc_names):
                all_svc_count += 1
                self._add(Finding(
                    rule_id="FORTIOS-EXPOSURE-001",
                    name="Inbound internet policy allows ALL services",
                    category="Attack Surface", severity=("CRITICAL" if src_all else "HIGH"),
                    file_path=_host, line_num=None,
                    line_content=f"policy {pid} ({name}): srcintf=WAN, src={'all' if src_all else 'restricted'}, service=ALL, action=accept",
                    description=(f"Inbound WAN policy {pid} '{name}' allows {src_desc} to reach ALL services on the "
                                 "destination(s). This is effectively no perimeter for the covered destinations and exposes "
                                 "every open port to scanning and exploitation."),
                    recommendation=("Replace this rule with least-privilege policies: specific destination objects, only the "
                                    "required services, and — for admin — trusted source IPs behind VPN/ZTNA. Add UTM inspection "
                                    "and logging."),
                    cwe="CWE-284",
                ))

        # Attack-surface summary.
        internet_open = sum(1 for e in exposed if e[2])
        any_all = any(e[2] and any(s.upper() in self._EXPO_ALL_SVC for s in e[3]) for e in exposed)
        sev = ("CRITICAL" if any_all else "HIGH" if risky_count
               else "MEDIUM" if internet_open else "LOW" if exposed else "INFO")
        wan_note = f"WAN interfaces: {', '.join(sorted(wan)) or '(none identified — checked any-source policies only)'}"
        self._add(Finding(
            rule_id="FORTIOS-EXPOSURE-SUMMARY",
            name=f"Attack surface: {len(exposed)} inbound internet policy(ies), {risky_count} high-risk exposure(s)",
            category="Attack Surface", severity=sev,
            file_path=_host, line_num=None,
            line_content=f"inbound_wan_accept={len(exposed)} any-source={internet_open} high-risk-services={risky_count} | {wan_note}",
            description=(f"Modelling reachability from the internet through the policy set: {len(exposed)} enabled inbound "
                         f"WAN allow policy(ies), of which {internet_open} accept ANY internet source, exposing {risky_count} "
                         "high-risk service instance(s) (SSH/RDP/SMB/DB and similar). This is the externally-reachable attack "
                         "surface an internet attacker sees first."),
            recommendation=("Minimise the internet-facing attack surface: publish only necessary services, restrict admin to "
                            "VPN/ZTNA, front web apps with a WAF, and remove any-source/all-service inbound rules. Re-run to "
                            "confirm the surface shrinks."),
            cwe="CWE-284",
        ))

    # ================================================================== #
    #  CHECK: SSL VPN                                                      #
    # ================================================================== #

    def _check_ssl_vpn(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        settings = self._api_get("vpn.ssl/settings")
        if isinstance(settings, list) and settings:
            settings = settings[0] if isinstance(settings[0], dict) else {}
        if not isinstance(settings, dict):
            return

        # SSL VPN enabled check
        if not settings:
            return

        # Weak TLS version
        ssl_min = str(settings.get("ssl-min-proto-ver", "")).lower()
        if ssl_min in WEAK_TLS:
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-001", name="SSL VPN allows weak TLS version",
                category="SSL VPN", severity="HIGH",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"ssl-min-proto-ver={ssl_min}",
                description=f"SSL VPN minimum TLS version is set to {ssl_min}, which is deprecated and vulnerable.",
                recommendation="Set ssl-min-proto-ver to tls1-2 or higher.",
                cwe="CWE-326",
            ))

        # Default port
        port = settings.get("port", 443)
        if port in (443, 10443):
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-002", name="SSL VPN using default port",
                category="SSL VPN", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"port={port}",
                description=f"SSL VPN is running on default port {port}, making it easily discoverable.",
                recommendation="Change the SSL VPN port to a non-standard port.",
                cwe="CWE-200",
            ))

        # Idle timeout
        idle = settings.get("idle-timeout", 300)
        if isinstance(idle, int) and idle > 600:
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-003", name="SSL VPN idle timeout too long",
                category="SSL VPN", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"idle-timeout={idle}s",
                description=f"SSL VPN idle timeout is {idle} seconds ({idle//60} min). Sessions left open increase hijacking risk.",
                recommendation="Set idle-timeout to 300 seconds (5 minutes) or less.",
                cwe="CWE-613",
            ))

        # Login attempt limit
        login_attempt = settings.get("login-attempt-limit", 2)
        if isinstance(login_attempt, int) and login_attempt > 5:
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-004", name="SSL VPN login attempt limit too high",
                category="SSL VPN", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"login-attempt-limit={login_attempt}",
                description=f"SSL VPN allows {login_attempt} failed login attempts, enabling brute-force attacks.",
                recommendation="Set login-attempt-limit to 3 or fewer.",
                cwe="CWE-307",
            ))

        # SSL-VPN is only actually in service once it is bound to an interface AND not
        # explicitly turned off; gate the exposure/hardening checks below on that so
        # they don't fire on a box that merely has a leftover vpn.ssl/settings block
        # (source-interface residue) with SSL-VPN administratively disabled — a common
        # post-CVE hardened baseline. Absent status (pre-7.4.1) => not "disable" => still
        # gated on source-interface, matching the codebase's MITRE-T1133 semantics.
        sslvpn_bound = (bool(settings.get("source-interface"))
                        and str(settings.get("status", "")).lower() != "disable")
        if sslvpn_bound:
            # No source-address restriction -> portal reachable from the whole internet.
            src_addr = settings.get("source-address")
            src_names: set = set()
            for o in (src_addr if isinstance(src_addr, list) else [src_addr]):
                if isinstance(o, dict) and o.get("name"):
                    src_names.add(str(o["name"]).lower())
                elif isinstance(o, str) and o:
                    src_names.update(t.lower() for t in o.split())
            if not src_names or "all" in src_names:
                self._add(Finding(
                    rule_id="FORTIOS-SSLVPN-015",
                    name="SSL VPN reachable from any source (no source-address restriction)",
                    category="SSL VPN", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"source-address={sorted(src_names) or 'unset (all)'}",
                    description="SSL VPN does not restrict which source addresses may reach the portal (source-address is unset or "
                                "'all'), so the portal is exposed to the entire internet. SSL-VPN is the #1 FortiGate compromise "
                                "vector (CVE-2024-21762, CVE-2018-13379, CVE-2022-42475); restricting the source is the single "
                                "biggest exposure-reduction lever and cuts CVE-scan / brute-force noise dramatically.",
                    recommendation="Restrict SSL-VPN to known source networks: config vpn ssl settings / set source-address <trusted-group>. "
                                   "Add a GeoIP address object or a local-in-policy for defence in depth.",
                    cwe="CWE-284",
                ))

            # Cipher algorithm strength — 'high' enforces strong AES-GCM suites.
            algo = str(settings.get("algorithm", "default")).lower()
            if algo != "high":
                self._add(Finding(
                    rule_id="FORTIOS-SSLVPN-017", name="SSL VPN cipher algorithm not set to 'high'",
                    category="SSL VPN", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"algorithm={algo}",
                    description="The SSL-VPN 'algorithm' setting governs which cipher suites the portal negotiates. Any value other "
                                "than 'high' permits weaker suites; 'high' restricts negotiation to strong (AES-GCM) ciphers.",
                    recommendation="config vpn ssl settings / set algorithm high.",
                    cwe="CWE-326",
                ))

        # Tunnel split routing (split tunnelling)
        tunnel_mode = settings.get("tunnel-connect-without-reauth", "")
        # Check portal settings for split tunnel
        portals = self._api_get("vpn.ssl.web/portal")
        if isinstance(portals, list):
            for portal in portals:
                pname = portal.get("name", "unknown")
                split = portal.get("split-tunneling", "")
                if split == "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-SSLVPN-005", name="SSL VPN split tunnelling enabled",
                        category="SSL VPN", severity="MEDIUM",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"portal={pname}, split-tunneling=enable",
                        description=f"Portal '{pname}' allows split tunnelling, sending only specific traffic through VPN. Users may access malicious sites via local internet.",
                        recommendation="Disable split tunnelling to route all traffic through the VPN: set split-tunneling disable.",
                        cwe="CWE-284",
                    ))

        # ---- MFA enforcement for VPN groups ---------------------------------
        user_groups = self._api_get("user/group")
        if isinstance(user_groups, list):
            vpn_groups = [g for g in user_groups if "vpn" in g.get("name", "").lower() or "ssl" in g.get("name", "").lower()]
            for grp in vpn_groups:
                gname = grp.get("name", "unknown")
                members = grp.get("member", [])
                # Check if group members have MFA
                match_entries = grp.get("match", [])
                has_mfa_ref = False
                if isinstance(match_entries, list):
                    for me in match_entries:
                        if isinstance(me, dict) and me.get("group-name", ""):
                            has_mfa_ref = True
                # If no match/group membership is validated, flag potential no-MFA
                if members and not has_mfa_ref:
                    self._add(Finding(
                        rule_id="FORTIOS-SSLVPN-006", name="VPN user group without MFA enforcement",
                        category="SSL VPN", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"user-group={gname}, members={len(members)}, mfa=unverified",
                        description=f"VPN user group '{gname}' with {len(members)} member(s) does not have clear MFA enforcement. VPN access without MFA is a high-risk vector.",
                        recommendation="Enforce two-factor authentication for all VPN user groups using FortiToken or RADIUS MFA.",
                        cwe="CWE-308",
                    ))

        # ---- SSL VPN tunnel mode checks ------------------------------------
        tunnel_ip_pools = settings.get("tunnel-ip-pools", [])
        if isinstance(tunnel_ip_pools, list) and not tunnel_ip_pools:
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-007", name="No SSL VPN tunnel IP pool configured",
                category="SSL VPN", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="tunnel-ip-pools=empty",
                description="No IP pool is configured for SSL VPN tunnel mode. Tunnel mode clients may not receive proper IP assignments.",
                recommendation="Configure dedicated tunnel IP pools for SSL VPN clients.",
                cwe="CWE-284",
            ))

        # DNS server for VPN clients
        dns_server1 = settings.get("dns-server1", "")
        dns_server2 = settings.get("dns-server2", "")
        if not dns_server1 and not dns_server2:
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-008", name="No DNS server configured for VPN clients",
                category="SSL VPN", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="dns-server1=none, dns-server2=none",
                description="No DNS servers are pushed to SSL VPN clients. Clients may use their local DNS, causing DNS leaks.",
                recommendation="Configure internal DNS servers for VPN clients: set dns-server1 <IP>.",
                cwe="CWE-200",
            ))

        # DTLS tunnel disabled (performance)
        dtls_tunnel = settings.get("dtls-tunnel", "")
        if str(dtls_tunnel).lower() == "disable":
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-009", name="DTLS tunnel disabled",
                category="SSL VPN", severity="INFO",
                file_path=_host, line_num=None,
                line_content="dtls-tunnel=disable",
                description="DTLS (Datagram TLS) tunnel is disabled. DTLS provides better VPN performance for latency-sensitive applications.",
                recommendation="Enable dtls-tunnel for improved VPN throughput on UDP-based traffic.",
                cwe="CWE-693",
            ))

        # Check banned ciphers
        banned_cipher = settings.get("banned-cipher", "")
        if isinstance(banned_cipher, str) and not banned_cipher:
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-010", name="No SSL VPN banned cipher suites configured",
                category="SSL VPN", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="banned-cipher=(empty)",
                description="No cipher suites are banned for SSL VPN. Weak ciphers (RC4, DES, NULL) may be negotiated.",
                recommendation="Ban weak ciphers: set banned-cipher RSA DES-CBC-SHA RC4 NULL.",
                cwe="CWE-326",
            ))

        # ---- SSL VPN web mode security checks --------------------------------
        # Check for web-mode portals (higher risk than tunnel-mode)
        if isinstance(portals, list):
            for portal in portals:
                pname = portal.get("name", "unknown")
                web_mode = portal.get("web-mode", "")
                if str(web_mode).lower() == "enable":
                    # Web/clientless mode is the code path behind most critical SSL-VPN
                    # RCEs (CVE-2024-21762, CVE-2018-13379, CVE-2022-42475); flag it as an
                    # attack-surface reduction where tunnel-only would suffice. Only when
                    # SSL-VPN is actually bound to an interface (advisory MEDIUM).
                    if sslvpn_bound:
                        self._add(Finding(
                            rule_id="FORTIOS-SSLVPN-016",
                            name="SSL VPN web (clientless) mode enabled — reduce attack surface",
                            category="SSL VPN", severity="MEDIUM",
                            file_path=_host, line_num=None,
                            line_content=f"portal={pname}, web-mode=enable",
                            description=(f"SSL VPN portal '{pname}' has web (clientless) mode enabled. The web-mode/proxy code path "
                                         "hosts the majority of critical SSL-VPN RCEs (CVE-2024-21762, CVE-2018-13379, "
                                         "CVE-2022-42475). Where users only need network access, tunnel mode eliminates this "
                                         "highest-risk surface."),
                            recommendation=("If clientless access is not required, disable web mode: config vpn ssl web portal / "
                                            "edit <portal> / set web-mode disable / set tunnel-mode enable. On FortiOS 7.4.1+ you can "
                                            "also enforce it globally: config vpn ssl settings / set sslvpn-web-mode disable."),
                            cwe="CWE-693",
                        ))
                    # Check for host check (endpoint compliance)
                    host_check = portal.get("host-check", "")
                    if str(host_check).lower() != "enable":
                        self._add(Finding(
                            rule_id="FORTIOS-SSLVPN-011", name="SSL VPN portal without host check",
                            category="SSL VPN", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"portal={pname}, host-check={host_check}",
                            description=f"SSL VPN portal '{pname}' does not enforce host checking. Unmanaged/compromised endpoints can connect.",
                            recommendation="Enable host-check to verify endpoint compliance (AV, OS version, etc.): set host-check enable.",
                            cwe="CWE-287",
                        ))

                    # Check for file download restriction
                    allow_user_access = portal.get("allow-user-access", "")
                    if isinstance(allow_user_access, str) and "ftp" in allow_user_access.lower():
                        self._add(Finding(
                            rule_id="FORTIOS-SSLVPN-012", name="SSL VPN portal allows FTP access",
                            category="SSL VPN", severity="MEDIUM",
                            file_path=_host, line_num=None,
                            line_content=f"portal={pname}, allow-user-access includes ftp",
                            description=f"SSL VPN portal '{pname}' allows FTP access, enabling unmonitored file transfers.",
                            recommendation="Restrict user access to only necessary protocols. Remove FTP if not required.",
                            cwe="CWE-284",
                        ))

                # Portal with no IP pool (address conflict risk)
                tunnel_ip = portal.get("ip-pools", portal.get("tunnel-mode", ""))
                limit_count = portal.get("limit-user-logins", "")
                if str(limit_count).lower() != "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-SSLVPN-013", name="SSL VPN portal without concurrent login limit",
                        category="SSL VPN", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"portal={pname}, limit-user-logins={limit_count}",
                        description=f"SSL VPN portal '{pname}' does not limit concurrent logins per user. Credential sharing goes undetected.",
                        recommendation="Enable concurrent login limits: set limit-user-logins enable.",
                        cwe="CWE-307",
                    ))

        # ---- SSL VPN compression check (CRIME/BREACH attack) ---------------
        compress = settings.get("http-compression", settings.get("deflate-compression-level", ""))
        if str(compress).lower() == "enable" or (isinstance(compress, int) and compress > 0):
            self._add(Finding(
                rule_id="FORTIOS-SSLVPN-014", name="SSL VPN HTTP compression enabled (CRIME/BREACH risk)",
                category="SSL VPN", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"http-compression={compress}",
                description="HTTP compression over SSL VPN is enabled. Compression combined with TLS is vulnerable to CRIME/BREACH attacks.",
                recommendation="Disable HTTP compression for SSL VPN: set http-compression disable.",
                cwe="CWE-326",
            ))

    # ================================================================== #
    #  CHECK: IPsec VPN                                                    #
    # ================================================================== #

    def _check_ipsec_vpn(self) -> None:
        phase1 = self._api_get("vpn.ipsec/phase1-interface")
        if not isinstance(phase1, list):
            return

        for p1 in phase1:
            p1_name = p1.get("name", "unknown")

            # Aggressive mode
            mode = p1.get("mode", "").lower()
            if mode == "aggressive":
                self._add(Finding(
                    rule_id="FORTIOS-IPSEC-001", name="IPsec Phase 1 aggressive mode",
                    category="IPsec VPN", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"tunnel={p1_name}, mode=aggressive",
                    description=f"IPsec tunnel '{p1_name}' uses aggressive mode, which sends identity in cleartext and is susceptible to offline brute-force attacks.",
                    recommendation="Use main mode (IKEv1) or IKEv2 instead of aggressive mode.",
                    cwe="CWE-319",
                ))

            # Weak proposals (Phase 1)
            proposals = p1.get("proposal", "")
            if isinstance(proposals, str):
                props = [p.strip().lower() for p in proposals.split()]
            elif isinstance(proposals, list):
                props = [str(p).lower() for p in proposals]
            else:
                props = []

            for prop in props:
                # Check encryption
                for weak in WEAK_CIPHERS:
                    if weak in prop:
                        self._add(Finding(
                            rule_id="FORTIOS-IPSEC-002", name="IPsec Phase 1 weak encryption",
                            category="IPsec VPN", severity="HIGH",
                            file_path=self._sys_info.get("hostname", self.host),
                            line_num=None, line_content=f"tunnel={p1_name}, proposal contains {prop}",
                            description=f"IPsec tunnel '{p1_name}' uses weak encryption algorithm '{prop}'.",
                            recommendation="Use AES-256 or AES-128 encryption. Remove DES, 3DES, RC4.",
                            cwe="CWE-327",
                        ))
                        break

                # Check hash
                for weak_h in WEAK_HASHES:
                    if weak_h in prop:
                        self._add(Finding(
                            rule_id="FORTIOS-IPSEC-003", name="IPsec Phase 1 weak hash algorithm",
                            category="IPsec VPN", severity="HIGH",
                            file_path=self._sys_info.get("hostname", self.host),
                            line_num=None, line_content=f"tunnel={p1_name}, proposal contains {prop}",
                            description=f"IPsec tunnel '{p1_name}' uses weak hash algorithm in '{prop}'.",
                            recommendation="Use SHA-256 or SHA-512 hashing. Remove MD5.",
                            cwe="CWE-327",
                        ))
                        break

            # Weak DH group
            dhgrp = str(p1.get("dhgrp", ""))
            dh_groups = [g.strip() for g in dhgrp.split()]
            for dh in dh_groups:
                if dh in WEAK_DH_GROUPS:
                    self._add(Finding(
                        rule_id="FORTIOS-IPSEC-004", name="IPsec Phase 1 weak DH group",
                        category="IPsec VPN", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"tunnel={p1_name}, dhgrp includes {dh}",
                        description=f"IPsec tunnel '{p1_name}' uses weak Diffie-Hellman group {dh}.",
                        recommendation="Use DH group 14 (2048-bit) or higher. Remove groups 1, 2, and 5.",
                        cwe="CWE-326",
                    ))

            # No DPD
            dpd = p1.get("dpd", "").lower()
            if dpd in ("disable", ""):
                self._add(Finding(
                    rule_id="FORTIOS-IPSEC-005", name="IPsec Dead Peer Detection disabled",
                    category="IPsec VPN", severity="MEDIUM",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"tunnel={p1_name}, dpd={dpd or 'disable'}",
                    description=f"IPsec tunnel '{p1_name}' has DPD disabled, which may leave stale tunnels consuming resources.",
                    recommendation="Enable DPD: set dpd on-demand or on-idle.",
                    cwe="CWE-400",
                ))

            # IKEv1 instead of IKEv2
            ike_version = str(p1.get("ike-version", "1"))
            if ike_version == "1":
                self._add(Finding(
                    rule_id="FORTIOS-IPSEC-007", name="IPsec using IKEv1 (legacy protocol)",
                    category="IPsec VPN", severity="MEDIUM",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"tunnel={p1_name}, ike-version=1",
                    description=f"IPsec tunnel '{p1_name}' uses IKEv1. IKEv2 provides better security, performance, and NAT traversal.",
                    recommendation="Migrate to IKEv2: set ike-version 2.",
                    cwe="CWE-327",
                ))

            # Phase 1 keylife too long
            keylife = p1.get("keylife", 86400)
            if isinstance(keylife, int) and keylife > 86400:
                self._add(Finding(
                    rule_id="FORTIOS-IPSEC-008", name="IPsec Phase 1 keylife too long",
                    category="IPsec VPN", severity="MEDIUM",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"tunnel={p1_name}, keylife={keylife}s ({keylife//3600}h)",
                    description=f"IPsec tunnel '{p1_name}' Phase 1 keylife is {keylife} seconds ({keylife//3600} hours). Long key lifetimes increase the window for key compromise.",
                    recommendation="Set Phase 1 keylife to 28800 seconds (8 hours) or less.",
                    cwe="CWE-326",
                ))

            # No certificate-based auth (PSK only)
            authmethod = str(p1.get("authmethod", "")).lower()
            if authmethod in ("psk", "pre-shared-key", ""):
                self._add(Finding(
                    rule_id="FORTIOS-IPSEC-009", name="IPsec using pre-shared key authentication",
                    category="IPsec VPN", severity="MEDIUM",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"tunnel={p1_name}, authmethod={authmethod or 'psk'}",
                    description=f"IPsec tunnel '{p1_name}' uses pre-shared key (PSK) authentication instead of certificates.",
                    recommendation="Use certificate-based authentication for stronger identity verification: set authmethod signature.",
                    cwe="CWE-287",
                ))

        # Phase 2
        phase2 = self._api_get("vpn.ipsec/phase2-interface")
        if isinstance(phase2, list):
            for p2 in phase2:
                p2_name = p2.get("name", "unknown")
                pfs = p2.get("pfs", "").lower()
                if pfs in ("disable", ""):
                    self._add(Finding(
                        rule_id="FORTIOS-IPSEC-006", name="IPsec Phase 2 PFS disabled",
                        category="IPsec VPN", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"tunnel={p2_name}, pfs={pfs or 'disable'}",
                        description=f"IPsec Phase 2 '{p2_name}' has Perfect Forward Secrecy disabled. Compromised keys can decrypt past sessions.",
                        recommendation="Enable PFS: set pfs enable with DH group 14 or higher.",
                        cwe="CWE-326",
                    ))

                # Phase 2 weak encryption
                p2_proposal = p2.get("proposal", "")
                if isinstance(p2_proposal, str):
                    p2_props = [p.strip().lower() for p in p2_proposal.split()]
                elif isinstance(p2_proposal, list):
                    p2_props = [str(p).lower() for p in p2_proposal]
                else:
                    p2_props = []
                for prop in p2_props:
                    for weak in WEAK_CIPHERS:
                        if weak in prop:
                            self._add(Finding(
                                rule_id="FORTIOS-IPSEC-010", name="IPsec Phase 2 weak encryption",
                                category="IPsec VPN", severity="HIGH",
                                file_path=self._sys_info.get("hostname", self.host),
                                line_num=None, line_content=f"tunnel={p2_name}, phase2 proposal contains {prop}",
                                description=f"IPsec Phase 2 '{p2_name}' uses weak encryption '{prop}'.",
                                recommendation="Use AES-256 or AES-128 for Phase 2 encryption. Remove DES, 3DES.",
                                cwe="CWE-327",
                            ))
                            break

                # Phase 2 keylife too long
                p2_keylife = p2.get("keylifeseconds", 43200)
                if isinstance(p2_keylife, int) and p2_keylife > 43200:
                    self._add(Finding(
                        rule_id="FORTIOS-IPSEC-011", name="IPsec Phase 2 keylife too long",
                        category="IPsec VPN", severity="MEDIUM",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"tunnel={p2_name}, keylifeseconds={p2_keylife}s",
                        description=f"IPsec Phase 2 '{p2_name}' keylife is {p2_keylife} seconds. Long key lifetimes increase compromise risk.",
                        recommendation="Set Phase 2 keylifeseconds to 3600-28800 seconds.",
                        cwe="CWE-326",
                    ))

                # Replay detection disabled
                replay = p2.get("replay", "")
                if str(replay).lower() == "disable":
                    self._add(Finding(
                        rule_id="FORTIOS-IPSEC-012", name="IPsec Phase 2 replay protection disabled",
                        category="IPsec VPN", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"tunnel={p2_name}, replay=disable",
                        description=f"IPsec Phase 2 '{p2_name}' has anti-replay protection disabled, allowing packet replay attacks.",
                        recommendation="Enable anti-replay: set replay enable.",
                        cwe="CWE-294",
                    ))

    # ================================================================== #
    #  CHECK: Security Profiles                                            #
    # ================================================================== #

    def _check_security_profiles(self) -> None:
        _host = self._sys_info.get("hostname", self.host)

        # ---- Antivirus profiles -------------------------------------------
        av = self._api_get("antivirus/profile")
        if not isinstance(av, list) or len(av) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-001", name="No antivirus profiles configured",
                category="Security Profiles", severity="HIGH",
                file_path=_host, line_num=None, line_content="antivirus/profile: empty",
                description="No antivirus profiles are configured on this FortiGate.",
                recommendation="Create antivirus profiles and apply them to firewall policies.",
                cwe="CWE-693",
            ))
        else:
            for prof in av:
                pname = prof.get("name", "unknown")
                # Check AV scanning mode
                http_mode = prof.get("http", {})
                if isinstance(http_mode, dict):
                    av_mode = http_mode.get("av-scan", http_mode.get("options", ""))
                    if str(av_mode).lower() in ("monitor", ""):
                        self._add(Finding(
                            rule_id="FORTIOS-AV-001", name="AV profile HTTP not in block mode",
                            category="Security Profiles", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"av-profile={pname}, http av-scan={av_mode}",
                            description=f"AV profile '{pname}' HTTP scanning is set to '{av_mode}' instead of blocking infected files.",
                            recommendation="Set HTTP AV scanning to block mode to prevent malware delivery.",
                            cwe="CWE-693",
                        ))
                # Check if outbreak prevention is enabled
                outbreak = prof.get("outbreak-prevention", "")
                if str(outbreak).lower() in ("disable", "disabled", ""):
                    self._add(Finding(
                        rule_id="FORTIOS-AV-002", name="AV outbreak prevention disabled",
                        category="Security Profiles", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"av-profile={pname}, outbreak-prevention={outbreak}",
                        description=f"AV profile '{pname}' does not have outbreak prevention enabled for zero-day malware detection.",
                        recommendation="Enable outbreak prevention to detect unknown threats via FortiGuard sandbox.",
                        cwe="CWE-693",
                    ))
                # Check analytics/sandbox
                analytics = prof.get("analytics-max-upload", 0)
                ft_analytics = prof.get("ftgd-analytics", prof.get("feature-set", ""))
                if str(ft_analytics).lower() in ("disable", ""):
                    self._add(Finding(
                        rule_id="FORTIOS-AV-003", name="AV cloud sandbox analysis disabled",
                        category="Security Profiles", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"av-profile={pname}, ftgd-analytics={ft_analytics}",
                        description=f"AV profile '{pname}' does not submit suspicious files to FortiGuard cloud sandbox.",
                        recommendation="Enable FortiGuard analytics for sandbox-based zero-day detection.",
                        cwe="CWE-693",
                    ))

        # ---- IPS sensors ---------------------------------------------------
        ips = self._api_get("ips/sensor")
        if not isinstance(ips, list) or len(ips) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-002", name="No IPS sensors configured",
                category="Security Profiles", severity="HIGH",
                file_path=_host, line_num=None, line_content="ips/sensor: empty",
                description="No IPS sensors are configured on this FortiGate.",
                recommendation="Create IPS sensors with appropriate signatures and apply to firewall policies.",
                cwe="CWE-693",
            ))
        else:
            for sensor in ips:
                sname = sensor.get("name", "unknown")
                entries = sensor.get("entries", sensor.get("filter", []))
                if isinstance(entries, list):
                    # Check if any IPS entries are set to monitor instead of block
                    monitor_entries = [e for e in entries if isinstance(e, dict) and e.get("action", "").lower() in ("pass", "monitor")]
                    if len(monitor_entries) == len(entries) and entries:
                        self._add(Finding(
                            rule_id="FORTIOS-IPS-001", name="IPS sensor in monitor-only mode",
                            category="Security Profiles", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"ips-sensor={sname}, all entries action=pass/monitor",
                            description=f"IPS sensor '{sname}' has all entries set to pass/monitor. No traffic is being blocked.",
                            recommendation="Set IPS entries to 'block' for critical and high severity signatures.",
                            cwe="CWE-693",
                        ))
                    # Check for overly broad exclusions
                    exempt_entries = [e for e in entries if isinstance(e, dict) and e.get("exempt-ip", [])]
                    if exempt_entries:
                        self._add(Finding(
                            rule_id="FORTIOS-IPS-002", name="IPS sensor has IP exemptions",
                            category="Security Profiles", severity="MEDIUM",
                            file_path=_host, line_num=None,
                            line_content=f"ips-sensor={sname}, {len(exempt_entries)} entries with exempt-ip",
                            description=f"IPS sensor '{sname}' has {len(exempt_entries)} entries with IP exemptions. Exempted IPs bypass IPS inspection.",
                            recommendation="Review and minimize IPS exemptions. Remove any that are no longer necessary.",
                            cwe="CWE-693",
                        ))

        # ---- Web filter profiles -------------------------------------------
        wf = self._api_get("webfilter/profile")
        if not isinstance(wf, list) or len(wf) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-003", name="No web filter profiles configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=_host, line_num=None, line_content="webfilter/profile: empty",
                description="No web filter profiles are configured.",
                recommendation="Create web filter profiles to block malicious and inappropriate web content.",
                cwe="CWE-693",
            ))
        else:
            for wfp in wf:
                wname = wfp.get("name", "unknown")
                # Check safe search enforcement
                safe_search = wfp.get("web", {})
                if isinstance(safe_search, dict):
                    ss_status = safe_search.get("safe-search", "")
                    if str(ss_status).lower() != "enable":
                        self._add(Finding(
                            rule_id="FORTIOS-WF-001", name="Web filter safe search not enforced",
                            category="Security Profiles", severity="LOW",
                            file_path=_host, line_num=None,
                            line_content=f"webfilter={wname}, safe-search={ss_status}",
                            description=f"Web filter '{wname}' does not enforce safe search on search engines.",
                            recommendation="Enable safe search enforcement to filter explicit content from search results.",
                            cwe="CWE-693",
                        ))
                # Check URL filter for phishing/malware
                ftgd = wfp.get("ftgd-wf", {})
                if isinstance(ftgd, dict):
                    filters = ftgd.get("filters", [])
                    if isinstance(filters, list) and not filters:
                        self._add(Finding(
                            rule_id="FORTIOS-WF-002", name="Web filter has no category filters",
                            category="Security Profiles", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"webfilter={wname}, ftgd-wf filters=empty",
                            description=f"Web filter '{wname}' has no FortiGuard category filters configured.",
                            recommendation="Configure category-based filtering to block malware, phishing, and high-risk sites.",
                            cwe="CWE-693",
                        ))

        # ---- Application control -------------------------------------------
        appctrl = self._api_get("application/list")
        if not isinstance(appctrl, list) or len(appctrl) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-004", name="No application control lists configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=_host, line_num=None, line_content="application/list: empty",
                description="No application control lists are configured.",
                recommendation="Create application control lists to identify and control application traffic.",
                cwe="CWE-693",
            ))
        else:
            for ac in appctrl:
                acname = ac.get("name", "unknown")
                entries = ac.get("entries", [])
                if isinstance(entries, list):
                    # Check for P2P/proxy apps allowed
                    for entry in entries:
                        if isinstance(entry, dict):
                            cat = entry.get("category", [])
                            action = entry.get("action", "").lower()
                            if action == "pass":
                                # Check if high-risk categories are allowed
                                if isinstance(cat, list):
                                    cat_ids = [c.get("id", 0) if isinstance(c, dict) else 0 for c in cat]
                                    # Category IDs for P2P, proxy, botnet typically 2, 15, 25
                                    high_risk = set(cat_ids) & {2, 15, 25}
                                    if high_risk:
                                        self._add(Finding(
                                            rule_id="FORTIOS-APP-001", name="High-risk app categories allowed",
                                            category="Security Profiles", severity="HIGH",
                                            file_path=_host, line_num=None,
                                            line_content=f"app-list={acname}, high-risk categories allowed (IDs: {high_risk})",
                                            description=f"Application control '{acname}' allows high-risk categories (P2P, proxy, botnet).",
                                            recommendation="Block high-risk application categories including P2P, proxy bypass, and botnet tools.",
                                            cwe="CWE-693",
                                        ))
                                        break

        # ---- DLP sensors ---------------------------------------------------
        dlp = self._api_get("dlp/sensor")
        if not isinstance(dlp, list) or len(dlp) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-005", name="No DLP sensors configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=_host, line_num=None, line_content="dlp/sensor: empty",
                description="No Data Loss Prevention sensors are configured.",
                recommendation="Create DLP sensors to detect and prevent sensitive data exfiltration.",
                cwe="CWE-200",
            ))
        else:
            for dlps in dlp:
                dname = dlps.get("name", "unknown")
                filters = dlps.get("filter", dlps.get("entries", []))
                if isinstance(filters, list):
                    # Check if DLP action is log-only
                    log_only = all(isinstance(f, dict) and f.get("action", "").lower() in ("log-only", "allow") for f in filters)
                    if log_only and filters:
                        self._add(Finding(
                            rule_id="FORTIOS-DLP-001", name="DLP sensor in log-only mode",
                            category="Security Profiles", severity="MEDIUM",
                            file_path=_host, line_num=None,
                            line_content=f"dlp-sensor={dname}, all filters action=log-only",
                            description=f"DLP sensor '{dname}' only logs data leaks without blocking. Sensitive data can still leave the network.",
                            recommendation="Set DLP filter actions to 'block' for critical data patterns (PII, financial, healthcare).",
                            cwe="CWE-200",
                        ))

        # ---- DNS filter ----------------------------------------------------
        dnsfilter = self._api_get("dnsfilter/profile")
        if not isinstance(dnsfilter, list) or len(dnsfilter) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-006", name="No DNS filter profiles configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=_host, line_num=None, line_content="dnsfilter/profile: empty",
                description="No DNS filter profiles are configured. DNS filtering blocks malicious domains at the DNS layer.",
                recommendation="Create DNS filter profiles to block known malicious domains.",
                cwe="CWE-693",
            ))
        else:
            for dnsp in dnsfilter:
                dname = dnsp.get("name", "unknown")
                botnet = dnsp.get("block-botnet", dnsp.get("sdns-domain-log", ""))
                if str(botnet).lower() in ("disable", ""):
                    self._add(Finding(
                        rule_id="FORTIOS-DNS-001", name="DNS filter botnet protection disabled",
                        category="Security Profiles", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"dnsfilter={dname}, block-botnet={botnet}",
                        description=f"DNS filter '{dname}' does not block botnet C2 domains.",
                        recommendation="Enable botnet domain blocking in DNS filter profiles.",
                        cwe="CWE-693",
                    ))

        # ---- SSL/SSH inspection profiles -----------------------------------
        ssl_profiles = self._api_get("firewall/ssl-ssh-profile")
        if isinstance(ssl_profiles, list):
            for sp in ssl_profiles:
                spname = sp.get("name", "unknown")
                # Check if deep inspection is used (vs certificate-inspection only)
                ssl_settings = sp.get("ssl", sp.get("https", {}))
                if isinstance(ssl_settings, dict):
                    inspect_all = ssl_settings.get("inspect-all", "")
                    if str(inspect_all).lower() in ("disable", "certificate-inspection", ""):
                        # Only flag non-default profiles
                        if spname not in ("certificate-inspection", "no-inspection"):
                            self._add(Finding(
                                rule_id="FORTIOS-PROFILE-007", name="SSL inspection profile not in deep inspection mode",
                                category="Security Profiles", severity="MEDIUM",
                                file_path=_host, line_num=None,
                                line_content=f"ssl-ssh-profile={spname}, inspect-all={inspect_all}",
                                description=f"SSL inspection profile '{spname}' does not perform deep content inspection. Encrypted malware may pass through undetected.",
                                recommendation="Enable deep SSL inspection for high-risk traffic. Use certificate inspection only where deep inspection causes compatibility issues.",
                                cwe="CWE-693",
                            ))
                # Check for untrusted cert action
                untrusted = sp.get("ssl-exempt", sp.get("untrusted-caname", ""))
                cert_invalid = ssl_settings.get("invalid-server-cert", "") if isinstance(ssl_settings, dict) else ""
                if str(cert_invalid).lower() == "allow":
                    self._add(Finding(
                        rule_id="FORTIOS-PROFILE-008", name="SSL profile allows invalid server certificates",
                        category="Security Profiles", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"ssl-ssh-profile={spname}, invalid-server-cert=allow",
                        description=f"SSL profile '{spname}' allows connections to servers with invalid certificates, enabling MitM attacks.",
                        recommendation="Set invalid-server-cert action to 'block' to prevent MitM attacks.",
                        cwe="CWE-295",
                    ))

        # ---- Email filter profiles -------------------------------------------
        emailfilter = self._api_get("emailfilter/profile")
        if not isinstance(emailfilter, list) or len(emailfilter) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-009", name="No email filter profiles configured",
                category="Security Profiles", severity="LOW",
                file_path=_host, line_num=None,
                line_content="emailfilter/profile: empty",
                description="No email filter profiles are configured. Email-borne threats (phishing, malware) are not inspected.",
                recommendation="Create email filter profiles if SMTP traffic passes through the FortiGate.",
                cwe="CWE-693",
            ))

        # ---- File filter profiles -------------------------------------------
        filefilter = self._api_get("file-filter/profile")
        if isinstance(filefilter, list):
            for ff in filefilter:
                fname = ff.get("name", "unknown")
                rules = ff.get("rules", [])
                if isinstance(rules, list) and not rules:
                    self._add(Finding(
                        rule_id="FORTIOS-PROFILE-010", name="File filter profile with no rules",
                        category="Security Profiles", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"file-filter={fname}, rules=empty",
                        description=f"File filter profile '{fname}' has no file type rules. No file types are being blocked.",
                        recommendation="Add rules to block dangerous file types (exe, bat, scr, dll, vbs, ps1).",
                        cwe="CWE-434",
                    ))

        # ---- ICAP profiles (external content inspection) --------------------
        icap = self._api_get("icap/profile")
        if isinstance(icap, list) and icap:
            for ip in icap:
                ipname = ip.get("name", "unknown")
                preview = ip.get("preview", "")
                if str(preview).lower() == "disable":
                    self._add(Finding(
                        rule_id="FORTIOS-PROFILE-011", name="ICAP profile without preview mode",
                        category="Security Profiles", severity="LOW",
                        file_path=_host, line_num=None,
                        line_content=f"icap-profile={ipname}, preview=disable",
                        description=f"ICAP profile '{ipname}' does not use preview mode. All traffic is sent to the ICAP server, increasing latency.",
                        recommendation="Enable preview mode for ICAP to send only the initial bytes for faster content decisions.",
                        cwe="CWE-693",
                    ))

    # ================================================================== #
    #  CHECK: Logging & Monitoring                                         #
    # ================================================================== #

    def _check_logging(self) -> None:
        _host = self._sys_info.get("hostname", self.host)

        # FortiAnalyzer
        faz = self._api_get("log.fortianalyzer/setting")
        if isinstance(faz, list) and faz:
            faz = faz[0] if isinstance(faz[0], dict) else {}
        if isinstance(faz, dict):
            faz_status = faz.get("status", "disable")
            if faz_status != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-001", name="FortiAnalyzer not configured",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"fortianalyzer status={faz_status}",
                    description="FortiAnalyzer is not enabled for centralized log management and analysis.",
                    recommendation="Configure FortiAnalyzer for centralized logging: config log fortianalyzer setting / set status enable.",
                    cwe="CWE-778",
                ))
            else:
                # FAZ enabled — check encryption
                faz_enc = faz.get("enc-algorithm", "")
                if str(faz_enc).lower() in ("default", "low", "disable", ""):
                    self._add(Finding(
                        rule_id="FORTIOS-LOG-005", name="FortiAnalyzer log encryption weak or disabled",
                        category="Logging & Monitoring", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"fortianalyzer enc-algorithm={faz_enc}",
                        description="Log traffic to FortiAnalyzer is not using strong encryption. Logs may be intercepted in transit.",
                        recommendation="Set enc-algorithm to high: config log fortianalyzer setting / set enc-algorithm high.",
                        cwe="CWE-319",
                    ))

                # FAZ reliable logging
                reliable = faz.get("reliable", "")
                if str(reliable).lower() != "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-LOG-006", name="FortiAnalyzer reliable logging not enabled",
                        category="Logging & Monitoring", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"fortianalyzer reliable={reliable}",
                        description="Reliable logging (TCP) is not enabled for FortiAnalyzer. UDP log transport may drop logs under load.",
                        recommendation="Enable reliable logging: set reliable enable (uses TCP instead of UDP).",
                        cwe="CWE-778",
                    ))

        # Syslog
        syslog = self._api_get("log.syslogd/setting")
        if isinstance(syslog, list) and syslog:
            syslog = syslog[0] if isinstance(syslog[0], dict) else {}
        if isinstance(syslog, dict):
            syslog_status = syslog.get("status", "disable")
            if syslog_status != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-002", name="Syslog forwarding not configured",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"syslogd status={syslog_status}",
                    description="Syslog forwarding is not enabled. Logs stored only locally may be lost if the device is compromised.",
                    recommendation="Configure syslog forwarding to a SIEM or log management platform.",
                    cwe="CWE-778",
                ))
            else:
                # Check syslog mode (reliable = TCP/TLS)
                syslog_mode = syslog.get("mode", "udp")
                if str(syslog_mode).lower() == "udp":
                    self._add(Finding(
                        rule_id="FORTIOS-LOG-007", name="Syslog using UDP (unreliable, unencrypted)",
                        category="Logging & Monitoring", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"syslogd mode={syslog_mode}",
                        description="Syslog is using UDP which is unreliable and transmits logs in cleartext.",
                        recommendation="Set syslog mode to reliable (TCP) or use TLS encryption for log transport.",
                        cwe="CWE-319",
                    ))

                # Check syslog server configured
                syslog_server = syslog.get("server", "")
                if not syslog_server:
                    self._add(Finding(
                        rule_id="FORTIOS-LOG-008", name="Syslog enabled but no server configured",
                        category="Logging & Monitoring", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content="syslogd status=enable, server=(empty)",
                        description="Syslog forwarding is enabled but no syslog server IP/hostname is configured.",
                        recommendation="Configure a syslog server: set server <IP-or-hostname>.",
                        cwe="CWE-778",
                    ))

        # General log settings
        log_setting = self._api_get("log/setting")
        if isinstance(log_setting, list) and log_setting:
            log_setting = log_setting[0] if isinstance(log_setting[0], dict) else {}
        if isinstance(log_setting, dict):
            # Log to disk full action
            full_action = log_setting.get("diskfull", "overwrite")
            if full_action == "overwrite":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-003", name="Log disk full action set to overwrite",
                    category="Logging & Monitoring", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"diskfull={full_action}",
                    description="When log disk is full, older logs are overwritten, potentially destroying forensic evidence.",
                    recommendation="Set diskfull action to 'nolog' or configure log forwarding to prevent data loss.",
                    cwe="CWE-778",
                ))

            # Implicit deny logging
            event_log = log_setting.get("fwpolicy-implicit-log", "disable")
            if event_log == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-004", name="Implicit deny logging disabled",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content="fwpolicy-implicit-log=disable",
                    description="Traffic denied by the implicit deny rule is not logged, hiding potential attack attempts.",
                    recommendation="Enable implicit deny logging: set fwpolicy-implicit-log enable.",
                    cwe="CWE-778",
                ))

            # Log user activity
            log_user = log_setting.get("log-user-in-upper", log_setting.get("user-anonymize", ""))
            # Check for local log status
            local_log = log_setting.get("local-in-allow", "")
            if str(local_log).lower() == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-009", name="Local-in traffic logging disabled",
                    category="Logging & Monitoring", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content="local-in-allow=disable",
                    description="Traffic destined to the FortiGate itself (local-in) is not logged. Admin and management access attempts go unrecorded.",
                    recommendation="Enable local-in-allow logging: set local-in-allow enable.",
                    cwe="CWE-778",
                ))

            local_deny = log_setting.get("local-in-deny-unicast", "")
            if str(local_deny).lower() == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-010", name="Local-in deny logging disabled",
                    category="Logging & Monitoring", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content="local-in-deny-unicast=disable",
                    description="Denied local-in unicast traffic is not logged. Reconnaissance and attack attempts on the firewall itself go undetected.",
                    recommendation="Enable local-in-deny-unicast logging: set local-in-deny-unicast enable.",
                    cwe="CWE-778",
                ))

        # ---- Event log filter settings ----------------------------------------
        event_filter = self._api_get("log/eventfilter")
        if isinstance(event_filter, list) and event_filter:
            event_filter = event_filter[0] if isinstance(event_filter[0], dict) else {}
        if isinstance(event_filter, dict):
            # System events
            sys_event = event_filter.get("event", "")
            if str(sys_event).lower() == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-011", name="System event logging disabled",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content="eventfilter event=disable",
                    description="System event logging is disabled. Configuration changes, admin logins, and system alerts are not recorded.",
                    recommendation="Enable system event logging: config log eventfilter / set event enable.",
                    cwe="CWE-778",
                ))

            # VPN event logging
            vpn_event = event_filter.get("vpn", "")
            if str(vpn_event).lower() == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-012", name="VPN event logging disabled",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content="eventfilter vpn=disable",
                    description="VPN event logging is disabled. VPN login failures, tunnel status changes, and session events are not recorded.",
                    recommendation="Enable VPN event logging: set vpn enable.",
                    cwe="CWE-778",
                ))

            # User authentication event logging
            user_event = event_filter.get("user", "")
            if str(user_event).lower() == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-013", name="User authentication event logging disabled",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content="eventfilter user=disable",
                    description="User authentication event logging is disabled. Login attempts and authentication failures are not recorded.",
                    recommendation="Enable user event logging: set user enable.",
                    cwe="CWE-778",
                ))

        # ---- SNMP trap / alert configuration --------------------------------
        alert_email = self._api_get("alertemail/setting")
        if isinstance(alert_email, list) and alert_email:
            alert_email = alert_email[0] if isinstance(alert_email[0], dict) else {}
        if isinstance(alert_email, dict):
            ae_status = alert_email.get("username", alert_email.get("mailto1", ""))
            if not ae_status:
                self._add(Finding(
                    rule_id="FORTIOS-LOG-014", name="Alert email not configured",
                    category="Logging & Monitoring", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content="alertemail mailto1=(empty)",
                    description="No alert email recipients configured. Critical security events will not trigger email notifications.",
                    recommendation="Configure alert email recipients: config alertemail setting / set mailto1 <email>.",
                    cwe="CWE-778",
                ))

        # ---- Automation / event triggers -----------------------------------
        automation = self._api_get("system/automation-trigger")
        if not isinstance(automation, list) or len(automation) == 0:
            self._add(Finding(
                rule_id="FORTIOS-LOG-015", name="No automation triggers configured",
                category="Logging & Monitoring", severity="LOW",
                file_path=_host, line_num=None,
                line_content="system/automation-trigger: empty",
                description="No automation triggers are configured. Automated responses to security events (IPS alerts, admin logins, HA failover) are not set up.",
                recommendation="Configure automation triggers and actions for critical security events.",
                cwe="CWE-778",
            ))

        # ---- Syslog redundancy check (secondary syslog) -------------------
        syslog2 = self._api_get("log.syslogd2/setting")
        if isinstance(syslog2, list) and syslog2:
            syslog2 = syslog2[0] if isinstance(syslog2[0], dict) else {}
        if isinstance(syslog2, dict):
            s2_status = syslog2.get("status", "disable")
        else:
            s2_status = "disable"
        # Only flag if primary syslog is enabled but secondary is not
        syslog_primary = self._api_get("log.syslogd/setting")
        if isinstance(syslog_primary, list) and syslog_primary:
            syslog_primary = syslog_primary[0] if isinstance(syslog_primary[0], dict) else {}
        if isinstance(syslog_primary, dict) and syslog_primary.get("status", "") == "enable":
            if s2_status != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-016", name="No redundant syslog server configured",
                    category="Logging & Monitoring", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content="syslogd2 status=disable",
                    description="Only one syslog server is configured. If the primary syslog server is unavailable, logs will be lost.",
                    recommendation="Configure a secondary syslog server: config log syslogd2 setting / set status enable.",
                    cwe="CWE-778",
                ))

    # ================================================================== #
    #  CHECK: High Availability                                            #
    # ================================================================== #

    def _check_ha(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        ha = self._api_get("system/ha")
        if isinstance(ha, list) and ha:
            ha = ha[0] if isinstance(ha[0], dict) else {}
        if not isinstance(ha, dict):
            return

        mode = ha.get("mode", "standalone")
        if mode == "standalone":
            self._add(Finding(
                rule_id="FORTIOS-HA-001", name="No High Availability configured",
                category="High Availability", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="ha mode=standalone",
                description="The FortiGate is running in standalone mode without HA, creating a single point of failure.",
                recommendation="Configure Active-Passive or Active-Active HA for resilience.",
                cwe="CWE-654",
            ))
            return

        # Heartbeat authentication
        hb_enc = ha.get("authentication", "disable")
        if hb_enc != "enable":
            self._add(Finding(
                rule_id="FORTIOS-HA-002", name="HA heartbeat not authenticated",
                category="High Availability", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"ha authentication={hb_enc}",
                description="HA heartbeat communication is not authenticated, allowing potential cluster hijacking.",
                recommendation="Enable HA authentication: set authentication enable / set password <strong-password>.",
                cwe="CWE-306",
            ))

        # Session pickup
        session_pickup = ha.get("session-pickup", "disable")
        if session_pickup != "enable":
            self._add(Finding(
                rule_id="FORTIOS-HA-003", name="HA session pickup disabled",
                category="High Availability", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"session-pickup={session_pickup}",
                description="Session pickup is disabled. Active sessions will be dropped during HA failover.",
                recommendation="Enable session-pickup for seamless failover: set session-pickup enable.",
                cwe="CWE-654",
            ))

        # HA encryption
        ha_encryption = ha.get("encryption", "disable")
        if str(ha_encryption).lower() != "enable":
            self._add(Finding(
                rule_id="FORTIOS-HA-005", name="HA cluster communication not encrypted",
                category="High Availability", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"ha encryption={ha_encryption}",
                description="HA cluster communication is not encrypted. Configuration and session data exchanged between peers may be intercepted.",
                recommendation="Enable HA encryption: config system ha / set encryption enable.",
                cwe="CWE-319",
            ))

        # HA heartbeat interfaces
        hb_dev = ha.get("hbdev", "")
        if not hb_dev:
            self._add(Finding(
                rule_id="FORTIOS-HA-006", name="No dedicated HA heartbeat interface",
                category="High Availability", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="hbdev=(empty)",
                description="No dedicated heartbeat interface is configured. HA heartbeat shares bandwidth with data traffic.",
                recommendation="Configure dedicated HA heartbeat interfaces: set hbdev <interface> <priority>.",
                cwe="CWE-654",
            ))

        # HA monitor interfaces
        ha_monitor = ha.get("monitor", "")
        if not ha_monitor:
            self._add(Finding(
                rule_id="FORTIOS-HA-007", name="No HA monitored interfaces configured",
                category="High Availability", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="ha monitor=(empty)",
                description="No interfaces are monitored for HA failover. Link failures on critical interfaces will not trigger failover.",
                recommendation="Configure monitored interfaces: set monitor <wan-interface> <lan-interface>.",
                cwe="CWE-654",
            ))

        # HA override disabled
        override = ha.get("override", "disable")
        if str(override).lower() == "enable":
            self._add(Finding(
                rule_id="FORTIOS-HA-008", name="HA override enabled (auto-failback)",
                category="High Availability", severity="LOW",
                file_path=_host, line_num=None,
                line_content=f"ha override={override}",
                description="HA override is enabled. The primary unit will automatically reclaim the primary role after recovery, causing a second failover.",
                recommendation="Consider disabling override to prevent unnecessary failover disruptions: set override disable.",
                cwe="CWE-654",
            ))

        # Check HA peers for firmware mismatch
        peers = self._api_get("system/ha-peer", monitor=True)
        if isinstance(peers, list) and len(peers) > 1:
            versions = set()
            for peer in peers:
                pv = peer.get("version", peer.get("sw_version", ""))
                if pv:
                    versions.add(pv)
            if len(versions) > 1:
                self._add(Finding(
                    rule_id="FORTIOS-HA-004", name="HA cluster firmware version mismatch",
                    category="High Availability", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"versions={', '.join(sorted(versions))}",
                    description=f"HA cluster members are running different firmware versions: {', '.join(sorted(versions))}.",
                    recommendation="Upgrade all HA cluster members to the same firmware version.",
                    cwe="CWE-1104",
                ))

    # ================================================================== #
    #  CHECK: Certificates                                                 #
    # ================================================================== #

    def _check_certificates(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        certs = self._api_get("vpn.certificate/local")
        if not isinstance(certs, list):
            certs = self._api_get("system/certificate", monitor=True)
        if not isinstance(certs, list):
            return

        if len(certs) == 0:
            self._add(Finding(
                rule_id="FORTIOS-CERT-007", name="No local certificates installed",
                category="Certificates", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="vpn.certificate/local: empty",
                description="No local certificates are installed. The FortiGate is using built-in default certificates for all services.",
                recommendation="Install CA-signed certificates for admin interface, SSL VPN, and other services.",
                cwe="CWE-295",
            ))
            return

        for cert in certs:
            cname = cert.get("name", cert.get("common-name", "unknown"))

            # Default Fortinet factory cert
            if "fortinet" in cname.lower() and ("factory" in cname.lower() or "self-sign" in cname.lower()):
                self._add(Finding(
                    rule_id="FORTIOS-CERT-001", name="Default Fortinet factory certificate in use",
                    category="Certificates", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"certificate={cname}",
                    description=f"The default Fortinet factory certificate '{cname}' is in use. This is a known, shared certificate.",
                    recommendation="Replace the factory certificate with a CA-signed certificate specific to your organisation.",
                    cwe="CWE-295",
                ))

            # Self-signed certificate detection (non-factory)
            issuer = cert.get("issuer", cert.get("ca-identifier", ""))
            subject = cert.get("subject", cert.get("common-name", ""))
            if isinstance(issuer, str) and isinstance(subject, str):
                if issuer == subject and "fortinet" not in cname.lower():
                    self._add(Finding(
                        rule_id="FORTIOS-CERT-004", name="Self-signed certificate detected",
                        category="Certificates", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"certificate={cname}, issuer=subject (self-signed)",
                        description=f"Certificate '{cname}' is self-signed. Self-signed certificates cannot be verified by clients and are vulnerable to MitM attacks.",
                        recommendation="Replace with a CA-signed certificate from a trusted Certificate Authority.",
                        cwe="CWE-295",
                    ))

            # Weak key size
            key_size = cert.get("key-size", cert.get("key_size", 0))
            if isinstance(key_size, int) and 0 < key_size < 2048:
                self._add(Finding(
                    rule_id="FORTIOS-CERT-005", name="Certificate with weak key size",
                    category="Certificates", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"certificate={cname}, key-size={key_size}",
                    description=f"Certificate '{cname}' uses a {key_size}-bit key. Keys shorter than 2048 bits are considered weak.",
                    recommendation="Replace with a certificate using at least 2048-bit RSA or 256-bit ECDSA key.",
                    cwe="CWE-326",
                ))

            # Weak signature algorithm (SHA1)
            sig_algo = cert.get("signature-algorithm", cert.get("sig_algorithm", ""))
            if isinstance(sig_algo, str) and "sha1" in sig_algo.lower() and "sha1" != "sha1withrsaencryption":
                self._add(Finding(
                    rule_id="FORTIOS-CERT-006", name="Certificate using SHA-1 signature algorithm",
                    category="Certificates", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"certificate={cname}, signature-algorithm={sig_algo}",
                    description=f"Certificate '{cname}' uses SHA-1 signature algorithm, which is deprecated and vulnerable to collision attacks.",
                    recommendation="Replace with a certificate using SHA-256 or SHA-384 signature algorithm.",
                    cwe="CWE-328",
                ))

            # Check expiry
            expiry = cert.get("expiry", cert.get("valid-to", ""))
            if expiry:
                try:
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%b %d %H:%M:%S %Y GMT"):
                        try:
                            exp_dt = datetime.strptime(expiry, fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        continue

                    now = datetime.now()
                    if exp_dt < now:
                        self._add(Finding(
                            rule_id="FORTIOS-CERT-002", name="Expired certificate",
                            category="Certificates", severity="CRITICAL",
                            file_path=_host, line_num=None,
                            line_content=f"certificate={cname}, expired={expiry}",
                            description=f"Certificate '{cname}' expired on {expiry}.",
                            recommendation="Replace the expired certificate immediately.",
                            cwe="CWE-295",
                        ))
                    elif exp_dt < now + timedelta(days=30):
                        self._add(Finding(
                            rule_id="FORTIOS-CERT-003", name="Certificate expiring within 30 days",
                            category="Certificates", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"certificate={cname}, expires={expiry}",
                            description=f"Certificate '{cname}' will expire on {expiry}.",
                            recommendation="Renew the certificate before expiry.",
                            cwe="CWE-295",
                        ))
                    elif exp_dt < now + timedelta(days=90):
                        self._add(Finding(
                            rule_id="FORTIOS-CERT-008", name="Certificate expiring within 90 days",
                            category="Certificates", severity="MEDIUM",
                            file_path=_host, line_num=None,
                            line_content=f"certificate={cname}, expires={expiry}",
                            description=f"Certificate '{cname}' will expire on {expiry}. Plan renewal ahead of time.",
                            recommendation="Schedule certificate renewal within the next 60 days.",
                            cwe="CWE-295",
                        ))
                except (ValueError, TypeError):
                    pass

            # Wildcard certificate
            cn = cert.get("common-name", cert.get("subject", ""))
            if isinstance(cn, str) and cn.startswith("*."):
                self._add(Finding(
                    rule_id="FORTIOS-CERT-009", name="Wildcard certificate in use",
                    category="Certificates", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"certificate={cname}, CN={cn}",
                    description=f"Certificate '{cname}' is a wildcard certificate ({cn}). Wildcard certs increase blast radius if compromised.",
                    recommendation="Use specific certificates per service where possible. Monitor wildcard cert usage closely.",
                    cwe="CWE-295",
                ))

        # ---- CRL / OCSP revocation check settings -------------------------
        crl_settings = self._api_get("vpn.certificate/crl")
        ocsp_settings = self._api_get("vpn.certificate/ocsp-server")
        has_revocation = False
        if isinstance(crl_settings, list) and crl_settings:
            has_revocation = True
        if isinstance(ocsp_settings, list) and ocsp_settings:
            has_revocation = True
        if not has_revocation:
            self._add(Finding(
                rule_id="FORTIOS-CERT-010", name="No certificate revocation checking configured",
                category="Certificates", severity="HIGH",
                file_path=_host, line_num=None,
                line_content="crl=empty, ocsp-server=empty",
                description="No CRL or OCSP servers are configured. Revoked certificates will still be accepted as valid.",
                recommendation="Configure CRL distribution points or OCSP servers for certificate revocation checking.",
                cwe="CWE-299",
            ))

    # ================================================================== #
    #  CHECK: Network Hardening                                            #
    # ================================================================== #

    def _mgmt_exposure(self) -> dict:
        """Shared management-plane exposure signals for NET-019 / NET-020.
        Returns sslvpn_enabled, mgmt_on_wan, the WAN interfaces exposing HTTPS/SSH,
        and the SSL-VPN settings dict (for its source-address)."""
        try:
            wan = self._wan_interfaces()
        except Exception:
            wan = set()
        mgmt_wan = []
        for i in (self._api_get("system/interface") or []):
            if not isinstance(i, dict) or i.get("name") not in wan:
                continue
            aa = i.get("allowaccess", "")
            if isinstance(aa, str):
                al = set(aa.lower().split())
            elif isinstance(aa, (list, set, tuple)):
                al = {str(x).lower() for x in aa}
            else:
                al = set()
            hit = al & {"https", "ssh"}
            if hit:
                mgmt_wan.append((i.get("name"), sorted(hit)))
        ssl = self._api_get("vpn.ssl/settings")
        if isinstance(ssl, list) and ssl:
            ssl = ssl[0] if isinstance(ssl[0], dict) else {}
        ssl = ssl if isinstance(ssl, dict) else {}
        return {
            "sslvpn_enabled": bool(ssl.get("source-interface")),
            "mgmt_on_wan": bool(mgmt_wan),
            "mgmt_wan": mgmt_wan,
            "ssl_settings": ssl,
        }

    def _check_network(self) -> None:
        _host = self._sys_info.get("hostname", self.host)

        # ---- DoS policies ------------------------------------------------
        dos = self._api_get("firewall/DoS-policy")
        if not isinstance(dos, list) or len(dos) == 0:
            self._add(Finding(
                rule_id="FORTIOS-NET-001", name="No DoS policy configured",
                category="Network Hardening", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="firewall/DoS-policy: empty",
                description="No DoS protection policies are configured to protect against volumetric attacks.",
                recommendation="Create DoS policies for WAN-facing interfaces to mitigate flood attacks.",
                cwe="CWE-400",
            ))
        elif isinstance(dos, list):
            for dp in dos:
                dp_id = dp.get("policyid", "?")
                anomalies = dp.get("anomaly", [])
                if isinstance(anomalies, list):
                    for anomaly in anomalies:
                        aname = anomaly.get("name", "")
                        status = anomaly.get("status", "")
                        threshold = anomaly.get("threshold", 0)
                        # SYN flood threshold too high
                        if "syn_flood" in aname.lower() and status == "enable" and isinstance(threshold, int) and threshold > 10000:
                            self._add(Finding(
                                rule_id="FORTIOS-NET-002", name="DoS SYN flood threshold too high",
                                category="Network Hardening", severity="MEDIUM",
                                file_path=_host, line_num=None,
                                line_content=f"dos-policy={dp_id}, {aname} threshold={threshold}",
                                description=f"DoS policy {dp_id} SYN flood threshold is {threshold} (>10,000). High thresholds may not protect against moderate floods.",
                                recommendation="Lower the SYN flood threshold to 2,000-5,000 per second based on normal traffic baselines.",
                                cwe="CWE-400",
                            ))
                        # UDP flood threshold too high
                        if "udp_flood" in aname.lower() and status == "enable" and isinstance(threshold, int) and threshold > 10000:
                            self._add(Finding(
                                rule_id="FORTIOS-NET-003", name="DoS UDP flood threshold too high",
                                category="Network Hardening", severity="MEDIUM",
                                file_path=_host, line_num=None,
                                line_content=f"dos-policy={dp_id}, {aname} threshold={threshold}",
                                description=f"DoS policy {dp_id} UDP flood threshold is {threshold}. High thresholds reduce protection effectiveness.",
                                recommendation="Lower the UDP flood threshold based on traffic baselines.",
                                cwe="CWE-400",
                            ))
                        # ICMP flood threshold too high
                        if "icmp_flood" in aname.lower() and status == "enable" and isinstance(threshold, int) and threshold > 1000:
                            self._add(Finding(
                                rule_id="FORTIOS-NET-004", name="DoS ICMP flood threshold too high",
                                category="Network Hardening", severity="LOW",
                                file_path=_host, line_num=None,
                                line_content=f"dos-policy={dp_id}, {aname} threshold={threshold}",
                                description=f"DoS policy {dp_id} ICMP flood threshold is {threshold}.",
                                recommendation="Lower ICMP flood threshold to 250-500 per second.",
                                cwe="CWE-400",
                            ))

        # ---- Interface-level network checks --------------------------------
        interfaces = self._api_get("system/interface")
        if isinstance(interfaces, list):
            for iface in interfaces:
                iface_name = iface.get("name", "unknown")
                role = iface.get("role", "")
                iface_type = iface.get("type", "")

                if iface_type in ("loopback", "aggregate", "redundant"):
                    continue

                # DHCP server on external interface
                if role == "wan":
                    dhcp_status = iface.get("dhcp-relay-service", "")
                    if str(dhcp_status).lower() == "enable":
                        self._add(Finding(
                            rule_id="FORTIOS-NET-005", name="DHCP relay on WAN interface",
                            category="Network Hardening", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"interface={iface_name}, dhcp-relay-service=enable",
                            description=f"WAN interface '{iface_name}' has DHCP relay enabled, potentially exposing internal DHCP to the internet.",
                            recommendation="Disable DHCP relay on WAN interfaces unless explicitly required.",
                            cwe="CWE-284",
                        ))

                    # DNS server override disabled on WAN
                    dns_override = iface.get("dns-server-override", "")
                    if str(dns_override).lower() == "disable":
                        self._add(Finding(
                            rule_id="FORTIOS-NET-006", name="DNS server override disabled on WAN",
                            category="Network Hardening", severity="LOW",
                            file_path=_host, line_num=None,
                            line_content=f"interface={iface_name}, dns-server-override=disable",
                            description=f"WAN interface '{iface_name}' does not override DNS from ISP. ISP DNS may not filter malicious domains.",
                            recommendation="Use FortiGuard DNS or a reputable DNS service and enable dns-server-override.",
                            cwe="CWE-350",
                        ))

                # Speed/duplex mismatch detection
                speed = iface.get("speed", "")
                if isinstance(speed, str) and speed.lower() not in ("", "auto", "auto-negotiate"):
                    # Non-auto speed may cause duplex mismatch
                    self._vprint(f"    Interface {iface_name} has fixed speed: {speed}")

                # IP spoofing / source-check
                if role in ("wan", "dmz"):
                    src_check = iface.get("src-check", "")
                    if str(src_check).lower() == "disable":
                        self._add(Finding(
                            rule_id="FORTIOS-NET-007", name="Source IP check disabled on external interface",
                            category="Network Hardening", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"interface={iface_name}, role={role}, src-check=disable",
                            description=f"Interface '{iface_name}' has source IP check (RPF/anti-spoofing) disabled, allowing spoofed packets.",
                            recommendation="Enable src-check on all WAN and DMZ interfaces: set src-check enable.",
                            cwe="CWE-290",
                        ))

        # ---- Global system settings for network hardening ------------------
        glb = self._api_get("system/global")
        if isinstance(glb, list) and glb:
            glb = glb[0] if isinstance(glb[0], dict) else {}
        if isinstance(glb, dict):
            # TCP session table max
            ses_limit = glb.get("tcp-session-without-syn", "")
            if str(ses_limit).lower() == "enable":
                self._add(Finding(
                    rule_id="FORTIOS-NET-008", name="TCP sessions without SYN allowed",
                    category="Network Hardening", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content="tcp-session-without-syn=enable",
                    description="FortiGate accepts TCP sessions without SYN, which can bypass firewall stateful inspection.",
                    recommendation="Disable tcp-session-without-syn: config system global / set tcp-session-without-syn disable.",
                    cwe="CWE-284",
                ))

            # Block IPv6 traffic if not configured
            ipv6_allow = glb.get("gui-ipv6", "")
            if str(ipv6_allow).lower() == "enable":
                # IPv6 is enabled — check if there are IPv6 firewall policies
                ipv6_policies = self._api_get("firewall/policy6")
                if not isinstance(ipv6_policies, list) or len(ipv6_policies) == 0:
                    self._add(Finding(
                        rule_id="FORTIOS-NET-009", name="IPv6 enabled but no IPv6 firewall policies",
                        category="Network Hardening", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content="gui-ipv6=enable, firewall/policy6: empty",
                        description="IPv6 is enabled on the FortiGate but no IPv6 firewall policies exist, potentially allowing unfiltered IPv6 traffic.",
                        recommendation="Create IPv6 firewall policies or disable IPv6 if not required.",
                        cwe="CWE-284",
                    ))

            # LLDP reception on untrusted interfaces
            lldp = glb.get("lldp-reception", "")
            if str(lldp).lower() == "enable":
                self._add(Finding(
                    rule_id="FORTIOS-NET-010", name="LLDP reception enabled globally",
                    category="Network Hardening", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content="lldp-reception=enable",
                    description="LLDP reception is enabled globally. LLDP can leak network topology information to adjacent devices.",
                    recommendation="Disable LLDP on untrusted interfaces. Use per-interface LLDP settings.",
                    cwe="CWE-200",
                ))

        # ---- Routing authentication ----------------------------------------
        # BGP neighbours
        bgp = self._api_get("router/bgp")
        if isinstance(bgp, list) and bgp:
            bgp = bgp[0] if isinstance(bgp[0], dict) else {}
        if isinstance(bgp, dict):
            neighbours = bgp.get("neighbor", [])
            if isinstance(neighbours, list):
                for nb in neighbours:
                    nb_ip = nb.get("ip", "unknown")
                    nb_pwd = nb.get("password", "")
                    if not nb_pwd:
                        self._add(Finding(
                            rule_id="FORTIOS-NET-011", name="BGP neighbour without authentication",
                            category="Network Hardening", severity="HIGH",
                            file_path=_host, line_num=None,
                            line_content=f"bgp neighbour={nb_ip}, password=none",
                            description=f"BGP neighbour {nb_ip} has no MD5 authentication, allowing BGP hijacking.",
                            recommendation="Configure BGP MD5 authentication for all neighbours: set password <key>.",
                            cwe="CWE-306",
                        ))

        # OSPF authentication
        ospf = self._api_get("router/ospf")
        if isinstance(ospf, list) and ospf:
            ospf = ospf[0] if isinstance(ospf[0], dict) else {}
        if isinstance(ospf, dict):
            ospf_areas = ospf.get("area", [])
            if isinstance(ospf_areas, list) and ospf_areas:
                ospf_ifaces = ospf.get("ospf-interface", [])
                if isinstance(ospf_ifaces, list):
                    for oi in ospf_ifaces:
                        oi_name = oi.get("name", "unknown")
                        auth_type = oi.get("authentication", "none")
                        if str(auth_type).lower() in ("none", ""):
                            self._add(Finding(
                                rule_id="FORTIOS-NET-012", name="OSPF interface without authentication",
                                category="Network Hardening", severity="HIGH",
                                file_path=_host, line_num=None,
                                line_content=f"ospf-interface={oi_name}, authentication=none",
                                description=f"OSPF interface '{oi_name}' has no authentication, allowing rogue router injection.",
                                recommendation="Enable OSPF authentication: set authentication md5 or text.",
                                cwe="CWE-306",
                            ))

        # ---- SNMP checks ---------------------------------------------------
        snmp_community = self._api_get("system.snmp/community")
        if isinstance(snmp_community, list):
            for comm in snmp_community:
                comm_name = comm.get("name", "")
                comm_id = comm.get("id", "?")
                if comm_name.lower() in ("public", "private"):
                    self._add(Finding(
                        rule_id="FORTIOS-NET-013", name="SNMP default community string",
                        category="Network Hardening", severity="CRITICAL",
                        file_path=_host, line_num=None,
                        line_content=f"snmp community={comm_name} (ID {comm_id})",
                        description=f"SNMP community string '{comm_name}' is a well-known default. Attackers can read device configuration.",
                        recommendation="Change SNMP community strings to complex values or migrate to SNMPv3 with authentication.",
                        cwe="CWE-1188",
                    ))
                # Check for SNMP v1/v2 (no v3 auth/encryption)
                query_v1 = comm.get("query-v1-status", "")
                query_v2 = comm.get("query-v2c-status", "")
                if str(query_v1).lower() == "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-NET-014", name="SNMPv1 enabled",
                        category="Network Hardening", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"snmp community={comm_name}, query-v1-status=enable",
                        description=f"SNMPv1 is enabled for community '{comm_name}'. SNMPv1 transmits data in cleartext without authentication.",
                        recommendation="Disable SNMPv1 and migrate to SNMPv3 with authPriv.",
                        cwe="CWE-319",
                    ))

        # SNMPv3 user check
        snmp_user = self._api_get("system.snmp/user")
        if isinstance(snmp_user, list):
            for su in snmp_user:
                su_name = su.get("name", "unknown")
                sec_level = su.get("security-level", "")
                if str(sec_level).lower() in ("no-auth-no-priv", "noauth", ""):
                    self._add(Finding(
                        rule_id="FORTIOS-NET-015", name="SNMPv3 user without authentication",
                        category="Network Hardening", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"snmpv3 user={su_name}, security-level={sec_level}",
                        description=f"SNMPv3 user '{su_name}' has no authentication or encryption.",
                        recommendation="Set SNMPv3 user security level to auth-priv with SHA and AES.",
                        cwe="CWE-306",
                    ))

        # ---- NTP authentication --------------------------------------------
        ntp = self._api_get("system/ntp")
        if isinstance(ntp, list) and ntp:
            ntp = ntp[0] if isinstance(ntp[0], dict) else {}
        if isinstance(ntp, dict):
            ntp_auth = ntp.get("authentication", "")
            ntp_servers = ntp.get("ntpserver", [])
            if isinstance(ntp_servers, list) and ntp_servers:
                if str(ntp_auth).lower() != "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-NET-016", name="NTP authentication not enabled",
                        category="Network Hardening", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"ntp authentication={ntp_auth}",
                        description="NTP authentication is not enabled. Attackers can inject false time via NTP spoofing, breaking log correlation and certificates.",
                        recommendation="Enable NTP authentication: config system ntp / set authentication enable.",
                        cwe="CWE-345",
                    ))

        # ---- Management-plane source restriction (local-in-policy + GeoIP) ----
        # Only evaluated when the management plane is actually exposed (SSL-VPN
        # enabled OR HTTPS/SSH on a WAN interface); a fully-internal box is exempt.
        expo = self._mgmt_exposure()
        if expo["sslvpn_enabled"] or expo["mgmt_on_wan"]:
            lip = self._api_get("firewall/local-in-policy")
            enabled_lip = ([p for p in lip if isinstance(p, dict)
                            and str(p.get("status", "enable")).lower() != "disable"]
                           if isinstance(lip, list) else [])
            if not enabled_lip:
                where = ("management (" + ", ".join(f"{n}:{'/'.join(p)}" for n, p in expo["mgmt_wan"])
                         + ") reachable on WAN" if expo["mgmt_on_wan"] else "SSL-VPN enabled")
                self._add(Finding(
                    rule_id="FORTIOS-NET-019",
                    name="No local-in-policy restricting management-plane access",
                    category="Network Hardening",
                    severity="HIGH" if expo["mgmt_on_wan"] else "MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"firewall/local-in-policy: none; exposure: {where}",
                    description=("No firewall local-in-policy restricts which sources may reach the FortiGate's own management / "
                                 "VPN services (admin GUI/SSH, SSL-VPN, IKE). "
                                 + ("Management (HTTPS/SSH) is reachable on a WAN interface. " if expo["mgmt_on_wan"]
                                    else "SSL-VPN is enabled. ")
                                 + "A local-in-policy is the control Fortinet recommends to whitelist trusted management sources "
                                   "and blunt SSL-VPN CVE scanning and brute-force from the internet."),
                    recommendation=("Add local-in-policies that permit admin/VPN services only from trusted sources and deny the rest: "
                                    "config firewall local-in-policy / edit 1 / set intf <wan> / set srcaddr <MGMT-TRUSTED> / "
                                    "set dstaddr all / set service HTTPS SSH / set action accept / next / end (add a trailing deny)."),
                    cwe="CWE-284",
                ))
            else:
                # Management IS source-restricted via local-in-policy — advise GeoIP as
                # an additional layer if no geography object is referenced anywhere.
                # Default the address table to empty when absent (offline configs often
                # omit the firewall/address section): "no address objects" means "no
                # geography objects", which is exactly what NET-020 flags — so absence
                # must NOT skip the finding (would be a false negative).
                addrs = self._api_get("firewall/address")
                addr_list = addrs if isinstance(addrs, list) else []
                geo_names = {a.get("name") for a in addr_list if isinstance(a, dict)
                             and str(a.get("type", "")).lower() == "geography" and a.get("name")}
                grps = self._api_get("firewall/addrgrp")
                gmap = ({g.get("name"): g for g in grps if isinstance(g, dict) and g.get("name")}
                        if isinstance(grps, list) else {})

                def _grp_has_geo(nm, seen=None):
                    seen = seen or set()
                    g = gmap.get(nm)
                    if not g or nm in seen:
                        return False
                    seen.add(nm)
                    for m in (g.get("member") or []):
                        mn = m.get("name") if isinstance(m, dict) else None
                        if mn in geo_names or _grp_has_geo(mn, seen):
                            return True
                    return False

                geo_like = geo_names | {n for n in gmap if _grp_has_geo(n)}

                def _refs_geo(objs):
                    return any((o.get("name") if isinstance(o, dict) else None) in geo_like
                               for o in (objs or []))

                geo_ref = any(isinstance(p, dict) and _refs_geo(p.get("srcaddr")) for p in enabled_lip)
                if not geo_ref:
                    geo_ref = _refs_geo(expo["ssl_settings"].get("source-address"))
                if not geo_ref:
                    self._add(Finding(
                        rule_id="FORTIOS-NET-020",
                        name="No GeoIP source restriction on internet-facing management/VPN",
                        category="Network Hardening", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content="no geography address object referenced by any local-in-policy or SSL-VPN source-address",
                        description=("The exposed management / SSL-VPN plane is source-restricted, but no GeoIP (geography) "
                                     "address object further limits the source countries. Geo-blocking untrusted regions on the "
                                     "management/VPN plane sharply cuts brute-force and CVE-scan noise. Advisory — only relevant "
                                     "where your administrators/users are geographically bounded."),
                        recommendation=("Create a geography allow object and reference it from the management/VPN local-in-policy "
                                        "or the SSL-VPN source-address: config firewall address / edit Geo-Allow / "
                                        "set type geography / set country <CC> / end."),
                        cwe="CWE-284",
                    ))

    # ================================================================== #
    #  CHECK: ZTNA / SASE                                                  #
    # ================================================================== #

    def _check_ztna(self) -> None:
        _host = self._sys_info.get("hostname", self.host)

        # Check for ZTNA access proxy
        ztna = self._api_get("firewall/access-proxy")
        if not isinstance(ztna, list) or len(ztna) == 0:
            self._add(Finding(
                rule_id="FORTIOS-ZTNA-001", name="ZTNA not implemented",
                category="ZTNA / SASE", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="firewall/access-proxy: empty",
                description="Zero Trust Network Access (ZTNA) is not configured. ZTNA provides identity-aware, context-based access control.",
                recommendation="Implement ZTNA access proxies for application-level access control with device posture checking.",
                cwe="CWE-284",
            ))
        else:
            for proxy in ztna:
                pname = proxy.get("name", "unknown")
                # Check for empty API gateway
                api_gateway = proxy.get("api-gateway", [])
                if isinstance(api_gateway, list) and not api_gateway:
                    self._add(Finding(
                        rule_id="FORTIOS-ZTNA-002", name="ZTNA access proxy with no API gateway rules",
                        category="ZTNA / SASE", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"access-proxy={pname}, api-gateway=empty",
                        description=f"ZTNA access proxy '{pname}' has no API gateway rules configured.",
                        recommendation="Configure API gateway rules to define application access policies.",
                        cwe="CWE-284",
                    ))

                # Check client cert requirement
                client_cert = proxy.get("client-cert", "")
                if str(client_cert).lower() != "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-ZTNA-003", name="ZTNA access proxy without client certificate",
                        category="ZTNA / SASE", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"access-proxy={pname}, client-cert={client_cert}",
                        description=f"ZTNA access proxy '{pname}' does not require client certificates for device identity verification.",
                        recommendation="Enable client certificate requirement: set client-cert enable.",
                        cwe="CWE-287",
                    ))

        # Check for SD-WAN configuration
        sdwan = self._api_get("system/sdwan")
        if isinstance(sdwan, list) and sdwan:
            sdwan = sdwan[0] if isinstance(sdwan[0], dict) else {}
        if isinstance(sdwan, dict):
            sdwan_status = sdwan.get("status", "disable")
            if str(sdwan_status).lower() == "enable":
                # Check SD-WAN health checks
                health_checks = sdwan.get("health-check", [])
                if isinstance(health_checks, list) and not health_checks:
                    self._add(Finding(
                        rule_id="FORTIOS-ZTNA-004", name="SD-WAN enabled without health checks",
                        category="ZTNA / SASE", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content="sd-wan status=enable, health-check=empty",
                        description="SD-WAN is enabled but no health checks are configured. SD-WAN cannot detect link quality issues without health checks.",
                        recommendation="Configure SD-WAN health checks (ping, HTTP, DNS) for all WAN links.",
                        cwe="CWE-754",
                    ))

                # Check SD-WAN SLA targets
                sla_rules = sdwan.get("service", [])
                if isinstance(sla_rules, list) and not sla_rules:
                    self._add(Finding(
                        rule_id="FORTIOS-ZTNA-005", name="SD-WAN without service/SLA rules",
                        category="ZTNA / SASE", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content="sd-wan service=empty",
                        description="SD-WAN has no service/SLA rules configured. Traffic will use default routing without quality-based path selection.",
                        recommendation="Configure SD-WAN service rules with SLA targets for critical applications.",
                        cwe="CWE-693",
                    ))

    # ================================================================== #
    #  CHECK: FortiGuard & Updates                                         #
    # ================================================================== #

    def _check_fortiguard(self) -> None:
        _host = self._sys_info.get("hostname", self.host)

        # License status
        license_data = self._api_get("license/status", monitor=True)
        if isinstance(license_data, dict):
            for svc_name, svc_data in license_data.items():
                if not isinstance(svc_data, dict):
                    continue
                status = svc_data.get("status", "")
                if status in ("expired", "disabled"):
                    self._add(Finding(
                        rule_id="FORTIOS-UPDATE-001", name=f"FortiGuard {svc_name} service {status}",
                        category="FortiGuard & Updates", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"{svc_name}={status}",
                        description=f"FortiGuard service '{svc_name}' is {status}. Security signatures may be outdated.",
                        recommendation=f"Renew the FortiGuard {svc_name} license to ensure up-to-date threat protection.",
                        cwe="CWE-1104",
                    ))

                # Check licence expiry date if available
                expiry = svc_data.get("expires", svc_data.get("expiry_date", ""))
                if expiry and status not in ("expired", "disabled"):
                    try:
                        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                            try:
                                exp_dt = datetime.strptime(str(expiry), fmt)
                                break
                            except ValueError:
                                continue
                        else:
                            exp_dt = None
                        if exp_dt and exp_dt < datetime.now() + timedelta(days=30):
                            self._add(Finding(
                                rule_id="FORTIOS-UPDATE-003", name=f"FortiGuard {svc_name} licence expiring soon",
                                category="FortiGuard & Updates", severity="MEDIUM",
                                file_path=_host, line_num=None,
                                line_content=f"{svc_name} expires={expiry}",
                                description=f"FortiGuard '{svc_name}' licence expires on {expiry}. Renewal is needed to maintain protection.",
                                recommendation=f"Renew the {svc_name} licence before it expires.",
                                cwe="CWE-1104",
                            ))
                    except (ValueError, TypeError):
                        pass

                # Check last update timestamp for signature age
                last_update = svc_data.get("last_update", svc_data.get("last-updated", ""))
                if last_update and status not in ("expired", "disabled"):
                    try:
                        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                            try:
                                upd_dt = datetime.strptime(str(last_update), fmt)
                                break
                            except ValueError:
                                continue
                        else:
                            upd_dt = None
                        if upd_dt:
                            age_days = (datetime.now() - upd_dt).days
                            if age_days > 7 and svc_name.lower() in ("antivirus", "ips", "av", "virus"):
                                self._add(Finding(
                                    rule_id="FORTIOS-UPDATE-004", name=f"FortiGuard {svc_name} signatures outdated",
                                    category="FortiGuard & Updates", severity="HIGH",
                                    file_path=_host, line_num=None,
                                    line_content=f"{svc_name} last_update={last_update} ({age_days} days ago)",
                                    description=f"FortiGuard {svc_name} signatures are {age_days} days old. AV/IPS signatures should update daily.",
                                    recommendation="Check FortiGuard connectivity and automatic update schedule. Signatures should update at least daily.",
                                    cwe="CWE-1104",
                                ))
                            elif age_days > 30:
                                self._add(Finding(
                                    rule_id="FORTIOS-UPDATE-005", name=f"FortiGuard {svc_name} not updated in {age_days} days",
                                    category="FortiGuard & Updates", severity="MEDIUM",
                                    file_path=_host, line_num=None,
                                    line_content=f"{svc_name} last_update={last_update} ({age_days} days ago)",
                                    description=f"FortiGuard {svc_name} has not been updated in {age_days} days.",
                                    recommendation="Verify FortiGuard update schedule and connectivity.",
                                    cwe="CWE-1104",
                                ))
                    except (ValueError, TypeError):
                        pass

        # FortiGuard connection status
        fg_status = self._api_get("system/fortiguard-service-status", monitor=True)
        if isinstance(fg_status, dict):
            connected = fg_status.get("connected", fg_status.get("service_connection_status", ""))
            if str(connected).lower() not in ("connected", "true", "1", "enable"):
                self._add(Finding(
                    rule_id="FORTIOS-UPDATE-002", name="FortiGuard not connected",
                    category="FortiGuard & Updates", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"fortiguard={connected}",
                    description="FortiGuard Distribution Network is not connected. Security updates cannot be downloaded.",
                    recommendation="Verify FortiGuard connectivity. Check DNS, proxy, and firewall rules for FortiGuard servers.",
                    cwe="CWE-1104",
                ))

        # FortiGuard update schedule
        autoupdate = self._api_get("system/autoupdate/schedule")
        if isinstance(autoupdate, list) and autoupdate:
            autoupdate = autoupdate[0] if isinstance(autoupdate[0], dict) else {}
        if isinstance(autoupdate, dict):
            update_status = autoupdate.get("status", "")
            if str(update_status).lower() != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-UPDATE-006", name="Automatic updates disabled",
                    category="FortiGuard & Updates", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"autoupdate status={update_status}",
                    description="Automatic signature updates are disabled. The FortiGate will not receive the latest threat definitions.",
                    recommendation="Enable automatic updates: config system autoupdate schedule / set status enable.",
                    cwe="CWE-1104",
                ))

        # Firmware version check — EOL branches
        if self._fw_version:
            major_minor = self._fw_version[:2] if len(self._fw_version) >= 2 else ()
            eol_branches = {(6, 0), (6, 2)}
            if major_minor in eol_branches:
                ver_str = ".".join(str(x) for x in self._fw_version)
                self._add(Finding(
                    rule_id="FORTIOS-UPDATE-007", name="FortiOS running on end-of-life branch",
                    category="FortiGuard & Updates", severity="CRITICAL",
                    file_path=_host, line_num=None,
                    line_content=f"FortiOS {ver_str} (branch {major_minor[0]}.{major_minor[1]} is EOL)",
                    description=f"FortiOS {ver_str} is on an end-of-life branch that no longer receives security patches.",
                    recommendation="Upgrade to a supported FortiOS branch (7.0, 7.2, or 7.4).",
                    cwe="CWE-1104",
                ))

    # ------------------------------------------------------------------ #
    #  Wireless Security                                                   #
    # ------------------------------------------------------------------ #
    def _check_wireless(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        wtp_profiles = self._api_get("wireless-controller/wtp-profile")
        vaps = self._api_get("wireless-controller/vap")
        wids = self._api_get("wireless-controller/wids-profile")

        if not wtp_profiles and not vaps:
            self._vprint("  No wireless controller / WTP profiles found — skipping wireless checks.")
            return

        # WIRELESS-001 — WPA2/WPA3 enforcement
        for vap in (vaps or []):
            sec = str(vap.get("security", "")).lower()
            name = vap.get("name", "unknown")
            if sec and ("open" in sec or "wep" in sec or "wpa-personal" == sec):
                self._add(Finding(
                    rule_id="FORTIOS-WIRELESS-001",
                    name="Weak wireless security mode",
                    category="Wireless Security", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"VAP '{name}' security={sec}",
                    description=f"Wireless SSID '{name}' uses weak security mode '{sec}'. Open/WEP/basic-WPA are trivially broken.",
                    recommendation="Configure WPA2-Enterprise (802.1X) or WPA3-SAE for all SSIDs.",
                    cwe="CWE-326",
                ))

        # WIRELESS-002 — Guest SSID isolation
        for vap in (vaps or []):
            name = str(vap.get("name", "")).lower()
            intra = str(vap.get("intra-vap-privacy", "disable")).lower()
            if ("guest" in name or "visitor" in name) and intra != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-WIRELESS-002",
                    name="Guest SSID lacks client isolation",
                    category="Wireless Security", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"VAP '{vap.get('name', '')}' intra-vap-privacy=disable",
                    description=f"Guest SSID '{vap.get('name', '')}' does not isolate wireless clients from each other.",
                    recommendation="Enable intra-vap-privacy (client isolation) on guest SSIDs to prevent lateral movement.",
                    cwe="CWE-284",
                ))

        # WIRELESS-003 — SSID broadcast suppression for internal networks
        for vap in (vaps or []):
            broadcast = str(vap.get("broadcast-ssid", "enable")).lower()
            name = str(vap.get("name", "")).lower()
            if broadcast == "enable" and ("mgmt" in name or "admin" in name or "internal" in name or "corp" in name):
                self._add(Finding(
                    rule_id="FORTIOS-WIRELESS-003",
                    name="Internal SSID broadcast enabled",
                    category="Wireless Security", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"VAP '{vap.get('name', '')}' broadcast-ssid=enable",
                    description=f"Internal/management SSID '{vap.get('name', '')}' broadcasts its SSID. This aids discovery by attackers.",
                    recommendation="Disable SSID broadcast for management and internal wireless networks.",
                    cwe="CWE-200",
                ))

        # WIRELESS-004 — Rogue AP detection (WIDS)
        if not wids:
            self._add(Finding(
                rule_id="FORTIOS-WIRELESS-004",
                name="No WIDS profile configured",
                category="Wireless Security", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="No wireless-controller/wids-profile entries",
                description="No Wireless Intrusion Detection System (WIDS) profile is configured to detect rogue APs.",
                recommendation="Create and apply a WIDS profile with rogue AP detection, deauthentication flood detection, and ASLEAP attack detection.",
                cwe="CWE-778",
            ))
        else:
            for wp in wids:
                name = wp.get("name", "unknown")
                rogue = str(wp.get("ap-scan", "disable")).lower()
                if rogue != "enable":
                    self._add(Finding(
                        rule_id="FORTIOS-WIRELESS-004",
                        name="WIDS rogue AP scanning disabled",
                        category="Wireless Security", severity="MEDIUM",
                        file_path=_host, line_num=None,
                        line_content=f"WIDS profile '{name}' ap-scan={rogue}",
                        description=f"WIDS profile '{name}' does not have rogue AP scanning enabled.",
                        recommendation="Enable ap-scan in the WIDS profile to detect unauthorized access points.",
                        cwe="CWE-778",
                    ))

        # WIRELESS-005 — Maximum client limit per SSID
        for vap in (vaps or []):
            max_clients = vap.get("max-clients", 0)
            name = vap.get("name", "unknown")
            if isinstance(max_clients, int) and max_clients == 0:
                self._add(Finding(
                    rule_id="FORTIOS-WIRELESS-005",
                    name="No maximum client limit on SSID",
                    category="Wireless Security", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"VAP '{name}' max-clients=0 (unlimited)",
                    description=f"SSID '{name}' has no maximum client limit, allowing resource exhaustion via mass association.",
                    recommendation="Set a reasonable max-clients limit per SSID to prevent DoS via excessive client connections.",
                    cwe="CWE-770",
                ))

        # WIRELESS-006 — PMF (Protected Management Frames / 802.11w)
        for vap in (vaps or []):
            pmf = str(vap.get("pmf", "disable")).lower()
            name = vap.get("name", "unknown")
            if pmf == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-WIRELESS-006",
                    name="Protected Management Frames disabled",
                    category="Wireless Security", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"VAP '{name}' pmf=disable",
                    description=f"SSID '{name}' does not enforce 802.11w Protected Management Frames, leaving it vulnerable to deauthentication attacks.",
                    recommendation="Enable PMF (802.11w) — set to 'optional' for compatibility or 'required' for maximum protection.",
                    cwe="CWE-345",
                ))

        # WIRELESS-007 — DTLS data encryption for CAPWAP
        for wtp in (wtp_profiles or []):
            dtls = str(wtp.get("dtls-policy", "")).lower()
            name = wtp.get("name", "unknown")
            if dtls and "clear-text" in dtls:
                self._add(Finding(
                    rule_id="FORTIOS-WIRELESS-007",
                    name="CAPWAP tunnel using cleartext",
                    category="Wireless Security", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"WTP profile '{name}' dtls-policy={dtls}",
                    description=f"WTP profile '{name}' allows cleartext CAPWAP tunnels. Wireless traffic between AP and controller is unencrypted.",
                    recommendation="Set dtls-policy to 'dtls-enabled' to encrypt CAPWAP data tunnels between APs and the controller.",
                    cwe="CWE-319",
                ))

        # WIRELESS-008 — Fast roaming (802.11r) misconfiguration
        for vap in (vaps or []):
            ft = str(vap.get("fast-roaming", "disable")).lower()
            ft_over_ds = str(vap.get("ft-over-ds", "enable")).lower()
            name = vap.get("name", "unknown")
            if ft == "enable" and ft_over_ds == "enable":
                self._add(Finding(
                    rule_id="FORTIOS-WIRELESS-008",
                    name="802.11r FT-over-DS enabled",
                    category="Wireless Security", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"VAP '{name}' ft-over-ds=enable",
                    description=f"SSID '{name}' has 802.11r Fast Transition over DS enabled, which has known vulnerabilities (CVE-2017-13082).",
                    recommendation="Disable ft-over-ds and use FT-over-Air instead for fast roaming.",
                    cwe="CWE-327",
                ))

    # ------------------------------------------------------------------ #
    #  Backup & Disaster Recovery                                          #
    # ------------------------------------------------------------------ #
    def _check_backup(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        global_settings = self._api_get("system/global")
        ha_config = self._api_get("system/ha")
        auto_backup = self._api_get("system.autoupdate/schedule")
        fortimanager = self._api_get("system/central-management")

        # BACKUP-001 — No central management (FortiManager) for config backup
        fm_mode = str((fortimanager or {}).get("mode", "normal")).lower()
        fm_fmg = (fortimanager or {}).get("fmg", "")
        if fm_mode == "normal" or not fm_fmg:
            self._add(Finding(
                rule_id="FORTIOS-BACKUP-001",
                name="No FortiManager for centralised backup",
                category="Backup & DR", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"central-management mode={fm_mode}, fmg={fm_fmg or 'not set'}",
                description="No FortiManager is configured for central configuration management and backup.",
                recommendation="Register this FortiGate with FortiManager for automated config backups, change tracking, and disaster recovery.",
                cwe="CWE-693",
            ))

        # BACKUP-002 — Config revision tracking
        revision_limit = (global_settings or {}).get("revision-backup-on-logout", "disable")
        if str(revision_limit).lower() == "disable":
            self._add(Finding(
                rule_id="FORTIOS-BACKUP-002",
                name="Config revision on logout disabled",
                category="Backup & DR", severity="LOW",
                file_path=_host, line_num=None,
                line_content=f"revision-backup-on-logout=disable",
                description="Automatic configuration revision backup on admin logout is disabled. Config changes may be lost.",
                recommendation="Enable revision-backup-on-logout under system/global to maintain configuration history.",
                cwe="CWE-693",
            ))

        # BACKUP-003 — HA without session pickup (DR capability)
        ha_mode = str((ha_config or {}).get("mode", "standalone")).lower()
        session_pickup = str((ha_config or {}).get("session-pickup", "disable")).lower()
        if ha_mode != "standalone" and session_pickup != "enable":
            self._add(Finding(
                rule_id="FORTIOS-BACKUP-003",
                name="HA session pickup disabled",
                category="Backup & DR", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"HA mode={ha_mode}, session-pickup={session_pickup}",
                description="HA cluster does not have session pickup enabled. Active sessions will be dropped during failover.",
                recommendation="Enable session-pickup in HA configuration to maintain sessions during failover events.",
                cwe="CWE-693",
            ))

        # BACKUP-004 — Backup encryption
        revision_image = str((global_settings or {}).get("revision-image-auto-backup", "disable")).lower()
        admin_restrict = (global_settings or {}).get("admin-restrict-local", "disable")
        cfg_save = str((global_settings or {}).get("cfg-save", "automatic")).lower()
        if cfg_save == "automatic":
            self._add(Finding(
                rule_id="FORTIOS-BACKUP-004",
                name="Automatic config save without review",
                category="Backup & DR", severity="LOW",
                file_path=_host, line_num=None,
                line_content=f"cfg-save=automatic",
                description="Configuration changes are saved automatically without manual review, increasing risk of unintended changes persisting.",
                recommendation="Consider setting cfg-save to 'revert' with a timeout to allow rollback of unintended changes.",
                cwe="CWE-693",
            ))

        # BACKUP-005 — USB auto-install (potential recovery risk or attack vector)
        usb_auto = str((global_settings or {}).get("auto-install-config", "enable")).lower()
        if usb_auto == "enable":
            self._add(Finding(
                rule_id="FORTIOS-BACKUP-005",
                name="USB auto-install config enabled",
                category="Backup & DR", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="auto-install-config=enable",
                description="USB auto-install of configuration is enabled. A malicious USB device could overwrite the running configuration.",
                recommendation="Disable auto-install-config and auto-install-image under system/global to prevent USB-based config tampering.",
                cwe="CWE-306",
            ))

    # ------------------------------------------------------------------ #
    #  Authentication — LDAP / RADIUS / SAML                               #
    # ------------------------------------------------------------------ #
    def _check_authentication(self) -> None:
        _host = self._sys_info.get("hostname", self.host)
        ldap_servers = self._api_get("user/ldap")
        radius_servers = self._api_get("user/radius")
        saml_sp = self._api_get("user/saml")
        fsso = self._api_get("user/fsso")
        local_users = self._api_get("user/local")

        # AUTH-001 — LDAP without TLS/STARTTLS
        for srv in (ldap_servers or []):
            name = srv.get("name", "unknown")
            secure = str(srv.get("secure", "disable")).lower()
            port = srv.get("port", 389)
            if secure == "disable" and port != 636:
                self._add(Finding(
                    rule_id="FORTIOS-AUTH-001",
                    name="LDAP server without TLS encryption",
                    category="Authentication", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"LDAP '{name}' secure={secure}, port={port}",
                    description=f"LDAP server '{name}' communicates in cleartext. Credentials and directory data are exposed on the network.",
                    recommendation="Enable LDAPS (port 636) or STARTTLS by setting secure to 'ldaps' or 'starttls'.",
                    cwe="CWE-319",
                ))

        # AUTH-002 — RADIUS without secret or short secret
        for srv in (radius_servers or []):
            name = srv.get("name", "unknown")
            secret = srv.get("secret", "")
            if isinstance(secret, str) and len(secret) < 16:
                self._add(Finding(
                    rule_id="FORTIOS-AUTH-002",
                    name="RADIUS shared secret too short",
                    category="Authentication", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"RADIUS '{name}' secret length < 16 chars",
                    description=f"RADIUS server '{name}' shared secret is less than 16 characters, making it vulnerable to brute-force attacks.",
                    recommendation="Use a RADIUS shared secret of at least 22 characters with mixed character types.",
                    cwe="CWE-521",
                ))

        # AUTH-003 — RADIUS timeout too long
        for srv in (radius_servers or []):
            name = srv.get("name", "unknown")
            timeout = srv.get("timeout", 5)
            if isinstance(timeout, int) and timeout > 30:
                self._add(Finding(
                    rule_id="FORTIOS-AUTH-003",
                    name="RADIUS timeout excessively long",
                    category="Authentication", severity="LOW",
                    file_path=_host, line_num=None,
                    line_content=f"RADIUS '{name}' timeout={timeout}s",
                    description=f"RADIUS server '{name}' has timeout of {timeout}s. Excessive timeouts can cause authentication delays and DoS.",
                    recommendation="Set RADIUS timeout to 5-10 seconds and configure a secondary RADIUS server for redundancy.",
                    cwe="CWE-400",
                ))

        # AUTH-004 — No SAML/SSO configured
        if not saml_sp and not fsso:
            self._add(Finding(
                rule_id="FORTIOS-AUTH-004",
                name="No SSO/SAML integration configured",
                category="Authentication", severity="LOW",
                file_path=_host, line_num=None,
                line_content="No user/saml or user/fsso entries",
                description="Neither SAML IdP nor Fortinet SSO (FSSO) is configured. Users rely solely on local or LDAP/RADIUS authentication.",
                recommendation="Integrate SAML 2.0 SSO or FSSO for centralised identity management and conditional access.",
                cwe="CWE-287",
            ))

        # AUTH-005 — Local user accounts without MFA
        for user in (local_users or []):
            name = user.get("name", "unknown")
            two_factor = str(user.get("two-factor", "disable")).lower()
            status = str(user.get("status", "enable")).lower()
            if status == "enable" and two_factor == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-AUTH-005",
                    name="Local user without MFA",
                    category="Authentication", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"User '{name}' two-factor=disable",
                    description=f"Local user '{name}' does not have two-factor authentication enabled.",
                    recommendation="Enable two-factor authentication (FortiToken, email, or SMS) for all local user accounts.",
                    cwe="CWE-308",
                ))

        # AUTH-006 — LDAP without server identity check
        for srv in (ldap_servers or []):
            name = srv.get("name", "unknown")
            server_id_check = str(srv.get("server-identity-check", "disable")).lower()
            secure = str(srv.get("secure", "disable")).lower()
            if secure != "disable" and server_id_check != "enable":
                self._add(Finding(
                    rule_id="FORTIOS-AUTH-006",
                    name="LDAP TLS without server identity check",
                    category="Authentication", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"LDAP '{name}' server-identity-check={server_id_check}",
                    description=f"LDAP server '{name}' uses TLS but does not verify the server certificate identity, allowing MITM attacks.",
                    recommendation="Enable server-identity-check on the LDAP server configuration to validate the TLS certificate.",
                    cwe="CWE-295",
                ))

    # ================================================================== #
    #  CHECK: Advanced Hardening (NEW)                                     #
    # ================================================================== #

    def _check_advanced_hardening(self) -> None:
        """Additional hardening checks: FIPS, session mgmt, FortiToken, policy analysis, log retention."""
        _host = self._sys_info.get("hostname", self.host)
        glb = self._api_get("system/global")
        if isinstance(glb, list) and glb:
            glb = glb[0] if isinstance(glb[0], dict) else {}
        if not isinstance(glb, dict):
            glb = {}

        # ── FIPS mode ───────────────────────────────────────────────
        fips = glb.get("fips-cc", glb.get("fips", ""))
        if str(fips).lower() not in ("enable", "enabled"):
            self._add(Finding(
                rule_id="FORTIOS-SYS-016", name="FIPS 140-2 mode not enabled",
                category="System Settings", severity="MEDIUM",
                file_path=_host, line_num=None, line_content=f"fips-cc={fips}",
                description="FIPS 140-2 validated cryptography mode is not enabled. Environments requiring FIPS compliance (government, financial) must enable this.",
                recommendation="Enable FIPS mode: config system global / set fips-cc enable. NOTE: Requires reboot and restricts cipher suites.",
                cwe="CWE-327",
            ))

        # ── SCP admin access ────────────────────────────────────────
        admin_scp = glb.get("admin-scp", "")
        if str(admin_scp).lower() not in ("enable", "enabled"):
            self._add(Finding(
                rule_id="FORTIOS-SYS-014", name="SCP admin access disabled",
                category="System Settings", severity="LOW",
                file_path=_host, line_num=None, line_content=f"admin-scp={admin_scp}",
                description="SCP (Secure Copy Protocol) access for admin file transfer is disabled. SCP provides encrypted file transfer for config backup/restore.",
                recommendation="Enable SCP access: config system global / set admin-scp enable.",
                cwe="CWE-319",
            ))

        # ── TCP session timers ──────────────────────────────────────
        tcp_halfopen = glb.get("tcp-halfopen-timer", 10)
        if isinstance(tcp_halfopen, int) and tcp_halfopen > 60:
            self._add(Finding(
                rule_id="FORTIOS-SYS-013", name="TCP half-open session timer too long",
                category="System Settings", severity="MEDIUM",
                file_path=_host, line_num=None, line_content=f"tcp-halfopen-timer={tcp_halfopen}",
                description=f"TCP half-open timer is {tcp_halfopen}s (recommended <=30). Long timers make the firewall vulnerable to SYN flood attacks.",
                recommendation="Set tcp-halfopen-timer to 30 or less: config system global / set tcp-halfopen-timer 30.",
                cwe="CWE-400",
            ))

        tcp_halfclose = glb.get("tcp-halfclose-timer", 120)
        if isinstance(tcp_halfclose, int) and tcp_halfclose > 300:
            self._add(Finding(
                rule_id="FORTIOS-SYS-017", name="TCP half-close session timer too long",
                category="System Settings", severity="LOW",
                file_path=_host, line_num=None, line_content=f"tcp-halfclose-timer={tcp_halfclose}",
                description=f"TCP half-close timer is {tcp_halfclose}s (recommended <=120). Excessive timers waste session table resources.",
                recommendation="Set tcp-halfclose-timer to 120: config system global / set tcp-halfclose-timer 120.",
                cwe="CWE-400",
            ))

        # ── SSH grace time ──────────────────────────────────────────
        ssh_grace = glb.get("admin-ssh-grace-time", 120)
        if isinstance(ssh_grace, int) and ssh_grace > 120:
            self._add(Finding(
                rule_id="FORTIOS-SYS-015", name="SSH grace time exceeds 120 seconds",
                category="System Settings", severity="LOW",
                file_path=_host, line_num=None, line_content=f"admin-ssh-grace-time={ssh_grace}",
                description=f"SSH grace time is {ssh_grace}s. This allows unauthenticated SSH sessions to remain open, consuming resources.",
                recommendation="Set admin-ssh-grace-time to 60: config system global / set admin-ssh-grace-time 60.",
                cwe="CWE-400",
            ))

        # ── Weak admin SSH KEX / cipher / MAC algorithms (version-aware) ──
        # FortiOS 7.0.2 is the boundary: earlier trains use boolean knobs
        # (ssh-cbc-cipher / ssh-hmac-md5 / ssh-kex-sha1 / ssh-mac-weak, default
        # enable = weak allowed); 7.0.2+ uses algo lists (ssh-kex-algo / ssh-enc-algo
        # / ssh-mac-algo, strong by default). Both branches fire only on an EXPLICIT
        # weak value, never on an absent (default) field — so no false positives.
        def _ssh_toks(raw):
            if isinstance(raw, list):
                return [(t.get("name") if isinstance(t, dict) else str(t)).lower() for t in raw if t]
            return [t.lower() for t in str(raw).replace(",", " ").split() if t]
        kex_weak = [t for t in _ssh_toks(glb.get("ssh-kex-algo", "")) if t.endswith("-sha1")]
        enc_weak = [t for t in _ssh_toks(glb.get("ssh-enc-algo", ""))
                    if t.endswith("-cbc") or t.startswith("3des") or t.startswith("arcfour") or t == "des"]
        mac_weak = [t for t in _ssh_toks(glb.get("ssh-mac-algo", ""))
                    if t.startswith("hmac-md5") or t == "hmac-sha1" or t.startswith("hmac-sha1-")
                    or t.startswith("hmac-ripemd") or t.startswith("umac-64")]
        legacy_weak = []
        if self._ver_lt("7.0.2") and str(glb.get("strong-crypto", "")).lower() != "enable":
            legacy_weak = [k for k in ("ssh-cbc-cipher", "ssh-hmac-md5", "ssh-kex-sha1", "ssh-mac-weak")
                           if str(glb.get(k, "")).lower() == "enable"]
        if kex_weak or enc_weak or mac_weak or legacy_weak:
            detail = f"kex={kex_weak} enc={enc_weak} mac={mac_weak} legacy={legacy_weak}"
            self._add(Finding(
                rule_id="FORTIOS-SYS-019", name="Weak SSH algorithms allowed on the admin SSH service",
                category="System Settings", severity="HIGH",
                file_path=_host, line_num=None, line_content=detail,
                description=("The administrative SSH service permits weak key-exchange / cipher / MAC algorithms "
                             f"({detail}). SHA-1 KEX, CBC-mode ciphers, 3DES/arcfour and MD5/SHA-1 MACs are cryptographically "
                             "weak and expose admin SSH to downgrade and integrity attacks."),
                recommendation=("Restrict admin SSH to strong algorithms. FortiOS 7.0.2+: config system global / "
                                "set ssh-kex-algo diffie-hellman-group14-sha256 curve25519-sha256@libssh.org / "
                                "set ssh-enc-algo aes256-gcm@openssh.com aes256-ctr / set ssh-mac-algo hmac-sha2-256 hmac-sha2-512. "
                                "Pre-7.0.2: enable strong-crypto and disable ssh-cbc-cipher / ssh-hmac-md5 / ssh-kex-sha1 / ssh-mac-weak."),
                cwe="CWE-326",
            ))

        # ── DNS over TLS/HTTPS ──────────────────────────────────────
        dns = self._api_get("system/dns")
        if isinstance(dns, list) and dns:
            dns = dns[0] if isinstance(dns[0], dict) else {}
        if isinstance(dns, dict):
            dns_protocol = str(dns.get("protocol", "cleartext")).lower()
            if dns_protocol in ("cleartext", "udp", ""):
                self._add(Finding(
                    rule_id="FORTIOS-NET-017", name="DNS queries not encrypted",
                    category="Network Hardening", severity="MEDIUM",
                    file_path=_host, line_num=None, line_content=f"dns-protocol={dns_protocol}",
                    description="DNS queries are sent in cleartext, exposing internal hostname lookups to eavesdropping and manipulation.",
                    recommendation="Enable DNS over TLS (DoT) or DNS over HTTPS (DoH): config system dns / set protocol dot.",
                    cwe="CWE-319",
                ))

        # ── FortiToken / two-factor coverage ────────────────────────
        admins = self._api_get("system/admin")
        if isinstance(admins, list):
            total_admins = len(admins)
            mfa_admins = sum(1 for a in admins if isinstance(a, dict) and str(a.get("two-factor", "")).lower() not in ("", "disable", "disabled"))
            if total_admins > 0 and mfa_admins < total_admins:
                pct = int(mfa_admins / total_admins * 100)
                self._add(Finding(
                    rule_id="FORTIOS-ADMIN-023", name=f"MFA coverage: {pct}% of admin accounts",
                    category="Admin Access", severity="HIGH" if pct < 50 else "MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"mfa_enabled={mfa_admins}/{total_admins} ({pct}%)",
                    description=f"Only {mfa_admins} of {total_admins} admin accounts ({pct}%) have two-factor authentication enabled. All admin accounts should require MFA.",
                    recommendation="Enable FortiToken or email-based 2FA for all admin accounts: config system admin / edit <name> / set two-factor fortitoken.",
                    cwe="CWE-308",
                ))

            # Admin password age check
            for admin in admins:
                if not isinstance(admin, dict):
                    continue
                name = admin.get("name", "")
                pwd_change = admin.get("password-expire", "")
                accprofile = admin.get("accprofile", "")
                # Check for default admin account with super_admin profile
                if name == "admin" and accprofile == "super_admin":
                    self._add(Finding(
                        rule_id="FORTIOS-ADMIN-024", name="Default 'admin' account with super_admin profile",
                        category="Admin Access", severity="MEDIUM",
                        file_path=_host, line_num=None, line_content=f"admin=admin, accprofile=super_admin",
                        description="The default 'admin' account exists with super_admin privileges. Best practice is to create named admin accounts and disable the default.",
                        recommendation="Create named admin accounts with appropriate profiles. Disable or rename the default 'admin' account.",
                        cwe="CWE-1188",
                    ))

        # ── Policy hit count analysis ───────────────────────────────
        policies = self._api_get("firewall/policy")
        if isinstance(policies, list):
            enabled_count = 0
            no_log_count = 0
            no_profile_count = 0
            all_any_count = 0
            for pol in policies:
                if not isinstance(pol, dict):
                    continue
                if str(pol.get("status", "enable")).lower() == "disable":
                    continue
                enabled_count += 1
                # Policies without any security profile
                has_profile = False
                for pf in ("av-profile", "ips-sensor", "webfilter-profile", "application-list",
                            "dlp-sensor", "emailfilter-profile", "file-filter-profile",
                            "dnsfilter-profile", "ssl-ssh-profile"):
                    if pol.get(pf, "") and str(pol.get(pf, "")) != "":
                        has_profile = True
                        break
                if not has_profile:
                    no_profile_count += 1
                # Log disabled
                logtraffic = str(pol.get("logtraffic", "")).lower()
                if logtraffic in ("disable", ""):
                    no_log_count += 1

            if no_profile_count > 0:
                pct = int(no_profile_count / max(enabled_count, 1) * 100)
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-015", name=f"{no_profile_count} active policies without security profiles",
                    category="Firewall Policies", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"no_profile={no_profile_count}/{enabled_count} ({pct}%)",
                    description=f"{no_profile_count} of {enabled_count} active policies ({pct}%) have no AV, IPS, WebFilter, or other security profile attached. Traffic matching these rules bypasses all security inspection.",
                    recommendation="Attach security profiles (AV, IPS, Web Filter, Application Control) to all allow policies.",
                    cwe="CWE-693",
                ))

            if no_log_count > 0:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-016", name=f"{no_log_count} active policies with logging disabled",
                    category="Firewall Policies", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"no_log={no_log_count}/{enabled_count}",
                    description=f"{no_log_count} of {enabled_count} active policies have traffic logging disabled. This creates blind spots in security monitoring.",
                    recommendation="Enable logging on all policies: config firewall policy / edit <id> / set logtraffic all.",
                    cwe="CWE-778",
                ))

        # ── Log retention check ─────────────────────────────────────
        log_setting = self._api_get("log/setting")
        if isinstance(log_setting, list) and log_setting:
            log_setting = log_setting[0] if isinstance(log_setting[0], dict) else {}
        if isinstance(log_setting, dict):
            log_mode = str(log_setting.get("log-mode", "")).lower()
            if log_mode in ("udp", ""):
                self._add(Finding(
                    rule_id="FORTIOS-LOG-017", name="Log transport not encrypted",
                    category="Logging & Monitoring", severity="MEDIUM",
                    file_path=_host, line_num=None, line_content=f"log-mode={log_mode}",
                    description="Logs are transported via unencrypted UDP. Log data may contain sensitive information visible to network eavesdroppers.",
                    recommendation="Use encrypted log transport (TCP with TLS) to FortiAnalyzer or syslog: config log fortianalyzer setting / set enc-algorithm high.",
                    cwe="CWE-319",
                ))

        # ── Certificate chain depth ─────────────────────────────────
        certs = self._api_get("vpn.certificate/local")
        if isinstance(certs, list):
            for cert in certs:
                if not isinstance(cert, dict):
                    continue
                cert_name = cert.get("name", cert.get("certname", ""))
                source = str(cert.get("source", "")).lower()
                # Check for self-signed certs used in production
                if source in ("self", "self-signed"):
                    self._add(Finding(
                        rule_id="FORTIOS-CERT-011", name=f"Self-signed certificate in use: {cert_name}",
                        category="Certificates", severity="MEDIUM",
                        file_path=_host, line_num=None, line_content=f"cert={cert_name}, source={source}",
                        description=f"Certificate '{cert_name}' is self-signed. Self-signed certificates are not trusted by clients and cannot be revoked.",
                        recommendation="Replace with a CA-signed certificate from a trusted Certificate Authority.",
                        cwe="CWE-295",
                    ))

        # ── Interface anti-spoofing ─────────────────────────────────
        interfaces = self._api_get("system/interface")
        if isinstance(interfaces, list):
            for iface in interfaces:
                if not isinstance(iface, dict):
                    continue
                iface_name = iface.get("name", "")
                role = str(iface.get("role", "")).lower()
                spoof_chk = str(iface.get("src-check", "")).lower()
                if role in ("wan", "dmz") and spoof_chk in ("disable", "disabled"):
                    self._add(Finding(
                        rule_id="FORTIOS-NET-018", name=f"Anti-spoofing disabled on {role} interface: {iface_name}",
                        category="Network Hardening", severity="HIGH",
                        file_path=_host, line_num=None, line_content=f"interface={iface_name}, src-check={spoof_chk}",
                        description=f"Source IP address validation (anti-spoofing) is disabled on {role} interface '{iface_name}'. This allows spoofed packets to traverse the firewall.",
                        recommendation=f"Enable anti-spoofing: config system interface / edit {iface_name} / set src-check enable.",
                        cwe="CWE-290",
                    ))

        # ── Automation stitches audit ───────────────────────────────
        auto_triggers = self._api_get("system/automation-trigger")
        if isinstance(auto_triggers, list) and len(auto_triggers) == 0:
            self._add(Finding(
                rule_id="FORTIOS-LOG-018", name="No automation stitches configured",
                category="Logging & Monitoring", severity="LOW",
                file_path=_host, line_num=None, line_content="automation-trigger count=0",
                description="No automation stitches are configured. Automation stitches enable automatic response to security events (e.g., quarantine compromised hosts, alert on config changes).",
                recommendation="Configure automation stitches for critical events: config system automation-trigger / edit <name>.",
                cwe="CWE-778",
            ))

        # ── SD-WAN health check depth ───────────────────────────────
        sdwan = self._api_get("system/sdwan")
        if isinstance(sdwan, list) and sdwan:
            sdwan = sdwan[0] if isinstance(sdwan[0], dict) else {}
        if isinstance(sdwan, dict) and str(sdwan.get("status", "")).lower() == "enable":
            health_checks = sdwan.get("health-check", [])
            if isinstance(health_checks, list) and len(health_checks) == 0:
                self._add(Finding(
                    rule_id="FORTIOS-ZTNA-006", name="SD-WAN enabled without health checks",
                    category="ZTNA / SASE", severity="MEDIUM",
                    file_path=_host, line_num=None, line_content="sdwan=enable, health-check=0",
                    description="SD-WAN is enabled but no health check probes are configured. Without health checks, failover between WAN links is blind to link quality.",
                    recommendation="Configure SD-WAN health checks with SLA targets: config system sdwan / config health-check.",
                    cwe="CWE-693",
                ))

    # ================================================================== #
    #  CHECK: MITRE ATT&CK Resilience (NEW v4.0.0)                        #
    # ================================================================== #

    def _check_mitre_attack_resilience(self) -> None:
        """Test firewall resilience against MITRE ATT&CK Enterprise techniques.

        Maps FortiGate security controls to specific ATT&CK techniques and
        verifies the firewall is configured to detect/block each attack vector.
        """
        _host = self._sys_info.get("hostname", self.host)

        # Cache API data for cross-check analysis
        policies = self._api_get("firewall/policy") or []
        if not isinstance(policies, list):
            policies = []
        av_profiles = self._api_get("antivirus/profile") or []
        if not isinstance(av_profiles, list):
            av_profiles = []
        ips_sensors = self._api_get("ips/sensor") or []
        if not isinstance(ips_sensors, list):
            ips_sensors = []
        wf_profiles = self._api_get("webfilter/profile") or []
        if not isinstance(wf_profiles, list):
            wf_profiles = []
        app_lists = self._api_get("application/list") or []
        if not isinstance(app_lists, list):
            app_lists = []
        ssl_profiles = self._api_get("firewall/ssl-ssh-profile") or []
        if not isinstance(ssl_profiles, list):
            ssl_profiles = []
        dns_profiles = self._api_get("dnsfilter/profile") or []
        if not isinstance(dns_profiles, list):
            dns_profiles = []
        interfaces = self._api_get("system/interface") or []
        if not isinstance(interfaces, list):
            interfaces = []
        glb = self._api_get("system/global")
        if isinstance(glb, list) and glb:
            glb = glb[0] if isinstance(glb[0], dict) else {}
        if not isinstance(glb, dict):
            glb = {}

        # Helper: count policies with a given profile type attached
        def _policies_with_profile(profile_key: str) -> int:
            count = 0
            for p in policies:
                if isinstance(p, dict) and str(p.get("status", "")).lower() != "disable":
                    val = p.get(profile_key, "")
                    if val and str(val).strip():
                        count += 1
            return count

        enabled_policy_count = sum(
            1 for p in policies
            if isinstance(p, dict) and str(p.get("status", "")).lower() != "disable"
        )

        # ================================================================
        # TA0001 — INITIAL ACCESS
        # ================================================================

        # T1190 — Exploit Public-Facing Application
        # Control: IPS + SSL Inspection + Web Application Firewall
        ips_on_policies = _policies_with_profile("ips-sensor")
        if enabled_policy_count > 0 and ips_on_policies < enabled_policy_count * 0.5:
            self._add(Finding(
                rule_id="MITRE-T1190-001",
                name="T1190 Exploit Public-Facing Application — IPS coverage gap",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"ips-sensor attached to {ips_on_policies}/{enabled_policy_count} policies ({int(ips_on_policies/max(enabled_policy_count,1)*100)}%)",
                description="MITRE T1190: Less than 50% of active firewall policies have IPS sensors attached. Exploits targeting public-facing applications (web servers, VPN portals, mail gateways) will not be detected on unprotected policies.",
                recommendation="Attach IPS sensors to all policies allowing inbound traffic, especially those for DMZ/public-facing services.",
                cwe="CWE-693",
            ))

        # T1566 — Phishing
        # Control: AV (malware attachments) + Web Filter (phishing URLs) + DNS Filter
        av_on_policies = _policies_with_profile("av-profile")
        wf_on_policies = _policies_with_profile("webfilter-profile")
        if enabled_policy_count > 0 and (av_on_policies < enabled_policy_count * 0.5 or wf_on_policies < enabled_policy_count * 0.5):
            self._add(Finding(
                rule_id="MITRE-T1566-001",
                name="T1566 Phishing — AV/WebFilter coverage gap",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"av={av_on_policies}/{enabled_policy_count}, webfilter={wf_on_policies}/{enabled_policy_count}",
                description="MITRE T1566: Antivirus and/or Web Filter profiles are not attached to the majority of policies. Phishing emails with malicious attachments or links may pass through without inspection.",
                recommendation="Attach both AV and Web Filter profiles to all policies that allow user internet traffic.",
                cwe="CWE-693",
            ))

        # T1133 — External Remote Services
        # Control: VPN hardening (checked by SSL VPN / IPsec checks)
        sslvpn = self._api_get("vpn.ssl/settings")
        if isinstance(sslvpn, list) and sslvpn:
            sslvpn = sslvpn[0] if isinstance(sslvpn[0], dict) else {}
        if isinstance(sslvpn, dict):
            status = str(sslvpn.get("status", "")).lower()
            reqcert = str(sslvpn.get("reqclientcert", "")).lower()
            if status == "enable" and reqcert not in ("enable", "enabled"):
                self._add(Finding(
                    rule_id="MITRE-T1133-001",
                    name="T1133 External Remote Services — SSL VPN without client cert",
                    category="MITRE ATT&CK Resilience", severity="MEDIUM",
                    file_path=_host, line_num=None,
                    line_content=f"sslvpn=enable, reqclientcert={reqcert}",
                    description="MITRE T1133: SSL VPN is enabled without client certificate requirement. Password-only VPN authentication is vulnerable to credential stuffing, phishing, and brute force attacks.",
                    recommendation="Enable client certificate verification: config vpn ssl settings / set reqclientcert enable.",
                    cwe="CWE-308",
                ))

        # ================================================================
        # TA0002 — EXECUTION
        # ================================================================

        # T1059 — Command and Scripting Interpreter
        # Control: Application Control (block scripting engines, web shells)
        app_on_policies = _policies_with_profile("application-list")
        if enabled_policy_count > 0 and app_on_policies < enabled_policy_count * 0.3:
            self._add(Finding(
                rule_id="MITRE-T1059-001",
                name="T1059 Command & Scripting — Application Control coverage gap",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"application-list attached to {app_on_policies}/{enabled_policy_count} policies",
                description="MITRE T1059: Application Control profiles are not widely deployed. Without Application Control, web shells, scripting engines, and malicious application traffic cannot be identified and blocked.",
                recommendation="Create Application Control profiles that block high-risk categories and attach to all outbound/DMZ policies.",
                cwe="CWE-693",
            ))

        # T1203 — Exploitation for Client Execution
        # Control: SSL Deep Inspection (inspect HTTPS for exploits)
        ssl_on_policies = _policies_with_profile("ssl-ssh-profile")
        deep_inspect = False
        for sslp in ssl_profiles:
            if isinstance(sslp, dict):
                https_mode = str(sslp.get("https", {}).get("status", sslp.get("ssl-exempt", ""))).lower() if isinstance(sslp.get("https"), dict) else ""
                name = sslp.get("name", "")
                if name and "deep" in name.lower():
                    deep_inspect = True
                    break
        if not deep_inspect and enabled_policy_count > 0:
            self._add(Finding(
                rule_id="MITRE-T1203-001",
                name="T1203 Exploitation for Client Execution — no deep SSL inspection",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"ssl-ssh-profile count={len(ssl_profiles)}, deep_inspection=false",
                description="MITRE T1203: No SSL deep inspection profile detected. Without HTTPS inspection, exploit kits, drive-by downloads, and malicious payloads in encrypted traffic are invisible to IPS/AV scanning.",
                recommendation="Create an SSL deep inspection profile and apply to policies for user internet traffic. Install the FortiGate CA cert on endpoints.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0003 — PERSISTENCE
        # ================================================================

        # T1078 — Valid Accounts
        # Control: Admin MFA + Strong Password + Trusted Hosts
        admins = self._api_get("system/admin") or []
        if isinstance(admins, list):
            no_mfa = [a.get("name", "?") for a in admins if isinstance(a, dict) and str(a.get("two-factor", "")).lower() in ("", "disable", "disabled")]
            no_trusted = [a.get("name", "?") for a in admins if isinstance(a, dict) and str(a.get("trusthost1", "0.0.0.0")).startswith("0.0.0.0")]
            if no_mfa:
                self._add(Finding(
                    rule_id="MITRE-T1078-001",
                    name="T1078 Valid Accounts — admin accounts without MFA",
                    category="MITRE ATT&CK Resilience", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"no_mfa: {', '.join(no_mfa[:5])}{'...' if len(no_mfa)>5 else ''} ({len(no_mfa)} accounts)",
                    description=f"MITRE T1078: {len(no_mfa)} admin account(s) lack two-factor authentication. Compromised credentials can grant full firewall control without additional verification.",
                    recommendation="Enable FortiToken or email-based 2FA for all admin accounts.",
                    cwe="CWE-308",
                ))

        # ================================================================
        # TA0005 — DEFENSE EVASION
        # ================================================================

        # T1071 — Application Layer Protocol (C2 over HTTP/HTTPS/DNS)
        # Control: SSL Inspection + DNS Filter + Web Filter
        dns_on_policies = _policies_with_profile("dnsfilter-profile")
        if enabled_policy_count > 0 and dns_on_policies < enabled_policy_count * 0.3:
            self._add(Finding(
                rule_id="MITRE-T1071-001",
                name="T1071 Application Layer Protocol — DNS filter coverage gap",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"dnsfilter-profile attached to {dns_on_policies}/{enabled_policy_count} policies",
                description="MITRE T1071: DNS filtering is not widely deployed. Adversaries use DNS tunneling, DNS over HTTPS (DoH), and malicious domain resolution for C2 communication and data exfiltration.",
                recommendation="Attach DNS Filter profiles (with botnet/C2 domain blocking) to all outbound policies.",
                cwe="CWE-693",
            ))

        # T1027 — Obfuscated Files or Information
        # Control: AV with sandbox / FortiGuard analytics
        sandbox_enabled = False
        for prof in av_profiles:
            if isinstance(prof, dict):
                ft_analytics = str(prof.get("ftgd-analytics", prof.get("feature-set", ""))).lower()
                outbreak = str(prof.get("outbreak-prevention", "")).lower()
                if ft_analytics not in ("disable", "") or outbreak not in ("disable", "disabled", ""):
                    sandbox_enabled = True
                    break
        if not sandbox_enabled and len(av_profiles) > 0:
            self._add(Finding(
                rule_id="MITRE-T1027-001",
                name="T1027 Obfuscated Files — no sandbox/outbreak prevention",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"av_profiles={len(av_profiles)}, sandbox=disabled, outbreak=disabled",
                description="MITRE T1027: No AV profiles have sandbox analysis or outbreak prevention enabled. Obfuscated, packed, or zero-day malware will bypass signature-based detection.",
                recommendation="Enable FortiGuard analytics (cloud sandbox) and outbreak prevention on AV profiles.",
                cwe="CWE-693",
            ))

        # T1562 — Impair Defenses
        # Control: Verify logging is active and cannot be easily disabled
        log_faz = self._api_get("log.fortianalyzer/setting")
        if isinstance(log_faz, list) and log_faz:
            log_faz = log_faz[0] if isinstance(log_faz[0], dict) else {}
        log_syslog = self._api_get("log.syslogd/setting")
        if isinstance(log_syslog, list) and log_syslog:
            log_syslog = log_syslog[0] if isinstance(log_syslog[0], dict) else {}
        faz_status = str((log_faz or {}).get("status", "")).lower() if isinstance(log_faz, dict) else ""
        syslog_status = str((log_syslog or {}).get("status", "")).lower() if isinstance(log_syslog, dict) else ""
        if faz_status not in ("enable", "enabled") and syslog_status not in ("enable", "enabled"):
            self._add(Finding(
                rule_id="MITRE-T1562-001",
                name="T1562 Impair Defenses — no external log forwarding",
                category="MITRE ATT&CK Resilience", severity="CRITICAL",
                file_path=_host, line_num=None,
                line_content=f"fortianalyzer={faz_status}, syslog={syslog_status}",
                description="MITRE T1562: No external log forwarding (FortiAnalyzer or Syslog) is configured. An attacker who compromises the firewall can delete local logs, destroying evidence of the intrusion.",
                recommendation="Configure log forwarding to FortiAnalyzer or external SIEM immediately. This is critical for incident response.",
                cwe="CWE-778",
            ))

        # ================================================================
        # TA0006 — CREDENTIAL ACCESS
        # ================================================================

        # T1110 — Brute Force
        # Control: Account lockout + Rate limiting
        lockout_threshold = glb.get("admin-lockout-threshold", 0)
        lockout_duration = glb.get("admin-lockout-duration", 0)
        if not isinstance(lockout_threshold, int) or lockout_threshold == 0:
            self._add(Finding(
                rule_id="MITRE-T1110-001",
                name="T1110 Brute Force — no admin account lockout",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"admin-lockout-threshold={lockout_threshold}, duration={lockout_duration}",
                description="MITRE T1110: Admin account lockout is not configured. Adversaries can perform unlimited password guessing attempts against the management interface.",
                recommendation="Set lockout: config system global / set admin-lockout-threshold 3 / set admin-lockout-duration 300.",
                cwe="CWE-307",
            ))

        # T1557 — Adversary-in-the-Middle
        # Control: SSL inspection + HSTS + certificate validation
        for iface in interfaces:
            if isinstance(iface, dict):
                role = str(iface.get("role", "")).lower()
                access_list = str(iface.get("allowaccess", "")).lower().split()
                if role in ("wan", "dmz") and "http" in access_list:
                    self._add(Finding(
                        rule_id="MITRE-T1557-001",
                        name=f"T1557 Adversary-in-the-Middle — HTTP on {role} interface",
                        category="MITRE ATT&CK Resilience", severity="HIGH",
                        file_path=_host, line_num=None,
                        line_content=f"interface={iface.get('name','?')}, role={role}, allowaccess includes http",
                        description=f"MITRE T1557: HTTP (unencrypted) is allowed on {role} interface '{iface.get('name','?')}'. This enables MitM attacks, credential interception, and session hijacking.",
                        recommendation=f"Remove HTTP from allowaccess on {role} interfaces. Use HTTPS only with admin-https-redirect.",
                        cwe="CWE-319",
                    ))
                    break  # One finding per type

        # ================================================================
        # TA0008 — LATERAL MOVEMENT
        # ================================================================

        # T1021 — Remote Services (SMB, RDP, SSH lateral)
        # Control: Inter-zone policies + segmentation
        any_any_policies = 0
        for p in policies:
            if isinstance(p, dict) and str(p.get("status", "")).lower() != "disable":
                src = str(p.get("srcintf", [{}])[0].get("name", "") if isinstance(p.get("srcintf"), list) and p.get("srcintf") else p.get("srcintf", "")).lower()
                dst = str(p.get("dstintf", [{}])[0].get("name", "") if isinstance(p.get("dstintf"), list) and p.get("dstintf") else p.get("dstintf", "")).lower()
                srcaddr = str(p.get("srcaddr", [{}])[0].get("name", "") if isinstance(p.get("srcaddr"), list) and p.get("srcaddr") else "").lower()
                dstaddr = str(p.get("dstaddr", [{}])[0].get("name", "") if isinstance(p.get("dstaddr"), list) and p.get("dstaddr") else "").lower()
                service = str(p.get("service", [{}])[0].get("name", "") if isinstance(p.get("service"), list) and p.get("service") else "").lower()
                if srcaddr == "all" and dstaddr == "all" and service == "all":
                    any_any_policies += 1
        if any_any_policies > 0:
            self._add(Finding(
                rule_id="MITRE-T1021-001",
                name=f"T1021 Remote Services — {any_any_policies} any/any/any policies allow lateral movement",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"any-any-any policies={any_any_policies}",
                description=f"MITRE T1021: {any_any_policies} firewall policies allow any source to any destination on any service. This permits unrestricted lateral movement (SMB, RDP, SSH, WMI) between network zones.",
                recommendation="Replace any/any/any rules with specific source, destination, and service restrictions. Implement network segmentation.",
                cwe="CWE-284",
            ))

        # ================================================================
        # TA0010 — EXFILTRATION
        # ================================================================

        # T1048 — Exfiltration Over Alternative Protocol
        # Control: DLP + Application Control + egress filtering
        dlp_on_policies = _policies_with_profile("dlp-sensor")
        if enabled_policy_count > 0 and dlp_on_policies == 0:
            self._add(Finding(
                rule_id="MITRE-T1048-001",
                name="T1048 Exfiltration Over Alternative Protocol — no DLP",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"dlp-sensor attached to 0/{enabled_policy_count} policies",
                description="MITRE T1048: No DLP (Data Loss Prevention) sensors are attached to any firewall policies. Sensitive data can be exfiltrated via DNS, ICMP, HTTP, or custom protocols without detection.",
                recommendation="Create DLP sensors to detect sensitive data patterns (SSN, credit cards, PII) and attach to outbound policies.",
                cwe="CWE-200",
            ))

        # T1041 — Exfiltration Over C2 Channel
        # Control: SSL inspection on outbound + botnet detection
        botnet_domain = False
        for dp in dns_profiles:
            if isinstance(dp, dict):
                domain_filter = dp.get("domain-filter", dp.get("block-botnet", ""))
                ftgd_dns = dp.get("ftgd-dns", {})
                if isinstance(ftgd_dns, dict) and ftgd_dns.get("options", ""):
                    botnet_domain = True
                    break
                if str(domain_filter).lower() in ("enable", "enabled"):
                    botnet_domain = True
                    break
        if not botnet_domain and len(dns_profiles) > 0:
            self._add(Finding(
                rule_id="MITRE-T1041-001",
                name="T1041 Exfiltration Over C2 — DNS botnet detection disabled",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"dns_profiles={len(dns_profiles)}, botnet_domain_filter=disabled",
                description="MITRE T1041: DNS botnet/C2 domain filtering is not enabled. Malware can use known C2 domains for command and control and data exfiltration without being blocked.",
                recommendation="Enable botnet C2 domain blocking in DNS Filter profiles: config dnsfilter profile / set block-botnet enable.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0011 — COMMAND AND CONTROL
        # ================================================================

        # T1573 — Encrypted Channel (C2 over TLS)
        # Control: SSL deep inspection
        if not deep_inspect:
            self._add(Finding(
                rule_id="MITRE-T1573-001",
                name="T1573 Encrypted Channel — encrypted C2 traffic invisible",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content="ssl-deep-inspection=not-detected",
                description="MITRE T1573: Without SSL deep inspection, adversaries can establish encrypted C2 channels over HTTPS that are completely invisible to IPS, AV, and application control.",
                recommendation="Deploy SSL deep inspection for outbound user traffic. Whitelist trusted financial/medical sites via SSL exemption lists.",
                cwe="CWE-693",
            ))

        # T1090 — Proxy (use of proxy for C2)
        # Control: Application Control blocking proxy/tunnel apps
        proxy_blocked = False
        for app_list in app_lists:
            if isinstance(app_list, dict):
                entries = app_list.get("entries", [])
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            cat = str(entry.get("category", "")).lower()
                            action = str(entry.get("action", "")).lower()
                            if "proxy" in cat and action == "block":
                                proxy_blocked = True
                                break
        if not proxy_blocked and len(app_lists) > 0:
            self._add(Finding(
                rule_id="MITRE-T1090-001",
                name="T1090 Proxy — proxy/tunnel applications not blocked",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"app-control profiles={len(app_lists)}, proxy-blocked=false",
                description="MITRE T1090: Application Control is not blocking proxy/tunnel applications (Tor, VPN tunnels, SOCKS proxies). Adversaries use these to disguise C2 traffic.",
                recommendation="Block proxy/tunnel application categories in Application Control profiles.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0040 — IMPACT
        # ================================================================

        # T1498 — Network Denial of Service
        # Control: DoS protection policies
        dos = self._api_get("firewall/DoS-policy") or []
        if not isinstance(dos, list) or len(dos) == 0:
            self._add(Finding(
                rule_id="MITRE-T1498-001",
                name="T1498 Network Denial of Service — no DoS protection",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content="DoS-policy: empty",
                description="MITRE T1498: No DoS protection policies are configured. The firewall and behind-firewall services are vulnerable to SYN flood, UDP flood, ICMP flood, and application-layer DoS attacks.",
                recommendation="Create DoS policies for all WAN-facing interfaces with appropriate thresholds for SYN/UDP/ICMP flood anomalies.",
                cwe="CWE-400",
            ))

        # T1486 — Data Encrypted for Impact (Ransomware)
        # Control: AV + Botnet C2 blocking + backup integrity
        if not sandbox_enabled:
            self._add(Finding(
                rule_id="MITRE-T1486-001",
                name="T1486 Data Encrypted for Impact — no ransomware sandbox detection",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"sandbox=disabled, outbreak_prevention=disabled",
                description="MITRE T1486: Cloud sandbox and outbreak prevention are disabled. Ransomware samples that evade signature detection (zero-day variants) will not be caught by behavioral analysis.",
                recommendation="Enable FortiGuard sandbox analysis and outbreak prevention on all AV profiles protecting user traffic.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0043 — RECONNAISSANCE
        # ================================================================

        # T1595 — Active Scanning
        # Control: IPS on WAN + management interface restrictions
        wan_has_mgmt = False
        for iface in interfaces:
            if isinstance(iface, dict):
                role = str(iface.get("role", "")).lower()
                access_list = str(iface.get("allowaccess", "")).lower().split()
                if role == "wan" and {"https", "ssh", "snmp", "http"} & set(access_list):
                    wan_has_mgmt = True
                    break
        if wan_has_mgmt:
            self._add(Finding(
                rule_id="MITRE-T1595-001",
                name="T1595 Active Scanning — management exposed on WAN",
                category="MITRE ATT&CK Resilience", severity="CRITICAL",
                file_path=_host, line_num=None,
                line_content="WAN interface has management protocols (HTTPS/SSH/SNMP/HTTP)",
                description="MITRE T1595: Management interfaces are exposed on WAN, allowing adversaries to discover, fingerprint, and attack the firewall's management plane directly from the internet. This is the #1 attack vector for FortiGate compromises (CVE-2024-55591, CVE-2024-21762).",
                recommendation="Remove all management protocols from WAN interfaces immediately. Use a dedicated management VLAN or VPN-only admin access.",
                cwe="CWE-284",
            ))

        # ================================================================
        # TA0005 — DEFENSE EVASION (Additional)
        # ================================================================

        # T1572 — Protocol Tunneling (DNS tunnel, ICMP tunnel, HTTP tunnel)
        # Control: IPS + DNS Filter + Application Control
        has_dns_filter = len(dns_profiles) > 0
        if not has_dns_filter:
            self._add(Finding(
                rule_id="MITRE-T1572-001",
                name="T1572 Protocol Tunneling — no DNS filter to detect tunnels",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content="dnsfilter/profile: empty",
                description="MITRE T1572: No DNS filter profiles configured. DNS tunneling tools (iodine, dnscat2) encode C2 traffic in DNS queries. Without DNS filtering, these tunnel long subdomains and TXT record abuse go undetected.",
                recommendation="Create DNS Filter profiles with botnet/C2 blocking enabled and attach to all outbound policies.",
                cwe="CWE-693",
            ))

        # T1571 — Non-Standard Port (C2 on unexpected ports)
        # Control: Application Control (identifies app regardless of port)
        if len(app_lists) == 0:
            self._add(Finding(
                rule_id="MITRE-T1571-001",
                name="T1571 Non-Standard Port — no Application Control for port-agnostic detection",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content="application/list: empty",
                description="MITRE T1571: No Application Control profiles exist. Without AppCtrl, the FortiGate relies solely on port numbers to classify traffic. Adversaries can run HTTP C2 on port 53 or SSH tunnels on port 443 without detection.",
                recommendation="Create Application Control profiles and attach to policies. AppCtrl identifies applications by behavior, not port.",
                cwe="CWE-693",
            ))

        # T1189 — Drive-by Compromise
        # Control: WebFilter + AV + SSL Inspection + Sandbox
        if enabled_policy_count > 0 and wf_on_policies < enabled_policy_count * 0.5:
            self._add(Finding(
                rule_id="MITRE-T1189-001",
                name="T1189 Drive-by Compromise — Web Filter coverage insufficient",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content=f"webfilter-profile on {wf_on_policies}/{enabled_policy_count} policies ({int(wf_on_policies/max(enabled_policy_count,1)*100)}%)",
                description="MITRE T1189: Web Filter profiles cover less than 50% of policies. Users visiting compromised websites (watering holes) will not have malicious URLs blocked by FortiGuard URL categorization.",
                recommendation="Attach Web Filter profiles to all policies allowing user internet traffic. Enable FortiGuard URL rating.",
                cwe="CWE-693",
            ))

        # T1105 — Ingress Tool Transfer
        # Control: AV + Sandbox + Web Filter (block malware downloads)
        if len(av_profiles) == 0:
            self._add(Finding(
                rule_id="MITRE-T1105-001",
                name="T1105 Ingress Tool Transfer — no AV to block attack tool downloads",
                category="MITRE ATT&CK Resilience", severity="CRITICAL",
                file_path=_host, line_num=None,
                line_content="antivirus/profile: empty",
                description="MITRE T1105: No antivirus profiles configured. Post-exploitation tools (Mimikatz, Cobalt Strike, PsExec) downloaded by attackers will not be detected or blocked.",
                recommendation="Create AV profiles with blocking enabled for all protocols (HTTP, FTP, SMTP, IMAP) and attach to all policies.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0007 — DISCOVERY
        # ================================================================

        # T1046 — Network Service Discovery (internal scanning)
        # Control: Inter-zone IPS + Firewall Policy segmentation
        has_inter_zone_ips = False
        for p in policies:
            if isinstance(p, dict) and str(p.get("status", "")).lower() != "disable":
                src = p.get("srcintf", [])
                dst = p.get("dstintf", [])
                src_name = src[0].get("name", "") if isinstance(src, list) and src else str(src)
                dst_name = dst[0].get("name", "") if isinstance(dst, list) and dst else str(dst)
                if src_name != dst_name and p.get("ips-sensor", ""):
                    has_inter_zone_ips = True
                    break
        if not has_inter_zone_ips and enabled_policy_count > 2:
            self._add(Finding(
                rule_id="MITRE-T1046-001",
                name="T1046 Network Service Discovery — no inter-zone IPS",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="No IPS sensor on inter-zone (east-west) policies",
                description="MITRE T1046: No IPS sensors are applied to inter-zone policies. Internal network scanning (Nmap, masscan) by a compromised host traversing the firewall between zones will not trigger IPS detection signatures.",
                recommendation="Apply IPS sensors to inter-zone (east-west) policies, not just inbound/outbound. This detects lateral movement scanning.",
                cwe="CWE-693",
            ))

        # T1210 — Exploitation of Remote Services (EternalBlue, PrintNightmare)
        # Control: Inter-zone IPS for exploit signatures
        if not has_inter_zone_ips and enabled_policy_count > 2:
            self._add(Finding(
                rule_id="MITRE-T1210-001",
                name="T1210 Exploitation of Remote Services — east-west exploits undetected",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content="No IPS on inter-zone policies for exploit detection",
                description="MITRE T1210: Without IPS on inter-zone policies, lateral exploitation (EternalBlue/MS17-010, PrintNightmare, Log4Shell targeting internal services) will not be detected as traffic passes between network zones.",
                recommendation="Enable IPS with exploit signatures on all inter-zone policies to detect lateral exploitation attempts.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0011 — C2 (Additional)
        # ================================================================

        # T1219 — Remote Access Software (TeamViewer, AnyDesk as C2)
        # Control: Application Control
        rat_blocked = False
        for app_list in app_lists:
            if isinstance(app_list, dict):
                entries = app_list.get("entries", [])
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            cat = str(entry.get("category", "")).lower()
                            action = str(entry.get("action", "")).lower()
                            if ("remote" in cat or "control" in cat) and action == "block":
                                rat_blocked = True
                                break
        if not rat_blocked and len(app_lists) > 0:
            self._add(Finding(
                rule_id="MITRE-T1219-001",
                name="T1219 Remote Access Software — RATs not blocked by AppCtrl",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"app-control profiles={len(app_lists)}, remote-access-blocked=false",
                description="MITRE T1219: Application Control is not blocking remote access tool categories (TeamViewer, AnyDesk, ScreenConnect, RustDesk). Adversaries deploy these legitimate tools as C2 channels to evade detection.",
                recommendation="Block unauthorized remote access applications in AppCtrl profiles. Whitelist only sanctioned tools.",
                cwe="CWE-693",
            ))

        # T1568 — Dynamic Resolution / DGA (Domain Generation Algorithms)
        # Control: DNS Filter with FortiGuard reputation
        if has_dns_filter:
            for dp in dns_profiles:
                if isinstance(dp, dict):
                    ftgd = dp.get("ftgd-dns", {})
                    if isinstance(ftgd, dict):
                        filters = ftgd.get("filters", [])
                        if not isinstance(filters, list) or len(filters) == 0:
                            self._add(Finding(
                                rule_id="MITRE-T1568-001",
                                name="T1568 Dynamic Resolution / DGA — DNS filter lacks category blocking",
                                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                                file_path=_host, line_num=None,
                                line_content=f"dnsfilter '{dp.get('name','?')}' has no FTGD category filters",
                                description="MITRE T1568: DNS filter profile exists but has no FortiGuard DNS category filters configured. DGA-generated domains and newly registered malicious domains will not be caught by reputation scoring.",
                                recommendation="Configure FortiGuard DNS category filters to block malicious, phishing, and newly-registered domain categories.",
                                cwe="CWE-693",
                            ))
                            break

        # T1102 — Web Service (C2 via Slack, Discord, GitHub, Pastebin)
        # Control: Application Control + SSL Inspection
        if not deep_inspect and len(app_lists) == 0:
            self._add(Finding(
                rule_id="MITRE-T1102-001",
                name="T1102 Web Service C2 — no visibility into cloud service abuse",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="No AppCtrl + No SSL deep inspection",
                description="MITRE T1102: Without Application Control and SSL deep inspection, adversaries can use legitimate cloud services (Slack, Discord, Telegram, GitHub, Pastebin) as C2 channels. These services use HTTPS, making traffic invisible without inspection.",
                recommendation="Deploy Application Control to identify cloud service usage. Enable SSL deep inspection for content visibility.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0010 — EXFILTRATION (Additional)
        # ================================================================

        # T1567 — Exfiltration to Cloud Storage
        # Control: DLP + Application Control + SSL Inspection
        if dlp_on_policies == 0 and len(app_lists) == 0:
            self._add(Finding(
                rule_id="MITRE-T1567-001",
                name="T1567 Exfiltration to Cloud Storage — no DLP or AppCtrl",
                category="MITRE ATT&CK Resilience", severity="HIGH",
                file_path=_host, line_num=None,
                line_content="dlp=0, app-control=0",
                description="MITRE T1567: Neither DLP nor Application Control is deployed. Sensitive data can be uploaded to Google Drive, Dropbox, OneDrive, or other cloud storage services without detection or policy enforcement.",
                recommendation="Deploy DLP sensors to detect sensitive data patterns. Use Application Control to restrict unauthorized cloud storage services.",
                cwe="CWE-200",
            ))

        # ================================================================
        # TA0040 — IMPACT (Additional)
        # ================================================================

        # T1499 — Endpoint Denial of Service (application-layer DoS)
        # Control: IPS rate-limiting + DoS policy
        if len(ips_sensors) == 0:
            self._add(Finding(
                rule_id="MITRE-T1499-001",
                name="T1499 Endpoint DoS — no IPS for application-layer attack detection",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="ips/sensor: empty",
                description="MITRE T1499: No IPS sensors configured. Application-layer DoS attacks (HTTP Slowloris, RUDY, ReDoS) targeting web servers behind the FortiGate will not be detected or rate-limited by IPS.",
                recommendation="Create IPS sensors with anomaly detection and rate-based signatures for application-layer DoS.",
                cwe="CWE-400",
            ))

        # T1496 — Resource Hijacking (cryptomining)
        # Control: Application Control + Botnet C2 detection
        if len(app_lists) == 0:
            self._add(Finding(
                rule_id="MITRE-T1496-001",
                name="T1496 Resource Hijacking — no AppCtrl to block cryptomining",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content="application/list: empty",
                description="MITRE T1496: Without Application Control, cryptomining traffic to mining pools (Stratum protocol) cannot be identified and blocked. Compromised internal hosts may be mining cryptocurrency undetected.",
                recommendation="Create Application Control profiles that block cryptocurrency mining application signatures.",
                cwe="CWE-693",
            ))

        # ================================================================
        # TA0003 PERSISTENCE / TA0009 COLLECTION / TA0006 CREDENTIAL ACCESS
        # ================================================================

        def _pnames(v):
            out = set()
            for x in (v if isinstance(v, list) else [v]):
                if isinstance(x, dict) and x.get("name"):
                    out.add(x["name"])
                elif isinstance(x, str) and x:
                    out.update(x.split())
            return out

        # T1505.003 — Server Software Component: Web Shell.
        # Inbound (WAN -> internal/DMZ) policies must carry BOTH IPS and AV: web
        # shells are uploaded through a public app, then served back to the attacker.
        wan_ifaces = {i.get("name") for i in interfaces
                      if isinstance(i, dict) and str(i.get("role", "")).lower() == "wan" and i.get("name")}
        prot_ifaces = {i.get("name") for i in interfaces
                       if isinstance(i, dict) and str(i.get("role", "")).lower() in ("lan", "dmz") and i.get("name")}
        if wan_ifaces and prot_ifaces:
            inbound = [p for p in policies
                       if isinstance(p, dict) and str(p.get("status", "enable")).lower() != "disable"
                       and (_pnames(p.get("srcintf")) & wan_ifaces)
                       and (_pnames(p.get("dstintf")) & prot_ifaces)]
            unprotected = [p for p in inbound
                           if not (str(p.get("ips-sensor", "")).strip() and str(p.get("av-profile", "")).strip())]
            if inbound and unprotected:
                self._add(Finding(
                    rule_id="MITRE-T1505-001",
                    name="T1505.003 Web Shell — inbound policy without IPS+AV",
                    category="MITRE ATT&CK Resilience", severity="HIGH",
                    file_path=_host, line_num=None,
                    line_content=f"{len(unprotected)}/{len(inbound)} WAN->internal/DMZ policy(ies) lack IPS+AV",
                    description="MITRE T1505.003: Inbound policies from a WAN interface to an internal/DMZ zone that do not carry BOTH "
                                "an IPS sensor and an antivirus profile cannot detect a web-shell upload or the malicious payload served "
                                "back. Web shells are a primary persistence mechanism after exploiting a public-facing application.",
                    recommendation="Attach both an IPS sensor and an AV profile (with web-shell signatures) to every inbound WAN->server policy.",
                    cwe="CWE-693",
                ))

        # T1602 — Data from Configuration Repository (SNMP config/state theft).
        snmp_comms = self._api_get("system.snmp/community") or []
        if not isinstance(snmp_comms, list):
            snmp_comms = []
        weak_snmp = []
        for c in snmp_comms:
            if not isinstance(c, dict):
                continue
            nm = str(c.get("name", ""))
            v1 = str(c.get("query-v1-status", "")).lower()
            v2 = str(c.get("query-v2c-status", "")).lower()
            if nm.lower() in ("public", "private"):
                weak_snmp.append(f"default community '{nm}'")
            elif "enable" in (v1, v2):
                weak_snmp.append(f"v1/v2c community '{nm}'")
        if weak_snmp:
            sev = "HIGH" if any("default" in w for w in weak_snmp) else "MEDIUM"
            self._add(Finding(
                rule_id="MITRE-T1602-001",
                name="T1602 Data from Config Repository — SNMP v1/v2c or default community",
                category="MITRE ATT&CK Resilience", severity=sev,
                file_path=_host, line_num=None,
                line_content="; ".join(weak_snmp[:5]),
                description="MITRE T1602: SNMP v1/v2c uses cleartext, guessable community strings, and the default 'public'/'private' "
                            "communities let a remote attacker pull device configuration and state to map the network. Prefer "
                            "authenticated, encrypted SNMPv3.",
                recommendation="Remove default communities, disable SNMP v1/v2c, and use SNMPv3 with authPriv (SHA + AES).",
                cwe="CWE-319",
            ))

        # T1552.001 — Unsecured Credentials in Files (config-backup secrets).
        pde = str(glb.get("private-data-encryption", "")).lower()
        if pde and pde != "enable":
            self._add(Finding(
                rule_id="MITRE-T1552-001",
                name="T1552.001 Unsecured Credentials — config secrets use the shared factory key",
                category="MITRE ATT&CK Resilience", severity="MEDIUM",
                file_path=_host, line_num=None,
                line_content=f"private-data-encryption={pde}",
                description="MITRE T1552.001: With private-data-encryption disabled, secrets in the configuration backup (LDAP/RADIUS "
                            "binds, VPN pre-shared keys, private keys) are ciphered with a hard-coded factory key (CVE-2019-6693) and can "
                            "be decrypted offline by anyone who obtains a backup file.",
                recommendation="config system global / set private-data-encryption enable, then set a device-specific passphrase so "
                               "backups are keyed per device.",
                cwe="CWE-312", cve="CVE-2019-6693",
            ))

        # ================================================================
        # RESILIENCE SUMMARY
        # ================================================================
        mitre_findings = [f for f in self.findings if f.rule_id.startswith("MITRE-")]
        total_techniques = 34  # distinct techniques tested (across 11 tactics)
        gaps = len(mitre_findings)
        if not mitre_findings:
            self._add(Finding(
                rule_id="MITRE-SUMMARY-PASS",
                name="MITRE ATT&CK Resilience — all tested controls passed",
                category="MITRE ATT&CK Resilience", severity="INFO",
                file_path=_host, line_num=None,
                line_content=f"All {total_techniques} MITRE ATT&CK resilience checks passed",
                description=f"All {total_techniques} tested MITRE ATT&CK technique mitigations are properly configured. Tactics tested: Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Lateral Movement, Exfiltration, C2, Impact, Reconnaissance.",
                recommendation="Continue regular security posture assessments and keep FortiOS firmware up to date.",
            ))
        else:
            score = max(0, int((1 - gaps / total_techniques) * 100))
            self._add(Finding(
                rule_id="MITRE-SUMMARY-SCORE",
                name=f"MITRE ATT&CK Resilience Score: {score}%",
                category="MITRE ATT&CK Resilience", severity="INFO",
                file_path=_host, line_num=None,
                line_content=f"score={score}%, gaps={gaps}/{total_techniques}",
                description=f"MITRE ATT&CK resilience score: {score}% ({total_techniques - gaps}/{total_techniques} controls properly configured, {gaps} gaps identified). Higher score = better defense against real-world attack techniques.",
                recommendation=f"Address the {gaps} MITRE ATT&CK finding(s) above to improve resilience. Prioritize CRITICAL and HIGH findings first.",
            ))

    # ================================================================== #
    #  REMEDIATION EXPORT                                                  #
    # ================================================================== #

    def save_remediation(self, output_path: str) -> None:
        """Export a detailed FortiOS remediation runbook — for every finding: risk,
        numbered steps, GUI path, CLI block, verification, rollback, service impact
        and references (from the remediation knowledge base, falling back to the
        finding's own recommendation / CLI)."""
        import textwrap

        def wrap(text: str, indent: str = "      ", width: int = 96) -> list[str]:
            out: list[str] = []
            for para in str(text).split("\n"):
                lines = textwrap.wrap(para, width=width - len(indent))
                if lines:
                    out.extend(indent + ln for ln in lines)
                else:
                    out.append("")
            return out

        kb = self._report_kb()
        si = getattr(self, "_sys_info", {}) or {}
        L: list[str] = [
            "=" * 96,
            " Fortinet FortiGate — Remediation Runbook",
            "=" * 96,
            f" Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f" Target    : {si.get('hostname', self.host)}  ({getattr(self, 'host', '')})",
            f" Model     : {si.get('model_name', si.get('model', 'N/A'))}",
            f" FortiOS   : {si.get('version', 'N/A')}",
            f" Findings  : {len(self.findings)}",
            "",
            " WARNING: Review every command before applying to production. Back up the",
            "          configuration first (execute backup config). Some changes require a",
            "          reboot or may disrupt admin / SSL-VPN / IPsec / HA sessions — see the",
            "          'SERVICE IMPACT' note on each item.",
            "=" * 96,
            "",
        ]
        ordered = sorted(self.findings, key=lambda x: (self.SEVERITY_ORDER.get(x.severity, 4), x.rule_id))
        for idx, f in enumerate(ordered, 1):
            d = kb.detail_for(f) if kb else {}
            L.append(f"[{idx}] [{f.severity}] {f.rule_id} — {f.name}")
            L.append(f"    Category  : {f.category}     Target: {f.file_path}")
            if f.line_content:
                L.append(f"    Evidence  : {f.line_content}")
            ref = " | ".join(x for x in (f.cwe, f.cve) if x)
            if ref:
                L.append(f"    Reference : {ref}")
            if f.compliance_str:
                L.append(f"    Compliance: {f.compliance_str}")
            L.append("")
            if d.get("risk"):
                L.append("    RISK"); L.extend(wrap(d["risk"])); L.append("")
            if d.get("steps"):
                L.append("    REMEDIATION STEPS")
                for n, s in enumerate(d["steps"], 1):
                    L.extend(wrap(f"{n}. {s}"))
                L.append("")
            if d.get("gui"):
                L.append("    GUI PATH"); L.extend(wrap(d["gui"])); L.append("")
            if d.get("cli"):
                L.append("    CLI")
                L.extend("      " + cl for cl in str(d["cli"]).split("\n"))
                L.append("")
            if d.get("verify"):
                L.append("    VERIFY"); L.extend(wrap(d["verify"])); L.append("")
            if d.get("rollback"):
                L.append("    ROLLBACK"); L.extend(wrap(d["rollback"])); L.append("")
            if d.get("impact"):
                L.append("    SERVICE IMPACT"); L.extend(wrap(d["impact"])); L.append("")
            if d.get("references"):
                L.append("    REFERENCES")
                L.extend(f"      - {r}" for r in d["references"])
                L.append("")
            L.append("-" * 96)
            L.append("")
        L.append(f"# Runbook covers all {len(self.findings)} finding(s).")
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(L))
        print(f"[+] Remediation runbook saved to: {output_path} ({len(self.findings)} findings)")

    def save_compliance_csv(self, output_path: str) -> None:
        """Export compliance mapping as CSV for audit evidence."""
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Rule ID", "Severity", "Name", "Category", "CIS", "PCI-DSS", "NIST 800-53", "SOC2", "HIPAA", "Description", "Recommendation"])
            for f in sorted(self.findings, key=lambda x: x.rule_id):
                comp = f.compliance
                writer.writerow([
                    f.rule_id, f.severity, f.name, f.category,
                    "; ".join(comp.get("CIS", [])),
                    "; ".join(comp.get("PCI-DSS", [])),
                    "; ".join(comp.get("NIST", [])),
                    "; ".join(comp.get("SOC2", [])),
                    "; ".join(comp.get("HIPAA", [])),
                    f.description, f.recommendation,
                ])
        print(f"[+] Compliance CSV saved to: {output_path}")


# ========================================================================== #
#  MULTI-DEVICE SCANNING                                                      #
# ========================================================================== #

class MultiDeviceScanner:
    """Scan multiple FortiGate devices with unified reporting."""

    def __init__(
        self,
        targets: list[dict[str, str]],
        verify_ssl: bool = False,
        timeout: int = 30,
        verbose: bool = False,
    ):
        """
        Args:
            targets: List of dicts with 'host' and 'token' keys.
                     Optional: 'name' for display label.
            verify_ssl: Verify SSL certificates.
            timeout: API request timeout.
            verbose: Verbose output.
        """
        self.targets = targets
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.verbose = verbose
        self.results: dict[str, FortinetScanner] = {}

    def scan_all(self) -> None:
        """Scan all targets sequentially."""
        total = len(self.targets)
        print(f"[*] Multi-device scan: {total} target(s)")
        print("=" * 60)

        for idx, target in enumerate(self.targets, 1):
            host = target.get("host", "")
            token = target.get("token", "")
            label = target.get("name", host)

            if not host or not token:
                print(f"[!] Skipping target {idx}: missing host or token")
                continue

            print(f"\n[{idx}/{total}] Scanning: {label}")
            print("-" * 40)

            try:
                scanner = FortinetScanner(
                    host=host,
                    token=token,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                    verbose=self.verbose,
                )
                scanner.scan()
                self.results[label] = scanner
            except Exception as exc:
                print(f"[!] Failed to scan {label}: {exc}")

        print(f"\n{'=' * 60}")
        print(f"[*] Multi-device scan complete. {len(self.results)}/{total} successful.")

    def print_summary(self) -> None:
        """Print unified summary across all devices."""
        if not self.results:
            print("[!] No scan results available.")
            return

        print(f"\n{'=' * 72}")
        print(f"  Multi-Device Security Summary")
        print(f"  Devices scanned: {len(self.results)}")
        print(f"{'=' * 72}\n")

        # Per-device summary
        grand_total = 0
        grand_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for label, scanner in sorted(self.results.items()):
            counts = scanner.summary()
            total = len(scanner.findings)
            grand_total += total
            for sev, cnt in counts.items():
                grand_counts[sev] = grand_counts.get(sev, 0) + cnt

            hostname = scanner._sys_info.get("hostname", label)
            version = scanner._sys_info.get("version", "N/A")
            model = scanner._sys_info.get("model_name", scanner._sys_info.get("model", "N/A"))

            crit = counts.get("CRITICAL", 0)
            high = counts.get("HIGH", 0)
            status = "\033[91mCRITICAL\033[0m" if crit else ("\033[93mHIGH\033[0m" if high else "\033[92mOK\033[0m")

            print(f"  {hostname:<25} {model:<20} FortiOS {version:<10} "
                  f"Findings: {total:>3}  (C:{crit} H:{high} M:{counts.get('MEDIUM', 0)} L:{counts.get('LOW', 0)})  [{status}]")

        print(f"\n  {'─' * 68}")
        print(f"  Grand total: {grand_total} findings across {len(self.results)} devices")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if grand_counts.get(sev, 0):
                print(f"    {sev:<10} {grand_counts[sev]}")
        print()

    def save_unified_json(self, output_path: str) -> None:
        """Save unified JSON report across all devices."""
        devices = []
        for label, scanner in sorted(self.results.items()):
            devices.append({
                "label": label,
                "host": scanner.host,
                "system_info": scanner._sys_info,
                "total_findings": len(scanner.findings),
                "summary": scanner.summary(),
                "findings": [f.to_dict() for f in scanner.findings],
            })

        report = {
            "scanner": f"Fortinet FortiOS Security Scanner v{VERSION}",
            "generated": datetime.now().isoformat(),
            "mode": "multi-device",
            "devices_scanned": len(self.results),
            "total_findings": sum(len(s.findings) for s in self.results.values()),
            "devices": devices,
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"[+] Unified JSON report saved to: {output_path}")


# ========================================================================== #
#  CLI                                                                        #
# ========================================================================== #

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fortinet_scanner",
        description=f"Fortinet FortiOS Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single device scan
  python fortinet_scanner.py 10.1.1.1 --token <API-TOKEN>
  python fortinet_scanner.py fw.corp.local --token <TOKEN> --json report.json --html report.html
  python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --severity HIGH --verbose

  # Export remediation commands
  python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --remediation fix.txt

  # Export compliance mapping
  python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --compliance-csv audit.csv

  # Multi-device scan (JSON inventory file)
  python fortinet_scanner.py --inventory devices.json --json unified_report.json

  # devices.json format:
  # [{"host": "fw1.corp.local", "token": "xxx", "name": "HQ-FW"},
  #  {"host": "fw2.corp.local", "token": "yyy", "name": "DR-FW"}]
""",
    )

    parser.add_argument("host", nargs="?", default=None, help="FortiGate hostname or IP address")
    parser.add_argument(
        "--token",
        default=os.environ.get("FORTIOS_API_TOKEN", ""),
        help="FortiOS REST API token. Env: FORTIOS_API_TOKEN",
    )
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate (default: disabled)")
    parser.add_argument("--timeout", type=int, default=30, help="API request timeout in seconds (default: 30)")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to FILE")
    parser.add_argument("--html", metavar="FILE", help="Save detailed HTML report to FILE")
    parser.add_argument("--pdf", metavar="FILE", help="Save detailed PDF report to FILE (stdlib only, no extra deps)")
    parser.add_argument("--remediation", metavar="FILE", help="Export a detailed remediation runbook to FILE")
    parser.add_argument("--compliance-csv", metavar="FILE", help="Export compliance mapping CSV (CIS, PCI-DSS, NIST, SOC2, HIPAA)")
    parser.add_argument("--sarif", metavar="FILE", help="Export findings as SARIF 2.1.0 (GitHub code-scanning / CI ingestion)")
    parser.add_argument("--ocsf", metavar="FILE", help="Export findings as OCSF Compliance Finding events (SIEM ingestion)")
    parser.add_argument("--fix-script", metavar="FILE", help="Generate a fix-first FortiOS CLI remediation script from the knowledge base")
    parser.add_argument("--rollback-script", metavar="FILE", help="Also write the paired rollback script (use with --fix-script)")
    parser.add_argument("--fix-tier", choices=["P1", "P2", "P3", "P4"], default="P4",
                        help="Highest priority tier to include in the fix script (default: P4 = all)")
    parser.add_argument("--fix-script-force", action="store_true",
                        help="Include disruptive fixes (reboot/HA/VPN-drop) uncommented in the fix script")
    parser.add_argument("--baseline", metavar="FILE", help="Prior --json report to diff against (config drift: new vs resolved findings + posture delta)")
    parser.add_argument("--inventory", metavar="FILE", help="Multi-device inventory JSON file for batch scanning")
    parser.add_argument("--top", type=int, nargs="?", const=10, default=None, metavar="N",
                        help="Print the risk-prioritized fix-first queue, showing the top N (default 10)")
    parser.add_argument("--refresh-intel", action="store_true",
                        help="Refresh the bundled threat-intel snapshot (CISA KEV + FIRST.org EPSS) "
                             "for all tracked CVEs, then exit. Requires internet access.")
    parser.add_argument("--export-intel", metavar="FILE",
                        help="Copy the current threat-intel snapshot to FILE (to sneakernet to an air-gapped host), then exit.")
    parser.add_argument("--import-intel", metavar="FILE",
                        help="Install a hand-carried threat-intel snapshot from FILE as the active snapshot, then exit.")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument("--csv", metavar="FILE", help="Export a full findings CSV (severity, tier, KEV, EPSS, CVE, compliance, evidence)")
    parser.add_argument("--framework", choices=["cis", "pci", "nist", "soc2", "hipaa"],
                        help="Print a scored benchmark (pass/fail per mapped control, per-section %) for the framework")
    parser.add_argument("--benchmark", metavar="FILE",
                        help="Save the per-control benchmark to FILE (.json or .csv); framework from --framework (default cis)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colour in console output (also honours the NO_COLOR env var)")
    parser.add_argument("--summary-only", "--quiet", dest="summary_only", action="store_true",
                        help="Print only the scorecard + fix-first queue (skip the full per-finding dump)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    # ── Threat-intel maintenance actions (standalone) ──────────────
    if args.refresh_intel:
        sys.exit(_refresh_intel())
    if args.export_intel:
        sys.exit(_transfer_intel("export", args.export_intel))
    if args.import_intel:
        sys.exit(_transfer_intel("import", args.import_intel))

    # ── Multi-device mode ──────────────────────────────────────────
    if args.inventory:
        try:
            with open(args.inventory, encoding="utf-8") as fh:
                targets = json.load(fh)
        except (json.JSONDecodeError, FileNotFoundError) as exc:
            parser.error(f"Cannot load inventory file: {exc}")

        if not isinstance(targets, list) or not targets:
            parser.error("Inventory file must contain a JSON array of device objects")

        multi = MultiDeviceScanner(
            targets=targets,
            verify_ssl=args.verify_ssl,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        multi.scan_all()
        multi.print_summary()

        if args.json:
            multi.save_unified_json(args.json)

        # Exit with 1 if any device has CRITICAL/HIGH
        has_critical = any(
            s.summary().get("CRITICAL", 0) or s.summary().get("HIGH", 0)
            for s in multi.results.values()
        )
        sys.exit(1 if has_critical else 0)

    # ── Single-device mode ─────────────────────────────────────────
    if not args.host:
        parser.error("host is required for single-device scan (or use --inventory for multi-device)")

    if not args.token:
        parser.error(
            "API token is required. Provide via --token or FORTIOS_API_TOKEN env var.\n"
            "Generate a token on the FortiGate: System > Administrators > Create New > REST API Admin"
        )

    scanner = FortinetScanner(
        host=args.host,
        token=args.token,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    scanner.scan()
    scanner.set_color(False if args.no_color else None)

    if args.severity:
        scanner.filter_severity(args.severity)
        scanner._sev_filter = f"{args.severity} and above"

    if args.baseline:
        scanner.apply_drift(args.baseline)

    if args.summary_only:
        scanner.print_summary_only()
    else:
        scanner.print_report()
        scanner.print_compliance_scorecard()
        scanner.print_priorities(args.top if args.top is not None else 10)

    benchmark_fw = args.framework or ("cis" if args.benchmark else None)
    if benchmark_fw:
        scanner.print_benchmark(benchmark_fw)

    if args.json:
        scanner.save_json(args.json)
    if args.csv:
        scanner.save_findings_csv(args.csv)
    if args.benchmark:
        scanner.save_benchmark(args.benchmark, benchmark_fw)
    if args.html:
        scanner.save_html(args.html)
    if args.pdf:
        scanner.save_pdf(args.pdf)
    if args.remediation:
        scanner.save_remediation(args.remediation)
    if args.compliance_csv:
        scanner.save_compliance_csv(args.compliance_csv)
    if args.sarif:
        scanner.save_sarif(args.sarif)
    if args.ocsf:
        scanner.save_ocsf(args.ocsf)
    if args.fix_script:
        scanner.save_remediation_script(args.fix_script, args.rollback_script,
                                        tier_max=args.fix_tier, force=args.fix_script_force)

    counts = scanner.summary()
    sys.exit(1 if (counts.get("CRITICAL", 0) or counts.get("HIGH", 0)) else 0)


def _refresh_intel() -> int:
    """Refresh the bundled threat-intel snapshot from the live CISA KEV + EPSS
    feeds for every tracked CVE. Returns a process exit code."""
    try:
        from risk_prioritizer import refresh_threat_intel
    except Exception as exc:  # pragma: no cover
        print(f"[!] Risk-prioritization module unavailable: {exc}", file=sys.stderr)
        return 1
    cves = sorted({c["cve"] for c in FORTIOS_CVES if c.get("cve")})
    print(f"[*] Refreshing threat intel for {len(cves)} tracked CVE(s) from CISA KEV + FIRST.org EPSS …")
    try:
        meta = refresh_threat_intel(cves)
    except Exception as exc:
        print(f"[!] Threat-intel refresh failed: {exc}\n"
              f"    (offline/air-gapped? The bundled snapshot remains in use.)", file=sys.stderr)
        return 1
    print(f"[+] Snapshot updated: {meta['cve_count']} CVE(s), {meta['kev_count']} KEV-listed "
          f"(snapshot {meta['snapshot_date']}).")
    return 0


def _transfer_intel(action: str, path: str) -> int:
    """Export the current threat-intel snapshot to a file, or import one from a
    file (validated), for sneakernet transfer to/from air-gapped hosts."""
    try:
        from risk_prioritizer import export_intel, import_intel
    except Exception as exc:  # pragma: no cover
        print(f"[!] Risk-prioritization module unavailable: {exc}", file=sys.stderr)
        return 1
    try:
        if action == "export":
            meta = export_intel(path)
            print(f"[+] Threat-intel snapshot exported to: {path} "
                  f"(snapshot {meta.get('snapshot_date', '?')}, {meta.get('cve_count', '?')} CVEs). "
                  f"Copy it to the air-gapped host and run --import-intel.")
        else:
            meta = import_intel(path)
            print(f"[+] Threat-intel snapshot imported from: {path} "
                  f"(snapshot {meta.get('snapshot_date', '?')}, {meta.get('cve_count', '?')} CVEs).")
    except Exception as exc:
        print(f"[!] Threat-intel {action} failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    main()
