#!/usr/bin/env python3
"""
Fortinet FortiGate / FortiOS Network Security Scanner v1.0.0

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
import urllib3
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# requests (required for API mode)
# ---------------------------------------------------------------------------
try:
    import requests as _requests
except ImportError:
    print("[!] 'requests' library is required: pip install requests", file=sys.stderr)
    sys.exit(1)

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        "affected": [
            {"train": "7.2", "fixed": "7.2.3"},
            {"train": "7.0", "fixed": "7.0.11"},
        ],
        "description": "An SQL injection vulnerability in FortiClient EMS allows an unauthenticated attacker to execute commands via specially crafted requests to the DAS component.",
        "recommendation": "Upgrade FortiClient EMS to the fixed version.",
        "cwe": "CWE-89",
    },
    {
        "id": "FORTIOS-CVE-008", "cve": "CVE-2024-0012", "severity": "CRITICAL",
        "name": "Management interface authentication bypass",
        "affected": [
            {"train": "7.0", "fixed": "7.0.17"},
        ],
        "description": "An authentication bypass in the FortiOS management interface allows a remote unauthenticated attacker to gain super-admin privileges.",
        "recommendation": "Upgrade to FortiOS 7.0.17+. Restrict management access to trusted internal networks only.",
        "cwe": "CWE-288",
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
        "name": "Stack-based buffer overflow in FortiOS IPS",
        "affected": [
            {"train": "7.4", "fixed": "7.4.3"},
            {"train": "7.2", "fixed": "7.2.7"},
            {"train": "7.0", "fixed": "7.0.14"},
        ],
        "description": "A stack-based buffer overflow in FortiOS IPS engine allows a remote unauthenticated attacker to achieve denial of service via crafted packets.",
        "recommendation": "Upgrade to the fixed version.",
        "cwe": "CWE-121",
    },
]

# ========================================================================== #
#  WEAK CRYPTO CONSTANTS                                                      #
# ========================================================================== #

WEAK_CIPHERS = {"des", "3des", "rc4", "null", "rc2", "idea", "seed", "aria128"}
WEAK_HASHES = {"md5", "md5-96"}
WEAK_DH_GROUPS = {"1", "2", "5"}
WEAK_TLS = {"sslv3", "tlsv1.0", "tlsv1-0", "tlsv1.1", "tlsv1-1", "tls1.0", "tls1.1", "tls-1.0", "tls-1.1"}

# ========================================================================== #
#  FINDING CLASS                                                              #
# ========================================================================== #

class Finding:
    """A single vulnerability finding."""

    __slots__ = (
        "rule_id", "name", "category", "severity",
        "file_path", "line_num", "line_content",
        "description", "recommendation", "cwe", "cve",
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

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}


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

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str) -> None:
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

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
            print(f"             Desc: {f.description[:180]}")
            print(f"              Fix: {f.recommendation[:180]}")
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
        report = {
            "scanner": f"Fortinet FortiOS Security Scanner v{VERSION}",
            "generated": datetime.now().isoformat(),
            "target": getattr(self, "host", ""),
            "system_info": sys_info,
            "total_findings": len(self.findings),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved to: {output_path}")

    def save_html(self, output_path: str) -> None:
        counts = self.summary()
        sys_info = getattr(self, "_sys_info", {})
        rows = ""
        for f in sorted(
            self.findings,
            key=lambda x: (self.SEVERITY_ORDER.get(x.severity, 4), x.category, x.rule_id),
        ):
            sev_cls = f.severity.lower()
            detail = _html.escape(f.line_content[:200]) if f.line_content else ""
            ref = _html.escape(f.cwe or "")
            if f.cve:
                ref += f" | {_html.escape(f.cve)}"
            rows += f"""<tr>
  <td><span class="chip {sev_cls}">{_html.escape(f.severity)}</span></td>
  <td>{_html.escape(f.rule_id)}</td>
  <td>{_html.escape(f.category)}</td>
  <td>{_html.escape(f.name)}</td>
  <td class="loc">{_html.escape(f.file_path)}</td>
  <td><code>{detail}</code></td>
  <td>{ref}</td>
  <td>{_html.escape(f.description)}</td>
  <td>{_html.escape(f.recommendation)}</td>
</tr>\n"""

        meta_extra = ""
        if sys_info:
            meta_extra = f" &middot; {_html.escape(sys_info.get('hostname', ''))} &middot; {_html.escape(sys_info.get('model_name', sys_info.get('model', '')))} &middot; FortiOS {_html.escape(sys_info.get('version', ''))}"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fortinet FortiOS Security Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#1a1b2e;color:#cdd6f4;line-height:1.5}}
.container{{max-width:1440px;margin:0 auto;padding:24px}}
h1{{font-size:1.6rem;margin-bottom:4px;color:#f38ba8}}
.meta{{color:#7f849c;font-size:0.85rem;margin-bottom:24px}}
.summary{{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}}
.summary .card{{background:#313244;border-radius:10px;padding:16px 24px;min-width:120px;text-align:center}}
.summary .card .count{{font-size:1.8rem;font-weight:700}}
.summary .card .label{{font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:#7f849c}}
.critical .count{{color:#f38ba8}} .high .count{{color:#fab387}}
.medium .count{{color:#89b4fa}} .low .count{{color:#a6e3a1}} .info .count{{color:#cdd6f4}}
.filters{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}}
.filters label{{color:#7f849c;font-size:0.85rem;margin-right:4px}}
.filters select,.filters input{{background:#313244;color:#cdd6f4;border:1px solid #45475a;border-radius:6px;padding:6px 10px;font-size:0.85rem}}
.filters input{{min-width:220px}}
table{{width:100%;border-collapse:collapse;font-size:0.82rem}}
thead{{position:sticky;top:0;background:#181825;z-index:1}}
th{{text-align:left;padding:10px 8px;border-bottom:2px solid #45475a;color:#f38ba8;font-weight:600;white-space:nowrap}}
td{{padding:8px;border-bottom:1px solid #313244;vertical-align:top}}
tr:hover{{background:#313244}}
code{{background:#1e1e2e;padding:2px 6px;border-radius:4px;font-size:0.78rem;word-break:break-all}}
.chip{{display:inline-block;padding:2px 10px;border-radius:100px;font-size:0.7rem;font-weight:700;text-transform:uppercase}}
.chip.critical{{background:rgba(243,139,168,0.18);color:#f38ba8}}
.chip.high{{background:rgba(250,179,135,0.18);color:#fab387}}
.chip.medium{{background:rgba(137,180,250,0.18);color:#89b4fa}}
.chip.low{{background:rgba(166,227,161,0.18);color:#a6e3a1}}
.chip.info{{background:rgba(205,214,244,0.12);color:#cdd6f4}}
.loc{{white-space:nowrap;font-size:0.78rem;color:#f38ba8}}
.wrap{{overflow-x:auto}}
</style>
</head>
<body>
<div class="container">
<h1>Fortinet FortiOS Security Scanner v{VERSION} — Report</h1>
<p class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &middot;
Target: {_html.escape(getattr(self, "host", ""))}{meta_extra} &middot;
Total findings: {len(self.findings)}</p>

<div class="summary">
  <div class="card critical"><div class="count">{counts.get("CRITICAL",0)}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="count">{counts.get("HIGH",0)}</div><div class="label">High</div></div>
  <div class="card medium"><div class="count">{counts.get("MEDIUM",0)}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="count">{counts.get("LOW",0)}</div><div class="label">Low</div></div>
  <div class="card info"><div class="count">{counts.get("INFO",0)}</div><div class="label">Info</div></div>
</div>

<div class="filters">
  <label>Severity:</label>
  <select id="fSev"><option value="">All</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
  <label>Category:</label>
  <select id="fCat"><option value="">All</option></select>
  <label>Search:</label>
  <input id="fSearch" placeholder="Filter by rule ID, name, detail…">
</div>

<div class="wrap">
<table id="tbl">
<thead><tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th><th>Name</th>
  <th>Target</th><th>Detail</th><th>Ref</th><th>Description</th><th>Recommendation</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>
<script>
(function(){{
  const tbl=document.getElementById('tbl'),rows=[...tbl.querySelectorAll('tbody tr')];
  const fSev=document.getElementById('fSev'),fCat=document.getElementById('fCat'),fSearch=document.getElementById('fSearch');
  const cats=[...new Set(rows.map(r=>r.children[2].textContent))].sort();
  cats.forEach(c=>{{const o=document.createElement('option');o.textContent=c;fCat.appendChild(o)}});
  function apply(){{
    const s=fSev.value.toLowerCase(),c=fCat.value,q=fSearch.value.toLowerCase();
    rows.forEach(r=>{{
      const sv=r.children[0].textContent.trim().toLowerCase(),ct=r.children[2].textContent,txt=r.textContent.toLowerCase();
      r.style.display=((!s||sv===s)&&(!c||ct===c)&&(!q||txt.includes(q)))?'':'none';
    }});
  }}
  fSev.onchange=fCat.onchange=apply;fSearch.oninput=apply;
}})();
</script>
</body></html>"""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"[+] HTML report saved to: {output_path}")


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
        prefix = "monitor" if monitor else "cmdb"
        url = f"{self.host}/api/v2/{prefix}/{path}"
        self._vprint(f"  [api] GET {url}")
        try:
            resp = _requests.get(
                url,
                headers={"Authorization": f"Bearer {self.token}"},
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except _requests.exceptions.ConnectionError as exc:
            self._warn(f"Connection failed: {exc}")
            return None
        except _requests.exceptions.Timeout:
            self._warn(f"Timeout for {path}")
            return None
        except _requests.exceptions.RequestException as exc:
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
            ("SSL VPN",              self._check_ssl_vpn),
            ("IPsec VPN",            self._check_ipsec_vpn),
            ("Security Profiles",    self._check_security_profiles),
            ("Logging & Monitoring", self._check_logging),
            ("High Availability",    self._check_ha),
            ("Certificates",         self._check_certificates),
            ("Network Hardening",    self._check_network),
            ("ZTNA / SASE",          self._check_ztna),
            ("FortiGuard & Updates", self._check_fortiguard),
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

    def _check_cves(self) -> None:
        if not self._fw_version:
            return
        for cve_entry in FORTIOS_CVES:
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
                    break  # One match per CVE is enough

    # ================================================================== #
    #  CHECK: Admin Access                                                 #
    # ================================================================== #

    def _check_admin_access(self) -> None:
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

        # Weak password policy
        admin_pwd_policy = glb.get("admin-password-policy", {})
        if isinstance(admin_pwd_policy, dict):
            min_len = admin_pwd_policy.get("min-length", 0)
            if isinstance(min_len, int) and min_len < 12:
                self._add(Finding(
                    rule_id="FORTIOS-ADMIN-003", name="Weak admin password policy",
                    category="Admin Access", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"min-length={min_len}",
                    description=f"Admin password minimum length is {min_len}. Minimum 12 characters recommended.",
                    recommendation="Set minimum password length to 12+: config system password-policy / set minimum-length 12.",
                    cwe="CWE-521",
                ))

        # Check admin accounts
        admins = self._api_get("system/admin")
        if isinstance(admins, list):
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
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"api-user={uname}, trusthost=none",
                        description=f"API user '{uname}' has no trusted host restrictions.",
                        recommendation="Configure trusted hosts for API users to restrict API access to known management IPs.",
                        cwe="CWE-284",
                    ))

    # ================================================================== #
    #  CHECK: System Settings                                              #
    # ================================================================== #

    def _check_system_settings(self) -> None:
        settings = self._api_get("system/settings")
        if isinstance(settings, list) and settings:
            settings = settings[0] if isinstance(settings[0], dict) else {}
        if not isinstance(settings, dict):
            return

        # Check management interfaces
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
                        line_num=None, line_content=f"interface={iface_name}, role=wan, mgmt_access={','.join(wan_bad)}",
                        description=f"WAN interface '{iface_name}' allows management protocols ({', '.join(wan_bad)}). This exposes the management plane to the internet.",
                        recommendation="Remove all management protocols from WAN interfaces. Use a dedicated management interface or VPN for admin access.",
                        cwe="CWE-284",
                    ))

    # ================================================================== #
    #  CHECK: Firewall Policies                                            #
    # ================================================================== #

    def _check_firewall_policies(self) -> None:
        policies = self._api_get("firewall/policy")
        if not isinstance(policies, list):
            return

        for pol in policies:
            pol_id = pol.get("policyid", "?")
            pol_name = pol.get("name", f"policy-{pol_id}")
            action = pol.get("action", "").lower()
            status = pol.get("status", "enable")

            # Disabled policies
            if status == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-001", name="Disabled firewall policy",
                    category="Firewall Policies", severity="LOW",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"policy={pol_name} (ID {pol_id}), status=disable",
                    description=f"Firewall policy '{pol_name}' (ID {pol_id}) is disabled. Disabled policies add clutter and may be accidentally re-enabled.",
                    recommendation="Remove disabled policies or document the reason for keeping them disabled.",
                    cwe="CWE-1078",
                ))
                continue

            if action != "accept":
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
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"policy={pol_name} (ID {pol_id}), src=all, dst=all",
                    description=f"Policy '{pol_name}' allows traffic from any source to any destination, bypassing segmentation.",
                    recommendation="Replace with specific source and destination address objects.",
                    cwe="CWE-284",
                ))

            # Source = all
            elif "all" in src_names:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-003", name="Allow policy with 'all' source",
                    category="Firewall Policies", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"policy={pol_name} (ID {pol_id}), srcaddr=all",
                    description=f"Policy '{pol_name}' allows traffic from any source address.",
                    recommendation="Restrict the source to specific address objects or groups.",
                    cwe="CWE-284",
                ))

            # Service = ALL
            if "ALL" in svc_names:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-004", name="Allow policy with ALL services",
                    category="Firewall Policies", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"policy={pol_name} (ID {pol_id}), service=ALL",
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
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"policy={pol_name} (ID {pol_id}), logtraffic={logtraffic or 'disable'}",
                    description=f"Policy '{pol_name}' does not log traffic, hindering forensic investigation.",
                    recommendation="Enable logtraffic=all or logtraffic=utm on all allow policies.",
                    cwe="CWE-778",
                ))

            # Missing UTM / security profiles
            utm_keys = ["av-profile", "webfilter-profile", "ips-sensor", "application-list",
                        "ssl-ssh-profile", "dlp-sensor", "dnsfilter-profile"]
            has_utm = any(pol.get(k) for k in utm_keys)
            inspection = pol.get("inspection-mode", pol.get("utm-status", ""))

            if not has_utm:
                self._add(Finding(
                    rule_id="FORTIOS-POLICY-006", name="Allow policy without security profiles",
                    category="Firewall Policies", severity="CRITICAL",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"policy={pol_name} (ID {pol_id}), utm_profiles=none",
                    description=f"Policy '{pol_name}' allows traffic without any UTM security profiles (AV, IPS, WebFilter, AppControl).",
                    recommendation="Apply security profiles (antivirus, IPS, web filter, application control) to all allow policies.",
                    cwe="CWE-693",
                ))

    # ================================================================== #
    #  CHECK: SSL VPN                                                      #
    # ================================================================== #

    def _check_ssl_vpn(self) -> None:
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

        # Check for MFA in authentication rules
        auth_rules = self._api_get("vpn.ssl.web/user-group-bookmark")
        # Simple check: look for two-factor in VPN-related user groups
        user_groups = self._api_get("user/group")
        if isinstance(user_groups, list):
            vpn_groups = [g for g in user_groups if "vpn" in g.get("name", "").lower() or "ssl" in g.get("name", "").lower()]
            for grp in vpn_groups:
                gname = grp.get("name", "unknown")
                members = grp.get("member", [])
                # If the group exists but we can't verify MFA, flag it as INFO
                if members:
                    self._vprint(f"    VPN group '{gname}' has {len(members)} member(s)")

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

    # ================================================================== #
    #  CHECK: Security Profiles                                            #
    # ================================================================== #

    def _check_security_profiles(self) -> None:
        # Check if AV profiles exist
        av = self._api_get("antivirus/profile")
        if not isinstance(av, list) or len(av) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-001", name="No antivirus profiles configured",
                category="Security Profiles", severity="HIGH",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="antivirus/profile: empty",
                description="No antivirus profiles are configured on this FortiGate.",
                recommendation="Create antivirus profiles and apply them to firewall policies.",
                cwe="CWE-693",
            ))

        # Check if IPS sensors exist
        ips = self._api_get("ips/sensor")
        if not isinstance(ips, list) or len(ips) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-002", name="No IPS sensors configured",
                category="Security Profiles", severity="HIGH",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="ips/sensor: empty",
                description="No IPS sensors are configured on this FortiGate.",
                recommendation="Create IPS sensors with appropriate signatures and apply to firewall policies.",
                cwe="CWE-693",
            ))

        # Check if web filter profiles exist
        wf = self._api_get("webfilter/profile")
        if not isinstance(wf, list) or len(wf) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-003", name="No web filter profiles configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="webfilter/profile: empty",
                description="No web filter profiles are configured.",
                recommendation="Create web filter profiles to block malicious and inappropriate web content.",
                cwe="CWE-693",
            ))

        # Check if application control lists exist
        appctrl = self._api_get("application/list")
        if not isinstance(appctrl, list) or len(appctrl) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-004", name="No application control lists configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="application/list: empty",
                description="No application control lists are configured.",
                recommendation="Create application control lists to identify and control application traffic.",
                cwe="CWE-693",
            ))

        # Check if DLP sensors exist
        dlp = self._api_get("dlp/sensor")
        if not isinstance(dlp, list) or len(dlp) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-005", name="No DLP sensors configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="dlp/sensor: empty",
                description="No Data Loss Prevention sensors are configured.",
                recommendation="Create DLP sensors to detect and prevent sensitive data exfiltration.",
                cwe="CWE-200",
            ))

        # DNS filter
        dnsfilter = self._api_get("dnsfilter/profile")
        if not isinstance(dnsfilter, list) or len(dnsfilter) == 0:
            self._add(Finding(
                rule_id="FORTIOS-PROFILE-006", name="No DNS filter profiles configured",
                category="Security Profiles", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="dnsfilter/profile: empty",
                description="No DNS filter profiles are configured. DNS filtering blocks malicious domains at the DNS layer.",
                recommendation="Create DNS filter profiles to block known malicious domains.",
                cwe="CWE-693",
            ))

    # ================================================================== #
    #  CHECK: Logging & Monitoring                                         #
    # ================================================================== #

    def _check_logging(self) -> None:
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
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"fortianalyzer status={faz_status}",
                    description="FortiAnalyzer is not enabled for centralized log management and analysis.",
                    recommendation="Configure FortiAnalyzer for centralized logging: config log fortianalyzer setting / set status enable.",
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
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"syslogd status={syslog_status}",
                    description="Syslog forwarding is not enabled. Logs stored only locally may be lost if the device is compromised.",
                    recommendation="Configure syslog forwarding to a SIEM or log management platform.",
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
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"diskfull={full_action}",
                    description="When log disk is full, older logs are overwritten, potentially destroying forensic evidence.",
                    recommendation="Set diskfull action to 'nolog' or configure log forwarding to prevent data loss.",
                    cwe="CWE-778",
                ))

            # Event logging
            event_log = log_setting.get("fwpolicy-implicit-log", "disable")
            if event_log == "disable":
                self._add(Finding(
                    rule_id="FORTIOS-LOG-004", name="Implicit deny logging disabled",
                    category="Logging & Monitoring", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"fwpolicy-implicit-log=disable",
                    description="Traffic denied by the implicit deny rule is not logged, hiding potential attack attempts.",
                    recommendation="Enable implicit deny logging: set fwpolicy-implicit-log enable.",
                    cwe="CWE-778",
                ))

    # ================================================================== #
    #  CHECK: High Availability                                            #
    # ================================================================== #

    def _check_ha(self) -> None:
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
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"ha mode=standalone",
                description="The FortiGate is running in standalone mode without HA, creating a single point of failure.",
                recommendation="Configure Active-Passive or Active-Active HA for resilience.",
                cwe="CWE-654",
            ))
            return

        # Heartbeat encryption
        hb_enc = ha.get("authentication", "disable")
        if hb_enc != "enable":
            self._add(Finding(
                rule_id="FORTIOS-HA-002", name="HA heartbeat not authenticated",
                category="High Availability", severity="HIGH",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"ha authentication={hb_enc}",
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
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content=f"session-pickup={session_pickup}",
                description="Session pickup is disabled. Active sessions will be dropped during HA failover.",
                recommendation="Enable session-pickup for seamless failover: set session-pickup enable.",
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
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"versions={', '.join(versions)}",
                    description=f"HA cluster members are running different firmware versions: {', '.join(versions)}.",
                    recommendation="Upgrade all HA cluster members to the same firmware version.",
                    cwe="CWE-1104",
                ))

    # ================================================================== #
    #  CHECK: Certificates                                                 #
    # ================================================================== #

    def _check_certificates(self) -> None:
        certs = self._api_get("vpn.certificate/local")
        if not isinstance(certs, list):
            certs = self._api_get("system/certificate", monitor=True)
        if not isinstance(certs, list):
            return

        for cert in certs:
            cname = cert.get("name", cert.get("common-name", "unknown"))

            # Default Fortinet factory cert
            if "fortinet" in cname.lower() and ("factory" in cname.lower() or "self-sign" in cname.lower()):
                self._add(Finding(
                    rule_id="FORTIOS-CERT-001", name="Default Fortinet factory certificate in use",
                    category="Certificates", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"certificate={cname}",
                    description=f"The default Fortinet factory certificate '{cname}' is in use. This is a known, shared certificate.",
                    recommendation="Replace the factory certificate with a CA-signed certificate specific to your organisation.",
                    cwe="CWE-295",
                ))

            # Check expiry
            expiry = cert.get("expiry", cert.get("valid-to", ""))
            if expiry:
                try:
                    # Try common date formats
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
                            file_path=self._sys_info.get("hostname", self.host),
                            line_num=None, line_content=f"certificate={cname}, expired={expiry}",
                            description=f"Certificate '{cname}' expired on {expiry}.",
                            recommendation="Replace the expired certificate immediately.",
                            cwe="CWE-295",
                        ))
                    elif exp_dt < now + timedelta(days=30):
                        self._add(Finding(
                            rule_id="FORTIOS-CERT-003", name="Certificate expiring within 30 days",
                            category="Certificates", severity="HIGH",
                            file_path=self._sys_info.get("hostname", self.host),
                            line_num=None, line_content=f"certificate={cname}, expires={expiry}",
                            description=f"Certificate '{cname}' will expire on {expiry}.",
                            recommendation="Renew the certificate before expiry.",
                            cwe="CWE-295",
                        ))
                except (ValueError, TypeError):
                    pass

    # ================================================================== #
    #  CHECK: Network Hardening                                            #
    # ================================================================== #

    def _check_network(self) -> None:
        interfaces = self._api_get("system/interface")
        if not isinstance(interfaces, list):
            return

        for iface in interfaces:
            iface_name = iface.get("name", "unknown")
            role = iface.get("role", "")

            # DNS server on WAN
            if role == "wan":
                dns_server = iface.get("dns-server-override", "")
                dhcp = iface.get("dhcp-relay-service", "")

        # DoS policy
        dos = self._api_get("firewall/DoS-policy")
        if not isinstance(dos, list) or len(dos) == 0:
            self._add(Finding(
                rule_id="FORTIOS-NET-001", name="No DoS policy configured",
                category="Network Hardening", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="firewall/DoS-policy: empty",
                description="No DoS protection policies are configured to protect against volumetric attacks.",
                recommendation="Create DoS policies for WAN-facing interfaces to mitigate flood attacks.",
                cwe="CWE-400",
            ))

    # ================================================================== #
    #  CHECK: ZTNA / SASE                                                  #
    # ================================================================== #

    def _check_ztna(self) -> None:
        # Check for ZTNA access proxy
        ztna = self._api_get("firewall/access-proxy")
        if not isinstance(ztna, list) or len(ztna) == 0:
            self._add(Finding(
                rule_id="FORTIOS-ZTNA-001", name="ZTNA not implemented",
                category="ZTNA / SASE", severity="MEDIUM",
                file_path=self._sys_info.get("hostname", self.host),
                line_num=None, line_content="firewall/access-proxy: empty",
                description="Zero Trust Network Access (ZTNA) is not configured. ZTNA provides identity-aware, context-based access control.",
                recommendation="Implement ZTNA access proxies for application-level access control with device posture checking.",
                cwe="CWE-284",
            ))

    # ================================================================== #
    #  CHECK: FortiGuard & Updates                                         #
    # ================================================================== #

    def _check_fortiguard(self) -> None:
        # License status
        license_data = self._api_get("license/status", monitor=True)
        if isinstance(license_data, dict):
            # Check individual services
            for svc_name, svc_data in license_data.items():
                if not isinstance(svc_data, dict):
                    continue
                status = svc_data.get("status", "")
                if status in ("expired", "disabled"):
                    self._add(Finding(
                        rule_id="FORTIOS-UPDATE-001", name=f"FortiGuard {svc_name} service {status}",
                        category="FortiGuard & Updates", severity="HIGH",
                        file_path=self._sys_info.get("hostname", self.host),
                        line_num=None, line_content=f"{svc_name}={status}",
                        description=f"FortiGuard service '{svc_name}' is {status}. Security signatures may be outdated.",
                        recommendation=f"Renew the FortiGuard {svc_name} license to ensure up-to-date threat protection.",
                        cwe="CWE-1104",
                    ))

        # FortiGuard connection status
        fg_status = self._api_get("system/fortiguard-service-status", monitor=True)
        if isinstance(fg_status, dict):
            connected = fg_status.get("connected", fg_status.get("service_connection_status", ""))
            if str(connected).lower() not in ("connected", "true", "1", "enable"):
                self._add(Finding(
                    rule_id="FORTIOS-UPDATE-002", name="FortiGuard not connected",
                    category="FortiGuard & Updates", severity="HIGH",
                    file_path=self._sys_info.get("hostname", self.host),
                    line_num=None, line_content=f"fortiguard={connected}",
                    description="FortiGuard Distribution Network is not connected. Security updates cannot be downloaded.",
                    recommendation="Verify FortiGuard connectivity. Check DNS, proxy, and firewall rules for FortiGuard servers.",
                    cwe="CWE-1104",
                ))


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
  python fortinet_scanner.py 10.1.1.1 --token <API-TOKEN>
  python fortinet_scanner.py fw.corp.local --token <TOKEN> --json report.json --html report.html
  python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --severity HIGH --verbose
""",
    )

    parser.add_argument("host", help="FortiGate hostname or IP address")
    parser.add_argument(
        "--token",
        default=os.environ.get("FORTIOS_API_TOKEN", ""),
        help="FortiOS REST API token. Env: FORTIOS_API_TOKEN",
    )
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate (default: disabled)")
    parser.add_argument("--timeout", type=int, default=30, help="API request timeout in seconds (default: 30)")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to FILE")
    parser.add_argument("--html", metavar="FILE", help="Save HTML report to FILE")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

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

    if args.severity:
        scanner.filter_severity(args.severity)

    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    counts = scanner.summary()
    sys.exit(1 if (counts.get("CRITICAL", 0) or counts.get("HIGH", 0)) else 0)


if __name__ == "__main__":
    main()
