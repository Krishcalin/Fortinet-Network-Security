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

VERSION = "2.0.0"

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
                        line_num=None, line_content=f"interface={iface_name}, role=wan, mgmt_access={','.join(wan_bad)}",
                        description=f"WAN interface '{iface_name}' allows management protocols ({', '.join(wan_bad)}). This exposes the management plane to the internet.",
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
                    line_content=f"versions={', '.join(versions)}",
                    description=f"HA cluster members are running different firmware versions: {', '.join(versions)}.",
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

    # ================================================================== #
    #  CHECK: Network Hardening                                            #
    # ================================================================== #

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
