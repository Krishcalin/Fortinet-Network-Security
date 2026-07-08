<p align="center">
  <img src="banner.svg" alt="Fortinet FortiGate Security Scanner" width="900"/>
</p>

<h1 align="center">Fortinet FortiGate Security Scanner</h1>

<p align="center">
  <strong>Agentless FortiGate NGFW posture assessment — live API or offline <code>.conf</code> — with MITRE ATT&CK resilience scoring,<br/>67 CVE checks, 5-framework compliance mapping, and a 226-entry detailed remediation runbook.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0.0-blue?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/FortiOS-6.x%20%7C%207.x-red?style=flat-square" alt="FortiOS"/>
  <img src="https://img.shields.io/badge/rules-260%2B-orange?style=flat-square" alt="Rules"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-31_techniques-dc2626?style=flat-square" alt="MITRE"/>
  <img src="https://img.shields.io/badge/CVEs-67-critical?style=flat-square" alt="CVEs"/>
  <img src="https://img.shields.io/badge/remediation_KB-226_entries-2ea043?style=flat-square" alt="Remediation KB"/>
  <img src="https://img.shields.io/badge/reports-HTML%20%7C%20PDF%20%7C%20JSON%20%7C%20CSV-8957e5?style=flat-square" alt="Reports"/>
  <img src="https://img.shields.io/badge/compliance-CIS%20%7C%20PCI--DSS%20%7C%20NIST%20%7C%20SOC2%20%7C%20HIPAA-blueviolet?style=flat-square" alt="Compliance"/>
  <img src="https://img.shields.io/badge/offline%20mode-OT%20%2F%20air--gapped-success?style=flat-square" alt="Offline"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
</p>

---

## Table of Contents

- [What It Does](#what-it-does)
- [What Sets It Apart](#what-sets-it-apart)
- [Quick Start](#quick-start)
- [Key Capabilities](#key-capabilities)
- [How It Works](#how-it-works)
- [Detailed Remediation](#detailed-remediation)
- [Reports & Output Formats](#reports--output-formats)
- [Detection Coverage](#detection-coverage)
  - [Check Categories](#check-categories)
  - [MITRE ATT&CK Resilience](#mitre-attck-resilience-testing)
  - [Known CVEs](#known-cves)
  - [Compliance Mapping](#compliance-mapping)
- [Installation](#installation)
- [API Token Setup](#api-token-setup)
- [Usage](#usage)
- [Offline Mode (OT / Air-Gapped)](#offline-mode-ot--air-gapped)
- [CLI Reference](#cli-reference)
- [CI/CD Integration](#cicd-integration)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## What It Does

The **Fortinet FortiGate Security Scanner** is a Python security-assessment tool that audits a FortiGate NGFW's *entire* posture — configuration, firmware CVEs, and its resilience to real attack techniques — then hands you a remediation runbook you can actually execute.

It runs in **two modes that share one engine, one rule set, and one report layer**:

| Mode | File | How it reads the device | Dependencies |
|------|------|-------------------------|--------------|
| **Live** | `fortinet_scanner.py` | FortiOS REST API (`/api/v2/cmdb`, `/api/v2/monitor`) | `requests` |
| **Offline** | `fortinet_offline_scanner.py` | Parses an exported `.conf` backup — **no network access** | **stdlib only** |

Offline mode exists for the places live scanning cannot reach: **OT / ICS networks, air-gapped enclaves, and locked-down operator workstations** where you cannot open a socket to the firewall or `pip install` anything.

> **260+ checks · 18 domains · 31 MITRE ATT&CK techniques · 67 FortiOS CVEs · 5 compliance frameworks · 226-entry remediation knowledge base · HTML + PDF + JSON + CSV reports**

---

## What Sets It Apart

Most config checkers stop at *"you have a problem."* This one is built around *"...and here is exactly how to fix it, verify it, and roll it back."*

- 🛠️ **Remediation that a firewall engineer can run.** Every finding maps to a knowledge-base entry with a **risk narrative, numbered steps, GUI path, verified FortiOS CLI, a verification command, a rollback plan, and a service-impact note** (does it reboot? drop VPN/HA sessions?). Not a one-line hint — a runbook. See [Detailed Remediation](#detailed-remediation).
- 🔌 **True offline / air-gapped operation.** The offline scanner reconstructs the REST-API data shape from a `.conf` backup and runs the *identical* checks — with **zero third-party dependencies**, so it works on a hardened OT jump box.
- 📄 **Board-ready reports with no heavy dependencies.** A rich self-contained **HTML** report (risk gauge, severity/compliance/ATT&CK visuals, collapsible per-finding remediation) and a paginated **PDF** — both generated with the **Python standard library only** (a hand-rolled PDF writer; no reportlab, weasyprint, or headless browser).
- 🎯 **Attack-aware, not just checklist-aware.** A dedicated MITRE ATT&CK resilience pass scores how well the device would actually *withstand* real techniques (IPS coverage, SSL inspection, DLP, DGA/C2 blocking, ...), not just whether a box is ticked.
- 🧩 **Fleet-scale & pipeline-native.** Scan a JSON inventory of devices with a unified report, and gate CI/CD on the exit code.

---

## Quick Start

```bash
git clone https://github.com/Krishcalin/Fortinet-Network-Security.git
cd Fortinet-Network-Security

# --- Live scan (needs 'requests' + a read-only REST API token) ---
pip install requests
python fortinet_scanner.py 10.1.1.1 --token <API-TOKEN> \
    --html report.html --pdf report.pdf --remediation runbook.txt

# --- Offline scan (no network, no pip install) ---
python fortinet_offline_scanner.py fortigate.conf \
    --html report.html --pdf report.pdf --remediation runbook.txt
```

Open `report.html` in any browser, hand `report.pdf` to management, and give `runbook.txt` to whoever owns the firewall.

---

## Key Capabilities

| Capability | Details |
|-----------|---------|
| **260+ security rules** | 18 check methods covering every FortiGate security domain |
| **31 MITRE ATT&CK techniques** | Resilience testing across 11 tactics with a 0–100% score |
| **67 known CVEs** | FortiGuard PSIRT 2019–2026, train-based firmware version matching (FortiOS 6.2 → 7.6) |
| **5 compliance frameworks** | CIS FortiGate, PCI-DSS 4.0, NIST 800-53 Rev 5, SOC 2 Type II, HIPAA — 77 rule-to-control mappings |
| **226-entry remediation KB** | Per finding: risk · numbered steps · GUI path · verified CLI · verification command · rollback · service impact · references |
| **HTML + PDF reports** | Rich self-contained HTML and paginated PDF — both **stdlib-only** (no reportlab / weasyprint) |
| **Offline / OT mode** | Audit from a `.conf` backup with no network access and no `pip install` |
| **Multi-device scanning** | Fleet-wide assessment via a JSON inventory, with a unified report |
| **7 output formats** | Console, JSON, HTML, PDF, compliance CSV, remediation runbook, ATT&CK score |
| **Agentless & read-only** | REST API (or an offline file) — nothing installed on the device, no config changes |
| **CI/CD ready** | Exit code `1` on CRITICAL/HIGH for pipeline gating |

---

## How It Works

```
                    ┌────────────────────────────┐            ┌────────────────────────────┐
   Live mode  ──▶   │  FortiOS REST API           │            │  FortiGate .conf backup     │   ◀── Offline mode
                    │  /api/v2/cmdb, /monitor      │            │  (parsed to the API shape)  │
                    └──────────────┬──────────────┘            └──────────────┬──────────────┘
                                   │                                          │
                                   └───────────────────┬──────────────────────┘
                                                       ▼
                                        ┌───────────────────────────────┐
                                        │  FortinetScanner engine        │
                                        │  18 _check_* methods (260+)     │
                                        │  + 67 CVE matches               │
                                        │  + 31 MITRE ATT&CK tests        │
                                        │  + compliance auto-mapping      │
                                        └───────────────┬───────────────┘
                                                        ▼
                                        ┌───────────────────────────────┐
                                        │  RemediationKB (226 entries)    │
                                        │  detail_for(finding)            │
                                        └───────────────┬───────────────┘
                                                        ▼
                     Console · JSON · HTML · PDF · Compliance CSV · Remediation runbook · ATT&CK score
```

The two scanners share the same engine through a single seam: the offline scanner subclasses the live one and overrides **only** `_api_get()`, feeding it configuration parsed from the `.conf` file instead of live HTTP responses. Every check, CVE match, compliance mapping, and report format therefore behaves identically in both modes.

**Scan flow:** Connect → Discover firmware → Collect (30+ endpoints) → Audit (18 methods) → CVE match → MITRE resilience → Compliance map → **Report**.

---

## Detailed Remediation

This is the headline of v4.0.0. Findings are joined at report time to a **226-entry remediation knowledge base** (`remediation_kb.json`) keyed by rule ID (with family-prefix fallback, so e.g. one `FORTIOS-CVE` entry serves every CVE). Every emitted rule is covered. When a rule has no KB entry the loader gracefully falls back to the finding's own recommendation, so a report section is never empty.

Each entry answers the questions an engineer actually asks:

| Field | What it gives you |
|-------|-------------------|
| **Risk** | The concrete attacker scenario and business impact — *why this matters* |
| **Steps** | A numbered 6–10 step procedure with the exact FortiOS commands inline |
| **GUI path** | The FortiGate GUI navigation (and FortiManager path where relevant) |
| **CLI** | The canonical, copy-pasteable FortiOS CLI block |
| **Verify** | The exact `get`/`show`/`diagnose` command and its expected output |
| **Rollback** | How to revert the change, and what breaks if you do |
| **Service impact** | Does it reboot? Drop SSL-VPN / IPsec / HA / admin sessions? Need a maintenance window? |
| **References** | CIS Benchmark section, Fortinet Hardening Guide, PSIRT/CVE, CWE, NIST/PCI controls |

**Example — a single finding as it appears in the runbook (`--remediation`):**

```text
[7] [MEDIUM] FORTIOS-ADMIN-002 — Admin idle timeout exceeds 5 minutes
    Category  : Admin Access     Target: HQ-EDGE-FW
    Evidence  : admintimeout=30 minutes
    Reference : CWE-613
    Compliance: CIS 2.1.2 | PCI-DSS 8.1.8 | NIST AC-11 | SOC2 CC6.1

    RISK
      An idle timeout longer than 5 minutes leaves authenticated GUI/CLI sessions open on
      unattended workstations. An attacker with brief access to an admin's machine (or a stolen
      session cookie) can ride the live session to reconfigure the firewall without re-auth.

    REMEDIATION STEPS
      1. Check the current value: get system global | grep admintimeout.
      2. Set the idle timeout to 5 minutes or less: config system global / set admintimeout 5 / end.
      3. For workflows that need longer, use a per-profile override rather than raising the global.
      ...

    GUI PATH
      System > Settings > Administration Settings > 'Idle timeout' (minutes).

    CLI
      config system global
        set admintimeout 5
      end

    VERIFY
      get system global | grep admintimeout  ->  admintimeout : 5

    ROLLBACK
      config system global / set admintimeout <old-value> / end.

    SERVICE IMPACT
      Non-disruptive, no reboot. Idle admin sessions log out sooner; active sessions unaffected.

    REFERENCES
      - CIS Fortinet FortiGate Benchmark - administrator idle timeout (CIS 2.1.2)
      - CWE-613: Insufficient Session Expiration
      - NIST SP 800-53 AC-11 (Session Lock)
```

The same content is rendered as collapsible cards in the HTML report and as detailed blocks in the PDF.

---

## Reports & Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| **Console** | *(default)* | Colour-coded findings with compliance refs and a CLI-fix preview |
| **HTML** | `--html` | Rich **self-contained** report: risk-score gauge, severity / compliance / ATT&CK visuals, collapsible per-finding cards with the full detailed remediation, live filtering/search, and a print stylesheet. No external assets — opens anywhere, even offline. |
| **PDF** | `--pdf` | Paginated, **board-ready** PDF: cover page + device panel, executive summary, and detailed findings with step-by-step remediation. Built on a hand-rolled PDF engine — **stdlib only**, no reportlab/weasyprint/headless-browser. |
| **Remediation runbook** | `--remediation` | The per-finding runbook shown above — risk, steps, GUI, CLI, verify, rollback, impact, references. |
| **JSON** | `--json` | Full machine-readable report: findings, compliance map, and remediation commands. |
| **Compliance CSV** | `--compliance-csv` | Audit-evidence spreadsheet with per-framework control columns (CIS, PCI-DSS, NIST, SOC2, HIPAA). |
| **Unified JSON** | `--inventory + --json` | Aggregated multi-device fleet report. |

All reports are self-contained and dependency-free — the exact same output is produced in live and offline mode.

---

## Detection Coverage

### Check Categories

**Configuration auditing — 16 categories, 200+ rules:**

| # | Category | Prefix | Rules | Representative Checks |
|:-:|----------|--------|:-----:|-----------------------|
| 1 | Admin Access | `FORTIOS-ADMIN` | 24 | HTTP/Telnet admin, idle timeout, password policy, MFA coverage, trusted hosts, API users, default `admin`, WAN-exposed management |
| 2 | System Settings | `FORTIOS-SYS` | 13 | Strong crypto, pre/post-login banners, account lockout, TLS enforcement, **private-data encryption** |
| 3 | Firewall Policies | `FORTIOS-POLICY` | 16 | Any/any rules, per-policy logging, security profiles, policy hygiene, egress filtering |
| 4 | SSL VPN | `FORTIOS-SSLVPN` | 14 | TLS version, ciphers, client cert, split tunneling, session limits, web-mode exposure |
| 5 | IPsec VPN | `FORTIOS-IPSEC` | 12 | Phase 1/2 crypto, DH groups, DPD, PFS, key lifetime, IKE version |
| 6 | Security Profiles | `FORTIOS-PROFILE/AV/IPS/WF/APP/DLP/DNS` | 11 | AV, IPS, WebFilter, AppControl, DLP, DNS filter, SSL inspection, email/file filters |
| 7 | Logging & Monitoring | `FORTIOS-LOG` | 18 | FortiAnalyzer, syslog, event logging, transport encryption, automation stitches, alerts |
| 8 | High Availability | `FORTIOS-HA` | 8 | HA mode, heartbeat auth/encryption, session pickup, firmware sync |
| 9 | Certificates | `FORTIOS-CERT` | 11 | Default certs, expiry, key strength, SHA-1, self-signed, wildcard, CRL/OCSP |
| 10 | Network Hardening | `FORTIOS-NET` | 18 | DoS policies, SNMP, routing auth, NTP, IPv6, anti-spoofing, LLDP, DNS encryption |
| 11 | FortiGuard Updates | `FORTIOS-UPDATE` | 7 | License status, signature freshness, EOL branch, auto-updates |
| 12 | ZTNA / SD-WAN | `FORTIOS-ZTNA` | 6 | Access proxy, client certs, SD-WAN health checks, SLA rules |
| 13 | Wireless Security | `FORTIOS-WIRELESS` | 9 | SSID security, WIDS, client isolation, CAPWAP, 802.11w/r |
| 14 | Backup & DR | `FORTIOS-BACKUP` | 5 | FortiManager, config revision, session pickup, USB auto-install |
| 15 | Authentication | `FORTIOS-AUTH` | 6 | LDAP/RADIUS/SAML security, MFA, server-identity verification |
| 16 | Advanced Hardening | mixed | ~15 | FIPS 140-2, TCP timers, SSH grace, SCP, MFA %, default admin, policy-profile analysis, log transport |

Plus two dynamic categories: **MITRE ATT&CK Resilience** (31 techniques) and **Known CVEs** (67).

### MITRE ATT&CK Resilience Testing

The scanner tests **31 MITRE ATT&CK Enterprise techniques across 11 tactics**, verifying that FortiGate controls can detect and block real-world attack scenarios. Each test checks a specific feature against the technique it should mitigate, and the run produces a **0–100% resilience score** (`MITRE-SUMMARY-SCORE`, or `MITRE-SUMMARY-PASS` at 100%).

| Tactic | Techniques | FortiGate Controls Verified |
|--------|:-:|-----------------------------|
| **Initial Access** | 4 | IPS coverage, AV + WebFilter on policies, VPN client cert, drive-by URL blocking |
| **Execution** | 2 | Application Control deployment, SSL deep inspection |
| **Persistence** | 1 | Admin MFA coverage |
| **Defense Evasion** | 5 | DNS filter, sandbox/outbreak prevention, external log forwarding, tunnel detection, port-agnostic AppCtrl |
| **Credential Access** | 2 | Account lockout threshold, HTTP on WAN/DMZ |
| **Discovery** | 1 | Inter-zone (east-west) IPS |
| **Lateral Movement** | 2 | Any/any/any policy detection, east-west exploit IPS |
| **Command & Control** | 6 | SSL deep inspection, proxy/RAT blocking, AV for tools, DGA detection, cloud-service C2 |
| **Exfiltration** | 3 | DLP sensors, DNS botnet/C2 blocking, cloud-storage control |
| **Impact** | 4 | DoS policies, ransomware sandbox, app-layer DoS, cryptomining detection |
| **Reconnaissance** | 1 | WAN management-interface exposure |

### Known CVEs

**67 CVEs (2019–2026)**, sourced from [FortiGuard PSIRT advisories](https://www.fortiguard.com/psirt?product=FortiOS) and matched against the parsed FortiOS version via train-based logic (trains 6.2, 6.4, 7.0, 7.2, 7.4, 7.6).

| Severity | Count | Highlights |
|----------|:-----:|------------|
| **CRITICAL** | 16 | CVE-2026-24858 (FortiCloud SSO bypass), CVE-2025-59718 (FortiCloud SSO SAML, CISA KEV), CVE-2024-55591 & CVE-2022-40684 (admin auth bypass, KEV), CVE-2024-47575 (FortiJump), CVE-2024-21762 (SSL-VPN OOB write), CVE-2023-27997 (xortigate), CVE-2022-42475 (sslvpnd) |
| **HIGH** | 27 | CVE-2026-22153 (LDAP/Agentless VPN bypass), CVE-2025-58325 (restricted CLI bypass), CVE-2025-53844 / CVE-2025-25249 (CAPWAP), CVE-2024-46670 (IPsec IKE OOB), CVE-2024-26009 (FGFM weak auth), CVE-2023-44250 (HA auth) |
| **MEDIUM** | 24 | CVE-2025-62439 (FSSO policy source-verification bypass), CVE-2025-68686 (SSL-VPN symlink re-persistence), CVE-2025-67862 (Lua CLI escape), CVE-2025-55018 (request smuggling), CVE-2024-3596 (Blast-RADIUS), CVE-2024-55599 (DNS-65 filter bypass), CVE-2024-50562 (SSL-VPN session expiration) |

> Related hardening check (not version-matched): `FORTIOS-SYS-018` flags disabled **private-data encryption**, the default-key weakness behind CVE-2026-25815 (exploited in the wild).

### Compliance Mapping

Every finding auto-resolves to controls across **5 frameworks** (77 rule-to-control mappings):

| Framework | Scope |
|-----------|-------|
| **CIS** | CIS FortiGate Benchmark, sections 2–14 |
| **PCI-DSS** | PCI-DSS 4.0, requirements 1, 2, 4, 5, 6, 7, 8, 10, 11, 12 |
| **NIST** | NIST SP 800-53 Rev 5 (AC, AU, CM, CP, IA, RA, SC, SI families) |
| **SOC 2** | SOC 2 Type II (CC6, CC7 criteria) |
| **HIPAA** | HIPAA Security Rule (§164.308, §164.312) |

Export the full mapping as audit evidence with `--compliance-csv`.

---

## Supported Targets

| Platform | FortiOS | Connection |
|----------|---------|------------|
| FortiGate NGFW (hardware) | 6.x, 7.x | REST API (HTTPS) or `.conf` |
| FortiGate-VM (cloud / on-prem) | 6.x, 7.x | REST API (HTTPS) or `.conf` |
| FortiWiFi appliances | 6.x, 7.x | REST API (HTTPS) or `.conf` |

---

## Installation

```bash
git clone https://github.com/Krishcalin/Fortinet-Network-Security.git
cd Fortinet-Network-Security

# Only needed for LIVE API mode:
pip install requests
```

**Offline mode needs no installation** — copy `fortinet_scanner.py`, `fortinet_offline_scanner.py`, and the four report modules (`remediation_kb.py`, `remediation_kb.json`, `fortinet_html.py`, `fortinet_pdf.py`, `pdf_writer.py`) to the operator workstation and run with the system Python. No `pip install`, no internet.

**Requirements:** Python 3.10+. Live mode also needs `requests`; offline mode is standard-library only.

---

## API Token Setup

1. On the FortiGate, go to **System → Administrators → Create New → REST API Admin**.
2. Set a username (e.g. `scanner-api`).
3. Assign an admin profile with **read-only** access.
4. (Recommended) Restrict **Trusted Hosts** to the scanner's IP.
5. Click **OK** and copy the generated API token.

> **Least privilege:** the scanner only reads configuration. A read-only profile is sufficient and strongly recommended. Store the token in an environment variable or secrets manager — never in code.

---

## Usage

```bash
# Basic scan (console output)
python fortinet_scanner.py 10.1.1.1 --token <API-TOKEN>

# Only HIGH and CRITICAL findings
python fortinet_scanner.py fw.corp.local --token <TOKEN> --severity HIGH

# Full report set: JSON + HTML + PDF + runbook + compliance CSV
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> \
    --json report.json --html report.html --pdf report.pdf \
    --remediation runbook.txt --compliance-csv audit.csv

# Token via environment variable
export FORTIOS_API_TOKEN="your-api-token-here"
python fortinet_scanner.py 10.1.1.1

# Verbose
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --verbose
```

### Multi-Device (Fleet) Scanning

```bash
# devices.json:
# [
#   {"host": "fw1.corp.local", "token": "token1", "name": "HQ-Firewall"},
#   {"host": "fw2.corp.local", "token": "token2", "name": "DR-Firewall"},
#   {"host": "10.1.1.1",       "token": "token3", "name": "Branch-FW"}
# ]

python fortinet_scanner.py --inventory devices.json --json unified_report.json
```

---

## Offline Mode (OT / Air-Gapped)

When the FortiGate lives in an OT / ICS / air-gapped network the live scanner cannot reach, audit an exported configuration backup instead. It runs the exact same 18 check methods and produces the same reports — with **zero third-party dependencies**.

**1. Export the config from the FortiGate** (one-time, by someone with console access):

```
FGT # execute backup config flash <filename>
# or via GUI: System > Configuration > Backup > Local PC
```

**2. Run the offline scanner on the backup file:**

```bash
# Console only
python fortinet_offline_scanner.py /path/to/fortigate.conf

# Full report set
python fortinet_offline_scanner.py fw1.conf \
    --json report.json --html report.html --pdf report.pdf \
    --remediation runbook.txt --compliance-csv audit.csv

# HIGH+ findings only, verbose
python fortinet_offline_scanner.py fw1.conf --severity HIGH -v
```

**Works offline (from the `.conf` alone):** all 18 check categories, all 67 CVEs, all 31 MITRE ATT&CK tests, all 77 compliance mappings, and the full 226-entry remediation runbook. Multi-VDOM configs collapse to the last-seen VDOM as an audit baseline.

**Skipped offline** (no runtime data in a static `.conf`): live FortiGuard license/subscription state, HA peer sync status, and current signature-database age. These fire normally in live mode.

---

## CLI Reference

**Live scanner**

```
usage: fortinet_scanner.py [-h] [--token TOKEN] [--verify-ssl] [--timeout SEC]
                           [--json FILE] [--html FILE] [--pdf FILE] [--remediation FILE]
                           [--compliance-csv FILE] [--inventory FILE]
                           [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                           [--verbose] [--version]
                           [host]

  host                    FortiGate hostname or IP (optional with --inventory)
  --token TOKEN           FortiOS REST API token (env: FORTIOS_API_TOKEN)
  --verify-ssl            Verify SSL certificate (default: disabled)
  --timeout SEC           API request timeout in seconds (default: 30)
  --json FILE             Save JSON report
  --html FILE             Save detailed interactive HTML report
  --pdf FILE              Save detailed PDF report (stdlib only)
  --remediation FILE      Export a detailed remediation runbook
  --compliance-csv FILE   Export compliance mapping CSV (CIS/PCI/NIST/SOC2/HIPAA)
  --inventory FILE        Multi-device JSON inventory for batch scanning
  --severity LEVEL        Minimum severity to report (default: LOW)
  --verbose, -v           Verbose output
  --version               Show version
```

**Offline scanner** — same reporting flags, minus the API/inventory options:

```
usage: fortinet_offline_scanner.py [-h] [--json FILE] [--html FILE] [--pdf FILE]
                                   [--remediation FILE] [--compliance-csv FILE]
                                   [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                                   [--verbose] [--version]
                                   conf
```

**Exit codes:** `0` = no CRITICAL/HIGH findings · `1` = one or more CRITICAL/HIGH findings (for CI/CD gating).

---

## CI/CD Integration

```yaml
- name: FortiGate Security Scan
  run: |
    pip install requests
    python fortinet_scanner.py ${{ secrets.FORTIGATE_HOST }} \
      --token ${{ secrets.FORTIOS_API_TOKEN }} \
      --severity HIGH \
      --json fortinet-report.json \
      --compliance-csv audit.csv \
      --remediation runbook.txt

- name: Upload Reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: fortinet-security-reports
    path: |
      fortinet-report.json
      audit.csv
      runbook.txt
```

The job fails automatically (exit `1`) whenever a CRITICAL or HIGH finding is present, gating the pipeline.

---

## Project Structure

```
Fortinet-Network-Security/
├── fortinet_scanner.py           # Live engine: checks, CVEs, MITRE, compliance, reports (~5,600 lines)
├── fortinet_offline_scanner.py   # Offline adapter: .conf parser + _api_get override (stdlib only)
├── remediation_kb.json           # 226-entry detailed remediation knowledge base
├── remediation_kb.py             # RemediationKB loader (exact + family-prefix resolution)
├── fortinet_html.py              # Rich self-contained HTML report generator
├── fortinet_pdf.py               # Paginated PDF report layout
├── pdf_writer.py                 # Minimal, dependency-free PDF 1.4 writer (stdlib only)
├── test_data/
│   ├── test_offline_parser.py    # 28 pytest cases for the .conf parser + end-to-end smoke
│   └── sample_insecure.conf      # Intentionally insecure config (~118 findings) for demos/tests
├── README.md
├── CLAUDE.md                     # Architecture & contributor notes
└── LICENSE
```

Run the tests with:

```bash
python -m pytest test_data/test_offline_parser.py -v
```

---

## Security Considerations

- **API token security** — store tokens in environment variables or a secrets manager, never in code.
- **Least privilege** — create API tokens with a **read-only** admin profile; the scanner never writes.
- **Trusted hosts** — restrict the API token to the scanner's source IP.
- **Network segmentation** — run scans from a dedicated management network.
- **SSL verification** — use `--verify-ssl` where the FortiGate presents a trusted certificate.
- **Review before applying** — the remediation runbook is guidance, not an auto-apply script. Read every command, note the *Service impact*, and test in a maintenance window.
- **Handle `.conf` files as secrets** — a FortiGate config backup contains every policy, certificate, pre-shared key, hashed admin password, and SNMP community on the device. Treat the `.conf` and all generated reports with the same controls you apply to the firewall itself: encrypted transport off the device, restricted storage, and deletion after the audit.

---

## Contributing

Issues and pull requests are welcome. When adding checks, CVEs, or remediation content:

- **New config check** — add findings inside the appropriate `_check_*` method; ID pattern `FORTIOS-{CATEGORY}-{NNN}`. Include `description`, `recommendation`, and `cwe`, and add a `COMPLIANCE_MAP` entry where applicable.
- **New CVE** — append to `FORTIOS_CVES` with `affected: [{"train": "7.4", "fixed": "7.4.10"}]` and verify the CVE ID/fixed version against the FortiGuard PSIRT advisory.
- **New remediation** — add a keyed entry to `remediation_kb.json` (`risk`, `steps`, `gui`, `cli`, `verify`, `rollback`, `impact`, `references`). Keep all report code **standard-library only** so offline mode keeps working.
- Add a test to `test_data/test_offline_parser.py` and keep the suite green.

See [CLAUDE.md](CLAUDE.md) for the full architecture and contributor guide.

---

## Disclaimer

This tool is provided for **authorized security assessment and educational use only**. It performs read-only analysis and does not modify the target device, but you are responsible for using it only against FortiGate devices you own or are explicitly authorized to assess. Remediation guidance is advisory; validate every change against your environment, vendor documentation, and change-management process before applying. Firmware upgrades and certain hardening changes can be service-affecting — see each finding's *Service impact* note. The authors accept no liability for misuse or for any disruption arising from applying the guidance.

---

## License

Licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

<p align="center"><sub>Built for network security engineers who have to fix the findings, not just list them.</sub></p>
