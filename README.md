<p align="center">
  <img src="banner.svg" alt="Fortinet FortiGate Security Scanner" width="900"/>
</p>

<h1 align="center">Fortinet FortiGate Security Scanner</h1>

<p align="center">
  <strong>Live-API & Offline Config Security Posture Assessment with MITRE ATT&CK Resilience Testing</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0.0-blue?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/FortiOS-6.x%20%7C%207.x-red?style=flat-square" alt="FortiOS"/>
  <img src="https://img.shields.io/badge/rules-260%2B-orange?style=flat-square" alt="Rules"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-30_techniques-dc2626?style=flat-square" alt="MITRE"/>
  <img src="https://img.shields.io/badge/CVEs-66-critical?style=flat-square" alt="CVEs"/>
  <img src="https://img.shields.io/badge/compliance-CIS%20%7C%20PCI--DSS%20%7C%20NIST%20%7C%20SOC2%20%7C%20HIPAA-blueviolet?style=flat-square" alt="Compliance"/>
  <img src="https://img.shields.io/badge/offline%20mode-OT%20%2F%20air--gapped-success?style=flat-square" alt="Offline"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
</p>

---

## Overview

The **Fortinet FortiGate Security Scanner** is a Python-based security assessment tool that evaluates FortiGate NGFW posture against industry best practices, compliance frameworks, MITRE ATT&CK techniques, and known vulnerabilities. It ships in two modes that share the same 260+ checks and rule set:

- **Live mode** (`fortinet_scanner.py`) — connects via the FortiOS REST API.
- **Offline mode** (`fortinet_offline_scanner.py`) — parses an exported `.conf` backup file with **zero network access** and **zero third-party dependencies**, designed for OT, ICS, and air-gapped environments where the live scanner cannot reach the firewall.

It performs **260+ security checks** across **18 check methods**, including:
- **Configuration auditing** — admin access, firewall policies, VPN, security profiles, logging, HA, certificates, network hardening, wireless, backup, authentication, ZTNA/SD-WAN, FIPS, session management
- **MITRE ATT&CK resilience** — 30 technique-specific tests across 10 tactics with a 0-100% resilience score
- **CVE detection** — 66 known FortiOS CVEs (2019-2026) with train-based firmware version matching, sourced from FortiGuard PSIRT
- **Compliance mapping** — CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA controls per finding
- **Remediation automation** — 42 FortiOS CLI config commands exported per finding

### Key Capabilities

| Capability | Details |
|-----------|---------|
| **260+ security rules** | 18 check methods covering all FortiGate security domains |
| **30 MITRE ATT&CK techniques** | Resilience testing across 10 tactics with percentage scoring |
| **66 known CVEs** | FortiGuard PSIRT 2019–2026 with train-based version matching (FortiOS 6.2 → 7.6) |
| **5 compliance frameworks** | CIS FortiGate, PCI-DSS 4.0, NIST 800-53 Rev 5, SOC 2 Type II, HIPAA |
| **42 remediation commands** | FortiOS CLI config blocks per finding (`--remediation`) |
| **Multi-device scanning** | Fleet-wide assessment via JSON inventory (`--inventory`) |
| **Offline / OT mode** | Audit from a `.conf` backup with no network access and no `pip install` |
| **6 output formats** | Console, JSON, HTML (dark theme), compliance CSV, remediation script, ATT&CK score |
| **Zero-agent** | REST API only, no software on target |
| **CI/CD ready** | Exit code 1 on CRITICAL/HIGH for pipeline gating |

---

## Features

| Feature | Description |
|---------|-------------|
| **18 Check Methods** | Admin access, system settings, firewall policies, SSL VPN, IPsec VPN, security profiles, logging, HA, certificates, network hardening, FortiGuard updates, ZTNA/SD-WAN, wireless, backup & DR, authentication, advanced hardening, MITRE ATT&CK resilience, known CVEs |
| **MITRE ATT&CK Resilience** | 30 techniques across 10 tactics: T1190, T1566, T1133, T1189, T1059, T1203, T1078, T1071, T1027, T1562, T1572, T1571, T1110, T1557, T1046, T1021, T1210, T1048, T1041, T1567, T1573, T1090, T1105, T1219, T1568, T1102, T1498, T1486, T1499, T1496, T1595 |
| **66 Known CVEs** | All major FortiGuard PSIRT advisories 2019–2026: CVE-2026-24858 (FortiCloud SSO), CVE-2025-59718, CVE-2025-24472, CVE-2025-22252, CVE-2024-55591, CVE-2024-21762, CVE-2024-23113, CVE-2024-47575 (FortiJump), CVE-2023-27997 (xortigate), CVE-2022-42475, CVE-2022-40684, and 55 more |
| **Compliance Mapping** | 76 rule-to-framework mappings across CIS, PCI-DSS, NIST, SOC2, HIPAA |
| **Remediation Export** | 42 FortiOS CLI config commands (`--remediation fix.txt`) |
| **Multi-Device Scanning** | JSON inventory for batch scanning with unified summary (`--inventory devices.json`) |
| **Compliance CSV** | Audit evidence export with per-framework control columns (`--compliance-csv`) |
| **Resilience Score** | 0-100% MITRE ATT&CK score showing defense coverage against real-world attacks |
| **Dark Theme HTML** | Interactive reports with severity filtering, search, and expandable details |
| **Single File** | Entire scanner in one Python file (~5,174 lines) |

---

## Supported Targets

| Platform | FortiOS Version | Connection |
|----------|----------------|------------|
| FortiGate NGFW (hardware) | 6.x, 7.x | REST API (HTTPS) |
| FortiGate-VM (cloud/on-prem) | 6.x, 7.x | REST API (HTTPS) |
| FortiWiFi appliances | 6.x, 7.x | REST API (HTTPS) |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  fortinet_scanner.py (v4.0.0)                 │
├──────────────────────────────────────────────────────────────┤
│  FORTIOS_CVES[]          30 CVE definitions (2019-2025)      │
│  COMPLIANCE_MAP{}        76 rule → CIS/PCI/NIST/SOC2/HIPAA   │
│  REMEDIATION_COMMANDS{}  42 FortiOS CLI fix commands          │
│  Finding                 __slots__ + compliance + remediation │
│  _ReportMixin            console, JSON, HTML, CSV, remediation│
│  FortinetScanner         18 _check_* methods (260+ rules)     │
│  MultiDeviceScanner      Fleet scanning + unified reports     │
│  _api_get(path)          Single swap point for live/offline   │
│  main()                  CLI with single + multi-device modes │
└──────────────────────────────────────────────────────────────┘
         ▲                              ▲
         │ inherits & overrides         │
         │ _api_get only                │
┌────────┴───────────────────────┐      │
│ fortinet_offline_scanner.py     │     │
│ (v1.0.0, stdlib only)           │     │
│   FortiGateConfParser           │     │
│   OfflineFortinetScanner        │     │
└─────────────────────────────────┘     │
         │                              │
         ▼                              ▼
   Live: FortiOS REST API        Offline: .conf backup
   /api/v2/cmdb/...                 (no network access)
   /api/v2/monitor/...
         │                              │
         └──────────────┬───────────────┘
                        ▼
                  Report Output
              Console | JSON | HTML
              CSV | Remediation | Score
```

### Scanner Flow

1. **Connect** — Authenticate to FortiGate via API token
2. **Discover** — Retrieve system info and firmware version
3. **Collect** — Pull configuration from 30+ API endpoints
4. **Audit** — Run 18 check methods across all security domains
5. **CVE Match** — Compare firmware against 30 known CVE version ranges
6. **MITRE Test** — Evaluate 30 ATT&CK technique mitigations, calculate resilience score
7. **Comply** — Map findings to CIS, PCI-DSS, NIST, SOC2, HIPAA controls
8. **Report** — Output to console, JSON, HTML, compliance CSV, remediation script

---

## Prerequisites

### Live mode (`fortinet_scanner.py`)
- **Python 3.10+**
- **requests** library (`pip install requests`)
- **FortiGate** with REST API enabled and an API token with read access

### Offline mode (`fortinet_offline_scanner.py`)
- **Python 3.10+** — **no other packages required** (stdlib only). Designed to run on locked-down
  OT operator workstations with no internet access for `pip install`.
- A FortiGate `.conf` backup file (`execute backup config flash` on the CLI or GUI > System >
  Configuration > Backup).

---

## Installation

```bash
git clone https://github.com/Krishcalin/Fortinet-Network-Security.git
cd Fortinet-Network-Security

# Only needed for live API mode:
pip install requests
```

For offline mode, copy `fortinet_scanner.py` and `fortinet_offline_scanner.py` to the operator
workstation. No installation step is required.

---

## API Token Setup

1. Navigate to **System > Administrators** on the FortiGate
2. Click **Create New > REST API Admin**
3. Set a username (e.g., `scanner-api`)
4. Assign an **admin profile** with **read-only** access
5. Optionally restrict **Trusted Hosts** to the scanner's IP
6. Click **OK** and copy the generated API token

> **Important**: Store the API token securely. It provides read access to the FortiGate configuration.

---

## Usage

### Basic Scan

```bash
python fortinet_scanner.py 10.1.1.1 --token <API-TOKEN>
```

### Filtered Scan

```bash
# Only show HIGH and CRITICAL findings
python fortinet_scanner.py fw.corp.local --token <TOKEN> --severity HIGH
```

### Report Generation

```bash
# Generate JSON and HTML reports
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --json report.json --html report.html

# Verbose output with all details
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --verbose
```

### Remediation Export

```bash
# Export FortiOS CLI config commands to fix findings
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --remediation fix_commands.txt
```

### Compliance Mapping Export

```bash
# Export audit evidence CSV mapped to CIS, PCI-DSS, NIST, SOC2, HIPAA
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --compliance-csv audit_evidence.csv
```

### Multi-Device Scanning

```bash
# Create an inventory file (devices.json):
# [
#   {"host": "fw1.corp.local", "token": "token1", "name": "HQ-Firewall"},
#   {"host": "fw2.corp.local", "token": "token2", "name": "DR-Firewall"},
#   {"host": "10.1.1.1",       "token": "token3", "name": "Branch-FW"}
# ]

# Scan all devices with unified reporting
python fortinet_scanner.py --inventory devices.json --json unified_report.json
```

### Environment Variables

```bash
export FORTIOS_API_TOKEN="your-api-token-here"
python fortinet_scanner.py 10.1.1.1
```

### Offline Mode (OT / Air-Gapped)

When the FortiGate sits in an OT / ICS / air-gapped network where the live scanner cannot
reach the management interface, use the offline scanner against a configuration backup file.
It runs the exact same 18 check methods and produces the same report formats.

**1. Export the config from the FortiGate** (one-time, by someone with console access):

```
FGT # execute backup config flash <filename>
# or via GUI: System > Configuration > Backup > Local PC
```

**2. Run the offline scanner on the backup file**:

```bash
# Console output only
python fortinet_offline_scanner.py /path/to/fortigate.conf

# Full report set
python fortinet_offline_scanner.py fw1.conf \
    --json   report.json \
    --html   report.html \
    --remediation     fix.txt \
    --compliance-csv  audit.csv

# Filter to HIGH+ findings only
python fortinet_offline_scanner.py fw1.conf --severity HIGH -v
```

**What works offline (from the .conf alone)**:
- All 18 check categories, all 30 CVEs, all 30 MITRE ATT&CK resilience tests, all 76 compliance
  mappings, all 42 remediation commands.
- Multi-VDOM configs (collapse to the last-seen VDOM as an audit baseline).

**What is skipped offline** (no runtime data in a .conf):
- Live FortiGuard license expiry / subscription state.
- HA peer sync status and firmware-mismatch detection.
- Current signature database age, active session tables.

These checks fire normally in live mode.

---

## MITRE ATT&CK Resilience Testing

The scanner tests **30 MITRE ATT&CK Enterprise techniques across 10 tactics**, verifying that FortiGate security controls can detect and block real-world attack scenarios. Each test checks a specific FortiGate feature against the ATT&CK technique it should mitigate.

| Tactic | Techniques Tested | FortiGate Controls Verified |
|--------|:-:|---------------------------|
| **Initial Access** | 4 | IPS coverage, AV + WebFilter on policies, VPN client cert, drive-by URL blocking |
| **Execution** | 2 | Application Control deployment, SSL deep inspection |
| **Persistence** | 1 | Admin MFA coverage percentage |
| **Defense Evasion** | 5 | DNS filter, sandbox/outbreak prevention, external log forwarding, tunnel detection, port-agnostic AppCtrl |
| **Credential Access** | 2 | Account lockout threshold, HTTP on WAN/DMZ |
| **Discovery** | 1 | Inter-zone (east-west) IPS |
| **Lateral Movement** | 2 | Any/any/any policy detection, east-west exploit IPS |
| **C2** | 6 | SSL deep inspection, proxy/RAT blocking, AV for tools, DGA detection, cloud service C2 |
| **Exfiltration** | 3 | DLP sensors, DNS botnet/C2 blocking, cloud storage control |
| **Impact** | 4 | DoS policies, ransomware sandbox, app-layer DoS, cryptomining detection |
| **Reconnaissance** | 1 | WAN management interface exposure |

**Resilience Score**: Each scan produces a 0-100% score. A `MITRE-SUMMARY-SCORE` finding shows how many of the 30 controls are properly configured. 100% = `MITRE-SUMMARY-PASS`.

---

## Check Categories

### Configuration Auditing (16 categories, 200+ rules)

| # | Category | Prefix | Rules | Key Checks |
|:-:|----------|--------|:-----:|------------|
| 1 | Admin Access | FORTIOS-ADMIN | 24 | HTTP admin, idle timeout, password policy, MFA, trusted hosts, API users, default admin |
| 2 | System Settings | FORTIOS-SYS | 12 | Strong crypto, banners, account lockout, TLS enforcement |
| 3 | Firewall Policies | FORTIOS-POLICY | 16 | Any/any rules, logging, security profiles, policy hygiene, egress filtering |
| 4 | SSL VPN | FORTIOS-SSLVPN | 14 | TLS version, ciphers, client cert, split tunneling, session limits, compression |
| 5 | IPsec VPN | FORTIOS-IPSEC | 12 | Phase 1/2 crypto, DH groups, DPD, PFS, key lifetime, IKE version |
| 6 | Security Profiles | FORTIOS-PROFILE | 11 | AV, IPS, WebFilter, AppControl, DLP, DNS, SSL inspection, email/file filters |
| 7 | Logging & Monitoring | FORTIOS-LOG | 18 | FortiAnalyzer, syslog, event logging, encryption, automation, alerts |
| 8 | High Availability | FORTIOS-HA | 8 | HA mode, heartbeat auth/encryption, session pickup, firmware sync |
| 9 | Certificates | FORTIOS-CERT | 11 | Default certs, expiry, key strength, SHA-1, self-signed, wildcard, CRL/OCSP |
| 10 | Network Hardening | FORTIOS-NET | 18 | DoS, SNMP, routing auth, NTP, IPv6, anti-spoofing, LLDP, DNS encryption |
| 11 | FortiGuard Updates | FORTIOS-UPDATE | 7 | License status, signature freshness, EOL branch, auto-updates |
| 12 | ZTNA / SD-WAN | FORTIOS-ZTNA | 6 | Access proxy, client certs, SD-WAN health checks, SLA rules |
| 13 | Wireless Security | FORTIOS-WIRELESS | 9 | SSID security, WIDS, client isolation, CAPWAP, 802.11w/r |
| 14 | Backup & DR | FORTIOS-BACKUP | 5 | FortiManager, config revision, session pickup, USB auto-install |
| 15 | Authentication | FORTIOS-AUTH | 6 | LDAP/RADIUS/SAML security, MFA, server identity verification |
| 16 | Advanced Hardening | FORTIOS-SYS/NET/etc. | ~15 | FIPS 140-2, TCP timers, SSH grace, SCP, DNS encryption, MFA %, default admin, policy profile analysis, log transport, certs, anti-spoofing, automation, SD-WAN |

### Known CVEs (66 CVEs across 2019–2026)

All CVEs are sourced from [FortiGuard PSIRT advisories](https://www.fortiguard.com/psirt?product=FortiOS) and matched against the parsed FortiOS version via the firmware train logic in `_check_cves`.

| Severity | Count | Highlights |
|----------|:-----:|------------|
| **CRITICAL** | 16 | CVE-2026-24858 (FortiCloud SSO bypass), CVE-2025-59718 (FortiCloud SSO multi-product), CVE-2025-24472 (CSF proxy), CVE-2025-22252 (TACACS+ bypass), CVE-2024-55591 (Node.js websocket), CVE-2024-47575 (FortiJump), CVE-2024-23113 (fgfmd format string), CVE-2024-21762 (SSL VPN OOB write), CVE-2023-42789 (captive portal), CVE-2023-27997 (xortigate), CVE-2022-42475 (sslvpnd + backdoor), CVE-2022-40684 (auth bypass) |
| **HIGH** | 27 | CVE-2026-22153 (LDAP/Agentless VPN bypass), CVE-2025-58325 (restricted CLI bypass), CVE-2025-53844 / CVE-2025-25249 (CAPWAP), CVE-2024-46670 (IPsec IKE OOB), CVE-2024-45324 (format strings), CVE-2024-26013 (FGFM cert), CVE-2024-26009 (FGFM weak auth), CVE-2023-44250 (HA auth), CVE-2023-41677 (admin cookie leakage) |
| **MEDIUM** | 23 | CVE-2025-68686 (SSL-VPN symlink re-persistence), CVE-2025-67862 (Lua CLI escape), CVE-2025-55018 (request smuggling), CVE-2024-3596 (RADIUS Blast-RADIUS), CVE-2024-55599 (DNS-65 filter bypass), CVE-2024-50562 (SSL-VPN session expiration) |

All entries include compliance mapping (CIS / PCI-DSS / NIST / SOC 2 / HIPAA) via the standard `FORTIOS-CVE` prefix in `COMPLIANCE_MAP`.

---

## CLI Reference

### Live scanner

```
usage: fortinet_scanner.py [-h] [--token TOKEN] [--verify-ssl] [--timeout SEC]
                           [--json FILE] [--html FILE] [--remediation FILE]
                           [--compliance-csv FILE] [--inventory FILE]
                           [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                           [--verbose] [--version]
                           [host]

positional arguments:
  host                    FortiGate hostname or IP (optional with --inventory)

options:
  --token TOKEN           FortiOS REST API token (env: FORTIOS_API_TOKEN)
  --verify-ssl            Verify SSL certificate (default: disabled)
  --timeout SEC           API request timeout in seconds (default: 30)
  --json FILE             Save JSON report
  --html FILE             Save interactive HTML report
  --remediation FILE      Export FortiOS CLI fix commands
  --compliance-csv FILE   Export compliance mapping CSV (CIS/PCI/NIST/SOC2/HIPAA)
  --inventory FILE        Multi-device JSON inventory for batch scanning
  --severity LEVEL        Minimum severity (default: LOW)
  --verbose, -v           Verbose output
  --version               Show version
```

### Offline scanner

```
usage: fortinet_offline_scanner.py [-h] [--json FILE] [--html FILE]
                                   [--remediation FILE] [--compliance-csv FILE]
                                   [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                                   [--verbose] [--version]
                                   conf

positional arguments:
  conf                    Path to a FortiGate .conf backup file

options:
  --json FILE             Save JSON report
  --html FILE             Save interactive HTML report
  --remediation FILE      Export FortiOS CLI fix commands
  --compliance-csv FILE   Export compliance mapping CSV (CIS/PCI/NIST/SOC2/HIPAA)
  --severity LEVEL        Minimum severity (default: LOW)
  --verbose, -v           Verbose output
  --version               Show version
```

---

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| **Console** | *(default)* | Colour-coded findings with compliance refs and CLI fix preview |
| **JSON** | `--json` | Full report with findings, compliance, remediation commands |
| **HTML** | `--html` | Dark-themed interactive report with filtering and search |
| **Remediation** | `--remediation` | FortiOS CLI config blocks per finding |
| **Compliance CSV** | `--compliance-csv` | Audit evidence: CIS, PCI-DSS, NIST, SOC2, HIPAA columns |
| **Unified JSON** | `--inventory + --json` | Multi-device aggregated report |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL or HIGH findings |
| `1` | One or more CRITICAL or HIGH findings detected |

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: FortiGate Security Scan
  run: |
    pip install requests
    python fortinet_scanner.py ${{ secrets.FORTIGATE_HOST }} \
      --token ${{ secrets.FORTIOS_API_TOKEN }} \
      --severity HIGH \
      --json fortinet-report.json \
      --compliance-csv audit.csv \
      --remediation fix.txt

- name: Upload Reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: fortinet-security-reports
    path: |
      fortinet-report.json
      audit.csv
      fix.txt
```

### Multi-Device Fleet Scan

```yaml
- name: Fleet Security Scan
  run: |
    pip install requests
    python fortinet_scanner.py \
      --inventory ${{ secrets.DEVICE_INVENTORY_PATH }} \
      --json fleet-report.json
```

---

## Security Considerations

- **API Token Security** — Store tokens in environment variables or secrets managers, never in code
- **Read-Only Access** — Create API tokens with read-only admin profiles
- **Trusted Hosts** — Restrict API token access to the scanner's IP address
- **Network Segmentation** — Run scans from a management network
- **SSL Verification** — Use `--verify-ssl` in environments with trusted certificates
- **Report Handling** — Reports contain sensitive configuration details; handle per data classification policy
- **Remediation Scripts** — Always review `--remediation` output before applying to production
- **Offline .conf Files** — A FortiGate config backup contains every policy, certificate, pre-shared key, hashed admin password, and SNMP community on the device. Treat the `.conf` artifact and any generated reports with the same controls you apply to the firewall itself: encrypted transport off the device, restricted storage, deletion after the audit.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
