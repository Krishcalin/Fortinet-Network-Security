# CLAUDE.md — Fortinet FortiGate Security Scanner

## Project Overview

Fortinet FortiGate Security Scanner — a live-API security posture assessment tool that connects
to FortiGate NGFW appliances via the FortiOS REST API and audits configuration against security
best practices, 5 compliance frameworks (CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA), 30 known
CVEs, and 30 MITRE ATT&CK technique resilience tests.

- **Language**: Python 3.10+ (requires `requests`)
- **Scanner file**: `fortinet_scanner.py` (single self-contained file, ~5,174 lines)
- **Version**: 4.0.0
- **License**: MIT

## Architecture

1. **`FORTIOS_CVES` list** — 30 known FortiOS CVEs (2019-2025) with train-based version matching.
2. **`COMPLIANCE_MAP` dict** — 76 rule-to-framework mappings (CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA).
3. **`REMEDIATION_COMMANDS` dict** — 42 FortiOS CLI config commands mapped to rule IDs.
4. **`Finding` class** — `__slots__` with `rule_id, name, category, severity, description, recommendation, cwe, cve, compliance, remediation_cmd`. Auto-resolves compliance + remediation on init.
5. **`_ReportMixin`** — `print_report`, `save_json`, `save_html`, `save_remediation`, `save_compliance_csv`, `summary`, `filter_severity`.
6. **`FortinetScanner(_ReportMixin)`** — 18 `_check_*` methods producing 260+ possible findings.
7. **`MultiDeviceScanner`** — batch scanning of multiple FortiGates with unified summary and JSON export.
8. **CLI** — `argparse` with `host`, `--token`, `--verify-ssl`, `--timeout`, `--json`, `--html`, `--remediation`, `--compliance-csv`, `--inventory`, `--severity`, `--verbose`, `--version`.
9. **Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise.

## API Connection

| Setting | Details |
|---------|---------|
| Base URL | `https://{host}/api/v2/` |
| Auth | `Authorization: Bearer {token}` header |
| Config endpoints | `/api/v2/cmdb/{path}` |
| Monitor endpoints | `/api/v2/monitor/{path}` |
| SSL | Self-signed certs accepted by default; `--verify-ssl` to enforce |
| Token env var | `FORTIOS_API_TOKEN` |

## Check Methods (18 methods, 260+ rules)

| Category | Prefix | Check Method | Rules |
|----------|--------|-------------|-------|
| Admin Access | FORTIOS-ADMIN | `_check_admin_access` | 24 |
| System Settings | FORTIOS-SYS | `_check_system_settings` | 12 |
| Firewall Policies | FORTIOS-POLICY | `_check_firewall_policies` | 16 |
| SSL VPN | FORTIOS-SSLVPN | `_check_ssl_vpn` | 14 |
| IPsec VPN | FORTIOS-IPSEC | `_check_ipsec_vpn` | 12 |
| Security Profiles | FORTIOS-PROFILE/AV/IPS/WF/APP/DLP/DNS | `_check_security_profiles` | 11 |
| Logging & Monitoring | FORTIOS-LOG | `_check_logging` | 18 |
| High Availability | FORTIOS-HA | `_check_ha` | 8 |
| Certificates | FORTIOS-CERT | `_check_certificates` | 11 |
| Network Hardening | FORTIOS-NET | `_check_network` | 18 |
| FortiGuard Updates | FORTIOS-UPDATE | `_check_fortiguard` | 7 |
| ZTNA / SASE / SD-WAN | FORTIOS-ZTNA | `_check_ztna` | 6 |
| Wireless Security | FORTIOS-WIRELESS | `_check_wireless` | 9 |
| Backup & DR | FORTIOS-BACKUP | `_check_backup` | 5 |
| Authentication | FORTIOS-AUTH | `_check_authentication` | 6 |
| Advanced Hardening | FORTIOS-SYS/NET/POLICY/LOG/CERT/ZTNA | `_check_advanced_hardening` | ~15 |
| MITRE ATT&CK Resilience | MITRE-T{NNNN}-{NNN} | `_check_mitre_attack_resilience` | ~30 |
| Known CVEs | FORTIOS-CVE | `_check_cves` | 30 |

## Compliance Framework Mapping

76 rule-to-framework mappings. Every finding auto-resolves compliance on init via `Finding._resolve_compliance()`.

| Framework | Scope | Controls Mapped |
|-----------|-------|-----------------|
| **CIS** | CIS FortiGate Benchmark | Sections 2-14 |
| **PCI-DSS** | PCI-DSS 4.0 | Requirements 1, 2, 4, 5, 6, 7, 8, 10, 11, 12 |
| **NIST** | NIST 800-53 Rev 5 | AC, AU, CM, CP, IA, RA, SC, SI families |
| **SOC2** | SOC 2 Type II | CC6, CC7 criteria |
| **HIPAA** | HIPAA Security Rule | 164.308, 164.312 sections |

Output: console (inline), JSON (`compliance` dict), compliance CSV (`--compliance-csv`).

## Remediation Automation

42 FortiOS CLI commands in `REMEDIATION_COMMANDS`. Auto-resolved per finding. Export via `--remediation fix.txt`.

## Multi-Device Scanning

`MultiDeviceScanner` class. Inventory file (`--inventory devices.json`): `[{"host":"fw1","token":"xxx","name":"HQ-FW"}]`. Features: sequential scan with error handling, unified summary table, unified JSON, exit code 1 if any device has CRITICAL/HIGH.

## MITRE ATT&CK Resilience Testing

`_check_mitre_attack_resilience()` tests **30 MITRE ATT&CK Enterprise techniques across 10 tactics**. Each test verifies a specific FortiGate control is configured to mitigate the attack vector. Produces a resilience score (0-100%).

| Tactic | Techniques |
|--------|-----------|
| **Initial Access** (TA0001) | T1190 (IPS coverage), T1566 (AV+WebFilter), T1133 (VPN cert auth), T1189 (WebFilter coverage) |
| **Execution** (TA0002) | T1059 (AppControl), T1203 (SSL deep inspection) |
| **Persistence** (TA0003) | T1078 (admin MFA) |
| **Defense Evasion** (TA0005) | T1071 (DNS filter), T1027 (sandbox), T1562 (log forwarding), T1572 (tunnel detection), T1571 (AppControl) |
| **Credential Access** (TA0006) | T1110 (account lockout), T1557 (HTTP on WAN) |
| **Discovery** (TA0007) | T1046 (inter-zone IPS) |
| **Lateral Movement** (TA0008) | T1021 (any/any/any policies), T1210 (east-west exploit detection) |
| **C2** (TA0011) | T1573 (SSL inspection), T1090 (proxy blocking), T1105 (AV for tools), T1219 (RAT blocking), T1568 (DGA/DNS), T1102 (cloud C2) |
| **Exfiltration** (TA0010) | T1048 (DLP), T1041 (DNS botnet), T1567 (cloud storage) |
| **Impact** (TA0040) | T1498 (DoS policies), T1486 (ransomware sandbox), T1499 (app-layer DoS), T1496 (cryptomining) |
| **Reconnaissance** (TA0043) | T1595 (WAN management exposure) |

Scoring: `MITRE-SUMMARY-PASS` (all 30 pass) or `MITRE-SUMMARY-SCORE` (percentage).

## Known CVEs (30 entries, 2019-2025)

| Range | Count | Severity Mix |
|-------|-------|-------------|
| CVE-001 to 008 | 8 | 6 CRITICAL, 2 HIGH |
| CVE-009 to 015 | 7 | 1 CRITICAL, 5 HIGH, 1 MEDIUM |
| CVE-016 to 020 | 5 | 1 CRITICAL, 3 HIGH, 1 MEDIUM |
| CVE-021 to 030 | 10 | 3 CRITICAL, 5 HIGH, 2 MEDIUM (2024-2025 new) |

Train-based matching: `_parse_ver()`, `_ver_in_train()`, `_ver_lt()`. Trains: 6.2, 6.4, 7.0, 7.2, 7.4, 7.6.

## API Endpoints Used (30+)

System status, admin accounts, API users, global settings, DNS, interfaces, firewall policies, SSL VPN, IPsec VPN, security profiles (AV, IPS, WebFilter, AppCtrl, DLP, DNS filter, SSL-SSH, email filter, file filter, ICAP), logging (FAZ, syslog, event), HA, certificates, network (DoS, BGP, OSPF, SNMP, NTP), ZTNA/SD-WAN, FortiGuard licensing, wireless (VAP, WTP, WIDS), central management, authentication (LDAP, RADIUS, SAML, local), automation triggers.

## Development Guidelines

### Adding New Config Checks
1. Add findings inside the appropriate `_check_*` method.
2. ID pattern: `FORTIOS-{CATEGORY}-{NNN}` or `MITRE-T{NNNN}-{NNN}`.
3. Always include `description`, `recommendation`, and `cwe`.
4. Add compliance mapping to `COMPLIANCE_MAP` if applicable.
5. Add remediation command to `REMEDIATION_COMMANDS` if applicable.

### Adding New CVEs
1. Append to `FORTIOS_CVES` list. ID: `FORTIOS-CVE-{NNN}`.
2. Include `affected` list with `{"train": "7.0", "fixed": "7.0.17"}` dicts.

### Adding MITRE ATT&CK Checks
1. Add to `_check_mitre_attack_resilience()`. ID: `MITRE-T{NNNN}-{NNN}`.
2. Add compliance mapping to `COMPLIANCE_MAP` with `MITRE-T{NNNN}` prefix key.
3. Update the total technique count in the resilience summary.

### Running
```bash
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --verbose
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --json report.json --html report.html
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --remediation fix.txt --compliance-csv audit.csv
python fortinet_scanner.py --inventory devices.json --json unified.json
```

## Conventions

- Single-file scanner: all logic in `fortinet_scanner.py`.
- Requires `requests` (`pip install requests`).
- Token via `--token` or env `FORTIOS_API_TOKEN`.
- SSL verification disabled by default (FortiGate self-signed certs).
- HTML reports: Catppuccin Mocha dark theme (`#1a1b2e` bg, `#cdd6f4` text).
- Every finding auto-resolves compliance mapping and remediation commands.
