# CLAUDE.md — Fortinet FortiGate Security Scanner

## Project Overview

Fortinet FortiGate Security Scanner — a live-API security posture assessment tool that connects to FortiGate NGFW appliances via the FortiOS REST API and audits configuration against security best practices, compliance frameworks (CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA), and known CVEs.

- **Language**: Python 3.10+ (requires `requests`)
- **Scanner file**: `fortinet_scanner.py` (single self-contained file, ~4,400 lines)
- **Version**: 4.0.0
- **License**: MIT

## Architecture

1. **`FORTIOS_CVES` list** — 30 known FortiOS CVEs (2019-2025) with train-based version matching.
2. **`COMPLIANCE_MAP` dict** — 45 rule-to-framework mappings (CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA).
3. **`REMEDIATION_COMMANDS` dict** — 42 FortiOS CLI config commands mapped to rule IDs.
4. **`Finding` class** — `rule_id, name, category, severity, description, recommendation, cwe, cve, compliance, remediation_cmd` (uses `__slots__`).
5. **`_ReportMixin`** — shared reporting: `print_report`, `save_json`, `save_html`, `save_remediation`, `save_compliance_csv`, `summary`, `filter_severity`.
6. **`FortinetScanner(_ReportMixin)`** — live API scanner with 17 check methods (220+ rules).
7. **`MultiDeviceScanner`** — batch scanning of multiple FortiGates with unified summary and JSON export.
8. **CLI**: `argparse` with `host`, `--token`, `--verify-ssl`, `--timeout`, `--json`, `--html`, `--remediation`, `--compliance-csv`, `--inventory`, `--severity`, `--verbose`, `--version`.
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

## Check Categories (17 check methods, 190+ config checks + 30 CVEs = 220+ rules)

| Category | Prefix | Check Method | Count |
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
| Known CVEs | FORTIOS-CVE | `_check_cves` | 30 |

## Compliance Framework Mapping (v4.0.0)

Every finding automatically resolves compliance references from `COMPLIANCE_MAP`:

| Framework | Scope | Controls Mapped |
|-----------|-------|-----------------|
| **CIS** | CIS FortiGate Benchmark | Sections 2-14 |
| **PCI-DSS** | PCI-DSS 4.0 | Requirements 1, 2, 4, 5, 6, 7, 8, 10, 11, 12 |
| **NIST** | NIST 800-53 Rev 5 | AC, AU, CM, CP, IA, RA, SC, SI families |
| **SOC2** | SOC 2 Type II | CC6, CC7 criteria |
| **HIPAA** | HIPAA Security Rule | 164.308, 164.312 sections |

Output formats:
- Console report: compliance refs inline per finding
- JSON report: `compliance` dict per finding
- Compliance CSV: `--compliance-csv audit.csv` (CIS/PCI-DSS/NIST/SOC2/HIPAA columns)

## Remediation Automation (v4.0.0)

42 FortiOS CLI remediation commands mapped in `REMEDIATION_COMMANDS`:

```bash
# Export remediation script
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --remediation fix.txt

# Output: FortiOS CLI config blocks per finding
# config system global
#   set admintimeout 5
# end
```

## Multi-Device Scanning (v4.0.0)

`MultiDeviceScanner` class enables fleet-wide assessment:

```bash
# Inventory file (devices.json):
# [{"host": "fw1", "token": "xxx", "name": "HQ-FW"},
#  {"host": "fw2", "token": "yyy", "name": "DR-FW"}]

python fortinet_scanner.py --inventory devices.json --json unified.json
```

Features:
- Sequential scanning with per-device error handling
- Unified summary table (hostname, model, version, finding counts, status)
- Grand total aggregation across all devices
- Unified JSON report with all devices and findings
- Exit code 1 if ANY device has CRITICAL/HIGH findings

## Known CVEs (30 entries, 2019-2025)

| ID Range | CVEs | Severity Mix |
|----------|------|-------------|
| FORTIOS-CVE-001 to 008 | 2024-2025 critical (auth bypass, RCE, format string) | 6 CRITICAL, 2 HIGH |
| FORTIOS-CVE-009 to 015 | 2020-2023 (session hijack, path traversal, buffer underwrite) | 1 CRITICAL, 5 HIGH, 1 MEDIUM |
| FORTIOS-CVE-016 to 020 | 2023-2024 (privilege, info disclosure, REST API, captive portal, IPS) | 1 CRITICAL, 3 HIGH, 1 MEDIUM |
| FORTIOS-CVE-021 to 030 | 2024-2025 NEW (path traversal, cookie bypass, CSF proxy, RADIUS, fgfmd, priv esc) | 3 CRITICAL, 5 HIGH, 2 MEDIUM |

## API Endpoints Used (30+)

| Check Group | Endpoint(s) |
|-------------|------------|
| System info | `/api/v2/monitor/system/status` |
| Admin access | `/api/v2/cmdb/system/admin`, `/api/v2/cmdb/system/api-user` |
| System settings | `/api/v2/cmdb/system/global`, `/api/v2/cmdb/system/settings`, `/api/v2/cmdb/system/dns` |
| Interfaces | `/api/v2/cmdb/system/interface` |
| Firewall policies | `/api/v2/cmdb/firewall/policy`, `/api/v2/cmdb/firewall/policy6` |
| SSL VPN | `/api/v2/cmdb/vpn.ssl/settings`, `/api/v2/cmdb/vpn.ssl.web/portal` |
| IPsec VPN | `/api/v2/cmdb/vpn.ipsec/phase1-interface`, `/api/v2/cmdb/vpn.ipsec/phase2-interface` |
| Security profiles | `/api/v2/cmdb/antivirus/profile`, `/api/v2/cmdb/ips/sensor`, `/api/v2/cmdb/webfilter/profile`, `/api/v2/cmdb/application/list`, `/api/v2/cmdb/dlp/sensor`, `/api/v2/cmdb/dnsfilter/profile`, `/api/v2/cmdb/firewall/ssl-ssh-profile` |
| Logging | `/api/v2/cmdb/log.fortianalyzer/setting`, `/api/v2/cmdb/log.syslogd/setting`, `/api/v2/cmdb/log/setting` |
| HA | `/api/v2/cmdb/system/ha` |
| Certificates | `/api/v2/cmdb/vpn.certificate/local` |
| Network | `/api/v2/cmdb/firewall/DoS-policy`, `/api/v2/cmdb/router/bgp`, `/api/v2/cmdb/router/ospf`, `/api/v2/cmdb/system.snmp/community`, `/api/v2/cmdb/system/ntp` |
| ZTNA / SD-WAN | `/api/v2/cmdb/firewall/access-proxy`, `/api/v2/cmdb/system/sdwan` |
| FortiGuard | `/api/v2/monitor/license/status`, `/api/v2/monitor/system/fortiguard-service-status` |
| Wireless | `/api/v2/cmdb/wireless-controller/wtp-profile`, `/api/v2/cmdb/wireless-controller/vap`, `/api/v2/cmdb/wireless-controller/wids-profile` |
| Backup & DR | `/api/v2/cmdb/system/central-management` |
| Authentication | `/api/v2/cmdb/user/ldap`, `/api/v2/cmdb/user/radius`, `/api/v2/cmdb/user/saml`, `/api/v2/cmdb/user/local` |
| Automation | `/api/v2/cmdb/system/automation-trigger` |

## CVE Version Matching

- `_parse_ver(s)` — splits version string into tuple of ints.
- `_ver_in_train(ver, train)` — checks if firmware is in a specific release train (e.g., `7.0.x`).
- `_ver_lt(a, b)` — lexicographic less-than comparison of version tuples.
- Each CVE has `affected` list of `{"train": "7.0", "fixed": "7.0.17"}` dicts.

## Development Guidelines

### Adding New Config Checks

1. Add findings inside the appropriate `_check_*` method (or `_check_advanced_hardening` for new domains).
2. Follow the ID pattern: `FORTIOS-{CATEGORY}-{NNN}`.
3. Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
4. Always include `description`, `recommendation`, and `cwe`.
5. Add compliance mapping to `COMPLIANCE_MAP` if applicable.
6. Add remediation command to `REMEDIATION_COMMANDS` if applicable.

### Adding New CVEs

1. Add the CVE dict to `FORTIOS_CVES` list at module level.
2. Follow the ID pattern: `FORTIOS-CVE-{NNN}`.
3. Include `affected` list with train-based version ranges.
4. Include `cve`, `cwe`, `description`, `recommendation`.

### Adding Compliance Mappings

1. Add to `COMPLIANCE_MAP` dict with rule ID as key.
2. Value is dict of framework -> list of control IDs.
3. Supported frameworks: `CIS`, `PCI-DSS`, `NIST`, `SOC2`, `HIPAA`.
4. Prefix matching: `FORTIOS-CVE` matches all CVE rules.

### Testing

```bash
python fortinet_scanner.py --version
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --verbose
python fortinet_scanner.py fw.corp.local --token <TOKEN> --json report.json --html report.html
python fortinet_scanner.py fw.corp.local --token <TOKEN> --remediation fix.txt --compliance-csv audit.csv
python fortinet_scanner.py --inventory devices.json --json unified.json
```

## Conventions

- Single-file scanner — all checks, engine, reports, and multi-device support in `fortinet_scanner.py`.
- Requires `requests` library (`pip install requests`).
- API token also accepted via env var: `FORTIOS_API_TOKEN`.
- SSL verification disabled by default (FortiGate appliances typically use self-signed certs).
- HTML reports use dark theme (Catppuccin Mocha palette: `#1a1b2e` background, `#cdd6f4` text).
- Keep check descriptions actionable — always include a concrete `recommendation`.
- Every finding auto-resolves compliance mapping and remediation commands.
