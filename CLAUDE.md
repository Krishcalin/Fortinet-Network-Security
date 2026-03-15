# CLAUDE.md — Fortinet FortiGate Security Scanner

## Project Overview

Fortinet FortiGate Security Scanner — a live-API security posture assessment tool that connects to FortiGate NGFW appliances via the FortiOS REST API and audits configuration against security best practices and known CVEs.

- **Language**: Python 3.10+ (requires `requests`)
- **Scanner file**: `fortinet_scanner.py` (single self-contained file)
- **Version**: 2.0.0
- **License**: MIT

## Architecture

1. **`FORTIOS_CVES` list** — 20 known FortiOS CVEs with train-based version matching.
2. **`Finding` class** — `rule_id, name, category, severity, description, recommendation, cwe, cve` (uses `__slots__`).
3. **`_ReportMixin`** — shared reporting: `SEVERITY_ORDER`, `print_report`, `save_json`, `save_html`, `summary`, `filter_severity`.
4. **`FortinetScanner(_ReportMixin)`** — live API scanner with 13 check methods.
5. **CLI**: `argparse` with `host`, `--token`, `--verify-ssl`, `--timeout`, `--json`, `--html`, `--severity`, `--verbose`, `--version`.
6. **Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise.

## API Connection

| Setting | Details |
|---------|---------|
| Base URL | `https://{host}/api/v2/` |
| Auth | `Authorization: Bearer {token}` header |
| Config endpoints | `/api/v2/cmdb/{path}` |
| Monitor endpoints | `/api/v2/monitor/{path}` |
| SSL | Self-signed certs accepted by default; `--verify-ssl` to enforce |
| Token env var | `FORTIOS_API_TOKEN` |

## Check Categories (12 groups, 133 config checks + 20 CVEs = 153 rules)

| Category | Prefix | Check Method | Count |
|----------|--------|-------------|-------|
| Admin Access | FORTIOS-ADMIN | `_check_admin_access` | 12 |
| System Settings | FORTIOS-SYS | `_check_system_settings` | 12 |
| Firewall Policies | FORTIOS-POLICY | `_check_firewall_policies` | 12 |
| SSL VPN | FORTIOS-SSLVPN | `_check_ssl_vpn` | 10 |
| IPsec VPN | FORTIOS-IPSEC | `_check_ipsec_vpn` | 12 |
| Security Profiles | FORTIOS-PROFILE/AV/IPS/WF/APP/DLP/DNS | `_check_security_profiles` | 19 |
| Logging & Monitoring | FORTIOS-LOG | `_check_logging` | 13 |
| High Availability | FORTIOS-HA | `_check_ha` | 8 |
| Certificates | FORTIOS-CERT | `_check_certificates` | 8 |
| Network Hardening | FORTIOS-NET | `_check_network` | 16 |
| FortiGuard Updates | FORTIOS-UPDATE | `_check_fortiguard` | 7 |
| ZTNA / SASE / SD-WAN | FORTIOS-ZTNA | `_check_ztna` | 5 |
| Known CVEs | FORTIOS-CVE | `_check_cves` | 20 |

## API Endpoints Used

| Check Group | Endpoint(s) |
|-------------|------------|
| System info | `/api/v2/monitor/system/status` |
| Admin access | `/api/v2/cmdb/system/admin`, `/api/v2/cmdb/system/api-user` |
| System settings | `/api/v2/cmdb/system/global`, `/api/v2/cmdb/system/settings` |
| Interfaces | `/api/v2/cmdb/system/interface` |
| Firewall policies | `/api/v2/cmdb/firewall/policy`, `/api/v2/cmdb/firewall/policy6` |
| SSL VPN | `/api/v2/cmdb/vpn.ssl/settings`, `/api/v2/cmdb/vpn.ssl.web/portal`, `/api/v2/cmdb/user/group` |
| IPsec VPN | `/api/v2/cmdb/vpn.ipsec/phase1-interface`, `/api/v2/cmdb/vpn.ipsec/phase2-interface` |
| Security profiles | `/api/v2/cmdb/antivirus/profile`, `/api/v2/cmdb/ips/sensor`, `/api/v2/cmdb/webfilter/profile`, `/api/v2/cmdb/application/list`, `/api/v2/cmdb/dlp/sensor`, `/api/v2/cmdb/dnsfilter/profile`, `/api/v2/cmdb/firewall/ssl-ssh-profile` |
| Logging | `/api/v2/cmdb/log.fortianalyzer/setting`, `/api/v2/cmdb/log.syslogd/setting`, `/api/v2/cmdb/log/setting`, `/api/v2/cmdb/log/eventfilter` |
| HA | `/api/v2/cmdb/system/ha`, `/api/v2/monitor/system/ha-peer` |
| Certificates | `/api/v2/cmdb/vpn.certificate/local`, `/api/v2/monitor/system/certificate` |
| Network | `/api/v2/cmdb/firewall/DoS-policy`, `/api/v2/cmdb/router/bgp`, `/api/v2/cmdb/router/ospf`, `/api/v2/cmdb/system.snmp/community`, `/api/v2/cmdb/system.snmp/user`, `/api/v2/cmdb/system/ntp` |
| ZTNA / SD-WAN | `/api/v2/cmdb/firewall/access-proxy`, `/api/v2/cmdb/system/sdwan` |
| FortiGuard | `/api/v2/monitor/license/status`, `/api/v2/monitor/system/fortiguard-service-status`, `/api/v2/cmdb/system/autoupdate/schedule` |

## CVE Version Matching

- `_parse_ver(s)` — splits version string into tuple of ints.
- `_ver_in_train(ver, train)` — checks if firmware is in a specific release train (e.g., `7.0.x`).
- `_ver_lt(a, b)` — lexicographic less-than comparison of version tuples.
- Each CVE has `affected` list of `{"train": "7.0", "fixed": "7.0.17"}` dicts.

## Development Guidelines

### Adding New Config Checks

1. Add findings inside the appropriate `_check_*` method.
2. Follow the ID pattern: `FORTIOS-{CATEGORY}-{NNN}`.
3. Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
4. Always include `description`, `recommendation`, and `cwe`.

### Adding New CVEs

1. Add the CVE dict to `FORTIOS_CVES` list at module level.
2. Follow the ID pattern: `FORTIOS-CVE-{NNN}`.
3. Include `affected` list with train-based version ranges.
4. Include `cve`, `cwe`, `description`, `recommendation`.

### Testing

```bash
python fortinet_scanner.py --version
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --verbose
python fortinet_scanner.py fw.corp.local --token <TOKEN> --json report.json --html report.html
```

## Conventions

- Single-file scanner — all checks, engine, and reports in `fortinet_scanner.py`.
- Requires `requests` library (`pip install requests`).
- API token also accepted via env var: `FORTIOS_API_TOKEN`.
- SSL verification disabled by default (FortiGate appliances typically use self-signed certs).
- HTML reports use dark theme (Catppuccin Mocha palette: `#1a1b2e` background, `#cdd6f4` text).
- Keep check descriptions actionable — always include a concrete `recommendation`.
