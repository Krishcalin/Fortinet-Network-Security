# CLAUDE.md — Fortinet FortiGate Security Scanner

## Project Overview

Fortinet FortiGate Security Scanner — a security posture assessment tool that audits FortiGate
NGFW configuration against security best practices, 5 compliance frameworks (CIS, PCI-DSS,
NIST 800-53, SOC 2, HIPAA), 67 known CVEs (2019–2026), and 31 MITRE ATT&CK technique
resilience tests.

Ships in two modes that share the same 18 check methods and rule set:
1. **Live mode** — `fortinet_scanner.py`, connects to FortiGate via the FortiOS REST API.
2. **Offline mode** — `fortinet_offline_scanner.py`, parses an exported `.conf` backup for
   OT / air-gapped environments where direct network access is impossible. Stdlib-only.

- **Language**: Python 3.10+ (live mode also needs `requests`; offline mode has no third-party deps)
- **Scanner files**: `fortinet_scanner.py` (~5,500 lines, all check logic) +
  `fortinet_offline_scanner.py` (~340 lines, parser + adapter)
- **Reporting files** (all stdlib-only, so offline mode keeps zero third-party deps):
  - `remediation_kb.py` + `remediation_kb.json` — 226-entry detailed remediation knowledge base
  - `fortinet_html.py` — rich self-contained HTML report (`FortinetHTMLReport`)
  - `fortinet_pdf.py` + `pdf_writer.py` — paginated PDF report (`FortinetPDFReport`) on a hand-rolled PDF 1.4 writer (no reportlab/weasyprint)
- **Version**: 4.0.0 (engine) / 1.0.0 (offline adapter)
- **License**: MIT

## Architecture

1. **`FORTIOS_CVES` list** — 67 known FortiOS CVEs (2019-2026) with train-based version matching, sourced from FortiGuard PSIRT advisories.
2. **`COMPLIANCE_MAP` dict** — 77 rule-to-framework mappings (CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA).
3. **`REMEDIATION_COMMANDS` dict** — 43 FortiOS CLI config commands mapped to rule IDs.
4. **`Finding` class** — `__slots__` with `rule_id, name, category, severity, description, recommendation, cwe, cve, compliance, remediation_cmd`. Auto-resolves compliance + remediation on init.
5. **`_ReportMixin`** — `print_report`, `save_json`, `save_html`, `save_pdf`, `save_remediation`, `save_compliance_csv`, `summary`, `filter_severity`, plus `_report_kb()` / `_report_meta()` helpers.
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
| System Settings | FORTIOS-SYS | `_check_system_settings` | 13 |
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
| MITRE ATT&CK Resilience | MITRE-T{NNNN}-{NNN} | `_check_mitre_attack_resilience` | 31 |
| Known CVEs | FORTIOS-CVE | `_check_cves` | 67 |

## Compliance Framework Mapping

77 rule-to-framework mappings. Every finding auto-resolves compliance on init via `Finding._resolve_compliance()`.

| Framework | Scope | Controls Mapped |
|-----------|-------|-----------------|
| **CIS** | CIS FortiGate Benchmark | Sections 2-14 |
| **PCI-DSS** | PCI-DSS 4.0 | Requirements 1, 2, 4, 5, 6, 7, 8, 10, 11, 12 |
| **NIST** | NIST 800-53 Rev 5 | AC, AU, CM, CP, IA, RA, SC, SI families |
| **SOC2** | SOC 2 Type II | CC6, CC7 criteria |
| **HIPAA** | HIPAA Security Rule | 164.308, 164.312 sections |

Output: console (inline), JSON (`compliance` dict), compliance CSV (`--compliance-csv`).

## Remediation & Reporting

**Two-tier remediation.** The bare `Finding` carries `recommendation` (one line) + `remediation_cmd`
(auto-resolved from the 43-entry `REMEDIATION_COMMANDS`). On top of that, `remediation_kb.json`
(226 entries, loaded by `RemediationKB` in `remediation_kb.py`) supplies the **detailed** fix per
rule: `risk`, numbered `steps`, `gui` path, canonical `cli`, `verify` command, `rollback`, service
`impact`, and `references`. `RemediationKB.detail_for(finding)` resolves exact `rule_id` → family
prefix (e.g. `FORTIOS-CVE` covers every CVE) → graceful fallback to the finding's own text, so a
report section is never empty. It covers **every** emitted rule_id (0 gaps).

**Reports** (all consume the KB via `_report_kb()` / `_report_meta()` on `_ReportMixin`):
- `save_html` → `fortinet_html.FortinetHTMLReport`: rich self-contained HTML (risk gauge, severity /
  compliance / ATT&CK visuals, collapsible per-finding cards with the full remediation, filters,
  `@media print`).
- `save_pdf` → `fortinet_pdf.FortinetPDFReport`: paginated PDF (cover + device panel, exec summary,
  detailed finding blocks) on the stdlib `pdf_writer.PDFWriter`.
- `save_remediation` → a detailed text **runbook** (risk / steps / GUI / CLI / verify / rollback /
  impact / references per finding), not a bare CLI dump.

CLI flags: `--html`, `--pdf`, `--remediation`, `--compliance-csv` (both live and offline scanners).

## Multi-Device Scanning

`MultiDeviceScanner` class. Inventory file (`--inventory devices.json`): `[{"host":"fw1","token":"xxx","name":"HQ-FW"}]`. Features: sequential scan with error handling, unified summary table, unified JSON, exit code 1 if any device has CRITICAL/HIGH.

## MITRE ATT&CK Resilience Testing

`_check_mitre_attack_resilience()` tests **31 MITRE ATT&CK Enterprise techniques across 11 tactics**. Each test verifies a specific FortiGate control is configured to mitigate the attack vector. Produces a resilience score (0-100%).

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

Scoring: `MITRE-SUMMARY-PASS` (all 31 pass) or `MITRE-SUMMARY-SCORE` (percentage).

## Known CVEs (67 entries, 2019-2026)

| Range | Count | Severity Mix | Notes |
|-------|-------|-------------|-------|
| CVE-001 to 015 | 15 | 8 CRITICAL, 6 HIGH, 1 MEDIUM | KEV-listed SSL VPN / fgfmd RCEs, FortiJump, xortigate |
| CVE-016 to 030 | 15 | 5 CRITICAL, 7 HIGH, 3 MEDIUM | 2024-2025 CVEs, CSF proxy auth bypass, TACACS+ bypass |
| CVE-031 to 046 | 16 | 2 CRITICAL, 14 HIGH | 2023-2026 sweep: CAPWAP, IPsec IKE, FGFM, restricted CLI escape, LDAP bypass |
| CVE-047 to 067 | 21 | 0 CRITICAL, 0 HIGH, 21 MEDIUM | SSL-VPN symlink re-persistence, RADIUS Blast-RADIUS, request smuggling, DNS-65 filter bypass, session expiration, FSSO policy source-verification bypass |

Totals: **16 CRITICAL, 27 HIGH, 24 MEDIUM** across all 6 supported version trains.

Train-based matching: `_parse_ver()`, `_ver_in_train()`, `_ver_lt()`. Trains: 6.2, 6.4, 7.0, 7.2, 7.4, 7.6.

Source: FortiGuard PSIRT advisories (https://www.fortiguard.com/psirt?product=FortiOS). Fixed
version derived as (max-affected-version + 1 patch) per Fortinet's release convention; verified
against several published advisories.

## API Endpoints Used (30+)

System status, admin accounts, API users, global settings, DNS, interfaces, firewall policies, SSL VPN, IPsec VPN, security profiles (AV, IPS, WebFilter, AppCtrl, DLP, DNS filter, SSL-SSH, email filter, file filter, ICAP), logging (FAZ, syslog, event), HA, certificates, network (DoS, BGP, OSPF, SNMP, NTP), ZTNA/SD-WAN, FortiGuard licensing, wireless (VAP, WTP, WIDS), central management, authentication (LDAP, RADIUS, SAML, local), automation triggers.

## Offline Scanner (`fortinet_offline_scanner.py`)

For OT / air-gapped environments. Parses a FortiGate `.conf` backup (from `execute backup config`
or GUI > System > Configuration > Backup) into the same dict shape the REST API returns, then
delegates to `FortinetScanner` so every existing check runs unchanged.

1. **`FortiGateConfParser`** — recursive descent over `config/edit/set/end/next` blocks.
   - CLI section `config vpn ssl settings` → API path `vpn.ssl/settings` (join all but last with
     dots, slash before last).
   - `edit "X"` → `{"name": "X", …}`; numeric `edit N` also sets `policyid` for
     firewall-policy paths or `id` for everything else.
   - `set` values: digit-only single tokens coerced to `int` so the scanner's many
     `isinstance(x, int) and x > N` checks fire (otherwise ~30 findings silently no-op).
   - Reference fields (`srcaddr`, `dstaddr`, `service`, `srcintf`, `dstintf`, `member`, `groups`,
     `users`, `match`, `ip-pools`, `tunnel-ip-pools`, `ssl-vpn-client-cert`, `api-gateway`,
     `split-tunneling-routing-address`) shaped as `[{"name": X}]` lists to match the live API.
   - VDOM/global wrappers (`config vdom; edit "root"; …; next; end`) transparently lifted —
     nested configs promoted to top-level endpoints (multi-VDOM configs collapse to last-seen).
   - Tolerant of: empty blocks, missing trailing `end`, mid-block `#` comments, blank lines,
     `unset`, deeply nested sub-blocks (BGP/OSPF interfaces, IPS sensor entries, VIP mapped IPs).

2. **`OfflineFortinetScanner(FortinetScanner)`** — subclass that overrides `_api_get(path, monitor)`.
   - Reads from a pre-parsed response dict instead of making HTTP calls.
   - `system/status` (monitor) synthesised from the `#config-version=FGT60F-7.0.10-FW-build1234`
     header so CVE matching against `_fw_version` works.
   - All other `monitor=True` endpoints (license/status, system/ha-peer, system/fortiguard-service-status,
     system/certificate) return `None` — live checks already tolerate this (skip-with-warn semantics).
   - Best-effort from `.conf` only: runtime-only findings (current FortiGuard subscription, HA peer
     sync state, signature DB age) are silently omitted; static config findings all fire.

3. **CLI** — same flags as live scanner minus `--token`/`--verify-ssl`/`--timeout`/`--inventory`:
   `python fortinet_offline_scanner.py <conf> [--json …] [--html …] [--remediation …]
   [--compliance-csv …] [--severity …] [-v]`.
   At startup reconfigures stdout/stderr to UTF-8 with `errors='replace'` so finding text with
   non-ASCII characters doesn't crash on Windows cp1252 consoles.

4. **Lazy-import refactor in `fortinet_scanner.py`** — `requests` and `urllib3` are imported on
   demand inside `_api_get` via `_ensure_requests()`. Offline mode requires zero third-party
   packages, important for locked-down OT operator workstations.

5. **Tests** — `test_data/test_offline_parser.py` (28 pytest cases) covers header parsing,
   section-to-API-path mapping, tokenisation, edit/policy/SNMP id handling, reference shaping,
   nested configs, VDOM/global wrappers, malformed input, and end-to-end smoke through
   `OfflineFortinetScanner`. Run: `python -m pytest test_data/test_offline_parser.py -v`.
   Smoke artefact: `test_data/sample_insecure.conf` (intentionally insecure mini-config that
   triggers ~115 findings across all 18 categories).

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

### Touching the Offline Scanner
1. New check method that reads a new endpoint? Confirm the endpoint comes from a `config X Y`
   block in real `.conf` exports — the parser handles it automatically. No code change needed.
2. New iterated reference field (`[a["name"] for a in …]`)? Add the field name to
   `REF_LIST_FIELDS` in `fortinet_offline_scanner.py` so flat `set` lines parse as
   `[{"name": X}]` lists instead of strings.
3. New numeric comparison (`isinstance(x, int) and x > N`)? Already covered — the parser
   coerces digit-only single tokens to `int` in `_coerce_value`.
4. New runtime-only endpoint? Document in the "best-effort offline" caveats; the parser will
   return `None` and the check should already guard with `if not data: return`.
5. Add a corresponding test case to `test_data/test_offline_parser.py`.

### Running
```bash
# Live (REST API)
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --verbose
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --json report.json --html report.html
python fortinet_scanner.py 10.1.1.1 --token <TOKEN> --remediation fix.txt --compliance-csv audit.csv
python fortinet_scanner.py --inventory devices.json --json unified.json

# Offline (.conf backup, no network access required)
python fortinet_offline_scanner.py /backups/fw1.conf
python fortinet_offline_scanner.py fw1.conf --json r.json --html r.html --compliance-csv audit.csv
python fortinet_offline_scanner.py fw1.conf --severity HIGH --remediation fix.txt -v

# Tests
python -m pytest test_data/test_offline_parser.py -v
```

## Conventions

- Live mode: single-file scanner in `fortinet_scanner.py`. Requires `requests`
  (`pip install requests`). Token via `--token` or env `FORTIOS_API_TOKEN`. SSL verification
  disabled by default (FortiGate self-signed certs).
- Offline mode: `fortinet_offline_scanner.py` + `fortinet_scanner.py`. Stdlib only — no
  `pip install` needed on the operator workstation.
- HTML reports: Catppuccin Mocha dark theme (`#1a1b2e` bg, `#cdd6f4` text).
- Every finding auto-resolves compliance mapping and remediation commands.
- Both modes share the same `Finding` schema, exit codes, and report formats.
