# CLAUDE.md — Fortinet FortiGate Security Scanner

## Project Overview

Fortinet FortiGate Security Scanner — a security posture assessment tool that audits FortiGate
NGFW configuration against security best practices, 5 compliance frameworks (CIS, PCI-DSS,
NIST 800-53, SOC 2, HIPAA), 70 known CVEs (2019–2026), and 31 MITRE ATT&CK technique
resilience tests.

Ships in two modes that share the same 22 check methods and rule set:
1. **Live mode** — `fortinet_scanner.py`, connects to FortiGate via the FortiOS REST API.
2. **Offline mode** — `fortinet_offline_scanner.py`, parses an exported `.conf` backup for
   OT / air-gapped environments where direct network access is impossible. Stdlib-only.

- **Language**: Python 3.10+ (live mode also needs `requests`; offline mode has no third-party deps)
- **Scanner files**: `fortinet_scanner.py` (~5,500 lines, all check logic) +
  `fortinet_offline_scanner.py` (~340 lines, parser + adapter)
- **Reporting files** (all stdlib-only, so offline mode keeps zero third-party deps):
  - `remediation_kb.py` + `remediation_kb.json` — 237-entry detailed remediation knowledge base
  - `risk_prioritizer.py` + `threat_intel.json` — Risk-Prioritization Engine (P1–P4) + bundled KEV/ransomware/EPSS snapshot
  - `cve_reachability.py` — per-CVE config-reachability gating (is the vulnerable feature enabled/internet-facing?)
  - `fortinet_html.py` — rich self-contained HTML report (`FortinetHTMLReport`)
  - `fortinet_pdf.py` + `pdf_writer.py` — paginated PDF report (`FortinetPDFReport`) on a hand-rolled PDF 1.4 writer (no reportlab/weasyprint)
- **Version**: 4.0.0 (engine) / 1.0.0 (offline adapter)
- **License**: MIT

## Architecture

1. **`FORTIOS_CVES` list** — 70 known FortiOS CVEs (2019-2026) with train-based version matching, sourced from FortiGuard PSIRT + NVD. Every entry is verified to affect FortiOS specifically (a prior bogus PAN-OS entry, CVE-2024-0012, was removed).
2. **`COMPLIANCE_MAP` dict** — 77 rule-to-framework mappings (CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA).
3. **`REMEDIATION_COMMANDS` dict** — 43 FortiOS CLI config commands mapped to rule IDs.
4. **`Finding` class** — `__slots__` with `rule_id, name, category, severity, description, recommendation, cwe, cve, compliance, remediation_cmd`. Auto-resolves compliance + remediation on init.
5. **`_ReportMixin`** — `print_report`, `save_json`, `save_html`, `save_pdf`, `save_remediation`, `save_compliance_csv`, `summary`, `filter_severity`, `prioritize()` / `print_priorities()`, plus `_report_kb()` / `_report_meta()` helpers.
6. **`FortinetScanner(_ReportMixin)`** — 22 `_check_*` methods producing 260+ possible findings.
7. **`RiskPrioritizer` + `ThreatIntel`** (`risk_prioritizer.py`) — post-scan engine that ranks every finding into P1–P4 fix-first tiers by fusing severity + CISA KEV + FIRST.org EPSS + internet-reachability. See [Risk-Prioritization Engine](#risk-prioritization-engine).
8. **`MultiDeviceScanner`** — batch scanning of multiple FortiGates with unified summary and JSON export.
9. **CLI** — `argparse` with `host`, `--token`, `--verify-ssl`, `--timeout`, `--json`, `--html`, `--pdf`, `--remediation`, `--compliance-csv`, `--baseline`, `--inventory`, `--top [N]`, `--refresh-intel`, `--severity`, `--verbose`, `--version`.
10. **Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise.

## API Connection

| Setting | Details |
|---------|---------|
| Base URL | `https://{host}/api/v2/` |
| Auth | `Authorization: Bearer {token}` header |
| Config endpoints | `/api/v2/cmdb/{path}` |
| Monitor endpoints | `/api/v2/monitor/{path}` |
| SSL | Self-signed certs accepted by default; `--verify-ssl` to enforce |
| Token env var | `FORTIOS_API_TOKEN` |

## Check Methods (22 methods, 260+ rules)

| Category | Prefix | Check Method | Rules |
|----------|--------|-------------|-------|
| Admin Access | FORTIOS-ADMIN | `_check_admin_access` | 24 |
| System Settings | FORTIOS-SYS | `_check_system_settings` | 13 |
| Firewall Policies | FORTIOS-POLICY | `_check_firewall_policies` | 16 |
| Rule-Base Analysis | FORTIOS-RULEBASE | `_check_rulebase` | shadow/redundant + Policy Control Index (SCORE) |
| Rule Usage (live) | FORTIOS-USAGE | `_check_rule_usage` | dormant-rule cleanup via `monitor/firewall/policy` |
| Object Hygiene | FORTIOS-OBJECT | `_check_object_hygiene` | orphaned address/service/profile objects |
| Attack Surface | FORTIOS-EXPOSURE | `_check_exposure` | WAN→internal reachability; internet-exposed high-risk services + summary |
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
| Known CVEs | FORTIOS-CVE | `_check_cves` | 70 |

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
(237 entries, loaded by `RemediationKB` in `remediation_kb.py`) supplies the **detailed** fix per
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

CLI flags: `--html`, `--pdf`, `--remediation`, `--compliance-csv`, `--baseline`, `--top`, `--refresh-intel` (both live and offline scanners).

## Risk-Prioritization Engine

`risk_prioritizer.py` — a **post-scan overlay** (like `RemediationKB`; never mutates `Finding`, works on objects *or* dicts) that answers "what do I fix first?" by fusing three signals into a **P1–P4** tier per finding:

1. **Base severity** → `BASE_POINTS` (CRITICAL 50 / HIGH 30 / MEDIUM 15 / LOW 6 / INFO 0).
2. **Real-world exploitability** (CVE findings) → `+35` if on the **CISA KEV** catalog, `+round(EPSS×20)` from **FIRST.org EPSS**. Data comes from the bundled `threat_intel.json`.
3. **Reachability** → the scanner's own attack-surface findings, modelled on **two planes**: `data` (from `FORTIOS-EXPOSURE-*`: WIDE_OPEN / EXPOSED / NONE) and `mgmt` (from `MITRE-T1595/T1557`: management on WAN). A finding takes the plane it lives on — Admin Access → mgmt only; Attack-Surface/SSL-VPN → data; **Known CVEs take the stronger** of the two. Bonus `+20` (wide-open/mgmt) or `+14` (exposed).

Score is capped at 100 and mapped by `TIER_THRESHOLDS` (P1≥70, P2≥42, P3≥20, else P4), with one **floor**: a KEV-listed CVE is never below P2. Every `PriorityResult` carries `factors` (label + points + detail) and a `rationale` string, so the ranking is fully explainable. `RiskPrioritizer.prioritize(findings)` returns them ordered fix-first.

- **`threat_intel.json`** — bundled snapshot (`meta` + `cves{CVE: {epss, epss_pct, kev, kev_date?}}`) for all 70 tracked CVEs (14 KEV-listed). Keeps the engine working **offline**; loader degrades to empty (severity+reachability only) if missing/corrupt.
- **`--refresh-intel`** (`_refresh_intel` / `_refresh_intel_offline`) — rebuilds the snapshot from the live CISA KEV catalog + FIRST.org EPSS API via **`urllib` (stdlib only)**, then exits. Handled *before* host/inventory validation so it runs standalone. EPSS is batched (60/req). Captures KEV `knownRansomwareCampaignUse` -> per-entry `ransomware` flag.
- **`--export-intel FILE` / `--import-intel FILE`** (`_transfer_intel`, `export_intel`/`import_intel`) — sneakernet a snapshot to/from an air-gapped host; import **validates** (`_validate_intel_doc`) before overwriting so a corrupt file can't replace a good snapshot. Staleness: `ThreatIntel.age_days()`/`is_stale(threshold=45)`; console + reports show a stale warning.
- **`--top [N]`** — `print_priorities(N)` prints the tier summary + fix-first queue (KEV/ransomware/EPSS/exposed tags) to the console (default 10).
- **Reports**: `FortinetHTMLReport` / `FortinetPDFReport` take an optional `priorities` list (else compute it), key it by `id(finding)`, and render a "Top Risks to Fix Now" section + per-finding P-badge/rationale. `_report_meta()` adds `intel_snapshot` / `intel_kev_count` / `intel_age_days` / `intel_stale`.
- **GOTCHA**: prioritization runs *after* `filter_severity` in `main()`; `filter_severity` snapshots `self._all_findings` (pre-filter) and `prioritize()` derives reachability from that, so a high `--severity` cannot strip the exposure signal.

**CVE reachability gating** (`cve_reachability.py` — stdlib, offline-safe): version-matched CVEs fire on firmware math alone, so `_check_cves` also assesses, from the parsed config, whether each CVE's vulnerable feature is enabled/internet-facing. Each CVE is tagged in `CVE_COMPONENTS` (fortinet_scanner.py, next to FORTIOS_CVES) with a component (sslvpn / admin-gui / admin-ssh / admin-auth / rest-api / fgfm / ipsec / capwap / proxy / ips / radius / tacacs / ldap / fsso / ha / dnsfilter / captive-portal / bluetooth / forticloud-sso / ecosystem); `build_view(scanner)` reads the needed endpoints once (via `_api_get`, same in live/offline) and per-component predicates return a verdict (`CONFIRMED_REACHABLE` / `CONFIGURED_NOT_EXPOSED` / `FEATURE_DISABLED` / `INDETERMINATE`) + cited evidence. `_check_cves` stashes `self._cve_reachability = {cve: {verdict, evidence, component}}`; `prioritize()` passes it to `RiskPrioritizer.prioritize(..., cve_reachability=)`. In `assess()`, a CVE with a decisive verdict uses it INSTEAD of the plane heuristic: CONFIRMED -> +20; DISABLED -> −25 **and tier capped at P3 (P2 if KEV)**; NOT_EXPOSED -> no bonus; INDETERMINATE -> plane fallback. **Safe by design: only downranks, never suppresses; KEV floor (>=P2) holds; evidence shown so an operator can override.** Component tags are **conservative** — ambiguous CVEs (038/045/057/061) and FortiManager/FortiClient ecosystem CVEs (006/007/010 = `ecosystem`) are INDETERMINATE. GOTCHA: `build_view` must read the same keys/shapes the offline parser and live API produce (e.g. `system/interface` list `allowaccess` string, phase1 `interface` str-or-list, `system/settings` VDOM `inspection-mode` for proxy) — verified against the parser. **SSL-VPN `set status` toggle only exists from FortiOS 7.4.1**: `_sslvpn` is version-aware (uses `view["fw_version"]`) — on <7.4.1 a configured block = in-use (absent status is NOT read as disabled); on >=7.4.1 absent status = disabled-by-default. `_names` splits space-joined multi-value strings (offline parser joins `source-interface` tokens). **Adversarial review round 2 (2026-07-09) fixed 7 confirmed bugs + 3 NVD-verified CVE mis-tags**: CVE-2024-35279 fgfm→**capwap** (crafted UDP via CAPWAP control), CVE-2025-22252 radius→**tacacs** (TACACS+ auth bypass, not RADIUS empty-secret — description/CWE corrected), CVE-2024-26010 ips→**untagged** (NVD names no component); import_intel now validates meta+every entry & writes only after normalizing (can't clobber a good snapshot); unknown verdict falls back to plane heuristic.
- **Tests**: `test_data/test_risk_prioritizer.py` (snapshot/KEV/EPSS/ransomware, plane reachability, scoring/tiers/floor, staleness, import/export hardening, dict-vs-object, graceful degradation, HTML) + `test_data/test_cve_reachability.py` (predicates per component incl. version-aware SSL-VPN / multi-WAN / proxy-vdom / tacacs, CVE_COMPONENTS+NVD-tag sanity, gating/cap/floor, unknown-verdict fallback, offline integration). **116 tests total green.**

**Config drift** (`_ReportMixin.apply_drift`, `--baseline prior.json`): diffs current findings vs a prior `--json` report by signature `(rule_id, file_path, line_content)`, prints new/resolved + posture-score delta, and adds a `FORTIOS-DRIFT-SUMMARY` finding. **Line_content must be deterministic** for signatures to match — sort any set before joining it into `line_content` (fixed `wan_bad`/`versions`).

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

## Known CVEs (70 entries, 2019-2026)

| Range | Count | Severity Mix | Notes |
|-------|-------|-------------|-------|
| CVE-001 to 015 | 15 | 8 CRITICAL, 6 HIGH, 1 MEDIUM | KEV-listed SSL VPN / fgfmd RCEs, FortiJump, xortigate |
| CVE-016 to 030 | 15 | 5 CRITICAL, 7 HIGH, 3 MEDIUM | 2024-2025 CVEs, CSF proxy auth bypass, TACACS+ bypass |
| CVE-031 to 046 | 16 | 2 CRITICAL, 14 HIGH | 2023-2026 sweep: CAPWAP, IPsec IKE, FGFM, restricted CLI escape, LDAP bypass |
| CVE-047 to 067 | 21 | 0 CRITICAL, 0 HIGH, 21 MEDIUM | SSL-VPN symlink re-persistence, RADIUS Blast-RADIUS, request smuggling, DNS-65 filter bypass, session expiration, FSSO policy source-verification bypass |

Totals: **19 CRITICAL, 27 HIGH, 24 MEDIUM** across all 6 supported version trains. CVE-068–070 are the 2021–2023 SSL-VPN/SSH/proxy criticals (CVE-2022-35843, CVE-2023-28001, CVE-2023-33308); FORTIOS-CVE-008 was re-slotted to CVE-2021-26109.

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

# Threat-intel refresh (KEV + EPSS), then exit
python fortinet_scanner.py --refresh-intel

# Fix-first queue to the console
python fortinet_offline_scanner.py fw1.conf --top 15

# Tests (116 cases: parser + rulebase + risk-prioritizer + cve-reachability)
python -m pytest test_data/ -v
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
