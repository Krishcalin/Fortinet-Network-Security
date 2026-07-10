# CLAUDE.md — Fortinet FortiGate Security Scanner

## Project Overview

Fortinet FortiGate Security Scanner — a security posture assessment tool that audits FortiGate
NGFW configuration against security best practices, 5 compliance frameworks (CIS, PCI-DSS,
NIST 800-53, SOC 2, HIPAA), 75 known CVEs (2018–2026), and 34 MITRE ATT&CK technique
resilience tests. Findings export to HTML/PDF/JSON/CSV plus **SARIF 2.1.0 and OCSF** for
CI / SIEM ingestion, **SOAR/ticketing payloads** (Jira / ServiceNow / Splunk SOAR / webhook)
for work-management systems, and a fix-first **remediation + rollback CLI script** can be generated
from the knowledge base.

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
  - `fleet_report.py` + `fleet_html.py` + `fleet_pdf.py` — Fleet Analysis Console (aggregate many scans → ranking + campaigns)
  - `posture.py` — Continuous Posture State (stable finding identity + history store + exceptions + SLA + trend)
  - `policy_analyzer.py` — Traffic-Aware Policy Engine (IP/port interval resolution + query + CIDR-overlap shadow + simulate)
  - `fortinet_html.py` — rich self-contained HTML report (`FortinetHTMLReport`)
  - `fortinet_pdf.py` + `pdf_writer.py` — paginated PDF report (`FortinetPDFReport`) on a hand-rolled PDF 1.4 writer (no reportlab/weasyprint)
- **Version**: 4.0.0 (engine) / 1.0.0 (offline adapter)
- **License**: MIT

## Architecture

1. **`FORTIOS_CVES` list** — 75 known FortiOS CVEs (2018-2026) with train-based version matching, sourced from FortiGuard PSIRT + NVD. Cross-product advisories (FortiManager/FortiClient EMS = `product` field) are tracked for documentation but **skipped** in `_check_cves` so they never false-positive against FortiGate firmware. Every entry is verified to affect FortiOS specifically (a prior bogus PAN-OS entry, CVE-2024-0012, was removed).
2. **`COMPLIANCE_MAP` dict** — 94 rule-to-framework mappings (CIS, PCI-DSS, NIST 800-53, SOC 2, HIPAA).
3. **`REMEDIATION_COMMANDS` dict** — 52 FortiOS CLI config commands mapped to rule IDs.
4. **`Finding` class** — `__slots__` with `rule_id, name, category, severity, description, recommendation, cwe, cve, compliance, remediation_cmd`. Auto-resolves compliance + remediation on init.
5. **`_ReportMixin`** — `print_report` / `print_summary_only`, `save_json` (schema v2: enriched with P-tier/KEV/EPSS + `compliance_scorecard` + `tier_summary`), `save_html`, `save_pdf`, `save_remediation`, `save_remediation_script` (fix + rollback CLI batch), `save_compliance_csv`, `save_findings_csv`, `save_sarif`, `save_ocsf`, `summary`, `filter_severity`, `set_color` (TTY-aware), `compliance_scorecard()` / `print_compliance_scorecard()`, `benchmark_score(framework)` / `print_benchmark()` / `save_benchmark()` (scored CIS/PCI/NIST/SOC2/HIPAA pass-fail-per-control profile), `prioritize()` / `print_priorities()`, plus `_report_kb()` / `_report_meta()` helpers.
6. **`FortinetScanner(_ReportMixin)`** — 22 `_check_*` methods producing 280+ possible findings.
7. **`RiskPrioritizer` + `ThreatIntel`** (`risk_prioritizer.py`) — post-scan engine that ranks every finding into P1–P4 fix-first tiers by fusing severity + CISA KEV + FIRST.org EPSS + internet-reachability. See [Risk-Prioritization Engine](#risk-prioritization-engine).
8. **`MultiDeviceScanner`** — batch scanning of multiple FortiGates with unified summary and JSON export.
9. **CLI** — `argparse` with `host`, `--token`, `--verify-ssl`, `--timeout`, `--json`, `--html`, `--pdf`, `--csv`, `--compliance-csv`, `--sarif`, `--ocsf`, `--remediation`, `--fix-script` / `--rollback-script` / `--fix-tier` / `--fix-script-force`, `--framework {cis,pci,nist,soc2,hipaa}` / `--benchmark FILE`, `--baseline`, `--inventory`, `--top [N]`, `--refresh-intel`, `--severity`, `--no-color`, `--summary-only` (alias `--quiet`), `--verbose`, `--version`. (The offline scanner mirrors all of these except the live-only `--token`/`--verify-ssl`/`--timeout`/`--inventory`.)
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

## Check Methods (22 methods, 280+ rules)

| Category | Prefix | Check Method | Rules |
|----------|--------|-------------|-------|
| Admin Access | FORTIOS-ADMIN | `_check_admin_access` | 26 |
| System Settings | FORTIOS-SYS | `_check_system_settings` | 13 |
| Firewall Policies | FORTIOS-POLICY | `_check_firewall_policies` | 16 |
| Rule-Base Analysis | FORTIOS-RULEBASE | `_check_rulebase` | shadow/redundant + Policy Control Index (SCORE) |
| Rule Usage (live) | FORTIOS-USAGE | `_check_rule_usage` | dormant-rule cleanup via `monitor/firewall/policy` |
| Object Hygiene | FORTIOS-OBJECT | `_check_object_hygiene` | orphaned address/service/profile objects |
| Attack Surface | FORTIOS-EXPOSURE | `_check_exposure` | WAN→internal reachability; internet-exposed high-risk services + summary |
| SSL VPN | FORTIOS-SSLVPN | `_check_ssl_vpn` | 17 |
| IPsec VPN | FORTIOS-IPSEC | `_check_ipsec_vpn` | 12 |
| Security Profiles | FORTIOS-PROFILE/AV/IPS/WF/APP/DLP/DNS | `_check_security_profiles` | 11 |
| Logging & Monitoring | FORTIOS-LOG | `_check_logging` | 18 |
| High Availability | FORTIOS-HA | `_check_ha` | 8 |
| Certificates | FORTIOS-CERT | `_check_certificates` (+ CERT-012 admin-server-cert in `_check_admin_access`) | 12 |
| Network Hardening | FORTIOS-NET | `_check_network` | 20 |
| FortiGuard Updates | FORTIOS-UPDATE | `_check_fortiguard` | 7 |
| ZTNA / SASE / SD-WAN | FORTIOS-ZTNA | `_check_ztna` | 6 |
| Wireless Security | FORTIOS-WIRELESS | `_check_wireless` | 9 |
| Backup & DR | FORTIOS-BACKUP | `_check_backup` | 5 |
| Authentication | FORTIOS-AUTH | `_check_authentication` | 6 |
| Advanced Hardening | FORTIOS-SYS/NET/POLICY/LOG/CERT/ZTNA | `_check_advanced_hardening` | ~15 |
| MITRE ATT&CK Resilience | MITRE-T{NNNN}-{NNN} | `_check_mitre_attack_resilience` | 34 |
| Known CVEs | FORTIOS-CVE | `_check_cves` | 75 |

## Compliance Framework Mapping

94 rule-to-framework mappings. Every finding auto-resolves compliance on init via `Finding._resolve_compliance()`.

| Framework | Scope | Controls Mapped |
|-----------|-------|-----------------|
| **CIS** | CIS FortiGate Benchmark | Sections 2-14 |
| **PCI-DSS** | PCI-DSS 4.0 | Requirements 1, 2, 4, 5, 6, 7, 8, 10, 11, 12 |
| **NIST** | NIST 800-53 Rev 5 | AC, AU, CM, CP, IA, RA, SC, SI families |
| **SOC2** | SOC 2 Type II | CC6, CC7 criteria |
| **HIPAA** | HIPAA Security Rule | 164.308, 164.312 sections |

Output: console (inline), JSON (`compliance` dict), compliance CSV (`--compliance-csv`).

**Scored benchmark profile** — `benchmark_score(framework)` turns those mappings into a pass/fail-per-control **scored** artifact (`--framework {cis,pci,nist,soc2,hipaa}` prints it; `--benchmark FILE` saves per-control CSV/JSON). Denominator = the distinct controls that framework maps in `COMPLIANCE_MAP` (the controls the tool evaluates); a control is PASS unless a reportable finding references it. Produces an overall % + per-section % (CIS 2-14, NIST AC/AU/…, etc.). Evaluated against the full pre-filter set minus INFO, so a `--severity` display filter can't inflate the score. The output states the denominator is the tool's mapped controls, not the full external benchmark (no overclaiming).

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
- `save_remediation_script` → a fix-first FortiOS CLI **batch** assembled from the KB (`--fix-script`),
  with a paired **rollback** batch (`--rollback-script`). Ordered P1→P4; disruptive fixes
  (reboot / HA failover / VPN drop, detected negation-aware from the KB `impact` field) are emitted
  **commented out** unless `--fix-script-force`. Generation only — it never executes anything.
- `save_sarif` / `save_ocsf` → machine-ingestible **SARIF 2.1.0** (GitHub code-scanning / CI) and
  **OCSF** Compliance Finding events (SIEM), built by `fortinet_export.py`. Each result/event carries
  the P-tier / KEV / EPSS / CVE / CWE / compliance enrichment. Stdlib-only.
- `save_jira` / `save_servicenow` / `save_splunk_soar` / `save_webhook` → **SOAR/ticketing** payloads
  (`build_jira`/`build_servicenow`/`build_splunk_soar`/`build_webhook` in `fortinet_export.py`), all
  routed through `_save_soar(path, builder, label, **cfg)` which passes `prio_by_id`, the KB, and
  `self._posture_delta`. See the **SOAR & Ticketing Export** section below.
- `save_findings_csv` (`--csv`) → full findings CSV (severity, tier, KEV, EPSS, CVE, CWE, compliance,
  evidence, remediation CLI). `compliance_scorecard()` gives a per-framework pass/fail rollup that
  the console (`print_compliance_scorecard`), enriched JSON (`schema_version: 2`) and HTML all render.
- Console UX: `set_color()` gates ANSI on `stdout.isatty()` + `NO_COLOR` (fixes escape codes leaking
  into piped output); `--no-color` forces off; `--summary-only` / `--quiet` prints just the scorecard
  + fix-first queue.

CLI flags: `--html`, `--pdf`, `--csv`, `--compliance-csv`, `--sarif`, `--ocsf`, `--remediation`,
`--fix-script` / `--rollback-script` / `--fix-tier` / `--fix-script-force`, `--baseline`, `--top`,
`--jira` / `--servicenow` / `--splunk-soar` / `--webhook` / `--jira-project` / `--jira-api-version` /
`--soar-min-tier`, `--no-color`, `--summary-only`, `--refresh-intel` (both live and offline scanners).

## Risk-Prioritization Engine

`risk_prioritizer.py` — a **post-scan overlay** (like `RemediationKB`; never mutates `Finding`, works on objects *or* dicts) that answers "what do I fix first?" by fusing three signals into a **P1–P4** tier per finding:

1. **Base severity** → `BASE_POINTS` (CRITICAL 50 / HIGH 30 / MEDIUM 15 / LOW 6 / INFO 0).
2. **Real-world exploitability** (CVE findings) → `+35` if on the **CISA KEV** catalog, `+round(EPSS×20)` from **FIRST.org EPSS**. Data comes from the bundled `threat_intel.json`.
3. **Reachability** → the scanner's own attack-surface findings, modelled on **two planes**: `data` (from `FORTIOS-EXPOSURE-*`: WIDE_OPEN / EXPOSED / NONE) and `mgmt` (from `MITRE-T1595/T1557`: management on WAN). A finding takes the plane it lives on — Admin Access → mgmt only; Attack-Surface/SSL-VPN → data; **Known CVEs take the stronger** of the two. Bonus `+20` (wide-open/mgmt) or `+14` (exposed).

Score is capped at 100 and mapped by `TIER_THRESHOLDS` (P1≥70, P2≥42, P3≥20, else P4), with one **floor**: a KEV-listed CVE is never below P2. Every `PriorityResult` carries `factors` (label + points + detail) and a `rationale` string, so the ranking is fully explainable. `RiskPrioritizer.prioritize(findings)` returns them ordered fix-first.

- **`threat_intel.json`** — bundled snapshot (`meta` + `cves{CVE: {epss, epss_pct, kev, kev_date?}}`) for all 75 tracked CVEs (19 KEV-listed). Keeps the engine working **offline**; loader degrades to empty (severity+reachability only) if missing/corrupt.
- **`--refresh-intel`** (`_refresh_intel` / `_refresh_intel_offline`) — rebuilds the snapshot from the live CISA KEV catalog + FIRST.org EPSS API via **`urllib` (stdlib only)**, then exits. Handled *before* host/inventory validation so it runs standalone. EPSS is batched (60/req). Captures KEV `knownRansomwareCampaignUse` -> per-entry `ransomware` flag.
- **`--export-intel FILE` / `--import-intel FILE`** (`_transfer_intel`, `export_intel`/`import_intel`) — sneakernet a snapshot to/from an air-gapped host; import **validates** (`_validate_intel_doc`) before overwriting so a corrupt file can't replace a good snapshot. Staleness: `ThreatIntel.age_days()`/`is_stale(threshold=45)`; console + reports show a stale warning.
- **`--top [N]`** — `print_priorities(N)` prints the tier summary + fix-first queue (KEV/ransomware/EPSS/exposed tags) to the console (default 10).
- **Reports**: `FortinetHTMLReport` / `FortinetPDFReport` take an optional `priorities` list (else compute it), key it by `id(finding)`, and render a "Top Risks to Fix Now" section + per-finding P-badge/rationale. `_report_meta()` adds `intel_snapshot` / `intel_kev_count` / `intel_age_days` / `intel_stale`.
- **GOTCHA**: prioritization runs *after* `filter_severity` in `main()`; `filter_severity` snapshots `self._all_findings` (pre-filter) and `prioritize()` derives reachability from that, so a high `--severity` cannot strip the exposure signal.

**CVE reachability gating** (`cve_reachability.py` — stdlib, offline-safe): version-matched CVEs fire on firmware math alone, so `_check_cves` also assesses, from the parsed config, whether each CVE's vulnerable feature is enabled/internet-facing. Each CVE is tagged in `CVE_COMPONENTS` (fortinet_scanner.py, next to FORTIOS_CVES) with a component (sslvpn / admin-gui / admin-ssh / admin-auth / rest-api / fgfm / ipsec / capwap / proxy / ips / radius / tacacs / ldap / fsso / ha / dnsfilter / captive-portal / bluetooth / forticloud-sso / ecosystem); `build_view(scanner)` reads the needed endpoints once (via `_api_get`, same in live/offline) and per-component predicates return a verdict (`CONFIRMED_REACHABLE` / `CONFIGURED_NOT_EXPOSED` / `FEATURE_DISABLED` / `INDETERMINATE`) + cited evidence. `_check_cves` stashes `self._cve_reachability = {cve: {verdict, evidence, component}}`; `prioritize()` passes it to `RiskPrioritizer.prioritize(..., cve_reachability=)`. In `assess()`, a CVE with a decisive verdict uses it INSTEAD of the plane heuristic: CONFIRMED -> +20; DISABLED -> −25 **and tier capped at P3 (P2 if KEV)**; NOT_EXPOSED -> no bonus; INDETERMINATE -> plane fallback. **Safe by design: only downranks, never suppresses; KEV floor (>=P2) holds; evidence shown so an operator can override.** Component tags are **conservative** — ambiguous CVEs (038/045/057/061) and FortiManager/FortiClient ecosystem CVEs (006/007/010 = `ecosystem`) are INDETERMINATE. GOTCHA: `build_view` must read the same keys/shapes the offline parser and live API produce (e.g. `system/interface` list `allowaccess` string, phase1 `interface` str-or-list, `system/settings` VDOM `inspection-mode` for proxy) — verified against the parser. **SSL-VPN `set status` toggle only exists from FortiOS 7.4.1**: `_sslvpn` is version-aware (uses `view["fw_version"]`) — on <7.4.1 a configured block = in-use (absent status is NOT read as disabled); on >=7.4.1 absent status = disabled-by-default. `_names` splits space-joined multi-value strings (offline parser joins `source-interface` tokens). **Adversarial review round 2 (2026-07-09) fixed 7 confirmed bugs + 3 NVD-verified CVE mis-tags**: CVE-2024-35279 fgfm→**capwap** (crafted UDP via CAPWAP control), CVE-2025-22252 radius→**tacacs** (TACACS+ auth bypass, not RADIUS empty-secret — description/CWE corrected), CVE-2024-26010 ips→**untagged** (NVD names no component); import_intel now validates meta+every entry & writes only after normalizing (can't clobber a good snapshot); unknown verdict falls back to plane heuristic.
- **Tests**: `test_data/test_risk_prioritizer.py` (snapshot/KEV/EPSS/ransomware, plane reachability, scoring/tiers/floor, staleness, import/export hardening, dict-vs-object, graceful degradation, HTML) + `test_data/test_cve_reachability.py` (predicates per component incl. version-aware SSL-VPN / multi-WAN / proxy-vdom / tacacs, CVE_COMPONENTS+NVD-tag sanity, gating/cap/floor, unknown-verdict fallback, offline integration) + `test_bugfixes.py` / `test_new_checks.py` / `test_exports.py` / `test_reporting.py` / `test_benchmark.py` / `test_hardening.py` (2026-07 regressions, new checks, SARIF/OCSF/fix-script, reporting/UX, scored benchmark, hardening check-pack incl. adversarial-verify edge cases). **198 tests total green.**

## Fleet Analysis Console

`fleet_report.py` (+ `fleet_html.py`/`fleet_pdf.py`, all stdlib) — aggregates many single-device scans into a fleet view. CLI on the **offline** scanner: `--conf-dir DIR` (scan every `*.conf` → fleet report) or `--fleet-inputs PATH...` (aggregate existing per-device `--json` reports; files/globs/dirs). In fleet mode `--html/--pdf/--json` write the FLEET report; `_fleet_mode(args)` in fortinet_offline_scanner.py orchestrates.
- **Device record** (`build_record(meta, findings, priorities, source)` / `record_from_json(doc)`): per-device counts, `risk_score` (mirrors `_ReportMixin._risk_score`), tier counts, and a per-rule priority index (`_pidx`: keep strongest tier, OR the reachable/kev/ransomware booleans). To feed the JSON-ingest path, **`save_json` now embeds `priorities` (PriorityResult.to_dict()) + `tier_summary`** — additive, doesn't affect drift (which keys on rule_id/file_path/line_content).
- **`FleetReport(records)`** computes: worst-device ranking (risk_score, P1, crit), **prevalence campaigns** (one entry per rule_id, counted once per device even if it fires multiple times, ranked by device coverage then severity; CVE campaigns show `reachable` count from the per-device verdict; verbatim fix from RemediationKB), **systemic** findings (≥`ceil(0.75*n)` devices), firmware/model distribution.
- **De-dup is hostname-first** (offline serial is the placeholder `"OFFLINE-CONFIG"`, useless for identity): a real serial disambiguates same-hostname devices; else hostname collisions get a `#N` suffix and are surfaced in `collisions` so counts are neither inflated nor collapsed. GOTCHA: `_record_from_conf` catches `SystemExit`+`Exception` so one unparseable backup can't abort the whole fleet run; `filter_severity` is NOT applied in fleet mode (aggregate needs all findings).
- **Tests**: `test_data/test_fleet_report.py` (record/counts, dedup+collision, ranking, campaign prevalence+reachability gating, systemic, JSON ingest, render JSON/HTML/PDF, empty-fleet safety, + review regressions: INFO-excluded, systemic float-rounding, phantom-config skip, realpath input dedup). **134 tests total green.** Adversarial review (11 agents) found 8 confirmed issues, all fixed — notably: an unparseable/garbage `.conf` was mis-scanned as a phantom score-100 device (the offline scanner never `sys.exit`s, so the SystemExit skip was dead code) → now requires a parsed FortiOS version; INFO dropped for cross-path consistency; `dict|dict` union replaced (py3.8-safe); systemic threshold `ceil(round(...))`; realpath input de-dup; positional conf folded into fleet mode.

## Traffic-Aware Policy Engine

`policy_analyzer.py` (stdlib `ipaddress` only) — reasons about real traffic, not object names. **Core promise: fail to OPAQUE, never guess** — any factor a static config can't resolve yields an OPAQUE verdict (or is excluded from overlap), never a false ALLOW/DENY.
- **`IPSet`** (merged [lo,hi] IPv4 interval list: from_cidr/from_subnet_field/from_range, contains/covers/overlaps) + **`PortSet`** (set of (proto,lo,hi) + `*`; matches/covers/overlaps). `PREDEFINED_SERVICES` bundles ~50 common FortiOS services; unknown predefined → OPAQUE (not guessed).
- **`Resolver`** resolves address objects/groups → `Addr(ipset, opaque, reason, vip)` and services → `Svc(portset, opaque, reason)`, recursive group expansion. OPAQUE on: FQDN/geography/dynamic/wildcard/interface-subnet/mac/internet-service types, IPv6, unknown objects, negated matches, TCP/UDP service with no portrange. A group is opaque if any member is (resolvable part still kept for definite-hit). VIP objects resolve to their extip + flagged `vip`.
- **`PolicyModel.from_scanner(scanner)`** reads `firewall/address|addrgrp|vip|policy` + **`firewall.service/custom|group`** (DOTTED path). Enabled policies sorted by policyid (first-match order).
- **`query(src,dst,port,proto,ingress?,egress?)`** → `QueryResult(ALLOW/DENY/OPAQUE, policy, reason, caveats)`. Per-component match is YES/NO/**MAYBE**; any MAYBE before a definite match → OPAQUE. Dst = a VIP extip → OPAQUE (DNAT). Schedule≠always / negation / VIP-dstaddr → MAYBE→OPAQUE. Interface only decisive with `--via`; else a "not verified" caveat (still returns a verdict). IPv6 → OPAQUE.
- **`overlap_findings()`** — true CIDR/port coverage shadow (earlier action≠later, later is DEAD) / redundant (same action); skips any policy with OPAQUE/VIP objects. Emitted by **`_check_policy_overlap`** as `FORTIOS-RULEBASE-101` (shadowed, HIGH, CWE-561) / `102` (redundant, LOW, CWE-710), **layered beside** the name-based `001/002` (registered in BOTH scan lists).
- **`simulate(proposed_policy_dict)`** — splice + report dead-on-arrival / shadows-existing / any-source-accept exposure. Descriptive only, never asserts "safe".
- **CLI** (both scanners): `--query "SRC DST PORT[/PROTO]"` + `--via "in,eg"`, `--simulate FILE`. Dispatched in `main()` BEFORE `scanner.scan()` (only needs parsed config, not a full scan) via `policy_action`/`_run_query`/`_run_simulate` in fortinet_scanner.py.
- **Tests**: `test_data/test_policy_analyzer.py` (interval math, OPAQUE resolution per type, query ALLOW/DENY/OPAQUE incl. VIP/FQDN/IPv6/negate/schedule/interface-via/zones, overlap redundant/shadowed + skip-opaque + interface-scope + name-covered-dedup, simulate, offline integration) + `test_data/sample_policy.conf`. **189 tests total green.** Adversarial review (13 agents) found 9 confirmed issues, all fixed — **notably 2 HIGH false-ALLOWs**: `srcaddr/dstaddr/service-negate` left the literal members in the set so `_addr_comp`/`_svc_comp` returned a definite YES before checking `opaque` (an IP INSIDE a negated set read as ALLOW) → added a `negated` flag that forces MAYBE→OPAQUE; and `internet-service enable` (ISDB) policies were matched only on srcaddr/dstaddr/service, ignoring the DB → now OPAQUE via `_isdb()`. Also (HIGH): interface **zones** now expand (`system/zone`), and a `--via` mismatch against an unclassifiable interface is OPAQUE not a false DENY; first-match now preserves **config/sequence order** (removed the wrong `policyid` sort). Plus 101 severity is HIGH only for accept-shadows-deny (else MEDIUM), overlap cap raised + `FORTIOS-RULEBASE-103` INFO on truncation, 101/102 de-duplicated vs name-based via `name_covered`, and `--via`/proto input validation.

## Continuous Posture State

`posture.py` (stdlib) — gives the scanner memory so it stops being amnesiac. CLI on BOTH scanners: `--history FILE` (the system-of-record JSON) + `--exceptions FILE` (risk-acceptance). `_ReportMixin.update_posture(history, exceptions)` + `_print_posture(delta)`; called in `main()` **before `filter_severity`** so a display filter can't record findings as resolved.
- **Stable identity (the prerequisite)**: `finding_fingerprint(f)` = `rule_id` or `rule_id|entity`, where `finding_entity()` extracts a *stable identifier* (`policy:N` / `iface:X` / `name:"..."`) — **NEVER line_content values** (which embed volatile `admintimeout=30`). Keying on the raw line would record a live finding as resolved+new on a cosmetic edit, corrupting the record. `apply_drift` was **refactored onto the same fingerprint** (fixing its identical latent bug); `sig_d` uses a `_fp_field` helper to read from dicts (baseline) or Finding objects (current).
- **`PostureStore.update(host, findings, priorities, exceptions, now, risk_score)`** → `PostureDelta`: new/carried/resolved/reopened (reopen restarts the SLA clock), SLA breaches (age vs `TIER_SLA_DAYS` {P1:3,P2:7,P3:30,P4:None}, accepted excluded), `newly_weaponized` (a carried finding whose stored `kev` was False and is now True), trend snapshot + risk_delta vs the previous snapshot. History JSON keyed by host; capped at 200 snapshots/device. Loads fail-open (corrupt/missing store → fresh, never crash).
- **`Exceptions`** (accept/defer + reason/approver/expiry): matches host(+`*` wildcard) + rule_id (+ entity if specified). **Fail open**: an expired or malformed exception suppresses nothing and expired ones are reported for re-approval. Scoping decision: exceptions affect the posture digest (active vs accepted), NOT the base scan/exit-code.
- **`now` is injectable** for deterministic tests (defaults to `datetime.now()`).
- **Tests**: `test_data/test_posture.py` (identity stability + entity extraction against REAL scanner formats, lifecycle, exceptions incl. wildcard/entity-scope/expired-fail-open/malformed-fail-open, SLA per-tier + boundary + accepted-excluded, newly-weaponized transition-only + sticky-KEV, priority-overlay-unwrap, trend/risk-delta, corrupt-store fail-open, drift-refactor regression). **159 tests total green.** Adversarial review (13 agents) found 10 confirmed issues, all fixed — notably (HIGH): the entity regexes didn't match the scanner's actual `policy=Name (ID n)` / single-quote / `key=name` formats so per-instance findings collapsed (hid live findings); and `finding_fingerprint(PriorityResult)` returned "" (tier/kev live on `.finding`) so the SLA/weaponization overlay was DEAD in production — unit tests missed it by passing dicts. Also: malformed `expires` now fails open (was permanent suppression), accepted excluded from new/carried, SLA uses `>=` full-timedelta, KEV sticky, host key adds a real serial, resolved records pruned at 180d.

**Config drift** (`_ReportMixin.apply_drift`, `--baseline prior.json`): diffs current findings vs a prior `--json` report by signature `(rule_id, file_path, line_content)`, prints new/resolved + posture-score delta, and adds a `FORTIOS-DRIFT-SUMMARY` finding. **Line_content must be deterministic** for signatures to match — sort any set before joining it into `line_content` (fixed `wan_bad`/`versions`).

## SOAR & Ticketing Export

`fortinet_export.py` — turns the posture record into ACTION: `build_jira` / `build_servicenow` / `build_splunk_soar` / `build_webhook` emit ready-to-POST payloads. All stdlib / JSON-serializable (preserves the offline guarantee); the scanner emits the JSON, a small online poster does the HTTP. CLI on BOTH scanners: `--jira`/`--servicenow`/`--splunk-soar`/`--webhook FILE` + `--jira-project`/`--jira-api-version {2,3}`/`--soar-min-tier {P1..P4}`; dispatched in `main()` **after** `--history` (so `self._posture_delta` exists) via `_ReportMixin.save_jira/…` → `_save_soar(path, builder, label, **cfg)` (passes `prio_by_id=self._prio_by_id()`, `kb=self._report_kb()`, `delta=self._posture_delta`, `scan_epoch`).
- **Uniform envelope** `{target, meta, items:[{op, dedup_key, body}]}` — `body` is the pristine native payload, `op` ∈ create/update/reopen/resolve/upsert tells the poster the HTTP verb.
- **The one dedup key** `_dedup_key(host, f)` = `sha1(f"{host}|{finding_fingerprint(f)}")[:16]`. Composes host + the posture fingerprint and hashes — do **NOT** reuse `finding_fingerprint` verbatim: it omits host (two devices' identical findings would collapse to one ticket) and returns a raw string with spaces/quotes (Jira label 400). Excludes `line_content` (cosmetic change = same ticket). `_dedup_key_from_rec(host, rec)` reconstructs `rule_id|entity` **identically** for resolved closures — must match or a ticket leaks. `_posture_host()` is shared with `update_posture` so live-finding keys and delta-rec keys agree (`hostname|serial`, or hostname when serial is absent/`OFFLINE-CONFIG`).
- **Lifecycle** (`_lifecycle(delta, host)` + `_plan`): new→create, carried→update, reopened→reopen, and **resolved→resolve closures** built from `delta.resolved` recs (they are ABSENT from `self.findings`, so iterating findings alone leaks stale tickets). `min_tier` filtering is symmetric across live and resolved via `_tier_of` / **`_tier_of_rec`** (both fall back to severity→tier when the prioritizer produced no tier — an earlier asymmetry here leaked closures for empty-tier recs under a stricter `--soar-min-tier`, caught by adversarial review).
- **Per-target fidelity** (researched against vendor docs): Jira v3 **ADF** description (every inline leaf `type:text`; no empty list nodes) or v2 plain string; space-free `fw-fp-<key>` label + `fwFinding` entity property; priority by tier. ServiceNow sets `urgency`+`impact` (**never** `priority` — OOB data lookup overwrites), `correlation_id=fwscan:<key>` (≤100 chars), short_desc≤160/desc≤4000. Splunk SOAR container+embedded artifact, `source_data_identifier` on **both** (`container_id` omitted on embedded artifact), lowercase `high/medium/low`. Webhook = **CloudEvents 1.0** + OCSF/ECS-lite `data` (identity is `data.dedup_key`/`subject`, NOT the per-emission `id`; `epss` is a probability, distinct from `epss_percentile`). KB remediation via `_kb_detail` (falls back to finding attrs when no KB).
- **Tests**: `test_data/test_soar_export.py` (dedup stability/host-scope/evidence-independence, live↔rec key equality, min-tier + severity fallback, Jira ADF/v2/labels/priority, ServiceNow no-priority + limits, Splunk SDI/severity/no-container_id, webhook CloudEvents identity + epss, full lifecycle incl. resolved closures across all 4 targets, save_* end-to-end). Built research(5-agent web workflow)→build→adversarial-review(6-lens+refute-verify) → 1 confirmed MEDIUM fixed (closure-leak asymmetry).

## Multi-Device Scanning

`MultiDeviceScanner` class. Inventory file (`--inventory devices.json`): `[{"host":"fw1","token":"xxx","name":"HQ-FW"}]`. Features: sequential scan with error handling, unified summary table, unified JSON, exit code 1 if any device has CRITICAL/HIGH.

## MITRE ATT&CK Resilience Testing

`_check_mitre_attack_resilience()` tests **34 MITRE ATT&CK Enterprise techniques across 11 tactics**. Each test verifies a specific FortiGate control is configured to mitigate the attack vector. Produces a resilience score (0-100%). (2026-07 additions: **T1505.003** Web Shell — inbound WAN→internal/DMZ policy without IPS+AV; **T1602** Data from Config Repository — SNMP v1/v2c or default community; **T1552.001** Unsecured Credentials — config secrets under the shared factory key / private-data-encryption disabled.)

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

Scoring: `MITRE-SUMMARY-PASS` (all 34 pass) or `MITRE-SUMMARY-SCORE` (percentage).

## Known CVEs (75 entries, 2018-2026)

| Range | Count | Severity Mix | Notes |
|-------|-------|-------------|-------|
| CVE-001 to 015 | 15 | 8 CRITICAL, 6 HIGH, 1 MEDIUM | KEV-listed SSL VPN / fgfmd RCEs, FortiJump, xortigate |
| CVE-016 to 030 | 15 | 5 CRITICAL, 7 HIGH, 3 MEDIUM | 2024-2025 CVEs, CSF proxy auth bypass, TACACS+ bypass |
| CVE-031 to 046 | 16 | 2 CRITICAL, 14 HIGH | 2023-2026 sweep: CAPWAP, IPsec IKE, FGFM, restricted CLI escape, LDAP bypass |
| CVE-047 to 070 | 24 | + proxy-mode RCE | SSL-VPN symlink re-persistence, RADIUS Blast-RADIUS, request smuggling, DNS-65 filter bypass, FSSO bypass, CVE-2023-33308 |
| CVE-071 to 075 | 5 | 1 CRITICAL, 2 HIGH, 2 MEDIUM | **Legacy CISA-KEV set (2018-2021)**: CVE-2018-13379/13382/13383 (SSL-VPN), CVE-2019-6693 (hard-coded config-backup key), CVE-2021-44168 (`execute restore` integrity) — legacy 5.x/6.0 trains |

Cross-product entries (FORTIOS-CVE-006/007/010 = FortiManager / FortiClient EMS) carry a `product`
field and are **skipped** by `_check_cves` — kept for documentation, never matched against FortiGate
firmware. Every new CVE that has a KEV floor is also present in `threat_intel.json`
(19 KEV-listed CVEs). CVE-002/004 now also carry the affected **6.0** train (EOL, sentinel `6.0.999`).

Train-based matching: `_parse_ver()`, `_ver_in_train()`, `_ver_lt()`. Trains: 5.2, 5.4, 5.6, 6.0, 6.2, 6.4, 7.0, 7.2, 7.4, 7.6.

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
     `split-tunneling-routing-address`, `source-address`, `source-address6`) shaped as
     `[{"name": X}]` lists to match the live API.
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
   `python fortinet_offline_scanner.py <conf> [--json …] [--html …] [--pdf …] [--csv …]
   [--compliance-csv …] [--sarif …] [--ocsf …] [--remediation …] [--fix-script …]
   [--rollback-script …] [--fix-tier P2] [--fix-script-force] [--framework cis]
   [--benchmark FILE] [--baseline …] [--severity …] [--no-color] [--summary-only] [--top N] [-v]`.
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

# Machine-ingestible exports (SARIF -> GitHub code-scanning/CI; OCSF -> SIEM) + full CSV
python fortinet_offline_scanner.py fw1.conf --sarif fw1.sarif --ocsf fw1.ocsf.json --csv findings.csv

# Generate a fix-first FortiOS CLI batch + paired rollback from the KB (P1-P2 only)
python fortinet_offline_scanner.py fw1.conf --fix-script fix.conf --rollback-script rollback.conf --fix-tier P2
#   disruptive fixes (reboot/HA/VPN-drop) are commented out unless --fix-script-force

# Compact console output (scorecard + fix-first queue only); disable colour for pipes
python fortinet_offline_scanner.py fw1.conf --summary-only --no-color

# Scored CIS benchmark to console + per-control CSV (or .json)
python fortinet_offline_scanner.py fw1.conf --framework cis --benchmark cis_benchmark.csv

# Threat-intel refresh (KEV + EPSS), then exit
python fortinet_scanner.py --refresh-intel

# Fix-first queue to the console
python fortinet_offline_scanner.py fw1.conf --top 15

# Fleet analysis — a whole folder of .conf backups into one report
python fortinet_offline_scanner.py --conf-dir /backups --html fleet.html --pdf fleet.pdf --json fleet.json
python fortinet_offline_scanner.py --fleet-inputs reports/ --html fleet.html

# Continuous posture (system of record + what-changed since last scan)
python fortinet_offline_scanner.py fw1.conf --history posture.json --exceptions accepted.json

# Traffic-aware policy engine — reachability query / simulate a proposed policy
python fortinet_offline_scanner.py fw1.conf --query "192.168.1.10 10.0.1.7 22/tcp"
python fortinet_offline_scanner.py fw1.conf --simulate proposed_policy.json

# Tests (271 cases: parser + rulebase + risk-prioritizer + cve-reachability + fleet +
#   posture + policy-engine + bug-fix regressions + new checks + exports + reporting +
#   benchmark + hardening)
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
