#!/usr/bin/env python3
"""
Fortinet FortiGate Offline Config Scanner v1.0.0

Audits a FortiGate firewall purely from an exported configuration backup
file (``execute backup config`` / GUI > System > Configuration > Backup).
No network access to the appliance is required, making this safe for
OT / air-gapped environments where the live REST API scanner cannot run.

Parses the FortiOS CLI-style .conf file into the same dict shape that the
live REST API returns, then delegates to ``FortinetScanner`` so every
existing config-based check (admin access, VPN, security profiles,
firewall policy, logging, HA, CVEs, MITRE ATT&CK resilience, etc.)
runs unchanged. Checks that require runtime telemetry (FortiGuard
license status, HA peer sync, current session table) are skipped
silently — they are not derivable from a static .conf.

Usage:
  python fortinet_offline_scanner.py /path/to/fortigate.conf
  python fortinet_offline_scanner.py fw1.conf --json report.json --html report.html
  python fortinet_offline_scanner.py fw1.conf --remediation fix.txt --compliance-csv audit.csv
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from fortinet_scanner import VERSION as ENGINE_VERSION
from fortinet_scanner import FortinetScanner

VERSION = "1.0.0"


# ========================================================================== #
#  CONFIG > API SHAPE TRANSLATION                                             #
# ========================================================================== #
#
# Fields whose API representation is a list of {"name": "X"} dicts but whose
# .conf form is a flat ``set key "val1" "val2"`` line. Without this shaping
# the scanner's policy/group/VPN checks (which do ``[a["name"] for a in ...]``)
# would crash with AttributeError on a plain string.
REF_LIST_FIELDS = frozenset({
    # firewall policy refs
    "srcaddr", "dstaddr", "srcaddr6", "dstaddr6",
    "service", "srcintf", "dstintf",
    "groups", "users",
    # SSL VPN / IPsec / user groups
    "member", "match",
    "ssl-vpn-client-cert",
    "ip-pools", "tunnel-ip-pools",
    # ZTNA / access proxy
    "api-gateway",
    # VPN portal split-tunnel address objects
    "split-tunneling-routing-address",
    # SSL-VPN source restriction (address-object references)
    "source-address", "source-address6",
})

# Sections whose `edit <id>` ID maps to a numeric ``policyid`` field instead
# of the default ``name`` field.
NUMERIC_EDIT_KEY = {
    "firewall/policy": "policyid",
    "firewall/policy6": "policyid",
    "firewall/DoS-policy": "policyid",
    "firewall/DoS-policy6": "policyid",
    "firewall/multicast-policy": "policyid",
    "firewall/local-in-policy": "policyid",
}

# Top-level wrappers that should be transparent — their nested ``config X Y``
# blocks are promoted to top-level endpoints. Covers VDOM-enabled configs and
# the global wrapper used in multi-VDOM exports.
WRAPPER_SECTIONS = frozenset({"vdom", "global"})


# ========================================================================== #
#  CONF PARSER                                                                #
# ========================================================================== #

class FortiGateConfParser:
    """Parse a FortiOS .conf backup file into ``{api_path: dict|list}``.

    The CLI section name (``config vpn ssl settings``) is converted into the
    REST API path (``vpn.ssl/settings``) by joining all words except the last
    with dots, then a slash, then the last word. Single-word sections become
    their own bare name (no slash).
    """

    # Tokenizes a line into quoted (group 1) or bare (group 2) tokens.
    _TOKEN_RE = re.compile(r'"((?:\\.|[^"\\])*)"|(\S+)')

    def __init__(self, text: str):
        self.lines = text.splitlines()
        self.pos = 0
        self.header_meta = self._parse_header()

    # ---------------------------------------------------------- header
    def _parse_header(self) -> dict:
        """Extract model/version/build from the ``#config-version=`` line.

        Header example:
            #config-version=FGT60F-7.2.5-FW-build1517-230718:opmode=0:vdom=0
            #buildno=1517
        """
        meta: dict = {}
        for line in self.lines[:30]:
            line = line.strip()
            if not line.startswith("#"):
                continue
            m = re.match(r"#config-version=([^:\s]+)", line)
            if m:
                parts = m.group(1).split("-")
                # ['FGT60F', '7.2.5', 'FW', 'build1517', '230718']
                if parts:
                    meta["model"] = parts[0]
                if len(parts) >= 2:
                    meta["version"] = parts[1]
                for tok in parts:
                    if tok.startswith("build") and tok[5:].isdigit():
                        meta["build"] = tok[5:]
                continue
            m = re.match(r"#buildno=(\d+)", line)
            if m:
                meta.setdefault("build", m.group(1))
        return meta

    # ---------------------------------------------------------- tokenize
    @classmethod
    def _tokenize(cls, line: str) -> list[str]:
        out: list[str] = []
        for m in cls._TOKEN_RE.finditer(line):
            tok = m.group(1) if m.group(1) is not None else m.group(2)
            out.append(tok)
        return out

    # ---------------------------------------------------------- path
    @staticmethod
    def _section_to_api_path(section: list[str]) -> str:
        if len(section) == 1:
            return section[0]
        return ".".join(section[:-1]) + "/" + section[-1]

    # ---------------------------------------------------------- entry
    def parse(self) -> dict:
        result: dict = {}
        self.pos = 0
        while self.pos < len(self.lines):
            line = self.lines[self.pos].strip()
            self.pos += 1
            if not line or line.startswith("#"):
                continue
            tokens = self._tokenize(line)
            if not tokens or tokens[0] != "config" or len(tokens) < 2:
                continue
            section = tokens[1:]
            if section[0] in WRAPPER_SECTIONS and len(section) == 1:
                self._consume_wrapper(result)
            else:
                api_path = self._section_to_api_path(section)
                result[api_path] = self._parse_block(api_path)
        return result

    # ---------------------------------------------------------- wrapper
    def _consume_wrapper(self, result: dict) -> None:
        """Inside ``config vdom`` / ``config global`` — lift nested configs.

        These wrappers may contain bare ``edit "root" ... next`` pairs whose
        body is a stack of real config sections. We flatten them so the
        scanner sees one canonical set of endpoints. Multi-VDOM configs
        collapse to the last-seen VDOM (acceptable for an audit baseline).
        """
        while self.pos < len(self.lines):
            line = self.lines[self.pos].strip()
            self.pos += 1
            if not line or line.startswith("#"):
                continue
            tokens = self._tokenize(line)
            if not tokens:
                continue
            cmd = tokens[0]
            if cmd == "end":
                return
            if cmd in ("edit", "next"):
                continue
            if cmd == "config" and len(tokens) >= 2:
                section = tokens[1:]
                api_path = self._section_to_api_path(section)
                result[api_path] = self._parse_block(api_path)

    # ---------------------------------------------------------- block
    def _parse_block(self, api_path: str) -> dict | list:
        """Parse from after ``config X`` until matching ``end``.

        If the block contains any ``edit`` lines, returns a list of dicts
        (one per entry). Otherwise returns a flat dict of set keys.
        """
        entries: list = []
        current: dict = {}
        is_list = False
        edit_key = NUMERIC_EDIT_KEY.get(api_path, "name")

        while self.pos < len(self.lines):
            line = self.lines[self.pos].strip()
            self.pos += 1
            if not line or line.startswith("#"):
                continue
            tokens = self._tokenize(line)
            if not tokens:
                continue
            cmd = tokens[0]

            if cmd == "end":
                return entries if is_list else current

            if cmd == "edit" and len(tokens) >= 2:
                is_list = True
                entries.append(self._parse_edit(tokens[1], edit_key))
            elif cmd == "set" and len(tokens) >= 2:
                current[tokens[1]] = self._coerce_value(tokens[1], tokens[2:])
            elif cmd == "unset" and len(tokens) >= 2:
                current[tokens[1]] = ""
            elif cmd == "config" and len(tokens) >= 2:
                # Nested sub-section at section root (rare — usually inside edit).
                sub_key = tokens[-1]
                current[sub_key] = self._parse_block(self._section_to_api_path(tokens[1:]))

        return entries if is_list else current

    # ---------------------------------------------------------- edit
    def _parse_edit(self, edit_id: str, edit_key: str) -> dict:
        """Parse from ``edit X`` until matching ``next``.

        Always sets ``name`` so display logic works. For numeric edit IDs
        also sets the appropriate integer key (``policyid`` for the policy
        endpoints listed in NUMERIC_EDIT_KEY, ``id`` for everything else
        like SNMP communities, BGP neighbours, automation triggers). This
        mirrors how the live REST API returns these objects.
        """
        entry: dict = {"name": edit_id}
        if self._INT_RE.match(edit_id):
            try:
                int_val = int(edit_id)
            except ValueError:
                int_val = None
            if int_val is not None:
                if edit_key == "policyid":
                    entry["policyid"] = int_val
                else:
                    entry["id"] = int_val
        elif edit_key == "policyid":
            # Non-numeric edit ID for a policy section (very unusual) — keep
            # the string form under policyid so subsequent checks still find it.
            entry["policyid"] = edit_id

        while self.pos < len(self.lines):
            line = self.lines[self.pos].strip()
            self.pos += 1
            if not line or line.startswith("#"):
                continue
            tokens = self._tokenize(line)
            if not tokens:
                continue
            cmd = tokens[0]

            if cmd == "next":
                return entry
            if cmd == "end":
                # Defensive: some malformed exports omit the trailing 'next'.
                self.pos -= 1
                return entry
            if cmd == "set" and len(tokens) >= 2:
                entry[tokens[1]] = self._coerce_value(tokens[1], tokens[2:])
            elif cmd == "unset" and len(tokens) >= 2:
                entry[tokens[1]] = ""
            elif cmd == "config" and len(tokens) >= 2:
                sub_key = tokens[-1]
                entry[sub_key] = self._parse_block(self._section_to_api_path(tokens[1:]))
            # ignore: rename, move, select, append, edit-error, etc.

        return entry

    # ---------------------------------------------------------- value
    _INT_RE = re.compile(r"^-?\d+$")

    @classmethod
    def _coerce_value(cls, key: str, vals: list[str]):
        """Map a `set` line's value tokens to the shape the live API returns.

        - Reference fields -> ``[{"name": v}, ...]`` so checks like
          ``[a["name"] for a in srcaddr]`` work.
        - Single digit-only token -> ``int`` so the scanner's many
          ``isinstance(x, int) and x > N`` comparisons fire correctly.
          Without this, ~30 admin-timeout / password-policy / VPN-keylife
          findings silently no-op.
        - Multi-token values stay as space-joined strings (preserves
          things like ``admin-https-ssl-versions "tlsv1-0 tlsv1-1 tlsv1-2"``).
        """
        if not vals:
            return ""
        if key in REF_LIST_FIELDS:
            return [{"name": v} for v in vals]
        if len(vals) == 1:
            v = vals[0]
            if cls._INT_RE.match(v):
                try:
                    return int(v)
                except ValueError:
                    pass
            return v
        return " ".join(vals)


# ========================================================================== #
#  OFFLINE SCANNER                                                            #
# ========================================================================== #

class OfflineFortinetScanner(FortinetScanner):
    """Drop-in replacement that resolves API paths from a parsed .conf.

    The 18 ``_check_*`` methods on ``FortinetScanner`` all funnel through
    ``_api_get``. Overriding that single method makes every check operate
    on the parsed file. Runtime-only endpoints (``monitor=True`` other than
    a synthesized ``system/status``) return ``None``; the live checks
    already handle this by skipping with a ``_warn``.
    """

    def __init__(self, conf_path: str, verbose: bool = False):
        self.host = conf_path
        self.token = ""
        self.verify_ssl = False
        self.timeout = 0
        self.verbose = verbose
        self.findings = []
        self._sys_info: dict = {}
        self._fw_version: tuple[int, ...] = ()

        text = Path(conf_path).read_text(encoding="utf-8", errors="replace")
        parser = FortiGateConfParser(text)
        self._responses = parser.parse()
        self._header_meta = parser.header_meta

    # ---------------------------------------------------------- _api_get
    def _api_get(self, path: str, monitor: bool = False):
        if path == "system/status" and monitor:
            return self._synth_system_status()
        if monitor:
            # No runtime telemetry available offline. The live checks already
            # tolerate None here (skip-with-warn semantics).
            return None
        return self._responses.get(path)

    # ---------------------------------------------------------- system_status
    def _synth_system_status(self) -> dict:
        glb = self._responses.get("system/global") or {}
        meta = self._header_meta
        version = meta.get("version", "")
        build_str = meta.get("build", "0")
        try:
            build_int = int(build_str)
        except (TypeError, ValueError):
            build_int = 0
        model = meta.get("model", "unknown")
        return {
            "version": f"v{version}" if version else "",
            "build": build_int,
            "hostname": glb.get("hostname", Path(self.host).stem),
            "model": model,
            "model_name": model,
            "serial": "OFFLINE-CONFIG",
        }

    # ---------------------------------------------------------- scan banner
    def scan(self) -> None:
        """Identical control flow to FortinetScanner.scan(), offline-friendly banner."""
        print(f"[*] Fortinet FortiOS Offline Scanner v{VERSION} (engine v{ENGINE_VERSION})")
        print(f"[*] Config file: {self.host}")
        print(f"[*] Parsing offline configuration ...")

        if not self._get_system_status():
            print(
                "[!] Could not determine FortiOS version from config header.\n"
                "    Expected a '#config-version=MODEL-VERSION-...' comment at the top of the file.",
                file=sys.stderr,
            )
            sys.exit(1)

        ver = self._sys_info.get("version", "N/A")
        hostname = self._sys_info.get("hostname", "N/A")
        model = self._sys_info.get("model_name", "N/A")
        endpoints = len(self._responses)
        print(f"[*] Parsed {endpoints} config sections from {hostname} ({model}), FortiOS {ver}")
        print(f"[*] Running offline security checks ...\n")

        checks = [
            ("Known CVEs",              self._check_cves),
            ("Admin Access",            self._check_admin_access),
            ("System Settings",         self._check_system_settings),
            ("Firewall Policies",       self._check_firewall_policies),
            ("Rule-Base Analysis",      self._check_rulebase),
            ("Rule Usage",              self._check_rule_usage),
            ("Object Hygiene",          self._check_object_hygiene),
            ("Attack Surface",          self._check_exposure),
            ("SSL VPN",                 self._check_ssl_vpn),
            ("IPsec VPN",               self._check_ipsec_vpn),
            ("Security Profiles",       self._check_security_profiles),
            ("Logging & Monitoring",    self._check_logging),
            ("High Availability",       self._check_ha),
            ("Certificates",            self._check_certificates),
            ("Network Hardening",       self._check_network),
            ("ZTNA / SASE",             self._check_ztna),
            ("FortiGuard & Updates",    self._check_fortiguard),
            ("Wireless Security",       self._check_wireless),
            ("Backup & DR",             self._check_backup),
            ("Authentication",          self._check_authentication),
            ("Advanced Hardening",      self._check_advanced_hardening),
            ("MITRE ATT&CK Resilience", self._check_mitre_attack_resilience),
        ]

        for name, func in checks:
            self._vprint(f"  [check] {name}")
            try:
                func()
            except Exception as exc:
                self._warn(f"{name} check failed: {exc}")

        print(f"\n[*] Offline scan complete. {len(self.findings)} finding(s).")


# ========================================================================== #
#  CLI                                                                        #
# ========================================================================== #

def _make_stdout_unicode_safe() -> None:
    """Reconfigure stdout/stderr so non-ASCII characters in finding text
    (e.g. an en-dash or arrow in a description) don't crash the run on
    Windows consoles that default to cp1252. Safe no-op everywhere else.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _make_stdout_unicode_safe()
    parser = argparse.ArgumentParser(
        prog="fortinet_offline_scanner",
        description=f"Fortinet FortiGate Offline Config Scanner v{VERSION} "
                    f"(engine v{ENGINE_VERSION})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fortinet_offline_scanner.py /backups/fw1.conf
  python fortinet_offline_scanner.py fw1.conf --json report.json --html report.html
  python fortinet_offline_scanner.py fw1.conf --remediation fix.txt --severity HIGH
  python fortinet_offline_scanner.py fw1.conf --compliance-csv audit.csv -v
""",
    )
    parser.add_argument("conf", nargs="?", default=None,
                        help="Path to a FortiGate .conf backup file "
                             "(optional when using --refresh-intel)")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to FILE")
    parser.add_argument("--html", metavar="FILE", help="Save detailed HTML report to FILE")
    parser.add_argument("--pdf", metavar="FILE",
                        help="Save detailed PDF report to FILE (stdlib only, no extra deps)")
    parser.add_argument("--remediation", metavar="FILE",
                        help="Export a detailed remediation runbook to FILE")
    parser.add_argument("--compliance-csv", metavar="FILE",
                        help="Export compliance CSV (CIS, PCI-DSS, NIST, SOC2, HIPAA)")
    parser.add_argument("--sarif", metavar="FILE",
                        help="Export findings as SARIF 2.1.0 (GitHub code-scanning / CI ingestion)")
    parser.add_argument("--ocsf", metavar="FILE",
                        help="Export findings as OCSF Compliance Finding events (SIEM ingestion)")
    parser.add_argument("--fix-script", metavar="FILE",
                        help="Generate a fix-first FortiOS CLI remediation script from the knowledge base")
    parser.add_argument("--rollback-script", metavar="FILE",
                        help="Also write the paired rollback script (use with --fix-script)")
    parser.add_argument("--fix-tier", choices=["P1", "P2", "P3", "P4"], default="P4",
                        help="Highest priority tier to include in the fix script (default: P4 = all)")
    parser.add_argument("--fix-script-force", action="store_true",
                        help="Include disruptive fixes (reboot/HA/VPN-drop) uncommented in the fix script")
    parser.add_argument("--baseline", metavar="FILE",
                        help="Prior --json report to diff against (config drift: new vs resolved + posture delta)")
    parser.add_argument("--top", type=int, nargs="?", const=10, default=None, metavar="N",
                        help="Print the risk-prioritized fix-first queue, showing the top N (default 10)")
    parser.add_argument("--refresh-intel", action="store_true",
                        help="Refresh the bundled threat-intel snapshot (CISA KEV + FIRST.org EPSS), then exit. "
                             "Requires internet access (not available on air-gapped hosts).")
    parser.add_argument("--export-intel", metavar="FILE",
                        help="Copy the current threat-intel snapshot to FILE (to sneakernet to an air-gapped host), then exit.")
    parser.add_argument("--import-intel", metavar="FILE",
                        help="Install a hand-carried threat-intel snapshot from FILE as the active snapshot, then exit.")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument("--csv", metavar="FILE",
                        help="Export a full findings CSV (severity, tier, KEV, EPSS, CVE, compliance, evidence)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour in console output (also honours the NO_COLOR env var)")
    parser.add_argument("--summary-only", "--quiet", dest="summary_only", action="store_true",
                        help="Print only the scorecard + fix-first queue (skip the full per-finding dump)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION} (engine {ENGINE_VERSION})")
    args = parser.parse_args(argv)

    if args.refresh_intel:
        return _refresh_intel_offline()
    if args.export_intel or args.import_intel:
        from fortinet_scanner import _transfer_intel
        if args.export_intel:
            return _transfer_intel("export", args.export_intel)
        return _transfer_intel("import", args.import_intel)

    if not args.conf:
        parser.error("conf is required (path to a FortiGate .conf backup), "
                     "unless using --refresh-intel")

    if not os.path.isfile(args.conf):
        print(f"[!] Config file not found: {args.conf}", file=sys.stderr)
        return 2

    scanner = OfflineFortinetScanner(args.conf, verbose=args.verbose)
    scanner.scan()
    scanner.set_color(False if args.no_color else None)

    if args.severity:
        scanner.filter_severity(args.severity)
        scanner._sev_filter = f"{args.severity} and above"

    if args.baseline:
        scanner.apply_drift(args.baseline)

    if args.summary_only:
        scanner.print_summary_only()
    else:
        scanner.print_report()
        scanner.print_compliance_scorecard()
        scanner.print_priorities(args.top if args.top is not None else 10)

    if args.json:
        scanner.save_json(args.json)
    if args.csv:
        scanner.save_findings_csv(args.csv)
    if args.html:
        scanner.save_html(args.html)
    if args.pdf:
        scanner.save_pdf(args.pdf)
    if args.remediation:
        scanner.save_remediation(args.remediation)
    if args.compliance_csv:
        scanner.save_compliance_csv(args.compliance_csv)
    if args.sarif:
        scanner.save_sarif(args.sarif)
    if args.ocsf:
        scanner.save_ocsf(args.ocsf)
    if args.fix_script:
        scanner.save_remediation_script(args.fix_script, args.rollback_script,
                                        tier_max=args.fix_tier, force=args.fix_script_force)

    counts = scanner.summary()
    if counts.get("CRITICAL", 0) or counts.get("HIGH", 0):
        return 1
    return 0


def _refresh_intel_offline() -> int:
    """Refresh the bundled threat-intel snapshot (CISA KEV + FIRST.org EPSS)."""
    try:
        from risk_prioritizer import refresh_threat_intel
        from fortinet_scanner import FORTIOS_CVES
    except Exception as exc:
        print(f"[!] Risk-prioritization module unavailable: {exc}", file=sys.stderr)
        return 1
    cves = sorted({c["cve"] for c in FORTIOS_CVES if c.get("cve")})
    print(f"[*] Refreshing threat intel for {len(cves)} tracked CVE(s) from CISA KEV + FIRST.org EPSS …")
    try:
        meta = refresh_threat_intel(cves)
    except Exception as exc:
        print(f"[!] Threat-intel refresh failed: {exc}\n"
              f"    (offline/air-gapped? The bundled snapshot remains in use.)", file=sys.stderr)
        return 1
    print(f"[+] Snapshot updated: {meta['cve_count']} CVE(s), {meta['kev_count']} KEV-listed "
          f"(snapshot {meta['snapshot_date']}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
