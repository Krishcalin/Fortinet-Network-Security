"""
Fortinet FortiGate — PDF Report Generator
=========================================
Renders the scan findings as a professional, paginated PDF security-assessment
report suitable for handing to a network / firewall team — built entirely on
``pdf_writer.PDFWriter`` (Python standard library only, no reportlab / weasyprint),
so it works in the offline / air-gapped scanner too.

Layout:
  - Cover page (title, device/scope metadata, overall risk posture, severity grid)
  - Executive summary (posture narrative, severity table, category breakdown,
    top-priority Critical/High findings)
  - Detailed findings — one styled block per finding with the full detailed
    remediation from the knowledge base (risk, numbered steps, GUI path, CLI
    block, verification, rollback, service impact, references) and the evidence,
    with automatic page breaks and running header/footer.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pdf_writer import PDFWriter
from remediation_kb import RemediationKB

# ── palette (print-friendly, Fortinet-flavoured) ──
BAND = (0.13, 0.15, 0.19)     # dark slate cover band / header
ACCENT = (0.85, 0.16, 0.11)   # Fortinet red
INK = (0.12, 0.16, 0.22)
MUTED = (0.42, 0.45, 0.50)
FAINT = (0.60, 0.63, 0.68)
RULE = (0.84, 0.86, 0.89)
LIGHT = (0.955, 0.965, 0.975)
CODEBG = (0.96, 0.97, 0.985)
LINK = (0.15, 0.39, 0.92)
WHITE = (1, 1, 1)

SEV_COLOR = {
    "CRITICAL": (0.72, 0.11, 0.11),
    "HIGH": (0.79, 0.29, 0.05),
    "MEDIUM": (0.11, 0.35, 0.72),
    "LOW": (0.09, 0.50, 0.20),
    "INFO": (0.30, 0.33, 0.38),
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

TIER_COLOR = {
    "P1": (0.72, 0.11, 0.11),
    "P2": (0.79, 0.29, 0.05),
    "P3": (0.11, 0.35, 0.72),
    "P4": (0.09, 0.50, 0.20),
}


def _g(f: Any, key: str, default: Any = "") -> Any:
    """Read a field from a Finding object or a dict."""
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def _compliance_str(f: Any) -> str:
    comp = _g(f, "compliance", {}) or {}
    if not isinstance(comp, dict):
        return ""
    parts = []
    for fw in ("CIS", "PCI-DSS", "NIST", "SOC2", "HIPAA"):
        vals = comp.get(fw)
        if vals:
            parts.append(f"{fw} {', '.join(vals)}")
    return "  -  ".join(parts)


class FortinetPDFReport:
    ML, MR, MT, MB = 45, 45, 56, 44

    def __init__(self, findings: List[Any], meta: Dict[str, Any],
                 kb: Optional[RemediationKB] = None,
                 priorities: Optional[List[Any]] = None):
        self.findings = findings
        self.meta = meta or {}
        self.kb = kb or RemediationKB()
        if priorities is None:
            try:
                from risk_prioritizer import RiskPrioritizer, ThreatIntel
                priorities = RiskPrioritizer(ThreatIntel()).prioritize(findings)
            except Exception:
                priorities = []
        self.priorities = priorities or []
        self.prio_by_id = {id(p.finding): p for p in self.priorities}
        self.w = PDFWriter()
        self.pw, self.ph = self.w.pw, self.w.ph
        self.cw = self.pw - self.ML - self.MR
        self.y = 0.0

        self.by_sev: Dict[str, int] = {}
        self.by_cat: Dict[str, int] = {}
        for f in findings:
            sev = _g(f, "severity", "INFO")
            cat = _g(f, "category", "Other")
            self.by_sev[sev] = self.by_sev.get(sev, 0) + 1
            self.by_cat[cat] = self.by_cat.get(cat, 0) + 1
        self.crit = self.by_sev.get("CRITICAL", 0)
        self.high = self.by_sev.get("HIGH", 0)
        self.med = self.by_sev.get("MEDIUM", 0)
        self.low = self.by_sev.get("LOW", 0)
        self.info = self.by_sev.get("INFO", 0)
        self.risk_score = min(100, self.crit * 25 + self.high * 10 + self.med * 4 + self.low * 1)
        self.risk_label, self.risk_col = self._risk_band(self.risk_score)

    @staticmethod
    def _risk_band(score: int):
        if score >= 75:
            return "Critical", SEV_COLOR["CRITICAL"]
        if score >= 50:
            return "High", SEV_COLOR["HIGH"]
        if score >= 25:
            return "Medium", SEV_COLOR["MEDIUM"]
        return "Low", SEV_COLOR["LOW"]

    # ── cursor helpers (top-down) ──
    def _new_content_page(self):
        self.w.add_page()
        self.w.text(self.ML, self.ph - 30, "Fortinet FortiGate — Security Assessment Report",
                    font="HB", size=7.5, color=MUTED)
        conf = "CONFIDENTIAL"
        self.w.text(self.pw - self.MR - self.w.string_width(conf, "HB", 7.5),
                    self.ph - 30, conf, font="HB", size=7.5, color=SEV_COLOR["CRITICAL"])
        self.w.line(self.ML, self.ph - 38, self.pw - self.MR, self.ph - 38, color=RULE, width=0.6)
        self.y = self.ph - self.MT

    def _ensure(self, h: float):
        if self.y - h < self.MB:
            self._new_content_page()

    def _para(self, text: str, font="H", size=9.5, color=INK, leading=13.5,
              gap_after=0.0, indent=0.0, x0: Optional[float] = None):
        if not text:
            return
        x0 = self.ML if x0 is None else x0
        for ln in self.w.wrap(text, font, size, self.cw - indent - (x0 - self.ML)):
            self._ensure(leading)
            self.w.text(x0 + indent, self.y - size, ln, font=font, size=size, color=color)
            self.y -= leading
        self.y -= gap_after

    def _numbered(self, steps: List[str], size=9.5, leading=13.5):
        """Render a numbered list with hanging indent."""
        hang = 20.0
        for i, step in enumerate(steps, 1):
            if not step:
                continue
            num = f"{i}."
            lines = self.w.wrap(step, "H", size, self.cw - hang)
            for j, ln in enumerate(lines):
                self._ensure(leading)
                if j == 0:
                    self.w.text(self.ML + 4, self.y - size, num, font="HB", size=size, color=INK)
                self.w.text(self.ML + hang, self.y - size, ln, font="H", size=size, color=INK)
                self.y -= leading
            self.y -= 1.5

    def _code_block(self, text: str, size=8.2, leading=11.0):
        """Render a CLI block in Courier inside a tinted box."""
        if not text:
            return
        lines: List[str] = []
        for raw in text.split("\n"):
            wrapped = self.w.wrap(raw, "C", size, self.cw - 24)
            lines.extend(wrapped or [""])
        block_h = len(lines) * leading + 10
        self._ensure(block_h + 4)
        top = self.y
        self.w.rect(self.ML, top - block_h, self.cw, block_h, fill=CODEBG, stroke=RULE, line_width=0.6)
        self.w.rect(self.ML, top - block_h, 3, block_h, fill=(0.35, 0.60, 0.45))
        yy = top - 5
        for ln in lines:
            yy -= leading
            self.w.text(self.ML + 12, yy, ln, font="C", size=size, color=(0.13, 0.20, 0.16))
        self.y = top - block_h - 4

    def _label(self, text: str, color=MUTED):
        self._ensure(15)
        self.w.text(self.ML, self.y - 8, text.upper(), font="HB", size=7.5, color=color)
        self.y -= 15

    # ── sections ──
    def generate(self, output_path: str):
        self._cover_page()
        self._exec_summary()
        self._priority_page()
        self._detailed_findings()
        self._footers()
        self.w.save(output_path)

    def _cover_page(self):
        w = self.w
        w.add_page()
        w.rect(0, self.ph - 150, self.pw, 150, fill=BAND)
        w.rect(0, self.ph - 154, self.pw, 4, fill=ACCENT)
        w.text(self.ML, self.ph - 62, "FORTINET FORTIGATE", font="HB", size=13, color=(0.95, 0.55, 0.50))
        w.text(self.ML, self.ph - 100, "Security Assessment Report", font="HB", size=26, color=WHITE)
        w.text(self.ML, self.ph - 124, "FortiOS NGFW configuration, CVE and MITRE ATT&CK posture review",
               font="H", size=10.5, color=(0.78, 0.80, 0.84))

        y = self.ph - 210
        # scope / device card
        card_h = 116
        w.rect(self.ML, y - card_h, self.cw, card_h, fill=LIGHT, stroke=RULE, line_width=0.8)
        kv = [
            ("Target host", str(self.meta.get("host", "N/A"))),
            ("Hostname", str(self.meta.get("hostname", "N/A"))),
            ("Model", str(self.meta.get("model", "N/A"))),
            ("FortiOS version", str(self.meta.get("version", "N/A"))),
            ("Serial", str(self.meta.get("serial", "N/A"))),
            ("Assessment date", str(self.meta.get("generated", ""))[:19]),
            ("Severity filter", str(self.meta.get("severity_filter", "ALL"))),
        ]
        yy = y - 20
        for k, v in kv:
            w.text(self.ML + 16, yy, k, font="HB", size=8.5, color=MUTED)
            w.text(self.ML + 150, yy, v[:70], font="H", size=9.5, color=INK)
            yy -= 14.2

        # risk posture + severity grid
        y2 = y - card_h - 16
        box_h = 118
        lw = 170
        w.rect(self.ML, y2 - box_h, lw, box_h, fill=WHITE, stroke=RULE, line_width=0.8)
        w.rect(self.ML, y2 - 4, lw, 4, fill=self.risk_col)
        w.text(self.ML + 16, y2 - 26, "OVERALL RISK", font="HB", size=8, color=MUTED)
        score = str(self.risk_score)
        w.text(self.ML + 16, y2 - 74, score, font="HB", size=46, color=self.risk_col)
        w.text(self.ML + 20 + w.string_width(score, "HB", 46), y2 - 74, "/100",
               font="H", size=12, color=FAINT)
        w.text(self.ML + 16, y2 - 96, self.risk_label.upper() + " RISK POSTURE",
               font="HB", size=9, color=self.risk_col)

        gx = self.ML + lw + 14
        gw = self.cw - lw - 14
        w.rect(gx, y2 - box_h, gw, box_h, fill=WHITE, stroke=RULE, line_width=0.8)
        w.text(gx + 16, y2 - 26, "FINDINGS BY SEVERITY   (total %d)" % len(self.findings),
               font="HB", size=8, color=MUTED)
        cells = [("CRITICAL", self.crit), ("HIGH", self.high), ("MEDIUM", self.med),
                 ("LOW", self.low), ("INFO", self.info)]
        cw2 = (gw - 32) / 5
        for i, (name, n) in enumerate(cells):
            cx = gx + 16 + i * cw2
            col = SEV_COLOR[name]
            w.text(cx, y2 - 66, str(n), font="HB", size=25, color=col)
            w.text(cx, y2 - 84, name, font="HB", size=6.8, color=MUTED)
            w.rect(cx, y2 - 92, cw2 - 8, 3, fill=col)

        note = ("CONFIDENTIAL - This report contains sensitive security information about "
                "network firewall infrastructure and is intended solely for authorized network, "
                "security and audit personnel. Handle, store and distribute it according to your "
                "organisation's information-classification policy. The scan is a point-in-time, "
                "read-only assessment of FortiGate configuration and firmware; it does not modify "
                "the device.")
        self.y = y2 - box_h - 24
        self._para(note, font="H", size=8, color=MUTED, leading=11.5)
        w.text(self.ML, self.MB + 6,
               "Generated by the Fortinet FortiGate Security Scanner", font="HB", size=8, color=FAINT)

    def _exec_summary(self):
        self._new_content_page()
        self._section_title("Executive Summary")
        total = len(self.findings)
        posture = (
            f"This assessment reviewed the FortiGate configuration, firmware and control posture "
            f"and produced {total} finding(s): {self.crit} Critical, {self.high} High, {self.med} "
            f"Medium, {self.low} Low and {self.info} Info. The computed risk score is "
            f"{self.risk_score}/100, an overall '{self.risk_label}' risk posture. Critical and High "
            "findings are directly exploitable or materially weaken the device's security or "
            "compliance posture and should be remediated first, in that order. Each finding in the "
            "detailed section states the specific security risk, the evidence observed, and a "
            "step-by-step remediation procedure (CLI and GUI) with verification, rollback and "
            "service-impact guidance the firewall team can execute."
        )
        self._para(posture, gap_after=8)

        self._label("Severity breakdown")
        rows = [("Severity", "Count", "Share")]
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = self.by_sev.get(name, 0)
            if n == 0 and name == "INFO":
                continue
            pct = (n / total * 100) if total else 0
            rows.append((name.title(), str(n), f"{pct:.0f}%"))
        self._sev_table(rows)
        self.y -= 8

        self._label("Findings by category")
        maxc = max(self.by_cat.values()) if self.by_cat else 1
        for cat, n in sorted(self.by_cat.items(), key=lambda x: -x[1]):
            self._ensure(16)
            self.w.text(self.ML, self.y - 8, cat[:46], font="H", size=8.5, color=INK)
            bar_x = self.ML + 210
            bar_w = self.cw - 210 - 30
            self.w.rect(bar_x, self.y - 10, bar_w, 8, fill=LIGHT)
            self.w.rect(bar_x, self.y - 10, max(2, bar_w * n / maxc), 8, fill=ACCENT)
            self.w.text(self.ML + self.cw - 20, self.y - 8, str(n), font="HB", size=8.5, color=MUTED)
            self.y -= 15
        self.y -= 8

        crits = [f for f in self.findings if _g(f, "severity") in ("CRITICAL", "HIGH")]
        crits.sort(key=lambda f: SEV_ORDER.get(_g(f, "severity"), 9))
        if crits:
            self._label("Top-priority findings (Critical & High)")
            for f in crits[:18]:
                self._ensure(15)
                col = SEV_COLOR[_g(f, "severity")]
                self.w.rect(self.ML, self.y - 11, 46, 11, fill=col)
                self.w.text(self.ML + 4, self.y - 9, _g(f, "severity")[:4], font="HB", size=7, color=WHITE)
                label = (str(_g(f, "rule_id")) + "  " + str(_g(f, "name")))
                self.w.text(self.ML + 54, self.y - 9, self._fit(label, "H", 8.5, self.cw - 60),
                            font="H", size=8.5, color=INK)
                self.y -= 14.5
            if len(crits) > 18:
                self._para(f"... and {len(crits) - 18} more Critical/High finding(s) in the detailed section.",
                           font="HO", size=8, color=MUTED)

    def _priority_page(self):
        if not self.priorities:
            return
        try:
            from risk_prioritizer import TIER_META
        except Exception:
            return
        counts: Dict[str, int] = {t: 0 for t in TIER_META}
        for r in self.priorities:
            counts[r.tier] = counts.get(r.tier, 0) + 1

        self._new_content_page()
        self._section_title("Risk-Prioritized Remediation Queue")
        snap = self.meta.get("intel_snapshot")
        kevn = self.meta.get("intel_kev_count")
        intro = ("Findings below are ranked into fix-first tiers by fusing three signals: the intrinsic "
                 "severity of the weakness, its real-world exploitability (CISA Known-Exploited-Vulnerabilities "
                 "membership and the FIRST.org EPSS exploitation-probability score for CVE findings), and whether "
                 "the affected surface is actually reachable from the internet on this device. This answers not "
                 "just 'how bad' but 'what to fix first'.")
        if snap:
            intro += (f" Threat-intel snapshot: {snap}"
                      + (f" ({kevn} KEV-listed CVE(s) applicable)." if kevn else "."))
        self._para(intro, gap_after=10)

        # tier cards row
        self._ensure(64)
        cw4 = (self.cw - 3 * 10) / 4
        top = self.y
        for i, t in enumerate(("P1", "P2", "P3", "P4")):
            m = TIER_META[t]
            col = TIER_COLOR[t]
            cx = self.ML + i * (cw4 + 10)
            self.w.rect(cx, top - 58, cw4, 58, fill=LIGHT, stroke=RULE, line_width=0.7)
            self.w.rect(cx, top - 4, cw4, 4, fill=col)
            self.w.text(cx + 10, top - 26, t, font="HB", size=17, color=col)
            self.w.text(cx + 40, top - 26, str(counts[t]), font="HB", size=15, color=INK)
            self.w.text(cx + 10, top - 40, m["label"][:22], font="HB", size=7.5, color=INK)
            self.w.text(cx + 10, top - 50, m["window"][:24], font="H", size=7, color=MUTED)
        self.y = top - 58 - 16

        # top risks table
        top_risks = [r for r in self.priorities if r.tier in ("P1", "P2")][:16]
        if not top_risks:
            top_risks = self.priorities[:10]
        if top_risks:
            self._label("Fix-first order")
            # header
            self._ensure(16)
            self.w.rect(self.ML, self.y - 15, self.cw, 15, fill=BAND)
            self.w.text(self.ML + 6, self.y - 11, "#", font="HB", size=7.5, color=WHITE)
            self.w.text(self.ML + 26, self.y - 11, "TIER", font="HB", size=7.5, color=WHITE)
            self.w.text(self.ML + 62, self.y - 11, "SCORE", font="HB", size=7.5, color=WHITE)
            self.w.text(self.ML + 100, self.y - 11, "FINDING", font="HB", size=7.5, color=WHITE)
            self.w.text(self.ML + self.cw - 96, self.y - 11, "EXPLOITABILITY", font="HB", size=7.5, color=WHITE)
            self.y -= 15
            for i, r in enumerate(top_risks, 1):
                f = r.finding
                rowh = 15
                self._ensure(rowh)
                if i % 2 == 0:
                    self.w.rect(self.ML, self.y - rowh, self.cw, rowh, fill=LIGHT)
                col = TIER_COLOR.get(r.tier, MUTED)
                self.w.text(self.ML + 6, self.y - 11, str(i), font="H", size=8, color=MUTED)
                self.w.rect(self.ML + 24, self.y - 12, 24, 10, fill=col)
                self.w.text(self.ML + 28, self.y - 10.5, r.tier, font="HB", size=7, color=WHITE)
                self.w.text(self.ML + 64, self.y - 11, str(r.score), font="HB", size=8.5, color=col)
                nm = str(_g(f, "name"))
                self.w.text(self.ML + 100, self.y - 11,
                            self._fit(nm, "H", 8, self.cw - 100 - 100), font="H", size=8, color=INK)
                tags = []
                if r.kev:
                    tags.append("KEV")
                if r.epss is not None and r.epss >= 0.10:
                    tags.append(f"EPSS {r.epss*100:.0f}%")
                if r.reachable:
                    tags.append("exposed")
                tstr = ", ".join(tags) if tags else "-"
                self.w.text(self.ML + self.cw - 96, self.y - 11,
                            self._fit(tstr, "H", 7.5, 94), font="HB", size=7.5, color=col if tags else FAINT)
                self.y -= rowh
            self.y -= 6
            legend = ("P1 Fix now (24-72h)   P2 Fix this week   P3 Planned (30d)   P4 Backlog/accept. "
                      "KEV = on CISA's actively-exploited list; EPSS = FIRST.org 30-day exploitation probability; "
                      "exposed = internet-reachable on this device.")
            self._para(legend, font="HO", size=7.5, color=MUTED, leading=10.5)

    def _detailed_findings(self):
        self._new_content_page()
        self._section_title("Detailed Findings & Remediation")
        ordered = sorted(self.findings,
                         key=lambda f: (SEV_ORDER.get(_g(f, "severity"), 9), str(_g(f, "rule_id"))))
        for f in ordered:
            self._finding_block(f)

    def _finding_block(self, f: Any):
        sev = _g(f, "severity", "INFO")
        col = SEV_COLOR.get(sev, MUTED)
        d = self.kb.detail_for(f)

        self._ensure(64)
        self.y -= 6
        top = self.y
        self.w.rect(self.ML, top - 30, self.cw, 30, fill=LIGHT, stroke=RULE, line_width=0.7)
        self.w.rect(self.ML, top - 30, 4, 30, fill=col)
        self.w.rect(self.ML + 12, top - 21, 54, 13, fill=col)
        self.w.text(self.ML + 16, top - 18.5, sev[:8], font="HB", size=7.5, color=WHITE)
        self.w.text(self.ML + 74, top - 19,
                    self._fit(str(_g(f, "name")), "HB", 10, self.cw - 74 - 120),
                    font="HB", size=10, color=INK)
        cid = str(_g(f, "rule_id"))
        self.w.text(self.pw - self.MR - 10 - self.w.string_width(cid, "H", 8.5), top - 19,
                    cid, font="H", size=8.5, color=MUTED)
        self.y = top - 38

        # priority tier line (fix-first rank + rationale)
        pr = self.prio_by_id.get(id(f))
        if pr is not None:
            pcol = TIER_COLOR.get(pr.tier, MUTED)
            self.w.rect(self.ML, self.y - 10, 26, 11, fill=pcol)
            self.w.text(self.ML + 4, self.y - 8.5, pr.tier, font="HB", size=7.5, color=WHITE)
            head = f"Priority {pr.tier}  -  score {pr.score}/100"
            self.w.text(self.ML + 32, self.y - 8, head, font="HB", size=8, color=pcol)
            self.y -= 13
            self.w.text(self.ML, self.y, self._fit(pr.rationale, "H", 7.8, self.cw),
                        font="HO", size=7.8, color=MUTED)
            self.y -= 12

        # context line: category | target
        ctx = "Category: " + str(_g(f, "category", "")) + "     Target: " + str(_g(f, "file_path", ""))
        self.w.text(self.ML, self.y, self._fit(ctx, "H", 8, self.cw), font="H", size=8, color=MUTED)
        self.y -= 13

        # evidence
        detail = str(_g(f, "line_content", "") or "")
        if detail:
            self.w.text(self.ML, self.y, self._fit("Evidence: " + detail, "H", 8, self.cw),
                        font="HO", size=8, color=FAINT)
            self.y -= 13

        # cross-refs (cwe / cve)
        cwe = _g(f, "cwe", None)
        cve = _g(f, "cve", None)
        xref = " | ".join([x for x in (cwe, cve) if x])
        if xref:
            self.w.text(self.ML, self.y, xref, font="HB", size=8, color=col)
            self.y -= 13

        # security risk
        self._label("Security risk", color=col)
        self._para(d["risk"], gap_after=5)

        # remediation steps
        if d["steps"]:
            self._label("Remediation - step by step")
            self._numbered(d["steps"])
            self.y -= 3

        # GUI path
        if d["gui"]:
            self._label("GUI path")
            self._para(d["gui"], font="H", size=9, gap_after=4)

        # CLI
        if d["cli"]:
            self._label("FortiOS CLI")
            self._code_block(d["cli"])

        # verify / rollback / impact
        if d["verify"]:
            self._label("Verification")
            self._para(d["verify"], font="H", size=9, gap_after=4)
        if d["rollback"]:
            self._label("Rollback")
            self._para(d["rollback"], font="H", size=9, gap_after=4)
        if d["impact"]:
            self._label("Service impact")
            self._para(d["impact"], font="H", size=9, gap_after=4)

        # references
        refs = d["references"] or []
        comp = _compliance_str(f)
        if comp:
            refs = list(refs) + [comp]
        if refs:
            self._label("References")
            for r in refs:
                self._ensure(12)
                self.w.text(self.ML + 8, self.y - 8, self._fit("- " + str(r), "H", 8, self.cw - 16),
                            font="H", size=8, color=LINK)
                self.y -= 11.5

        if not d.get("_detailed"):
            self._para("(No detailed knowledge-base entry for this rule; the finding's own "
                       "recommendation and CLI are shown.)", font="HO", size=7.5, color=FAINT)

        self._ensure(10)
        self.w.line(self.ML, self.y - 2, self.pw - self.MR, self.y - 2, color=RULE, width=0.5)
        self.y -= 10

    # ── small helpers ──
    def _section_title(self, text: str):
        self.w.rect(self.ML, self.y - 4, 30, 4, fill=ACCENT)
        self.y -= 12
        self.w.text(self.ML, self.y - 16, text, font="HB", size=16, color=BAND)
        self.y -= 26

    def _sev_table(self, rows: List[Tuple[str, str, str]]):
        col_x = [self.ML + 8, self.ML + 180, self.ML + 280]
        self._ensure(20)
        self.w.rect(self.ML, self.y - 16, self.cw, 16, fill=BAND)
        for i, h in enumerate(rows[0]):
            self.w.text(col_x[i], self.y - 12, h, font="HB", size=8, color=WHITE)
        self.y -= 16
        for ri, row in enumerate(rows[1:]):
            self._ensure(15)
            if ri % 2 == 0:
                self.w.rect(self.ML, self.y - 14, self.cw, 14, fill=LIGHT)
            sev_name = row[0].upper()
            dot = SEV_COLOR.get(sev_name)
            if dot:
                self.w.rect(self.ML + 8, self.y - 11, 8, 8, fill=dot)
            self.w.text(col_x[0] + (14 if dot else 0), self.y - 11, row[0], font="HB", size=8.5, color=INK)
            self.w.text(col_x[1], self.y - 11, row[1], font="H", size=8.5, color=INK)
            self.w.text(col_x[2], self.y - 11, row[2], font="H", size=8.5, color=MUTED)
            self.y -= 14

    def _fit(self, s: str, font: str, size: float, max_w: float) -> str:
        if self.w.string_width(s, font, size) <= max_w:
            return s
        ell = "..."
        while s and self.w.string_width(s + ell, font, size) > max_w:
            s = s[:-1]
        return s + ell

    def _footers(self):
        total = self.w.page_count
        gen = str(self.meta.get("generated", ""))[:19]
        for i in range(1, total):  # skip cover (index 0)
            saved = self.w._cur
            self.w._cur = self.w._pages[i]
            self.w.line(self.ML, self.MB - 6, self.pw - self.MR, self.MB - 6, color=RULE, width=0.5)
            self.w.text(self.ML, self.MB - 18, "Fortinet FortiGate Security Scanner", font="H", size=7, color=FAINT)
            label = "Page %d of %d" % (i + 1, total)
            self.w.text(self.pw - self.MR - self.w.string_width(label, "H", 7), self.MB - 18,
                        label, font="H", size=7, color=FAINT)
            if gen:
                mid = "Generated " + gen
                self.w.text((self.pw - self.w.string_width(mid, "H", 7)) / 2, self.MB - 18,
                            mid, font="H", size=7, color=FAINT)
            self.w._cur = saved
