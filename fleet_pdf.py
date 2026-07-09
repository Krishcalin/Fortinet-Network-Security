"""
Fortinet FortiGate — Fleet Analysis PDF Report
==============================================
A paginated, board-ready fleet report (cover + fleet KPIs, worst-device ranking,
remediation campaigns, firmware distribution) built entirely on the stdlib
``pdf_writer.PDFWriter`` (no reportlab / weasyprint) so it runs in the offline
scanner too.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pdf_writer import PDFWriter

BAND = (0.13, 0.15, 0.19)
ACCENT = (0.85, 0.16, 0.11)
INK = (0.12, 0.16, 0.22)
MUTED = (0.42, 0.45, 0.50)
FAINT = (0.60, 0.63, 0.68)
RULE = (0.84, 0.86, 0.89)
LIGHT = (0.955, 0.965, 0.975)
WHITE = (1, 1, 1)
SEV_COLOR = {"CRITICAL": (0.72, 0.11, 0.11), "HIGH": (0.79, 0.29, 0.05),
             "MEDIUM": (0.11, 0.35, 0.72), "LOW": (0.09, 0.50, 0.20), "INFO": (0.30, 0.33, 0.38)}


def _fit(w: PDFWriter, s: Any, font: str, size: float, max_w: float) -> str:
    s = "" if s is None else str(s)
    if w.string_width(s, font, size) <= max_w:
        return s
    while s and w.string_width(s + "...", font, size) > max_w:
        s = s[:-1]
    return s + "..."


class _Fleet:
    ML, MR, MT, MB = 45, 45, 56, 44

    def __init__(self, fleet: Any):
        self.a = fleet.agg
        self.w = PDFWriter()
        self.pw, self.ph = self.w.pw, self.w.ph
        self.cw = self.pw - self.ML - self.MR
        self.y = 0.0

    # cursor helpers
    def _page(self):
        self.w.add_page()
        self.w.text(self.ML, self.ph - 30, "Fortinet FortiGate — Fleet Analysis Report",
                    font="HB", size=7.5, color=MUTED)
        conf = "CONFIDENTIAL"
        self.w.text(self.pw - self.MR - self.w.string_width(conf, "HB", 7.5), self.ph - 30,
                    conf, font="HB", size=7.5, color=SEV_COLOR["CRITICAL"])
        self.w.line(self.ML, self.ph - 38, self.pw - self.MR, self.ph - 38, color=RULE, width=0.6)
        self.y = self.ph - self.MT

    def _ensure(self, h):
        if self.y - h < self.MB:
            self._page()

    def _title(self, t):
        self.w.rect(self.ML, self.y - 4, 30, 4, fill=ACCENT)
        self.y -= 12
        self.w.text(self.ML, self.y - 16, t, font="HB", size=15, color=BAND)
        self.y -= 26

    def _para(self, text, size=9.5, color=INK, leading=13.5, gap=0.0, font="H"):
        for ln in self.w.wrap(text, font, size, self.cw):
            self._ensure(leading)
            self.w.text(self.ML, self.y - size, ln, font=font, size=size, color=color)
            self.y -= leading
        self.y -= gap

    # sections
    def build(self, path):
        self._cover()
        self._worst()
        self._campaigns()
        self._firmware()
        self._footers()
        self.w.save(path)

    def _cover(self):
        a = self.a
        w = self.w
        w.add_page()
        w.rect(0, self.ph - 150, self.pw, 150, fill=BAND)
        w.rect(0, self.ph - 154, self.pw, 4, fill=ACCENT)
        w.text(self.ML, self.ph - 62, "FORTINET FORTIGATE", font="HB", size=13, color=(0.95, 0.55, 0.50))
        w.text(self.ML, self.ph - 100, "Fleet Analysis Report", font="HB", size=26, color=WHITE)
        w.text(self.ML, self.ph - 124, "Aggregated NGFW posture, worst-device ranking and remediation campaigns",
               font="H", size=10.5, color=(0.78, 0.80, 0.84))

        y = self.ph - 200
        # KPI cards
        cards = [("DEVICES", str(a["device_count"]), (0.09, 0.50, 0.45)),
                 ("FINDINGS", str(a["total_findings"]), (0.35, 0.30, 0.60)),
                 ("P1 FIX-NOW", str(a["tier_totals"].get("P1", 0)), SEV_COLOR["CRITICAL"]),
                 ("WORST SCORE", str(a["risk_max"]), SEV_COLOR["HIGH"]),
                 ("AVG SCORE", str(a["risk_avg"]), MUTED)]
        cw = (self.cw - 4 * 10) / 5
        for i, (lab, val, col) in enumerate(cards):
            cx = self.ML + i * (cw + 10)
            w.rect(cx, y - 60, cw, 60, fill=WHITE, stroke=RULE, line_width=0.8)
            w.rect(cx, y - 4, cw, 4, fill=col)
            w.text(cx + 10, y - 34, val, font="HB", size=22, color=col)
            w.text(cx + 10, y - 50, lab, font="HB", size=7, color=MUTED)

        # severity + tier line
        y2 = y - 60 - 20
        sev = a["severity_totals"]
        line = "Severity  " + "   ".join(f"{s.title()} {sev.get(s,0)}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        w.text(self.ML, y2, line, font="HB", size=9, color=INK)
        tiers = a["tier_totals"]
        tline = "Fix-first  " + "   ".join(f"{t} {tiers.get(t,0)}" for t in ("P1", "P2", "P3", "P4"))
        w.text(self.ML, y2 - 16, tline, font="HB", size=9, color=INK)

        self.y = y2 - 40
        if a["collisions"]:
            self._para("NOTE: " + str(len(a["collisions"])) + " duplicate hostname(s) across inputs were "
                       "disambiguated with #N suffixes so device counts are not inflated — verify they are "
                       "distinct devices.", size=8, color=SEV_COLOR["HIGH"], leading=11)
        self._para("This report aggregates single-device FortiGate scans into a fleet view. Devices are ranked "
                   "worst-first by risk score; remediation campaigns show how many firewalls each single fix "
                   "clears. CVE campaigns are gated on per-device reachability. It is a point-in-time, read-only "
                   "assessment and does not modify any device.", size=8.5, color=MUTED, leading=12)
        w.text(self.ML, self.MB + 6, "Generated by the Fortinet FortiGate Fleet Analysis Console",
               font="HB", size=8, color=FAINT)

    def _worst(self):
        a = self.a
        self._page()
        self._title("Worst Devices — Fix These First")
        self._row_header(["#", "HOSTNAME", "MODEL / FORTIOS", "RISK", "P1/P2", "CRIT/HIGH"],
                         [24, 150, 150, 40, 44, 60])
        for i, r in enumerate(a["worst_devices"], 1):
            self._ensure(14)
            if i % 2 == 0:
                self.w.rect(self.ML, self.y - 13, self.cw, 13, fill=LIGHT)
            x = self.ML + 4
            self.w.text(x, self.y - 10, str(i), font="H", size=8, color=MUTED)
            self.w.text(x + 24, self.y - 10, _fit(self.w, r["hostname"], "HB", 8.5, 146), font="HB", size=8.5, color=INK)
            self.w.text(x + 174, self.y - 10, _fit(self.w, f"{r['model']} · {r['version']}", "H", 8, 146), font="H", size=8, color=INK)
            self.w.text(x + 324, self.y - 10, str(r["risk_score"]), font="HB", size=8.5,
                        color=SEV_COLOR["CRITICAL"] if r["risk_score"] >= 75 else INK)
            self.w.text(x + 364, self.y - 10, f"{r['tiers'].get('P1',0)}/{r['tiers'].get('P2',0)}", font="H", size=8, color=INK)
            self.w.text(x + 408, self.y - 10, f"{r['counts'].get('CRITICAL',0)}/{r['counts'].get('HIGH',0)}", font="H", size=8, color=INK)
            self.y -= 13

    def _campaigns(self):
        a = self.a
        self._page()
        self._title("Remediation Campaigns — One Fix, Many Firewalls")
        self._para("Ranked by fleet coverage. 'Reach' = devices where the vulnerable service is internet-reachable "
                   "(CVE findings). Apply the listed change across the covered devices.", size=8, color=MUTED, leading=11, gap=4)
        for c in a["campaigns"][:26]:
            self._ensure(30)
            col = SEV_COLOR.get(c["severity"], MUTED)
            self.w.rect(self.ML, self.y - 15, self.cw, 15, fill=LIGHT)
            self.w.rect(self.ML, self.y - 15, 3, 15, fill=col)
            cov = f"{c['device_count']}/{a['device_count']}"
            if c.get("reachable"):
                cov += f"  ({c['reachable']} reach)"
            tags = ""
            if c.get("kev"):
                tags += " [KEV]"
            if c.get("ransomware"):
                tags += " [RW]"
            self.w.text(self.ML + 8, self.y - 11, c["severity"][:4], font="HB", size=7, color=col)
            self.w.text(self.ML + 34, self.y - 11, _fit(self.w, c["name"] + tags, "HB", 8.5, self.cw - 34 - 120),
                        font="HB", size=8.5, color=INK)
            self.w.text(self.pw - self.MR - 8 - self.w.string_width(cov, "HB", 8.5), self.y - 11,
                        cov, font="HB", size=8.5, color=col)
            self.y -= 15
            self.w.text(self.ML + 8, self.y - 9, _fit(self.w, c["rule_id"], "H", 7.5, 120), font="H", size=7.5, color=MUTED)
            fix = (c.get("fix") or {}).get("cli") or (c.get("fix") or {}).get("steps") or ""
            if fix:
                fix = fix.replace("\n", "  /  ")
                self.w.text(self.ML + 90, self.y - 9, _fit(self.w, fix, "C", 7.2, self.cw - 96),
                            font="C", size=7.2, color=(0.13, 0.30, 0.18))
            self.y -= 13

    def _firmware(self):
        a = self.a
        self._ensure(60)
        self._title("Firmware Distribution")
        mx = max(a["versions"].values()) if a["versions"] else 1
        for ver, cnt in sorted(a["versions"].items(), key=lambda x: -x[1]):
            self._ensure(16)
            self.w.text(self.ML, self.y - 9, _fit(self.w, "FortiOS " + str(ver), "H", 8.5, 130), font="H", size=8.5, color=INK)
            bx, bw = self.ML + 140, self.cw - 140 - 30
            self.w.rect(bx, self.y - 11, bw, 8, fill=LIGHT)
            self.w.rect(bx, self.y - 11, max(2, bw * cnt / mx), 8, fill=ACCENT)
            self.w.text(self.ML + self.cw - 20, self.y - 9, str(cnt), font="HB", size=8.5, color=MUTED)
            self.y -= 15

    def _row_header(self, cols, widths):
        self._ensure(16)
        self.w.rect(self.ML, self.y - 15, self.cw, 15, fill=BAND)
        x = self.ML + 4
        for c, wd in zip(cols, widths):
            self.w.text(x, self.y - 11, c, font="HB", size=7.5, color=WHITE)
            x += wd
        self.y -= 15

    def _footers(self):
        total = self.w.page_count
        gen = datetime.now().strftime("%Y-%m-%d %H:%M")
        for i in range(1, total):
            saved = self.w._cur
            self.w._cur = self.w._pages[i]
            self.w.line(self.ML, self.MB - 6, self.pw - self.MR, self.MB - 6, color=RULE, width=0.5)
            self.w.text(self.ML, self.MB - 18, "Fortinet FortiGate Fleet Analysis", font="H", size=7, color=FAINT)
            lab = "Page %d of %d" % (i + 1, total)
            self.w.text(self.pw - self.MR - self.w.string_width(lab, "H", 7), self.MB - 18, lab, font="H", size=7, color=FAINT)
            mid = "Generated " + gen
            self.w.text((self.pw - self.w.string_width(mid, "H", 7)) / 2, self.MB - 18, mid, font="H", size=7, color=FAINT)
            self.w._cur = saved


def render_fleet_pdf(fleet: Any, path: str) -> None:
    _Fleet(fleet).build(path)
