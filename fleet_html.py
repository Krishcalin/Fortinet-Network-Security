"""
Fortinet FortiGate — Fleet Analysis HTML Report
===============================================
A single self-contained (no external assets) fleet report: fleet KPIs, a
worst-device ranking, prevalence "one fix clears N firewalls" campaigns, systemic
findings, and firmware/model distribution. Dark Catppuccin-Mocha theme + print
stylesheet. Standard library only.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List

from fleet_report import FleetReport, SEV_LIST, TIER_LIST, esc

_CSS = r"""
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#181926;--bg2:#1e1e2e;--mantle:#181825;--surf0:#313244;--surf1:#45475a;
--text:#cdd6f4;--sub:#a6adc8;--muted:#7f849c;--crit:#f38ba8;--high:#fab387;
--med:#89b4fa;--low:#a6e3a1;--info:#cdd6f4;--accent:#f38ba8;--mauve:#cba6f7;--teal:#94e2d5}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.55}
.container{max-width:1180px;margin:0 auto;padding:28px 24px 64px}
code{font-family:'Cascadia Code','Consolas',monospace}
.head{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;border-bottom:1px solid var(--surf0);padding-bottom:20px;margin-bottom:24px;flex-wrap:wrap}
.head h1{font-size:1.5rem;font-weight:800;letter-spacing:-.01em}
.head h1 span{color:var(--accent)}
.head .sub{color:var(--muted);font-size:.85rem;margin-top:4px}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:16px}
@media(max-width:760px){.kpis{grid-template-columns:repeat(3,1fr)}}
.kpi{background:var(--bg2);border:1px solid var(--surf0);border-radius:12px;padding:14px 10px;text-align:center;border-top:2px solid var(--surf1)}
.kpi .n{font-size:1.8rem;font-weight:800}.kpi .l{font-size:.64rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-top:2px}
.kpi.p1{border-top-color:var(--crit)}.kpi.p1 .n{color:var(--crit)}
.kpi.worst{border-top-color:var(--high)}.kpi.worst .n{color:var(--high)}
.kpi.dev .n{color:var(--teal)}.kpi.find .n{color:var(--mauve)}
h2{font-size:.74rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:800;margin:26px 0 12px}
.panel{background:var(--bg2);border:1px solid var(--surf0);border-radius:12px;overflow:hidden}
.warn{background:rgba(250,179,135,.12);border:1px solid var(--high);color:var(--high);border-radius:10px;padding:12px 16px;font-size:.84rem;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:.84rem}
th{text-align:left;background:var(--mantle);color:var(--muted);font-size:.66rem;text-transform:uppercase;letter-spacing:.05em;padding:10px 14px;font-weight:800}
td{padding:10px 14px;border-top:1px solid var(--surf0);vertical-align:top}
tbody tr:hover{background:var(--surf0)}
.rank{color:var(--muted);font-weight:800;text-align:center;width:34px}
.score{font-weight:800}
.sev-crit{color:var(--crit)}.sev-high{color:var(--high)}.sev-med{color:var(--med)}.sev-low{color:var(--low)}
.muted{color:var(--muted)}
.pill{display:inline-block;padding:2px 8px;border-radius:100px;font-size:.66rem;font-weight:800;text-transform:uppercase}
.pill.crit{background:rgba(243,139,168,.18);color:var(--crit)}.pill.high{background:rgba(250,179,135,.18);color:var(--high)}
.pill.med{background:rgba(137,180,250,.18);color:var(--med)}.pill.low{background:rgba(166,227,161,.18);color:var(--low)}.pill.info{background:rgba(205,214,244,.12);color:var(--info)}
.tag{display:inline-block;padding:2px 7px;border-radius:100px;font-size:.6rem;font-weight:800;text-transform:uppercase;margin-left:4px}
.tag.kev{background:rgba(243,139,168,.2);color:var(--crit)}.tag.rw{background:rgba(243,139,168,.3);color:var(--crit)}
.tag.exp{background:rgba(203,166,247,.18);color:var(--mauve)}
.cov{font-weight:800}.rid{font-family:monospace;font-size:.72rem;color:var(--muted)}
.fix{font-family:monospace;font-size:.74rem;color:#b5e8c9;background:var(--bg);border-radius:6px;padding:6px 10px;margin-top:6px;white-space:pre-wrap;word-break:break-word;border-left:3px solid var(--low)}
.bar-row{display:grid;grid-template-columns:150px 1fr 44px;align-items:center;gap:10px;padding:6px 14px;font-size:.82rem}
.bar-row .lbl{color:var(--sub);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{background:var(--mantle);border-radius:5px;height:9px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px;background:linear-gradient(90deg,var(--mauve),var(--med))}
.bar-row .val{color:var(--muted);font-weight:700;text-align:right}
.foot{margin-top:34px;padding-top:16px;border-top:1px solid var(--surf0);color:var(--muted);font-size:.76rem;text-align:center}
@media print{body{background:#fff;color:#1e1e2e}.panel,.kpi{background:#fff;border-color:#ddd}.fix{background:#f6f7f9;color:#14532d}th{background:#f2f3f5}}
"""


def _sevcell(counts: dict) -> str:
    bits = []
    for s, cls in (("CRITICAL", "crit"), ("HIGH", "high"), ("MEDIUM", "med"), ("LOW", "low")):
        n = counts.get(s, 0)
        if n:
            bits.append(f"<span class=\"sev-{cls}\">{n}{s[0]}</span>")
    return " ".join(bits) or "<span class=\"muted\">0</span>"


def render_fleet_html(fleet: FleetReport) -> str:
    a = fleet.agg
    gen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    p: List[str] = []
    p.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">")
    p.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    p.append("<title>Fortinet FortiGate — Fleet Analysis</title>")
    p.append("<style>" + _CSS + "</style></head><body><div class=\"container\">")

    p.append("<div class=\"head\"><div><h1>Fortinet <span>FortiGate</span> Fleet Analysis</h1>"
             "<div class=\"sub\">Aggregated posture across " + str(a["device_count"]) +
             " device(s) &middot; Generated " + esc(gen) + "</div></div></div>")

    # KPIs
    p.append("<div class=\"kpis\">")
    for cls, n, l in (("dev", a["device_count"], "Devices"),
                      ("find", a["total_findings"], "Findings"),
                      ("p1", a["tier_totals"].get("P1", 0), "P1 Fix-Now"),
                      ("", a["severity_totals"].get("CRITICAL", 0), "Critical"),
                      ("worst", a["risk_max"], "Worst Score"),
                      ("", a["risk_avg"], "Avg Score")):
        p.append("<div class=\"kpi " + cls + "\"><div class=\"n\">" + esc(n) + "</div><div class=\"l\">" + l + "</div></div>")
    p.append("</div>")

    if a["collisions"]:
        hosts = ", ".join(sorted({esc(c["hostname"]) for c in a["collisions"]}))
        p.append("<div class=\"warn\">&#9888; " + str(len(a["collisions"])) +
                 " duplicate hostname(s) across inputs (" + hosts + ") — disambiguated with #N suffixes "
                 "so device counts are not inflated. Verify these are distinct devices.</div>")

    # systemic
    if a["systemic"]:
        p.append("<h2>Systemic Findings — present on most of the fleet</h2><div class=\"panel\"><table>"
                 "<thead><tr><th>Finding</th><th>Severity</th><th>Devices</th></tr></thead><tbody>")
        for c in a["systemic"][:12]:
            p.append("<tr><td>" + esc(c["name"]) + " <span class=\"rid\">" + esc(c["rule_id"]) + "</span></td>"
                     "<td>" + _pill(c["severity"]) + "</td><td class=\"cov\">" +
                     str(c["device_count"]) + "/" + str(a["device_count"]) + "</td></tr>")
        p.append("</tbody></table></div>")

    # worst devices
    p.append("<h2>Worst Devices — fix these first</h2><div class=\"panel\"><table>"
             "<thead><tr><th class=\"rank\">#</th><th>Hostname</th><th>Model / FortiOS</th>"
             "<th>Risk</th><th>P1/P2</th><th>Severity mix</th></tr></thead><tbody>")
    for i, r in enumerate(a["worst_devices"], 1):
        p.append("<tr><td class=\"rank\">" + str(i) + "</td>"
                 "<td><b>" + esc(r["hostname"]) + "</b><div class=\"rid\">" + esc(r.get("source", "")) + "</div></td>"
                 "<td>" + esc(r["model"]) + " &middot; " + esc(r["version"]) + "</td>"
                 "<td class=\"score\">" + str(r["risk_score"]) + "</td>"
                 "<td>" + str(r["tiers"].get("P1", 0)) + " / " + str(r["tiers"].get("P2", 0)) + "</td>"
                 "<td>" + _sevcell(r["counts"]) + "</td></tr>")
    p.append("</tbody></table></div>")

    # campaigns
    p.append("<h2>Remediation Campaigns — one fix, many firewalls</h2><div class=\"panel\"><table>"
             "<thead><tr><th>Finding</th><th>Sev</th><th>Coverage</th><th>Fix (one change clears all)</th></tr></thead><tbody>")
    for c in a["campaigns"][:25]:
        tags = ""
        if c.get("kev"):
            tags += "<span class=\"tag kev\">KEV</span>"
        if c.get("ransomware"):
            tags += "<span class=\"tag rw\">RW</span>"
        reach = ""
        if c.get("reachable"):
            reach = ("<span class=\"tag exp\">" + str(c["reachable"]) + " reachable</span>")
        fixd = c.get("fix") if isinstance(c.get("fix"), dict) else {}
        fix = fixd.get("cli") or fixd.get("steps") or ""
        fixhtml = ("<div class=\"fix\">" + esc(fix[:400]) + "</div>") if fix else ""
        p.append("<tr><td><b>" + esc(c["name"]) + "</b>" + tags +
                 " <span class=\"rid\">" + esc(c["rule_id"]) + "</span></td>"
                 "<td>" + _pill(c["severity"]) + "</td>"
                 "<td class=\"cov\">" + str(c["device_count"]) + "/" + str(a["device_count"]) + reach + "</td>"
                 "<td>" + fixhtml + "</td></tr>")
    p.append("</tbody></table></div>")

    # firmware distribution
    p.append("<h2>Firmware Distribution</h2><div class=\"panel\" style=\"padding:10px 0\">")
    mx = max(a["versions"].values()) if a["versions"] else 1
    for ver, cnt in sorted(a["versions"].items(), key=lambda x: -x[1]):
        p.append("<div class=\"bar-row\"><div class=\"lbl\">FortiOS " + esc(ver) + "</div>"
                 "<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:" + f"{cnt/mx*100:.0f}" + "%\"></div></div>"
                 "<div class=\"val\">" + str(cnt) + "</div></div>")
    p.append("</div>")

    p.append("<div class=\"foot\">Fortinet FortiGate Fleet Analysis Console &middot; Generated " + esc(gen) +
             " &middot; For authorized security assessments only.</div>")
    p.append("</div></body></html>")
    return "".join(p)


def _pill(sev: str) -> str:
    cls = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}.get(sev, "info")
    return "<span class=\"pill " + cls + "\">" + esc(sev) + "</span>"
