"""
Fortinet FortiGate — HTML Report Generator
==========================================
A single self-contained (no external assets / CDN / web-fonts) interactive HTML
security-assessment report. Dark Catppuccin-Mocha theme with a print stylesheet.
Consumes the RemediationKB so every finding card shows the full detailed fix
(risk, numbered steps, GUI path, CLI block, verification, rollback, impact,
references). Standard library only.
"""

from __future__ import annotations

import html as _html
from datetime import datetime
from typing import Any, Dict, List, Optional

from remediation_kb import RemediationKB

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
FRAMEWORKS = ["CIS", "PCI-DSS", "NIST", "SOC2", "HIPAA"]


def _g(f: Any, key: str, default: Any = "") -> Any:
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def esc(s: Any) -> str:
    return _html.escape(str(s if s is not None else ""))


_CSS = r"""
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#181926;--bg2:#1e1e2e;--mantle:#181825;--surf0:#313244;--surf1:#45475a;
  --text:#cdd6f4;--sub:#a6adc8;--muted:#7f849c;
  --crit:#f38ba8;--high:#fab387;--med:#89b4fa;--low:#a6e3a1;--info:#cdd6f4;
  --accent:#f38ba8;--mauve:#cba6f7;--teal:#94e2d5;
}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.55}
.container{max-width:1200px;margin:0 auto;padding:28px 24px 64px}
a{color:var(--med);text-decoration:none}
code,pre{font-family:'Cascadia Code','Consolas','JetBrains Mono',monospace}

/* header */
.rpt-head{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;
  border-bottom:1px solid var(--surf0);padding-bottom:22px;margin-bottom:26px;flex-wrap:wrap}
.rpt-head h1{font-size:1.55rem;font-weight:800;letter-spacing:-.01em}
.rpt-head h1 span{color:var(--accent)}
.rpt-head .sub{color:var(--muted);font-size:.85rem;margin-top:4px}
.device{background:var(--bg2);border:1px solid var(--surf0);border-radius:10px;padding:14px 18px;font-size:.8rem;min-width:280px}
.device div{display:flex;justify-content:space-between;gap:16px;padding:2px 0}
.device .k{color:var(--muted)} .device .v{color:var(--text);font-weight:600}

/* summary grid */
.grid{display:grid;grid-template-columns:280px 1fr;gap:20px;margin-bottom:26px}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
.panel{background:var(--bg2);border:1px solid var(--surf0);border-radius:14px;padding:22px}
.panel h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:16px;font-weight:700}
.gauge{display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge svg{width:170px;height:170px}
.gauge .score{font-size:2.6rem;font-weight:800}
.gauge .band{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
@media(max-width:560px){.kpis{grid-template-columns:repeat(2,1fr)}}
.kpi{background:var(--mantle);border-radius:10px;padding:14px 8px;text-align:center;border-top:2px solid var(--surf1)}
.kpi .n{font-size:1.7rem;font-weight:800}
.kpi .l{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-top:2px}
.kpi.critical{border-top-color:var(--crit)} .kpi.critical .n{color:var(--crit)}
.kpi.high{border-top-color:var(--high)} .kpi.high .n{color:var(--high)}
.kpi.medium{border-top-color:var(--med)} .kpi.medium .n{color:var(--med)}
.kpi.low{border-top-color:var(--low)} .kpi.low .n{color:var(--low)}
.kpi.info{border-top-color:var(--info)} .kpi.info .n{color:var(--info)}

.cols{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:26px}
@media(max-width:820px){.cols{grid-template-columns:1fr}}
.bar-row{display:grid;grid-template-columns:130px 1fr 40px;align-items:center;gap:10px;margin-bottom:9px;font-size:.8rem}
.bar-row .lbl{color:var(--sub);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{background:var(--mantle);border-radius:5px;height:9px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px;background:linear-gradient(90deg,var(--mauve),var(--med))}
.bar-row .val{color:var(--muted);font-weight:700;text-align:right}
.mitre-note{font-size:.82rem;color:var(--sub);margin-top:6px}

/* risk-prioritization */
.prio-wrap{margin-bottom:26px}
.prio-tiers{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
@media(max-width:680px){.prio-tiers{grid-template-columns:repeat(2,1fr)}}
.tier-card{background:var(--bg2);border:1px solid var(--surf0);border-radius:12px;padding:14px 16px;border-top:3px solid var(--surf1)}
.tier-card .t{font-size:1.7rem;font-weight:800;letter-spacing:-.02em}
.tier-card .n{font-size:1.05rem;font-weight:700;margin-left:6px}
.tier-card .lab{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--sub);font-weight:700;margin-top:4px}
.tier-card .win{font-size:.72rem;color:var(--muted);margin-top:2px}
.tier-card.p1{border-top-color:var(--crit)} .tier-card.p1 .t{color:var(--crit)}
.tier-card.p2{border-top-color:var(--high)} .tier-card.p2 .t{color:var(--high)}
.tier-card.p3{border-top-color:var(--med)} .tier-card.p3 .t{color:var(--med)}
.tier-card.p4{border-top-color:var(--low)} .tier-card.p4 .t{color:var(--low)}
.toprisks{background:var(--bg2);border:1px solid var(--surf0);border-radius:14px;padding:8px 6px}
.tr-row{display:grid;grid-template-columns:34px 60px 1fr auto;align-items:center;gap:12px;padding:11px 14px;border-bottom:1px solid var(--surf0)}
.tr-row:last-child{border-bottom:none}
.tr-rank{font-size:.9rem;font-weight:800;color:var(--muted);text-align:center}
.tr-score{text-align:center}
.tr-score .sv{font-size:1.15rem;font-weight:800;line-height:1}
.tr-score .sl{font-size:.6rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.tr-main .nm{font-weight:700;font-size:.9rem}
.tr-main .rid{font-family:monospace;font-size:.72rem;color:var(--muted)}
.tr-main .why{font-size:.76rem;color:var(--sub);margin-top:3px}
.tr-tags{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;max-width:230px}
.tag{font-size:.64rem;font-weight:800;text-transform:uppercase;letter-spacing:.03em;padding:3px 8px;border-radius:100px;white-space:nowrap}
.tag.kev{background:rgba(243,139,168,.2);color:var(--crit)}
.tag.rw{background:rgba(243,139,168,.28);color:var(--crit)}
.tag.epss{background:rgba(250,179,135,.18);color:var(--high)}
.tag.exp{background:rgba(203,166,247,.18);color:var(--mauve)}
.pbadge{display:inline-block;padding:3px 9px;border-radius:7px;font-size:.68rem;font-weight:800;letter-spacing:.02em;flex-shrink:0}
.pbadge.p1{background:rgba(243,139,168,.2);color:var(--crit)}
.pbadge.p2{background:rgba(250,179,135,.18);color:var(--high)}
.pbadge.p3{background:rgba(137,180,250,.16);color:var(--med)}
.pbadge.p4{background:rgba(166,227,161,.16);color:var(--low)}
.f-prio{margin:10px 0 2px;padding:9px 12px;background:var(--mantle);border-radius:8px;border-left:3px solid var(--surf1);font-size:.8rem;color:var(--sub)}
.f-prio b{color:var(--text)}
.f-facts{display:flex;flex-wrap:wrap;gap:6px 10px;margin-top:6px}
.f-facts span{font-size:.72rem;color:var(--muted)}
.f-facts .pt{color:var(--teal);font-weight:700}

/* filters */
.filters{display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap;align-items:center}
.filters label{color:var(--muted);font-size:.82rem}
.filters select,.filters input{background:var(--surf0);color:var(--text);border:1px solid var(--surf1);
  border-radius:7px;padding:7px 11px;font-size:.82rem}
.filters input{min-width:240px}
.filters .btn{background:var(--surf0);border:1px solid var(--surf1);color:var(--sub);border-radius:7px;
  padding:7px 12px;font-size:.8rem;cursor:pointer}
.filters .btn:hover{border-color:var(--accent);color:var(--text)}

/* finding cards */
.finding{background:var(--bg2);border:1px solid var(--surf0);border-left:4px solid var(--surf1);
  border-radius:12px;margin-bottom:12px;overflow:hidden}
.finding.critical{border-left-color:var(--crit)} .finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)} .finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)}
.f-head{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer;user-select:none}
.f-head:hover{background:var(--surf0)}
.chip{display:inline-block;padding:3px 10px;border-radius:100px;font-size:.66rem;font-weight:800;
  text-transform:uppercase;letter-spacing:.03em;flex-shrink:0}
.chip.critical{background:rgba(243,139,168,.18);color:var(--crit)}
.chip.high{background:rgba(250,179,135,.18);color:var(--high)}
.chip.medium{background:rgba(137,180,250,.18);color:var(--med)}
.chip.low{background:rgba(166,227,161,.18);color:var(--low)}
.chip.info{background:rgba(205,214,244,.12);color:var(--info)}
.f-title{font-weight:700;font-size:.95rem;flex:1;min-width:0}
.f-id{color:var(--muted);font-size:.76rem;font-family:monospace;white-space:nowrap}
.f-chev{color:var(--muted);transition:transform .2s;flex-shrink:0}
.finding.open .f-chev{transform:rotate(90deg)}
.f-body{display:none;padding:4px 18px 20px;border-top:1px solid var(--surf0)}
.finding.open .f-body{display:block}
.f-meta{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:.78rem;color:var(--muted);margin:12px 0 4px}
.f-meta b{color:var(--sub);font-weight:600}
.f-evi{font-size:.78rem;color:var(--sub);background:var(--mantle);border-radius:6px;padding:6px 10px;margin:6px 0;font-family:monospace;word-break:break-all}
.sec{margin-top:14px}
.sec .h{font-size:.68rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:700;margin-bottom:6px}
.sec.risk .h{color:var(--accent)}
.sec p{font-size:.86rem;color:var(--text)}
ol.steps{margin:0;padding-left:20px}
ol.steps li{font-size:.86rem;margin-bottom:5px;padding-left:4px}
pre.cli{background:var(--bg);border:1px solid var(--surf0);border-left:3px solid var(--low);
  border-radius:8px;padding:12px 14px;font-size:.8rem;color:#b5e8c9;overflow-x:auto;white-space:pre;line-height:1.5}
.pill-refs{display:flex;flex-wrap:wrap;gap:6px}
.pill-refs span{background:var(--mantle);border:1px solid var(--surf0);border-radius:6px;
  padding:3px 9px;font-size:.74rem;color:var(--sub)}
.gui,.verify,.rollback,.impact{font-size:.84rem;color:var(--text)}
.verify code,.gui code{background:var(--mantle);padding:1px 6px;border-radius:4px;font-size:.8rem}
.impact.warn{color:var(--high)}
.footer{margin-top:36px;padding-top:18px;border-top:1px solid var(--surf0);color:var(--muted);font-size:.78rem;text-align:center}

@media print{
  body{background:#fff;color:#1e1e2e}
  .filters,.f-chev{display:none}
  .container{max-width:none;padding:0}
  .panel,.device,.finding{border-color:#ddd;background:#fff;break-inside:avoid}
  .f-body{display:block!important}
  pre.cli{background:#f6f7f9;color:#14532d}
  .kpi,.f-evi,.bar-track,.pill-refs span{background:#f2f3f5}
  a{color:#1e40af}
}
"""

_JS = r"""
(function(){
  document.querySelectorAll('.f-head').forEach(function(h){
    h.addEventListener('click',function(){h.parentElement.classList.toggle('open');});
  });
  var fSev=document.getElementById('fSev'),fCat=document.getElementById('fCat'),fSearch=document.getElementById('fSearch');
  var cards=[].slice.call(document.querySelectorAll('.finding'));
  function apply(){
    var s=(fSev.value||'').toLowerCase(),c=fCat.value||'',q=(fSearch.value||'').toLowerCase();
    cards.forEach(function(card){
      var sv=card.getAttribute('data-sev'),ct=card.getAttribute('data-cat'),txt=card.textContent.toLowerCase();
      card.style.display=((!s||sv===s)&&(!c||ct===c)&&(!q||txt.indexOf(q)>-1))?'':'none';
    });
  }
  if(fSev){fSev.onchange=fCat.onchange=apply;fSearch.oninput=apply;}
  var eAll=document.getElementById('expAll'),cAll=document.getElementById('colAll');
  if(eAll)eAll.onclick=function(){cards.forEach(function(c){c.classList.add('open');});};
  if(cAll)cAll.onclick=function(){cards.forEach(function(c){c.classList.remove('open');});};
  window.addEventListener('beforeprint',function(){cards.forEach(function(c){c.classList.add('open');});});
})();
"""


class FortinetHTMLReport:
    def __init__(self, findings: List[Any], meta: Dict[str, Any],
                 kb: Optional[RemediationKB] = None,
                 priorities: Optional[List[Any]] = None):
        self.findings = findings
        self.meta = meta or {}
        self.kb = kb or RemediationKB()
        # Risk-prioritization overlay (P1–P4). Compute here if not supplied so the
        # report works standalone; map by id(finding) for per-card lookup.
        if priorities is None:
            try:
                from risk_prioritizer import RiskPrioritizer, ThreatIntel
                priorities = RiskPrioritizer(ThreatIntel()).prioritize(findings)
            except Exception:
                priorities = []
        self.priorities = priorities or []
        self.prio_by_id = {id(p.finding): p for p in self.priorities}

    def _stats(self):
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        by_fw: Dict[str, int] = {k: 0 for k in FRAMEWORKS}
        mitre_fail = 0
        for f in self.findings:
            sev = _g(f, "severity", "INFO")
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_cat[_g(f, "category", "Other")] = by_cat.get(_g(f, "category", "Other"), 0) + 1
            comp = _g(f, "compliance", {}) or {}
            if isinstance(comp, dict):
                for fw in FRAMEWORKS:
                    if comp.get(fw):
                        by_fw[fw] += 1
            if str(_g(f, "rule_id", "")).startswith("MITRE-T"):
                mitre_fail += 1
        return by_sev, by_cat, by_fw, mitre_fail

    @staticmethod
    def _band(score: int):
        if score >= 75:
            return "Critical", "#f38ba8"
        if score >= 50:
            return "High", "#fab387"
        if score >= 25:
            return "Medium", "#89b4fa"
        return "Low", "#a6e3a1"

    def generate(self, output_path: str) -> None:
        by_sev, by_cat, by_fw, mitre_fail = self._stats()
        crit = by_sev.get("CRITICAL", 0); high = by_sev.get("HIGH", 0)
        med = by_sev.get("MEDIUM", 0); low = by_sev.get("LOW", 0); info = by_sev.get("INFO", 0)
        total = len(self.findings)
        score = min(100, crit * 25 + high * 10 + med * 4 + low * 1)
        band, band_col = self._band(score)
        circ = 377.0
        dash = circ * score / 100.0
        gen = self.meta.get("generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        p: List[str] = []
        p.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">")
        p.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
        p.append("<title>Fortinet FortiGate — Security Assessment Report</title>")
        p.append("<style>" + _CSS + "</style></head><body><div class=\"container\">")

        # header + device panel
        dev = self.meta
        p.append("<div class=\"rpt-head\"><div>")
        p.append("<h1>Fortinet <span>FortiGate</span> Security Assessment</h1>")
        p.append("<div class=\"sub\">FortiOS configuration, CVE &amp; MITRE ATT&amp;CK posture review &middot; Generated " + esc(gen) + "</div>")
        p.append("</div><div class=\"device\">")
        for k, key in (("Target", "host"), ("Hostname", "hostname"), ("Model", "model"),
                       ("FortiOS", "version"), ("Serial", "serial"), ("Findings", None)):
            v = str(total) if key is None else esc(dev.get(key, "N/A"))
            p.append("<div><span class=\"k\">" + k + "</span><span class=\"v\">" + v + "</span></div>")
        p.append("</div></div>")

        # summary grid: gauge + kpis
        p.append("<div class=\"grid\">")
        p.append("<div class=\"panel gauge\"><h2>Overall Risk</h2>")
        p.append("<svg viewBox=\"0 0 140 140\">")
        p.append("<circle cx=\"70\" cy=\"70\" r=\"60\" fill=\"none\" stroke=\"#313244\" stroke-width=\"12\"/>")
        p.append("<circle cx=\"70\" cy=\"70\" r=\"60\" fill=\"none\" stroke=\"" + band_col + "\" stroke-width=\"12\" "
                 "stroke-linecap=\"round\" stroke-dasharray=\"" + f"{dash:.1f} {circ - dash:.1f}" + "\" "
                 "transform=\"rotate(-90 70 70)\"/>"
                 "<text x=\"70\" y=\"78\" text-anchor=\"middle\" font-size=\"34\" font-weight=\"800\" fill=\"" + band_col + "\">" + str(score) + "</text>"
                 "<text x=\"70\" y=\"98\" text-anchor=\"middle\" font-size=\"10\" fill=\"#7f849c\">/ 100</text></svg>")
        p.append("<div class=\"band\" style=\"color:" + band_col + "\">" + band + " posture</div></div>")

        p.append("<div class=\"panel\"><h2>Findings by Severity &middot; total " + str(total) + "</h2><div class=\"kpis\">")
        for cls, label, n in (("critical", "Critical", crit), ("high", "High", high),
                              ("medium", "Medium", med), ("low", "Low", low), ("info", "Info", info)):
            p.append("<div class=\"kpi " + cls + "\"><div class=\"n\">" + str(n) + "</div><div class=\"l\">" + label + "</div></div>")
        p.append("</div></div></div>")

        # risk-prioritized "fix first" section
        p.append(self._priority_section())

        # category + compliance columns
        p.append("<div class=\"cols\">")
        p.append("<div class=\"panel\"><h2>Findings by Category</h2>")
        maxc = max(by_cat.values()) if by_cat else 1
        for cat, n in sorted(by_cat.items(), key=lambda x: -x[1]):
            p.append("<div class=\"bar-row\"><div class=\"lbl\">" + esc(cat) + "</div>"
                     "<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:" + f"{n / maxc * 100:.0f}" + "%\"></div></div>"
                     "<div class=\"val\">" + str(n) + "</div></div>")
        p.append("</div>")
        p.append("<div class=\"panel\"><h2>Compliance Framework Exposure</h2>")
        maxf = max(by_fw.values()) if any(by_fw.values()) else 1
        for fw in FRAMEWORKS:
            n = by_fw[fw]
            p.append("<div class=\"bar-row\"><div class=\"lbl\">" + fw + "</div>"
                     "<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:" + f"{n / maxf * 100:.0f}" + "%\"></div></div>"
                     "<div class=\"val\">" + str(n) + "</div></div>")
        resil = max(0, 31 - mitre_fail)
        p.append("<div class=\"mitre-note\">MITRE ATT&amp;CK resilience: <b>" + str(resil) + "/31</b> techniques mitigated "
                 "(" + str(mitre_fail) + " gap" + ("" if mitre_fail == 1 else "s") + " found).</div>")
        p.append("</div></div>")

        # filters
        p.append("<div class=\"filters\"><label>Severity</label>"
                 "<select id=\"fSev\"><option value=\"\">All</option><option>CRITICAL</option><option>HIGH</option>"
                 "<option>MEDIUM</option><option>LOW</option><option>INFO</option></select>"
                 "<label>Category</label><select id=\"fCat\"><option value=\"\">All</option>")
        for cat in sorted(by_cat):
            p.append("<option>" + esc(cat) + "</option>")
        p.append("</select><label>Search</label><input id=\"fSearch\" placeholder=\"rule id, name, detail…\">"
                 "<span class=\"btn\" id=\"expAll\">Expand all</span><span class=\"btn\" id=\"colAll\">Collapse all</span></div>")

        # findings
        ordered = sorted(self.findings, key=lambda f: (SEV_ORDER.get(_g(f, "severity"), 9),
                                                       _g(f, "category", ""), str(_g(f, "rule_id"))))
        for f in ordered:
            p.append(self._card(f))

        p.append("<div class=\"footer\">Fortinet FortiGate Security Scanner &middot; Generated " + esc(gen) +
                 " &middot; For authorized security assessments only. Review every command before applying to production.</div>")
        p.append("</div><script>" + _JS + "</script></body></html>")

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("".join(p))
        print(f"[+] HTML report saved to: {output_path}")

    def _priority_section(self) -> str:
        if not self.priorities:
            return ""
        try:
            from risk_prioritizer import TIER_META
        except Exception:
            return ""
        counts: Dict[str, int] = {t: 0 for t in TIER_META}
        for r in self.priorities:
            counts[r.tier] = counts.get(r.tier, 0) + 1

        h: List[str] = ["<div class=\"prio-wrap\">"]
        snap = self.meta.get("intel_snapshot")
        kevn = self.meta.get("intel_kev_count")
        sub = ("Findings ranked by severity &times; real-world exploitability (CISA KEV + FIRST.org EPSS) "
               "&times; internet-reachability")
        if snap:
            sub += (f" &middot; threat-intel snapshot {esc(snap)}"
                    + (f", {esc(kevn)} KEV-listed CVE(s) applicable" if kevn else ""))
        h.append("<div class=\"panel\" style=\"margin-bottom:16px\"><h2>Risk-Prioritized Remediation Queue</h2>")
        h.append("<div style=\"font-size:.8rem;color:var(--sub);margin:-6px 0 14px\">" + sub + "</div>")
        if self.meta.get("intel_stale"):
            age = self.meta.get("intel_age_days")
            h.append("<div style=\"font-size:.78rem;color:var(--high);font-weight:700;margin:-8px 0 14px\">"
                     "&#9888; Threat-intel snapshot is stale"
                     + (f" ({esc(age)} days old)" if age is not None else "")
                     + " — refresh with <code>--refresh-intel</code> (or <code>--import-intel</code> on air-gapped hosts).</div>")
        h.append("<div class=\"prio-tiers\">")
        for t in ("P1", "P2", "P3", "P4"):
            m = TIER_META[t]
            h.append("<div class=\"tier-card " + t.lower() + "\">"
                     "<div><span class=\"t\">" + t + "</span><span class=\"n\">" + str(counts[t]) + "</span></div>"
                     "<div class=\"lab\">" + esc(m["label"]) + "</div>"
                     "<div class=\"win\">" + esc(m["window"]) + "</div></div>")
        h.append("</div>")

        top = [r for r in self.priorities if r.tier in ("P1", "P2")][:12]
        if not top:
            top = self.priorities[:8]
        if top:
            h.append("<div style=\"font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);"
                     "font-weight:700;margin:6px 0 8px\">Top " + str(len(top)) + " to fix first</div>")
            h.append("<div class=\"toprisks\">")
            for i, r in enumerate(top, 1):
                f = r.finding
                sev = _g(f, "severity", "INFO")
                col = {"CRITICAL": "var(--crit)", "HIGH": "var(--high)", "MEDIUM": "var(--med)",
                       "LOW": "var(--low)", "INFO": "var(--info)"}.get(sev, "var(--info)")
                tags = []
                if r.kev:
                    tags.append("<span class=\"tag kev\">KEV" + (" " + esc(r.kev_date) if r.kev_date else "") + "</span>")
                if getattr(r, "ransomware", False):
                    tags.append("<span class=\"tag rw\">Ransomware</span>")
                if r.epss is not None and r.epss >= 0.10:
                    tags.append("<span class=\"tag epss\">EPSS " + f"{r.epss*100:.0f}%" + "</span>")
                if r.reachable:
                    tags.append("<span class=\"tag exp\">Internet-exposed</span>")
                h.append("<div class=\"tr-row\">")
                h.append("<div class=\"tr-rank\">" + str(i) + "</div>")
                h.append("<div class=\"tr-score\"><div class=\"sv\" style=\"color:" + col + "\">" + str(r.score) +
                         "</div><div class=\"sl\">" + esc(r.tier) + "</div></div>")
                h.append("<div class=\"tr-main\"><span class=\"nm\">" + esc(_g(f, "name")) + "</span> "
                         "<span class=\"rid\">" + esc(_g(f, "rule_id")) + "</span>"
                         "<div class=\"why\">" + esc(r.rationale) + "</div></div>")
                h.append("<div class=\"tr-tags\">" + "".join(tags) + "</div>")
                h.append("</div>")
            h.append("</div>")
        h.append("</div></div>")
        return "".join(h)

    def _card(self, f: Any) -> str:
        sev = _g(f, "severity", "INFO"); scls = sev.lower()
        d = self.kb.detail_for(f)
        rid = esc(_g(f, "rule_id")); name = esc(_g(f, "name"))
        cat = esc(_g(f, "category"))
        pr = self.prio_by_id.get(id(f))
        pbadge = ""
        if pr is not None:
            pbadge = ("<span class=\"pbadge " + pr.tier.lower() + "\">" + esc(pr.tier) +
                      " &middot; " + str(pr.score) + "</span>")
        h: List[str] = []
        h.append("<div class=\"finding " + scls + "\" data-sev=\"" + scls + "\" data-cat=\"" + esc(_g(f, "category")) + "\">")
        h.append("<div class=\"f-head\"><span class=\"chip " + scls + "\">" + esc(sev) + "</span>"
                 + pbadge +
                 "<span class=\"f-title\">" + name + "</span><span class=\"f-id\">" + rid + "</span>"
                 "<span class=\"f-chev\">&#9656;</span></div>")
        h.append("<div class=\"f-body\">")
        # priority rationale (why this ranks where it does)
        if pr is not None:
            try:
                from risk_prioritizer import TIER_META
                tlabel = TIER_META[pr.tier]["label"]
            except Exception:
                tlabel = pr.tier
            facts = "".join(
                "<span><b class=\"pt\">+" + str(fc.get("points", 0)) + "</b> " + esc(fc.get("label", "")) +
                (" — " + esc(fc.get("detail", "")) if fc.get("detail") else "") + "</span>"
                for fc in pr.factors)
            h.append("<div class=\"f-prio\"><b>Priority " + esc(pr.tier) + " — " + esc(tlabel) +
                     "</b> (score " + str(pr.score) + "/100). " + esc(pr.rationale) +
                     "<div class=\"f-facts\">" + facts + "</div></div>")
        # meta line
        cwe = _g(f, "cwe", None); cve = _g(f, "cve", None)
        meta_bits = ["<b>Category:</b> " + cat, "<b>Target:</b> " + esc(_g(f, "file_path"))]
        if cwe:
            meta_bits.append("<b>CWE:</b> " + esc(cwe))
        if cve:
            meta_bits.append("<b>CVE:</b> " + esc(cve))
        comp = _g(f, "compliance", {}) or {}
        if isinstance(comp, dict) and comp:
            cstr = " · ".join(fw + " " + ", ".join(comp[fw]) for fw in FRAMEWORKS if comp.get(fw))
            if cstr:
                meta_bits.append("<b>Compliance:</b> " + esc(cstr))
        h.append("<div class=\"f-meta\">" + "&nbsp;&nbsp;".join(meta_bits) + "</div>")
        evi = _g(f, "line_content", "")
        if evi:
            h.append("<div class=\"f-evi\">" + esc(evi) + "</div>")

        # risk
        if d["risk"]:
            h.append("<div class=\"sec risk\"><div class=\"h\">Security Risk</div><p>" + esc(d["risk"]) + "</p></div>")
        # steps
        if d["steps"]:
            h.append("<div class=\"sec\"><div class=\"h\">Remediation — step by step</div><ol class=\"steps\">")
            for s in d["steps"]:
                h.append("<li>" + esc(s) + "</li>")
            h.append("</ol></div>")
        # gui
        if d["gui"]:
            h.append("<div class=\"sec\"><div class=\"h\">GUI path</div><div class=\"gui\">" + esc(d["gui"]) + "</div></div>")
        # cli
        if d["cli"]:
            h.append("<div class=\"sec\"><div class=\"h\">FortiOS CLI</div><pre class=\"cli\">" + esc(d["cli"]) + "</pre></div>")
        # verify / rollback / impact
        if d["verify"]:
            h.append("<div class=\"sec\"><div class=\"h\">Verification</div><div class=\"verify\">" + esc(d["verify"]) + "</div></div>")
        if d["rollback"]:
            h.append("<div class=\"sec\"><div class=\"h\">Rollback</div><div class=\"rollback\">" + esc(d["rollback"]) + "</div></div>")
        if d["impact"]:
            warn = " warn" if any(w in d["impact"].lower() for w in ("reboot", "disrupt", "drop", "outage", "maintenance")) else ""
            h.append("<div class=\"sec\"><div class=\"h\">Service impact</div><div class=\"impact" + warn + "\">" + esc(d["impact"]) + "</div></div>")
        # references
        refs = list(d["references"] or [])
        if refs:
            h.append("<div class=\"sec\"><div class=\"h\">References</div><div class=\"pill-refs\">")
            for r in refs:
                h.append("<span>" + esc(r) + "</span>")
            h.append("</div></div>")
        if not d.get("_detailed"):
            h.append("<div class=\"sec\"><p style=\"color:var(--muted);font-size:.78rem;font-style:italic\">"
                     "No detailed knowledge-base entry for this rule; the finding's own recommendation is shown.</p></div>")
        h.append("</div></div>")
        return "".join(h)
