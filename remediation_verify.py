"""
Fortinet FortiGate Scanner — Remediation Verification Loop
==========================================================
Closes the loop the remediation runbook opens: after you apply fixes, *prove they
landed*. Point ``--verify-fixes prev.json`` at the ``--json`` report you were
remediating; the scanner re-reads the device now and classifies each finding you
set out to fix:

* **REMEDIATED** — the finding is gone (the fix worked).
* **PERSISTING** — the finding is still present with the *same* evidence line — the
  fix was not applied (or not effective).
* **CHANGED** — the rule still fires but the evidence value moved (a partial or
  ineffective change — e.g. ``admintimeout 30`` → ``20``, still over the limit).
* **REGRESSION** — a finding present now that was *not* in the prior report — a new
  problem introduced since (often by the very change you made).

For each it shows the **before → after** config evidence and the knowledge-base
**verify command** so an operator can independently confirm, and it reports a
**remediation rate** so a change window can be signed off (or gated in CI).

Distinct from ``--baseline`` (which folds a bidirectional drift *summary finding*
into the normal report) and ``--history`` (a multi-scan system of record): this is
a focused, finding-level A/B *"did my fixes work?"* report with evidence pairing and
independent-verify commands. Matching uses the same stable identity as posture
(``rule_id | entity``), so a cosmetic value change reads as CHANGED, not
remediated+new. Pure stdlib.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Rollup / score pseudo-findings are not remediable items — exclude from the A/B.
_PSEUDO_SUFFIX = ("-SUMMARY", "-SCORE", "-PASS")
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_STATUS_ORDER = {"REGRESSION": 0, "PERSISTING": 1, "CHANGED": 2, "REMEDIATED": 3}


def _g(obj: Any, key: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _is_pseudo(rule_id: Any) -> bool:
    rid = str(rule_id or "")
    return any(rid.endswith(s) for s in _PSEUDO_SUFFIX)


def _fp(finding: Any) -> str:
    """Stable identity = rule_id|entity (posture fingerprint), evidence-independent."""
    try:
        from posture import finding_fingerprint
        return finding_fingerprint(finding)
    except Exception:  # pragma: no cover
        return str(_g(finding, "rule_id", ""))


def _reportable(findings: List[Any]) -> List[Any]:
    return [f for f in (findings or [])
            if isinstance(f, (dict,)) or f is not None
            if not _is_pseudo(_g(f, "rule_id", ""))
            and str(_g(f, "severity", "")).upper() != "INFO"]


def _tier_of(finding: Any, prio_by_id: Optional[dict]) -> Optional[str]:
    # prefer a live prioritization overlay (current objects), else a prior report's
    # embedded per-finding "priority" block (save_json embeds it), else None.
    if prio_by_id and not isinstance(finding, dict):
        pr = prio_by_id.get(id(finding))
        if pr:
            return pr.get("tier")
    if isinstance(finding, dict):
        p = finding.get("priority") or {}
        if isinstance(p, dict) and p.get("tier"):
            return p["tier"]
    return None


def _verify_cmd(kb: Any, rule_id: str) -> str:
    if kb is None:
        return ""
    try:
        entry = kb.lookup(rule_id)
        return str((entry or {}).get("verify", "") or "")
    except Exception:  # pragma: no cover
        return ""


def _item(status: str, rep_finding: Any, before: Optional[str], after: Optional[str],
          kb: Any, tier: Optional[str]) -> Dict[str, Any]:
    rid = str(_g(rep_finding, "rule_id", ""))
    return {
        "status": status,
        "rule_id": rid,
        "name": str(_g(rep_finding, "name", "")),
        "severity": str(_g(rep_finding, "severity", "")).upper(),
        "tier": tier,
        "category": str(_g(rep_finding, "category", "")),
        "cve": _g(rep_finding, "cve") or None,
        "before": before,
        "after": after,
        "verify_cmd": _verify_cmd(kb, rid),
    }


def build_verification(prior: List[Any], current: List[Any], *,
                       kb: Any = None, prio_by_id: Optional[dict] = None,
                       host: str = "") -> Dict[str, Any]:
    """Classify each prior finding vs the current scan. Returns a report dict:
    {host, summary{...}, items[REMEDIATED/PERSISTING/CHANGED], regressions[REGRESSION]}."""
    prior_r = _reportable(prior)
    current_r = _reportable(current)
    prior_by: Dict[str, Any] = {}
    for d in prior_r:
        prior_by[_fp(d)] = d          # last wins (same convention as posture/drift)
    curr_by: Dict[str, Any] = {}
    for f in current_r:
        curr_by[_fp(f)] = f

    items: List[Dict[str, Any]] = []
    for fp, pd in prior_by.items():
        before = str(_g(pd, "line_content", ""))
        cf = curr_by.get(fp)
        if cf is None:
            items.append(_item("REMEDIATED", pd, before, None, kb, _tier_of(pd, prio_by_id)))
        else:
            after = str(_g(cf, "line_content", ""))
            status = "PERSISTING" if after == before else "CHANGED"
            # report from the CURRENT finding (fresh name/severity), tier from current
            it = _item(status, cf, before, after, kb, _tier_of(cf, prio_by_id))
            items.append(it)

    # Severity-scope guard: a prior report generated with --severity only contains
    # findings at/above that threshold, so a current finding BELOW the prior report's
    # observed floor could NOT have appeared in it — its "absence" proves nothing and
    # must not be a regression (else a filtered prior floods false regressions and can
    # falsely flip `clean` / return exit 2, gating a CI change window that introduced
    # nothing). Infer the floor as the least-severe severity present in the reportable
    # prior set (most-permissive/INFO when the prior is empty, so nothing is suppressed).
    prior_floor_rank = max(
        (_SEV_RANK.get(str(_g(d, "severity", "")).upper(), 4) for d in prior_by.values()),
        default=_SEV_RANK["INFO"])

    regressions: List[Dict[str, Any]] = []
    for fp, cf in curr_by.items():
        if fp in prior_by:
            continue
        if _SEV_RANK.get(str(_g(cf, "severity", "")).upper(), 4) > prior_floor_rank:
            continue  # below the prior report's severity floor — not a genuine regression
        regressions.append(_item("REGRESSION", cf, None, str(_g(cf, "line_content", "")),
                                 kb, _tier_of(cf, prio_by_id)))

    def _sort(lst):
        lst.sort(key=lambda i: (_STATUS_ORDER.get(i["status"], 9),
                                _SEV_RANK.get(i["severity"], 5), i["rule_id"]))
        return lst
    _sort(items)
    _sort(regressions)

    total_prior = len(prior_by)
    remediated = sum(1 for i in items if i["status"] == "REMEDIATED")
    persisting = sum(1 for i in items if i["status"] == "PERSISTING")
    changed = sum(1 for i in items if i["status"] == "CHANGED")
    # "unresolved" = still failing in some form (persisting or changed)
    unresolved_high = [i for i in items
                       if i["status"] in ("PERSISTING", "CHANGED")
                       and i["severity"] in ("CRITICAL", "HIGH")]
    regressions_high = [i for i in regressions if i["severity"] in ("CRITICAL", "HIGH")]
    rate = round(remediated / total_prior * 100) if total_prior else 100

    summary = {
        "host": host,
        "total_prior": total_prior,
        "remediated": remediated,
        "persisting": persisting,
        "changed": changed,
        "regressions": len(regressions),
        "remediation_rate_pct": rate,
        "unresolved_critical_high": len(unresolved_high),
        "regressions_critical_high": len(regressions_high),
        # clean = every prior CRITICAL/HIGH remediated AND no new CRITICAL/HIGH regression
        "clean": not unresolved_high and not regressions_high,
    }
    return {"host": host, "summary": summary, "items": items, "regressions": regressions}


# --------------------------------------------------------------------------- #
#  rendering                                                                   #
# --------------------------------------------------------------------------- #

_MARK = {"REMEDIATED": "[fixed]", "PERSISTING": "[STILL OPEN]",
         "CHANGED": "[CHANGED]", "REGRESSION": "[REGRESSION]"}


def render_text(report: Dict[str, Any], baseline_label: str = "") -> str:
    s = report["summary"]
    W = 74
    out: List[str] = []
    out.append("=" * W)
    out.append("  Remediation Verification" + (f" — {s['host']}" if s.get("host") else ""))
    if baseline_label:
        out.append(f"  Target report: {baseline_label}")
    out.append("=" * W)
    out.append(f"  Remediated {s['remediated']}/{s['total_prior']}  ({s['remediation_rate_pct']}%)"
               f"   Still-open {s['persisting']}   Changed {s['changed']}   Regressions {s['regressions']}")
    if s["unresolved_critical_high"]:
        out.append(f"  [!] {s['unresolved_critical_high']} CRITICAL/HIGH finding(s) NOT remediated")
    if s["regressions_critical_high"]:
        out.append(f"  [!] {s['regressions_critical_high']} new CRITICAL/HIGH regression(s)")
    out.append(f"  Verdict: {'CLEAN — targeted criticals fixed, no new ones' if s['clean'] else 'ACTION REQUIRED'}")
    out.append("-" * W)

    def _block(title, lst):
        if not lst:
            return
        out.append(f"  {title}")
        for i in lst:
            tier = f" {i['tier']}" if i.get("tier") else ""
            out.append(f"    {_MARK.get(i['status'],''):13} [{i['severity']}]{tier} {i['rule_id']} — {i['name'][:56]}")
            if i["status"] == "CHANGED":
                out.append(f"        before: {i['before']}")
                out.append(f"        after : {i['after']}")
            elif i["status"] == "PERSISTING":
                out.append(f"        still : {i['after']}")
            elif i["status"] == "REGRESSION":
                out.append(f"        now   : {i['after']}")
            if i["status"] in ("PERSISTING", "CHANGED", "REMEDIATED") and i.get("verify_cmd"):
                out.append(f"        verify: {i['verify_cmd']}")
        out.append("")

    still = [i for i in report["items"] if i["status"] in ("PERSISTING", "CHANGED")]
    _block("STILL OPEN / CHANGED (fix not confirmed):", still)
    _block("NEW REGRESSIONS (introduced since the target report):", report["regressions"])
    _block("REMEDIATED (confirmed fixed):", [i for i in report["items"] if i["status"] == "REMEDIATED"])
    out.append("=" * W)
    return "\n".join(out) + "\n"


def _esc(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(report: Dict[str, Any], baseline_label: str = "") -> str:
    s = report["summary"]
    rows = []
    for i in report["items"] + report["regressions"]:
        cls = i["status"].lower()
        eve = ""
        if i["status"] == "CHANGED":
            eve = f"<div class='ev'>before: {_esc(i['before'])}<br>after: {_esc(i['after'])}</div>"
        elif i["status"] in ("PERSISTING", "REGRESSION"):
            eve = f"<div class='ev'>{_esc(i['after'])}</div>"
        vc = f"<div class='vc'>verify: <code>{_esc(i['verify_cmd'])}</code></div>" if i.get("verify_cmd") and i["status"] != "REGRESSION" else ""
        rows.append(
            f"<tr class='{cls}'><td>{_esc(i['status'])}</td><td>{_esc(i['severity'])}</td>"
            f"<td>{_esc(i.get('tier') or '')}</td><td><b>{_esc(i['rule_id'])}</b><br>{_esc(i['name'])}{eve}{vc}</td></tr>")
    verdict = "CLEAN" if s["clean"] else "ACTION REQUIRED"
    vcls = "clean" if s["clean"] else "action"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Remediation Verification — {_esc(s.get('host',''))}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#1a1b2e}}
 .wrap{{max-width:1000px;margin:0 auto;padding:26px}} h1{{font-size:20px;margin:0 0 6px}}
 .kpi{{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}}
 .kpi div{{background:#fff;border-radius:8px;padding:10px 14px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 .kpi b{{font-size:20px;display:block}}
 .verdict{{display:inline-block;padding:5px 12px;border-radius:6px;font-weight:700;color:#fff}}
 .verdict.clean{{background:#2ea043}} .verdict.action{{background:#dc2626}}
 table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-top:14px}}
 th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid #eef0f3;vertical-align:top}} th{{background:#1a1b2e;color:#fff;font-size:12px}}
 tr.remediated td:first-child{{color:#2ea043;font-weight:700}} tr.persisting td:first-child,tr.changed td:first-child{{color:#dc2626;font-weight:700}}
 tr.regression td:first-child{{color:#d29922;font-weight:700}}
 .ev,.vc{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#556;margin-top:4px}} code{{background:#f0f1f4;padding:1px 4px;border-radius:3px}}
</style></head><body><div class="wrap">
<h1>Remediation Verification{f' — {_esc(s.get("host",""))}' if s.get('host') else ''}</h1>
<div>Target report: <code>{_esc(baseline_label)}</code> · Verdict: <span class="verdict {vcls}">{verdict}</span></div>
<div class="kpi">
 <div><b>{s['remediation_rate_pct']}%</b>remediated ({s['remediated']}/{s['total_prior']})</div>
 <div><b>{s['persisting']}</b>still open</div>
 <div><b>{s['changed']}</b>changed</div>
 <div><b>{s['regressions']}</b>regressions</div>
 <div><b>{s['unresolved_critical_high']}</b>unresolved crit/high</div>
</div>
<table><tr><th>Status</th><th>Severity</th><th>Tier</th><th>Finding</th></tr>
{''.join(rows)}</table>
</div></body></html>"""
