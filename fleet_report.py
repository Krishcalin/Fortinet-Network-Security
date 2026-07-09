"""
Fortinet FortiGate — Fleet Analysis Console
===========================================
Aggregates many single-device scans (a folder of ``.conf`` backups, or a set of
per-device ``--json`` reports) into one fleet-wide view that answers the two
questions a firewall team actually asks each week:

  * "Which of my 50 firewalls are worst?"  -> a worst-device ranking.
  * "Which single fix clears the most boxes?" -> prevalence campaigns
    ("FORTIOS-ADMIN-003 on 34/50 devices — one CLI block fixes all").

Design:
  * Standard library only (works in the offline/OT scanner; PDF via pdf_writer).
  * The heavy lifting is sorting + counting + pulling verbatim fixes from the
    RemediationKB — deliberately low fabrication risk.
  * Prevalence campaigns for CVE findings are gated on the per-device
    reachability verdict, so a campaign reports "34 affected / 21 reachable"
    rather than a version-only over-count amplified across the fleet.
  * Device identity is hostname-first (offline serials are all "OFFLINE-CONFIG"),
    and hostname collisions across sources are surfaced so a mis-merge can never
    silently inflate or hide a device count.
"""

from __future__ import annotations

import html as _html
import json
import math
import os
from typing import Any, Dict, List, Optional

from remediation_kb import RemediationKB

SEV_LIST = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_ORDER = {s: i for i, s in enumerate(SEV_LIST)}
TIER_LIST = ["P1", "P2", "P3", "P4"]
TIER_RANK = {t: i for i, t in enumerate(TIER_LIST)}


def _g(o: Any, key: str, default: Any = "") -> Any:
    if isinstance(o, dict):
        return o.get(key, default)
    return getattr(o, key, default)


def esc(s: Any) -> str:
    return _html.escape(str(s if s is not None else ""))


def risk_score(counts: Dict[str, int]) -> int:
    """Mirror _ReportMixin._risk_score so fleet scores match per-device scores."""
    return min(100, counts.get("CRITICAL", 0) * 25 + counts.get("HIGH", 0) * 10
               + counts.get("MEDIUM", 0) * 4 + counts.get("LOW", 0) * 1)


# --------------------------------------------------------------------------- #
#  device record                                                              #
# --------------------------------------------------------------------------- #

def build_record(meta: Dict[str, Any], findings: List[Any],
                 priorities: Optional[List[Any]] = None,
                 source: str = "", drop_info: bool = True) -> Dict[str, Any]:
    """Normalize one device's scan into a fleet record.

    meta       -- {hostname, model, version, serial, ...}
    findings   -- list of finding dicts (or Finding objects)
    priorities -- list of PriorityResult.to_dict() (or None); joined by rule_id
    source     -- filename / host the scan came from (for de-dup + provenance)
    drop_info  -- exclude INFO-severity findings (default): they carry no risk-score
                  weight and are filtered inconsistently across ingest paths, so
                  keeping them would make cross-device totals non-comparable.
    """
    if drop_info:
        findings = [f for f in findings if str(_g(f, "severity", "")).upper() != "INFO"]
        if priorities:
            priorities = [p for p in priorities if str(_g(p, "severity", "")).upper() != "INFO"]
    counts = {s: 0 for s in SEV_LIST}
    for f in findings:
        sev = str(_g(f, "severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1

    tiers = {t: 0 for t in TIER_LIST}
    # Per-rule priority overlay: keep the strongest (lowest tier rank; reachable
    # if any instance is reachable) for prevalence-campaign gating.
    pidx: Dict[str, Dict[str, Any]] = {}
    for p in (priorities or []):
        tier = str(_g(p, "tier", "P4"))
        tiers[tier] = tiers.get(tier, 0) + 1
        rid = str(_g(p, "rule_id", ""))
        if not rid:
            continue
        rec = pidx.get(rid)
        cur = {"tier": tier,
               "reachable": bool(_g(p, "internet_reachable", False)),
               "kev": bool(_g(p, "kev", False)),
               "ransomware": bool(_g(p, "ransomware", False))}
        if rec is None or TIER_RANK.get(tier, 9) < TIER_RANK.get(rec["tier"], 9):
            # keep strongest tier, but OR the boolean signals
            cur["reachable"] = cur["reachable"] or (rec or {}).get("reachable", False)
            cur["kev"] = cur["kev"] or (rec or {}).get("kev", False)
            cur["ransomware"] = cur["ransomware"] or (rec or {}).get("ransomware", False)
            pidx[rid] = cur
        else:
            rec["reachable"] = rec["reachable"] or cur["reachable"]
            rec["kev"] = rec["kev"] or cur["kev"]
            rec["ransomware"] = rec["ransomware"] or cur["ransomware"]

    hostname = str(meta.get("hostname") or meta.get("host") or "").strip() or "(unknown)"
    return {
        "hostname": hostname,
        "model": str(meta.get("model_name", meta.get("model", "N/A"))),
        "version": str(meta.get("version", "N/A")).lstrip("v"),
        "serial": str(meta.get("serial", "N/A")),
        "source": source or hostname,
        "counts": counts,
        "risk_score": risk_score(counts),
        "tiers": tiers,
        "findings": findings,
        "_pidx": pidx,
    }


def record_from_json(doc: Dict[str, Any], source: str = "") -> Dict[str, Any]:
    """Build a device record from a single-device ``--json`` report dict."""
    meta = doc.get("system_info", {}) or {}
    findings = doc.get("findings", []) or []
    priorities = doc.get("priorities")  # present if the scan embedded the overlay
    return build_record(meta, findings, priorities,
                        source=source or doc.get("target", "") or meta.get("hostname", ""))


# --------------------------------------------------------------------------- #
#  fleet aggregation                                                          #
# --------------------------------------------------------------------------- #

class FleetReport:
    def __init__(self, records: List[Dict[str, Any]],
                 kb: Optional[RemediationKB] = None,
                 systemic_frac: float = 0.75):
        self.kb = kb or RemediationKB()
        self.systemic_frac = systemic_frac
        self.records = list(records)
        self._dedup()
        self.agg = self._aggregate()

    # ---- device identity / de-dup (hostname-first; surface collisions) ----
    def _dedup(self) -> None:
        seen: Dict[str, int] = {}
        self.collisions: List[Dict[str, str]] = []
        for r in self.records:
            key = r["hostname"]
            # a real serial disambiguates same-hostname devices; the offline
            # placeholder serial does not, so fall back to the source filename.
            serial = r.get("serial", "")
            if serial and serial != "OFFLINE-CONFIG":
                key = f"{r['hostname']}::{serial}"
            if key in seen:
                seen[key] += 1
                r["device_id"] = f"{key}#{seen[key]}"
                self.collisions.append({"hostname": r["hostname"], "device_id": r["device_id"],
                                        "source": r.get("source", "")})
            else:
                seen[key] = 1
                r["device_id"] = key

    def _aggregate(self) -> Dict[str, Any]:
        n = len(self.records)
        sev_tot = {s: 0 for s in SEV_LIST}
        tier_tot = {t: 0 for t in TIER_LIST}
        versions: Dict[str, int] = {}
        models: Dict[str, int] = {}
        for r in self.records:
            for s in SEV_LIST:
                sev_tot[s] += r["counts"].get(s, 0)
            for t in TIER_LIST:
                tier_tot[t] += r["tiers"].get(t, 0)
            versions[r["version"]] = versions.get(r["version"], 0) + 1
            models[r["model"]] = models.get(r["model"], 0) + 1

        scores = [r["risk_score"] for r in self.records] or [0]
        worst = sorted(self.records, key=lambda r: (
            -r["risk_score"], -r["tiers"].get("P1", 0), -r["counts"].get("CRITICAL", 0), r["device_id"]))

        campaigns = self._campaigns(n)
        # round() before ceil() avoids a float-representation overshoot (e.g.
        # 0.14*50 == 7.0000000000000009 -> ceil 8) that would drop a systemic rule.
        threshold = max(2, math.ceil(round(self.systemic_frac * n, 9)))
        systemic = [c for c in campaigns if c["device_count"] >= threshold]

        return {
            "device_count": n,
            "total_findings": sum(sev_tot.values()),
            "severity_totals": sev_tot,
            "tier_totals": tier_tot,
            "risk_avg": round(sum(scores) / len(scores), 1),
            "risk_max": max(scores),
            "versions": versions,
            "models": models,
            "worst_devices": worst,
            "campaigns": campaigns,
            "systemic": systemic,
            "collisions": self.collisions,
        }

    def _campaigns(self, n: int) -> List[Dict[str, Any]]:
        """One entry per rule_id: how many devices have it, how many are
        internet-reachable, and the verbatim fix from the KB."""
        camp: Dict[str, Dict[str, Any]] = {}
        for r in self.records:
            seen_rules: set = set()
            for f in r["findings"]:
                rid = str(_g(f, "rule_id", ""))
                if not rid or rid in seen_rules:
                    continue
                seen_rules.add(rid)
                c = camp.get(rid)
                if c is None:
                    c = camp[rid] = {
                        "rule_id": rid,
                        "name": str(_g(f, "name", "")),
                        "severity": str(_g(f, "severity", "INFO")).upper(),
                        "category": str(_g(f, "category", "")),
                        "cve": _g(f, "cve", None),
                        "devices": [], "reachable": 0, "kev": False, "ransomware": False,
                        "_sample": f,
                    }
                c["devices"].append(r["device_id"])
                pi = r["_pidx"].get(rid, {})
                if pi.get("reachable"):
                    c["reachable"] += 1
                c["kev"] = c["kev"] or pi.get("kev", False)
                c["ransomware"] = c["ransomware"] or pi.get("ransomware", False)

        out = []
        for rid, c in camp.items():
            c["device_count"] = len(c["devices"])
            c["fix"] = self._fix_for(c["_sample"])
            del c["_sample"]
            out.append(c)
        # rank by reach (breadth of impact) then severity then reachability
        out.sort(key=lambda c: (-c["device_count"], SEV_ORDER.get(c["severity"], 9), -c["reachable"], c["rule_id"]))
        return out

    def _fix_for(self, finding: Any) -> Dict[str, str]:
        try:
            d = self.kb.detail_for(finding)
            return {"cli": d.get("cli", "") or "",
                    "steps": (d.get("steps") or [None])[0] or "",
                    "gui": d.get("gui", "") or ""}
        except Exception:
            return {"cli": str(_g(finding, "remediation_cmd", "")), "steps": "", "gui": ""}

    # ---- exports ------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        a = self.agg
        return {
            "report": "Fortinet FortiGate Fleet Analysis",
            "device_count": a["device_count"],
            "total_findings": a["total_findings"],
            "severity_totals": a["severity_totals"],
            "tier_totals": a["tier_totals"],
            "risk_avg": a["risk_avg"],
            "risk_max": a["risk_max"],
            "versions": a["versions"],
            "models": a["models"],
            "collisions": a["collisions"],
            "worst_devices": [{
                "device_id": r["device_id"], "hostname": r["hostname"], "model": r["model"],
                "version": r["version"], "risk_score": r["risk_score"],
                "severity": r["counts"], "tiers": r["tiers"], "source": r.get("source", ""),
            } for r in a["worst_devices"]],
            "campaigns": [{**{k: v for k, v in c.items() if k != "fix"}, "fix_cli": c["fix"]["cli"]}
                          for c in a["campaigns"]],
        }

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
        print(f"[+] Fleet JSON report saved to: {path}")

    def save_html(self, path: str) -> None:
        from fleet_html import render_fleet_html
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_fleet_html(self))
        print(f"[+] Fleet HTML report saved to: {path}")

    def save_pdf(self, path: str) -> None:
        from fleet_pdf import render_fleet_pdf
        render_fleet_pdf(self, path)
        print(f"[+] Fleet PDF report saved to: {path}")
