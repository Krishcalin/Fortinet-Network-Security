"""
Fortinet FortiGate — Risk-Prioritization Engine
===============================================
Turns a flat list of findings into an ordered, defensible *fix-first* work queue.

Severity alone answers "how bad is this weakness in theory"; it does not answer
"which of my 40 findings do I fix on Monday morning". This engine fuses three
independent signals into a single P1-P4 priority tier per finding:

  1. Base severity            — the intrinsic weakness rating (CRITICAL..INFO).
  2. Real-world exploitability — for CVE findings, whether the CVE is on the
     CISA KEV catalog (proven exploited in the wild) and its FIRST.org EPSS
     score (probability of exploitation in the next 30 days).
  3. Reachability / exposure  — the scanner's own attack-surface analysis: is
     the affected surface actually reachable from the internet on THIS device.

The output is transparent: every prioritized finding carries the exact factors
and points that produced its tier, so an engineer (or an auditor) can see *why*
"fix this now" and not merely be told to.

Design notes:
  * Standard library only — the bundled ``threat_intel.json`` snapshot keeps the
    engine fully functional in air-gapped / OT deployments. ``refresh_threat_intel``
    updates the snapshot from the live CISA + FIRST.org feeds when online.
  * Works on both ``Finding`` objects (``__slots__``) and plain dicts, so it is
    an *overlay* — it never mutates findings and requires no schema change,
    mirroring how ``RemediationKB`` is layered on top.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INTEL_PATH = os.path.join(_HERE, "threat_intel.json")

# EPSS / KEV live feed endpoints (used only by --refresh-intel).
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# --------------------------------------------------------------------------- #
#  scoring model                                                              #
# --------------------------------------------------------------------------- #

# Base points by intrinsic severity. A CRITICAL config weakness that is NOT
# internet-reachable lands at 50 -> P2; add reachability (+20) to reach P1.
BASE_POINTS: Dict[str, int] = {
    "CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 6, "INFO": 0,
}

KEV_POINTS = 35            # proven exploited in the wild — decisive
EPSS_MAX_POINTS = 20       # EPSS 0.0..1.0 scaled to 0..20
EXPOSURE_POINTS = {"WIDE_OPEN": 20, "EXPOSED": 14, "NONE": 0}

# Tier thresholds on the fused 0..100 score.
TIER_THRESHOLDS = [(70, "P1"), (42, "P2"), (20, "P3"), (0, "P4")]
TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

TIER_META: Dict[str, Dict[str, str]] = {
    "P1": {"label": "Fix Now",           "window": "24–72 hours",
           "blurb": "Critical and actively exploited, or critical on the internet edge — treat as an incident.",
           "color": "#f38ba8"},
    "P2": {"label": "Fix This Week",      "window": "within 7 days",
           "blurb": "Critical weakness, a known-exploited (KEV) vulnerability, or a high-risk internet exposure — schedule a change now.",
           "color": "#fab387"},
    "P3": {"label": "Planned Remediation", "window": "within 30 days",
           "blurb": "Meaningful hardening gap — fold into the next maintenance window.",
           "color": "#89b4fa"},
    "P4": {"label": "Backlog / Accept",   "window": "next review cycle",
           "blurb": "Low residual risk — remediate opportunistically or formally accept.",
           "color": "#a6e3a1"},
}

# Reachability is modelled on two independent planes, because they are exposed
# by different config and a finding only benefits from the plane it lives on:
#   * DATA plane   — services behind the firewall reachable from the internet
#                    (from the FORTIOS-EXPOSURE-* attack-surface analysis).
#   * MGMT plane   — the appliance's own management surface reachable from the
#                    WAN (management protocols on a WAN interface / http on WAN).
# Data-plane findings (service CVEs, SSL-VPN, attack-surface) take the data
# signal; management findings (admin hardening) take the mgmt signal; generic
# FortiOS CVEs — which may be either service- or management-reachable — take the
# stronger of the two. The bonus only applies when that plane is actually exposed.
DATA_CATEGORIES = {"Attack Surface", "SSL VPN", "IPsec VPN", "ZTNA / SASE"}
MGMT_CATEGORIES = {"Admin Access"}
DATA_RULE_PREFIXES = ("FORTIOS-EXPOSURE", "MITRE-T1557")   # inbound data path / http on wan
MGMT_RULE_PREFIXES = ("MITRE-T1595",)                       # management exposed on WAN


def _g(f: Any, key: str, default: Any = "") -> Any:
    """Read a field from a Finding object (``__slots__``) or a dict."""
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


# --------------------------------------------------------------------------- #
#  threat-intel snapshot                                                       #
# --------------------------------------------------------------------------- #

class ThreatIntel:
    """Loads the bundled KEV + EPSS snapshot. Missing/broken snapshot degrades
    gracefully to an empty intel set (prioritization then uses severity +
    reachability only)."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or DEFAULT_INTEL_PATH
        self.meta: Dict[str, Any] = {}
        self.cves: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if isinstance(doc, dict):
                self.meta = doc.get("meta", {}) or {}
                raw = doc.get("cves", {}) or {}
                if isinstance(raw, dict):
                    self.cves = {str(k).upper(): v for k, v in raw.items()
                                 if isinstance(v, dict)}
        except (OSError, ValueError):
            self.meta, self.cves = {}, {}

    def get(self, cve: Optional[str]) -> Optional[Dict[str, Any]]:
        if not cve:
            return None
        return self.cves.get(str(cve).upper())

    @property
    def available(self) -> bool:
        return bool(self.cves)

    @property
    def snapshot_date(self) -> str:
        return str(self.meta.get("snapshot_date", "unknown"))

    @property
    def kev_count(self) -> int:
        return sum(1 for v in self.cves.values() if v.get("kev"))


# --------------------------------------------------------------------------- #
#  per-finding priority result                                                 #
# --------------------------------------------------------------------------- #

class PriorityResult:
    """The prioritization overlay for a single finding. Immutable-ish value
    object; ``finding`` is the original object/dict, untouched."""

    __slots__ = ("finding", "tier", "score", "factors", "rationale",
                 "kev", "kev_date", "epss", "epss_pct", "reachable")

    def __init__(self, finding: Any, tier: str, score: int,
                 factors: List[Dict[str, Any]], rationale: str,
                 kev: bool, kev_date: str, epss: Optional[float],
                 epss_pct: Optional[float], reachable: bool):
        self.finding = finding
        self.tier = tier
        self.score = score
        self.factors = factors
        self.rationale = rationale
        self.kev = kev
        self.kev_date = kev_date
        self.epss = epss
        self.epss_pct = epss_pct
        self.reachable = reachable

    @property
    def tier_rank(self) -> int:
        return TIER_RANK.get(self.tier, 9)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": _g(self.finding, "rule_id"),
            "severity": _g(self.finding, "severity"),
            "tier": self.tier,
            "tier_label": TIER_META[self.tier]["label"],
            "priority_score": self.score,
            "kev": self.kev,
            "kev_date": self.kev_date or None,
            "epss": self.epss,
            "epss_pct": self.epss_pct,
            "internet_reachable": self.reachable,
            "rationale": self.rationale,
            "factors": self.factors,
        }


# --------------------------------------------------------------------------- #
#  the engine                                                                  #
# --------------------------------------------------------------------------- #

class RiskPrioritizer:
    def __init__(self, intel: Optional[ThreatIntel] = None):
        self.intel = intel or ThreatIntel()

    # ---- reachability model ----

    @staticmethod
    def exposure_context(findings: List[Any]) -> Dict[str, Any]:
        """Derive the device's internet-exposure on each plane from the scanner's
        own attack-surface / MITRE findings.
          data: WIDE_OPEN (any-source all-service inbound), EXPOSED (a high-risk
                service reachable), or NONE.
          mgmt: True when a management protocol is reachable from the WAN."""
        data = "NONE"
        mgmt = False
        for f in findings:
            rid = str(_g(f, "rule_id", ""))
            sev = str(_g(f, "severity", "")).upper()  # case-insensitive, like assess()
            if rid in ("FORTIOS-EXPOSURE-001", "FORTIOS-EXPOSURE-SUMMARY") and sev == "CRITICAL":
                data = "WIDE_OPEN"
            elif rid.startswith("FORTIOS-EXPOSURE") and sev in ("HIGH", "MEDIUM") and data == "NONE":
                data = "EXPOSED"
            if rid in ("MITRE-T1595-001", "MITRE-T1557-001"):  # mgmt / http on WAN
                mgmt = True
        return {"data": data, "mgmt": mgmt}

    @classmethod
    def _reachability(cls, f: Any, ctx: Dict[str, Any]):
        """Return (points, source) where source is 'data'|'mgmt'|None. Chooses
        the plane the finding lives on; generic FortiOS CVEs take the stronger."""
        cat = str(_g(f, "category", ""))
        rid = str(_g(f, "rule_id", ""))
        data_pts = EXPOSURE_POINTS.get(ctx.get("data", "NONE"), 0)
        # Management-on-WAN is a single binary signal, so it is graded at the
        # EXPOSED level — on the SAME scale as one exposed data service. Keeping
        # it below WIDE_OPEN prevents an irrelevant admin exposure from out-
        # ranking a genuinely wide-open data path when a CVE takes the stronger
        # plane (a single admin protocol is not a fully wide-open firewall).
        mgmt_pts = EXPOSURE_POINTS["EXPOSED"] if ctx.get("mgmt") else 0

        is_mgmt = cat in MGMT_CATEGORIES or rid.startswith(MGMT_RULE_PREFIXES)
        is_data = cat in DATA_CATEGORIES or rid.startswith(DATA_RULE_PREFIXES)
        is_cve = cat == "Known CVEs"

        if is_cve:  # could be service- or management-reachable — take the stronger
            if mgmt_pts >= data_pts and mgmt_pts > 0:
                return mgmt_pts, "mgmt"
            return data_pts, ("data" if data_pts else None)
        if is_mgmt:
            return mgmt_pts, ("mgmt" if mgmt_pts else None)
        if is_data:
            return data_pts, ("data" if data_pts else None)
        return 0, None

    # ---- scoring ----

    def assess(self, f: Any, ctx: Optional[Dict[str, Any]] = None) -> PriorityResult:
        ctx = ctx or {"data": "NONE", "mgmt": False}
        sev = str(_g(f, "severity", "INFO")).upper()
        base = BASE_POINTS.get(sev, 0)
        score = base
        factors: List[Dict[str, Any]] = [
            {"label": "Severity", "detail": f"{sev.title()} weakness rating", "points": base},
        ]

        # --- exploitability (CVE findings) ---
        cve = _g(f, "cve", None)
        entry = self.intel.get(cve) if cve else None
        kev = bool(entry and entry.get("kev"))
        kev_date = str(entry.get("kev_date", "")) if entry else ""
        epss = None
        epss_pct = None
        if entry:
            try:
                epss = float(entry.get("epss"))
            except (TypeError, ValueError):
                epss = None
            try:
                epss_pct = float(entry.get("epss_pct"))
            except (TypeError, ValueError):
                epss_pct = None

        if kev:
            score += KEV_POINTS
            when = f" (catalogued {kev_date})" if kev_date else ""
            factors.append({
                "label": "CISA KEV",
                "detail": f"listed as actively exploited in the wild{when}",
                "points": KEV_POINTS,
            })
        if epss is not None:
            eb = int(round(epss * EPSS_MAX_POINTS))
            top = f"top {max(0.0, (1.0 - epss_pct) * 100):.1f}% of all CVEs" if epss_pct is not None else ""
            if eb:
                score += eb
                factors.append({
                    "label": "EPSS",
                    "detail": (f"{epss * 100:.1f}% probability of exploitation in 30 days"
                               + (f" — {top}" if top else "")),
                    "points": eb,
                })

        # --- reachability / exposure ---
        exp_pts, source = self._reachability(f, ctx)
        if exp_pts and source:
            if source == "mgmt":
                desc = "the appliance management plane is reachable from the internet"
            elif ctx.get("data") == "WIDE_OPEN":
                desc = "reachable through an any-source / all-service inbound path"
            else:
                desc = "on the internet-facing attack surface"
            score += exp_pts
            factors.append({
                "label": "Internet-exposed",
                "detail": desc,
                "points": exp_pts,
            })

        score = min(100, score)

        # --- tier ---
        tier = "P4"
        for thr, name in TIER_THRESHOLDS:
            if score >= thr:
                tier = name
                break
        # Floor: a known-exploited vulnerability is never below "fix this week".
        if kev and TIER_RANK[tier] > TIER_RANK["P2"]:
            tier = "P2"

        exposed = bool(exp_pts and source)
        rationale = self._rationale(tier, sev, kev, kev_date, epss, epss_pct,
                                    exposed, source, ctx.get("data", "NONE"))
        return PriorityResult(f, tier, score, factors, rationale,
                              kev, kev_date, epss, epss_pct, exposed)

    @staticmethod
    def _rationale(tier, sev, kev, kev_date, epss, epss_pct, exposed, source, degree) -> str:
        bits: List[str] = []
        if kev:
            bits.append("actively exploited (CISA KEV"
                        + (f", {kev_date}" if kev_date else "") + ")")
        if epss is not None and epss >= 0.10:
            bits.append(f"{epss * 100:.0f}% EPSS exploit probability")
        if exposed:
            if source == "mgmt":
                bits.append("management plane is internet-exposed on this device")
            else:
                bits.append("internet-reachable on this device"
                            + (" via a wide-open inbound path" if degree == "WIDE_OPEN" else ""))
        drivers = "; ".join(bits) if bits else f"{sev.title()} severity"
        meta = TIER_META[tier]
        return (f"{tier} ({meta['label']}, {meta['window']}): {drivers}. "
                f"{meta['blurb']}")

    # ---- collection API ----

    def prioritize(self, findings: List[Any],
                   context_findings: Optional[List[Any]] = None) -> List[PriorityResult]:
        """Return every finding as a PriorityResult, ordered fix-first
        (tier, then score desc, then severity, then rule id).

        ``context_findings`` (default: ``findings``) is the set used to derive
        internet-reachability. Pass the FULL, unfiltered finding set here when
        ``findings`` has been severity-filtered — reachability is an objective
        property of the device and must not be weakened by a display filter that
        happens to drop the attack-surface findings that signal it."""
        ctx = self.exposure_context(context_findings if context_findings is not None else findings)
        results = [self.assess(f, ctx) for f in findings]
        results.sort(key=lambda r: (
            r.tier_rank, -r.score,
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                str(_g(r.finding, "severity", "INFO")).upper(), 9),
            str(_g(r.finding, "rule_id", "")),
        ))
        return results

    def tier_counts(self, results: List[PriorityResult]) -> Dict[str, int]:
        counts = {t: 0 for t in TIER_META}
        for r in results:
            counts[r.tier] = counts.get(r.tier, 0) + 1
        return counts


def by_finding(results: List[PriorityResult]) -> Dict[int, PriorityResult]:
    """id(finding) -> PriorityResult, for report renderers that iterate the
    original finding list and need each one's priority overlay."""
    return {id(r.finding): r for r in results}


# --------------------------------------------------------------------------- #
#  online refresh (opt-in; --refresh-intel)                                    #
# --------------------------------------------------------------------------- #

def refresh_threat_intel(cve_ids: List[str], path: Optional[str] = None,
                         timeout: int = 30) -> Dict[str, Any]:
    """Rebuild ``threat_intel.json`` from the live CISA KEV catalog and the
    FIRST.org EPSS API for the given CVE IDs. Requires internet access; raises
    on failure so the caller can report it. Standard library only (urllib)."""
    import urllib.request
    import urllib.parse

    cve_ids = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    if not cve_ids:
        raise ValueError("no CVE IDs supplied to refresh")

    def _fetch(url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "fortinet-scanner/risk-intel"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted hosts)
            return resp.read()

    # --- EPSS (batched to keep URLs sane) ---
    epss: Dict[str, Dict[str, float]] = {}
    BATCH = 60
    for i in range(0, len(cve_ids), BATCH):
        chunk = cve_ids[i:i + BATCH]
        url = EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
        data = json.loads(_fetch(url).decode("utf-8"))
        # Defensive: the container may be null / not a list, and individual rows
        # may be non-dicts, if an upstream proxy or rate-limiter mangles the JSON.
        # Skip malformed structure rather than aborting the whole refresh (which
        # would discard every batch already fetched).
        rows = data.get("data") if isinstance(data, dict) else None
        for row in (rows if isinstance(rows, list) else []):
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).upper()
            if not cve:
                continue
            try:
                epss[cve] = {"epss": round(float(row.get("epss")), 5),
                             "epss_pct": round(float(row.get("percentile")), 5)}
            except (TypeError, ValueError):
                continue

    # --- KEV ---
    kev_doc = json.loads(_fetch(KEV_FEED).decode("utf-8"))
    kev_vulns = kev_doc.get("vulnerabilities") if isinstance(kev_doc, dict) else None
    kevmap = {str(v.get("cveID", "")).upper(): str(v.get("dateAdded", ""))
              for v in (kev_vulns if isinstance(kev_vulns, list) else []) if isinstance(v, dict)}

    cves: Dict[str, Dict[str, Any]] = {}
    for cve in cve_ids:
        e = epss.get(cve, {})
        entry: Dict[str, Any] = {
            "epss": e.get("epss", 0.0),
            "epss_pct": e.get("epss_pct", 0.0),
            "kev": cve in kevmap,
        }
        if cve in kevmap:
            entry["kev_date"] = kevmap[cve]
        cves[cve] = entry

    from datetime import datetime
    doc = {
        "meta": {
            "schema": "fortinet-threat-intel/1",
            "snapshot_date": datetime.now().strftime("%Y-%m-%d"),
            "cve_count": len(cves),
            "kev_count": sum(1 for c in cves.values() if c["kev"]),
            "sources": {
                "kev": "CISA Known Exploited Vulnerabilities Catalog (cisa.gov/kev)",
                "epss": "FIRST.org EPSS v3 (first.org/epss)",
            },
            "note": ("Threat-intel snapshot for the Risk-Prioritization Engine. "
                     "Refreshed online with: fortinet_scanner.py --refresh-intel"),
        },
        "cves": dict(sorted(cves.items())),
    }
    out = path or DEFAULT_INTEL_PATH
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return doc["meta"]
