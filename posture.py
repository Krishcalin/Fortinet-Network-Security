"""
Fortinet FortiGate — Continuous Posture State
=============================================
Every scan is otherwise amnesiac: a formally-accepted risk re-nags at full
severity on every run, burying the handful of genuinely-new findings and, over
time, making operators stop running the tool. This module gives the scanner a
memory — a file-based system of record that, run after run, answers:

  * What is NEW, CARRIED-OVER, RESOLVED, or REOPENED since last time?
  * Which risks have been formally ACCEPTED (with reason/approver/expiry) and
    should stop nagging — until the exception EXPIRES, when they resurface?
  * Which open findings have blown their remediation SLA (P1 = 72h, P2 = 7d, …)?
  * Which still-open finding just became NEWLY WEAPONIZED (now on CISA KEV)?
  * How is each device's risk trending over time?

Two safety principles, because a "system of record" and a suppression channel are
both ways to silently hide a live finding:

  1. **Stable identity.** Findings are matched across scans by ``host | rule_id |
     entity`` — NOT by ``line_content``, which embeds volatile values
     (``admintimeout=30``, ``min-length=6``). Keying on the raw line would record
     a live finding as "resolved" the moment a cosmetic value changes. The entity
     is a *stable identifier* (policy id / interface / object name) extracted
     conservatively; singletons key on ``host|rule_id`` alone.
  2. **Fail open.** An expired or malformed exception is ignored and the finding
     re-appears — a suppression can never outlive its approval or hide a finding
     through a typo.

Standard library only, so it runs in the offline/air-gapped scanner too.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "fortinet-posture/1"

# Remediation SLA windows per fix-first tier (days). P4 has no hard SLA.
TIER_SLA_DAYS = {"P1": 3, "P2": 7, "P3": 30, "P4": None}

# "expiring soon" horizon for accepted-risk warnings (days).
EXPIRY_SOON_DAYS = 30


def _g(o: Any, key: str, default: Any = "") -> Any:
    if isinstance(o, dict):
        return o.get(key, default)
    return getattr(o, key, default)


# --------------------------------------------------------------------------- #
#  stable finding identity                                                     #
# --------------------------------------------------------------------------- #

# A single- or double-quoted object name — the scanner names LDAP/RADIUS/User/
# VAP/WIDS/WTP/dnsfilter objects as e.g.  LDAP 'DC1'  or  VAP 'office'.
_RE_QUOTED = re.compile(r"['\"]([^'\"]{1,80})['\"]")
# Policy id in either emitted form: `policy=Name (ID 10)` or `policy 5 (name)`.
_RE_POLICY = re.compile(r"\(ID\s+(\d+)\)|\bpolicy\s+(?:ID\s+)?(\d+)\b")
_RE_IFACE = re.compile(r"\binterface[=:\s]+([A-Za-z0-9_.\-]+)")
# Object-reference `key=name` forms (allowlisted so a volatile setting value like
# admintimeout=30 is NOT mistaken for identity — only these keys name an object).
_IDENTITY_KEYS = ("admin", "api-user", "av-profile", "certificate", "dnsfilter",
                  "icap-profile", "dos-policy", "ospf-interface")
_RE_KEYVAL = re.compile(r"\b(" + "|".join(k.replace("-", r"\-") for k in _IDENTITY_KEYS)
                        + r")=([A-Za-z0-9_.\-]+)")


def finding_entity(rule_id: str, line_content: str) -> str:
    """Extract a STABLE sub-identity for a finding that can fire more than once
    per device (per-policy / per-interface / per-named-object), so those
    instances are tracked separately without depending on volatile values.
    Returns "" for singleton findings (keyed on rule_id alone). Conservative by
    design — only clear identifier patterns (quoted object names, policy ids,
    interfaces, allowlisted object-reference keys) qualify, matched against the
    actual line_content formats the scanner emits."""
    lc = line_content or ""
    m = _RE_QUOTED.search(lc)
    if m:
        return "name:" + m.group(1)
    m = _RE_POLICY.search(lc)
    if m:
        return "policy:" + (m.group(1) or m.group(2))
    m = _RE_IFACE.search(lc)
    if m:
        return "iface:" + m.group(1)
    m = _RE_KEYVAL.search(lc)
    if m:
        return m.group(1) + ":" + m.group(2)
    return ""


def finding_fingerprint(finding: Any) -> str:
    """Stable within-device key: ``rule_id`` or ``rule_id|entity``. Deliberately
    excludes line_content values so a cosmetic config change (e.g. admintimeout
    30 -> 20, both still findings) does NOT read as resolved+new."""
    rid = str(_g(finding, "rule_id", ""))
    entity = finding_entity(rid, str(_g(finding, "line_content", "")))
    return f"{rid}|{entity}" if entity else rid


# --------------------------------------------------------------------------- #
#  exceptions (risk acceptance / deferral)                                     #
# --------------------------------------------------------------------------- #

def _parse_date(s: Any) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(str(s)[:19], fmt)
        except (TypeError, ValueError):
            continue
    return None


class Exceptions:
    """Accepted/deferred risks. Each entry: {host, rule_id, entity?, reason,
    approver, expires?, status}. Matching is host + rule_id (+ entity if the
    exception specifies one). FAIL OPEN: an expired or unparseable entry does not
    suppress anything, and expired ones are reported so they get re-approved."""

    def __init__(self, entries: Optional[List[dict]] = None):
        self.entries = [e for e in (entries or []) if isinstance(e, dict)]

    @classmethod
    def load(cls, path: Optional[str]) -> "Exceptions":
        if not path:
            return cls([])
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return cls([])
        if isinstance(doc, dict):
            doc = doc.get("exceptions", [])
        return cls(doc if isinstance(doc, list) else [])

    def match(self, host: str, rule_id: str, entity: str, now: datetime
              ) -> Tuple[Optional[dict], bool]:
        """Return (active_exception, had_expired). active_exception is the
        matching, non-expired entry (or None); had_expired is True if a matching
        entry exists but has expired (so the finding fails open, flagged)."""
        expired = False
        for e in self.entries:
            eh = str(e.get("host", "*")) or "*"
            if eh not in ("*", host):
                continue
            if str(e.get("rule_id", "")) != rule_id:
                continue
            ent = str(e.get("entity", "") or "")
            if ent and ent != entity:
                continue
            if "expires" in e and e.get("expires") not in (None, ""):
                exp = _parse_date(e.get("expires"))
                # An expires that is present but UNPARSEABLE must fail open (treat
                # as expired) — never let a typo'd date suppress a live finding.
                if exp is None or now > exp:
                    expired = True
                    continue
            return e, expired
        return None, expired


# --------------------------------------------------------------------------- #
#  posture delta (result of one update)                                        #
# --------------------------------------------------------------------------- #

class PostureDelta:
    def __init__(self):
        self.host = ""
        self.prev_date: Optional[str] = None
        self.new: List[dict] = []
        self.carried: List[dict] = []
        self.resolved: List[dict] = []
        self.reopened: List[dict] = []
        self.accepted: List[dict] = []          # {rec, exception}
        self.expired_exceptions: List[dict] = []
        self.sla_breaches: List[dict] = []       # {rec, age_days, window}
        self.newly_weaponized: List[dict] = []
        self.risk_score = 0
        self.prev_risk_score: Optional[int] = None
        self.open_active = 0
        self.open_accepted = 0

    @property
    def risk_delta(self) -> Optional[int]:
        if self.prev_risk_score is None:
            return None
        return self.risk_score - self.prev_risk_score

    def to_dict(self) -> Dict[str, Any]:
        def slim(recs, keys=("rule_id", "entity", "severity", "name", "tier")):
            return [{k: r.get(k) for k in keys} for r in recs]
        return {
            "host": self.host,
            "prev_scan": self.prev_date,
            "risk_score": self.risk_score,
            "prev_risk_score": self.prev_risk_score,
            "risk_delta": self.risk_delta,
            "open_active": self.open_active,
            "open_accepted": self.open_accepted,
            "new": slim(self.new),
            "resolved": slim(self.resolved),
            "reopened": slim(self.reopened),
            "carried": len(self.carried),
            "accepted": [{**{k: a["rec"].get(k) for k in ("rule_id", "entity", "severity", "name")},
                          "reason": a["exception"].get("reason"),
                          "approver": a["exception"].get("approver"),
                          "expires": a["exception"].get("expires")} for a in self.accepted],
            "expired_exceptions": self.expired_exceptions,
            "sla_breaches": [{**{k: b["rec"].get(k) for k in ("rule_id", "severity", "name", "tier")},
                              "age_days": b["age_days"], "sla_days": b["window"]} for b in self.sla_breaches],
            "newly_weaponized": slim(self.newly_weaponized),
        }


# --------------------------------------------------------------------------- #
#  the store                                                                    #
# --------------------------------------------------------------------------- #

class PostureStore:
    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Any] = {"schema": SCHEMA, "devices": {}}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if isinstance(doc, dict) and isinstance(doc.get("devices"), dict):
                self.data = doc
                self.data.setdefault("schema", SCHEMA)
        except (OSError, ValueError):
            pass  # first run / unreadable -> start fresh (fail open, never crash)

    @staticmethod
    def _iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    def update(self, host: str, findings: List[Any], priorities: Optional[List[Any]] = None,
               exceptions: Optional[Exceptions] = None, now: Optional[datetime] = None,
               risk_score: int = 0) -> PostureDelta:
        now = now or datetime.now()
        exceptions = exceptions or Exceptions([])
        host = str(host or "unknown")
        dev = self.data["devices"].setdefault(host, {"findings": {}, "history": []})
        stored: Dict[str, dict] = dev["findings"]

        # Priority overlay (tier/kev for SLA + weaponization) indexed by the
        # finding's fingerprint. PriorityResult wraps the finding on `.finding`,
        # so unwrap before fingerprinting — fingerprinting the wrapper yields ""
        # and the whole overlay would silently attach to nothing.
        prio_by_fp: Dict[str, dict] = {}
        for p in (priorities or []):
            pf = _g(p, "finding", p)
            prio_by_fp[finding_fingerprint(pf)] = {"tier": str(_g(p, "tier", "")),
                                                   "kev": bool(_g(p, "kev", False))}

        delta = PostureDelta()
        delta.host = host
        delta.risk_score = risk_score
        prev = dev["history"][-1] if dev["history"] else None
        if prev:
            delta.prev_date = prev.get("date")
            delta.prev_risk_score = prev.get("risk_score")

        current: Dict[str, Any] = {}
        for f in findings:
            current[finding_fingerprint(f)] = f

        # ---- lifecycle + acceptance + SLA in one pass over current findings ----
        for fp, f in current.items():
            pri = prio_by_fp.get(fp, {})
            kev = bool(pri.get("kev", False))
            tier = pri.get("tier", "")
            rid = str(_g(f, "rule_id", ""))
            entity = finding_entity(rid, str(_g(f, "line_content", "")))

            # acceptance is decided first, so an accepted risk is excluded from the
            # new/carried/reopened/weaponized nag lists (that is the whole point).
            exc, had_expired = exceptions.match(host, rid, entity, now)
            accepted = exc is not None
            if had_expired and not accepted:
                delta.expired_exceptions.append({"rule_id": rid, "entity": entity})

            rec = stored.get(fp)
            if rec is None:
                rec = stored[fp] = {
                    "rule_id": rid, "entity": entity,
                    "severity": str(_g(f, "severity", "")), "name": str(_g(f, "name", "")),
                    "first_seen": self._iso(now), "last_seen": self._iso(now),
                    "status": "open", "kev": kev, "tier": tier,
                }
                if not accepted:
                    delta.new.append(rec)
            else:
                was_kev = bool(rec.get("kev"))
                if rec.get("status") == "resolved":
                    rec["status"] = "open"
                    rec["first_seen"] = self._iso(now)  # reopened -> SLA clock restarts
                    rec.pop("resolved_at", None)
                    if not accepted:
                        delta.reopened.append(rec)
                elif not accepted:
                    delta.carried.append(rec)
                if kev and not was_kev and not accepted:
                    delta.newly_weaponized.append(rec)
                rec["last_seen"] = self._iso(now)
                rec["severity"] = str(_g(f, "severity", ""))
                rec["name"] = str(_g(f, "name", "")) or rec.get("name", "")
                # KEV is STICKY: a scan with missing enrichment must not clear a
                # known KEV flag (or weaponization would re-fire forever).
                rec["kev"] = was_kev or kev
                rec["tier"] = tier

            if accepted:
                delta.accepted.append({"rec": rec, "exception": exc})
                delta.open_accepted += 1
                continue  # accepted risk: excluded from active count + SLA
            delta.open_active += 1
            window = TIER_SLA_DAYS.get(rec.get("tier", ""))
            if window is not None:
                first = _parse_date(rec.get("first_seen"))
                if first is not None and (now - first) >= timedelta(days=window):
                    delta.sla_breaches.append({"rec": rec, "age_days": (now - first).days, "window": window})

        # ---- resolved: previously-open, absent now ----
        for fp, rec in stored.items():
            if rec.get("status") == "open" and fp not in current:
                rec["status"] = "resolved"
                rec["resolved_at"] = self._iso(now)
                delta.resolved.append(rec)

        # prune long-resolved records so the per-device map does not grow forever
        # (a reopen after this horizon is simply reported as new, which is fine).
        self._prune_resolved(stored, now)

        delta.sla_breaches.sort(key=lambda b: -b["age_days"])

        # ---- trend snapshot ----
        counts: Dict[str, int] = {}
        for f in findings:
            sev = str(_g(f, "severity", "INFO")).upper()
            counts[sev] = counts.get(sev, 0) + 1
        dev["history"].append({
            "date": self._iso(now), "risk_score": risk_score,
            "open": len(current), "new": len(delta.new), "resolved": len(delta.resolved),
            "counts": counts,
        })
        # bound history growth (keep the last 200 snapshots per device)
        if len(dev["history"]) > 200:
            dev["history"] = dev["history"][-200:]
        return delta

    RESOLVED_RETENTION_DAYS = 180

    def _prune_resolved(self, stored: Dict[str, dict], now: datetime) -> None:
        cutoff = now - timedelta(days=self.RESOLVED_RETENTION_DAYS)
        for fp in [k for k, r in stored.items()
                   if r.get("status") == "resolved"
                   and (_parse_date(r.get("resolved_at")) or now) < cutoff]:
            del stored[fp]

    def trend(self, host: str, n: int = 12) -> List[Dict[str, Any]]:
        dev = self.data["devices"].get(host, {})
        return list(dev.get("history", []))[-n:]

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
