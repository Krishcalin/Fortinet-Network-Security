"""
Remediation Knowledge Base
==========================
Detailed, per-rule remediation guidance for the Fortinet FortiGate scanner.

The KB is an external overlay keyed by ``rule_id`` (with family-prefix fallback,
mirroring ``COMPLIANCE_MAP`` resolution) that supplies the rich fix content the
bare ``Finding`` cannot hold: a business/technical **risk** narrative, numbered
**steps**, the FortiGate **gui** path, the canonical **cli** block, a **verify**
command, a **rollback** plan, a service-disruption **impact** note, and
**references**. Both the HTML and PDF reports call :meth:`RemediationKB.detail_for`
and render its result identically; when a rule has no KB entry the loader falls
back to the finding's own ``recommendation`` / ``remediation_cmd`` / ``cwe`` /
``cve`` so a report section is never empty.

Standard library only — safe for the offline / air-gapped scanner.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

_KB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "remediation_kb.json")

# Canonical field set for a KB entry.
_FIELDS = ("risk", "steps", "gui", "cli", "verify", "rollback", "impact", "references")


def _blank() -> Dict[str, Any]:
    return {"risk": "", "steps": [], "gui": "", "cli": "", "verify": "",
            "rollback": "", "impact": "", "references": []}


class RemediationKB:
    """Loads ``remediation_kb.json`` and resolves detailed remediation per finding."""

    def __init__(self, path: Optional[str] = None):
        self._kb: Dict[str, Dict[str, Any]] = {}
        self._load(path or _KB_PATH)

    def _load(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, ValueError, OSError):
            self._kb = {}
            return
        if isinstance(data, dict):
            # Accept either a bare {rule_id: {...}} map or {"knowledge_base": {...}}.
            self._kb = data.get("knowledge_base", data) if "knowledge_base" in data else data
        else:
            self._kb = {}

    @property
    def size(self) -> int:
        return len(self._kb)

    def lookup(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Exact match, then progressively shorter family-prefix match.

        ``FORTIOS-ADMIN-002`` -> ``FORTIOS-ADMIN`` -> ``FORTIOS``;
        ``MITRE-T1190-001`` -> ``MITRE-T1190`` -> ``MITRE``.
        """
        if not rule_id:
            return None
        if rule_id in self._kb:
            return self._kb[rule_id]
        parts = rule_id.split("-")
        while len(parts) > 1:
            parts = parts[:-1]
            key = "-".join(parts)
            if key in self._kb:
                return self._kb[key]
        return None

    def detail_for(self, finding: Any) -> Dict[str, Any]:
        """Return the structured remediation dict for a Finding.

        Always returns a fully-populated dict; missing KB fields are filled from
        the finding's own attributes so no report section is ever empty. Adds a
        boolean ``_detailed`` flag (True when a real KB entry matched).
        """
        rid = getattr(finding, "rule_id", "") or ""
        entry = self.lookup(rid)
        out = _blank()
        if entry:
            for k in _FIELDS:
                val = entry.get(k)
                if val:
                    out[k] = val

        # ---- graceful fallbacks from the finding itself ----
        if not out["risk"]:
            out["risk"] = getattr(finding, "description", "") or ""
        if not out["steps"]:
            rec = getattr(finding, "recommendation", "") or ""
            out["steps"] = [rec] if rec else []
        if not out["cli"]:
            out["cli"] = getattr(finding, "remediation_cmd", "") or ""
        if not out["references"]:
            refs: List[str] = []
            cwe = getattr(finding, "cwe", None)
            cve = getattr(finding, "cve", None)
            if cwe:
                refs.append(str(cwe))
            if cve:
                refs.append(str(cve))
            out["references"] = refs

        out["_detailed"] = entry is not None
        return out
