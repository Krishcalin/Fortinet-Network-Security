"""
Fortinet FortiGate Scanner — machine-ingestible export formats
==============================================================
Turns scanner Findings into two standard, tool-agnostic formats so the audit
plugs straight into CI/security pipelines:

* **SARIF 2.1.0** (``build_sarif``) — the Static Analysis Results Interchange
  Format. Drops findings into GitHub Advanced Security code-scanning (per-rule,
  dedup, PR annotations) or any SARIF viewer. A firewall config is a code
  artifact, so this is a natural fit.
* **OCSF** (``build_ocsf``) — Open Cybersecurity Schema Framework Compliance
  Finding (class_uid 2003) events for SIEM ingestion (Splunk, Sentinel, Amazon
  Security Lake, Elastic).

Pure standard library (json-serialisable dicts only) so it preserves the
offline / air-gapped scanner's zero-dependency guarantee. The functions take
plain data (findings + an optional per-finding prioritisation map) and return
dicts/lists; the ``_ReportMixin`` wires them to files.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

# severity -> SARIF result level
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "INFO": "note"}
# severity -> GitHub code-scanning "security-severity" (numeric, drives sorting)
_SECSEV = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 1.0}
# severity -> OCSF severity_id (1 Informational .. 5 Critical)
_OCSF_SEV = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

_INFO_URI = "https://github.com/Krishcalin/Fortinet-Network-Security"


def _g(obj: Any, key: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _tags(f: Any) -> List[str]:
    tags = ["security", "fortigate"]
    cat = str(_g(f, "category", "")).strip()
    if cat:
        tags.append(cat.lower().replace(" ", "-"))
    if _g(f, "cve"):
        tags.append("cve")
    return tags


def _help_uri(f: Any) -> Optional[str]:
    cve = _g(f, "cve")
    if cve:
        return f"https://nvd.nist.gov/vuln/detail/{cve}"
    cwe = str(_g(f, "cwe", "") or "")
    if cwe.upper().startswith("CWE-") and cwe[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"
    return None


def _fingerprint(*parts: str) -> str:
    return hashlib.sha1("|".join(p or "" for p in parts).encode("utf-8")).hexdigest()[:16]


def build_sarif(findings: List[Any], *, tool_version: str = "",
                artifact_uri: str = "fortigate-config",
                prio_by_id: Optional[Dict[int, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Return a SARIF 2.1.0 log for ``findings``.

    ``prio_by_id`` (optional) maps ``id(finding)`` -> a prioritisation dict
    (PriorityResult.to_dict()) so each result carries its P-tier / KEV / EPSS.
    """
    prio_by_id = prio_by_id or {}
    rules: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for f in findings:
        rid = str(_g(f, "rule_id", "") or "")
        if not rid or rid in rules:
            continue
        order.append(rid)
        sev = str(_g(f, "severity", "") or "").upper()
        rule = {
            "id": rid,
            "name": (str(_g(f, "name", "") or rid))[:120],
            "shortDescription": {"text": (str(_g(f, "name", "") or rid))[:1000]},
            "fullDescription": {"text": (str(_g(f, "description", "") or ""))[:3000]},
            "defaultConfiguration": {"level": _LEVEL.get(sev, "warning")},
            "properties": {
                "security-severity": str(_SECSEV.get(sev, 5.0)),
                "tags": _tags(f),
            },
        }
        help_uri = _help_uri(f)
        if help_uri:
            rule["helpUri"] = help_uri
        rec = str(_g(f, "recommendation", "") or "")
        if rec:
            rule["help"] = {"text": rec[:2000]}
        rules[rid] = rule

    results: List[Dict[str, Any]] = []
    for f in findings:
        rid = str(_g(f, "rule_id", "") or "")
        sev = str(_g(f, "severity", "") or "").upper()
        pr = prio_by_id.get(id(f), {})
        props: Dict[str, Any] = {}
        if pr.get("tier"):
            props["priority_tier"] = pr["tier"]
        if pr.get("priority_score") is not None:
            props["priority_score"] = pr["priority_score"]
        if pr.get("kev"):
            props["kev"] = True
        if pr.get("epss") is not None:
            props["epss"] = pr["epss"]
        for k in ("cve", "cwe"):
            if _g(f, k):
                props[k] = _g(f, k)
        comp = _g(f, "compliance") or {}
        if comp:
            props["compliance"] = comp

        phys: Dict[str, Any] = {"artifactLocation": {"uri": artifact_uri}}
        ln = _g(f, "line_num")
        if isinstance(ln, int) and ln > 0:
            phys["region"] = {"startLine": ln}

        res = {
            "ruleId": rid,
            "level": _LEVEL.get(sev, "warning"),
            "message": {"text": str(_g(f, "description", "") or _g(f, "name", "") or rid)},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {
                "fortigateFindingHash": _fingerprint(rid, str(_g(f, "file_path", "")),
                                                      str(_g(f, "line_content", "")))
            },
        }
        if props:
            res["properties"] = props
        results.append(res)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "FortiGate Security Scanner",
                "informationUri": _INFO_URI,
                "version": str(tool_version or "0"),
                "rules": [rules[r] for r in order],
            }},
            "results": results,
        }],
    }


def build_ocsf(findings: List[Any], *, meta: Optional[Dict[str, Any]] = None,
               prio_by_id: Optional[Dict[int, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Return a list of OCSF Compliance Finding (class_uid 2003) events.

    ``meta`` may carry ``hostname``, ``version`` and ``epoch`` (ms). ``prio_by_id``
    maps ``id(finding)`` -> a prioritisation dict for KEV/EPSS/tier enrichment.
    """
    meta = meta or {}
    prio_by_id = prio_by_id or {}
    epoch = int(meta.get("epoch") or 0)
    host = meta.get("hostname") or ""
    events: List[Dict[str, Any]] = []
    for f in findings:
        sev = str(_g(f, "severity", "") or "").upper()
        pr = prio_by_id.get(id(f), {})
        events.append({
            "class_uid": 2003, "class_name": "Compliance Finding",
            "category_uid": 2, "category_name": "Findings",
            "type_uid": 200301, "type_name": "Compliance Finding: Create",
            "activity_id": 1, "activity_name": "Create",
            "severity_id": _OCSF_SEV.get(sev, 1),
            "severity": (sev.title() if sev else "Informational"),
            "status": "New",
            "time": epoch,
            "message": str(_g(f, "name", "") or _g(f, "rule_id", "")),
            "metadata": {
                "product": {"name": "FortiGate Security Scanner",
                            "vendor_name": "Krishcalin",
                            "version": str(meta.get("version", ""))},
                "version": "1.3.0",
            },
            "finding_info": {
                "uid": _g(f, "rule_id"),
                "title": _g(f, "name"),
                "desc": _g(f, "description"),
            },
            "compliance": {"requirements": _compliance_reqs(f)},
            "remediation": {"desc": _g(f, "recommendation")},
            "resources": [{"name": host or _g(f, "file_path"), "type": "Firewall"}],
            "unmapped": {
                "category": _g(f, "category"),
                "cve": _g(f, "cve") or None,
                "cwe": _g(f, "cwe") or None,
                "compliance": _g(f, "compliance") or {},
                "priority_tier": pr.get("tier"),
                "priority_score": pr.get("priority_score"),
                "kev": bool(pr.get("kev", False)),
                "epss": pr.get("epss"),
                "remediation_cmd": _g(f, "remediation_cmd") or None,
            },
        })
    return events


def _compliance_reqs(f: Any) -> List[str]:
    comp = _g(f, "compliance") or {}
    reqs: List[str] = []
    if isinstance(comp, dict):
        for framework, controls in comp.items():
            for c in (controls or []):
                reqs.append(f"{framework}:{c}")
    return reqs
