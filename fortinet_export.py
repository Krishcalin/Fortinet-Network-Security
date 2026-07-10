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


def _compliance_flat(f: Any) -> str:
    return ", ".join(_compliance_reqs(f)) or "-"


# ============================================================================ #
#  SOAR / ticketing exports — Jira, ServiceNow, Splunk SOAR, generic webhook   #
# ============================================================================ #
# Turn the prioritized findings into ready-to-POST payloads for external work-
# management systems, so the scanner's system-of-record becomes ACTION, not just
# a report. Every item carries a stable dedup key (device host + the posture
# fingerprint, hashed) so a re-scan UPDATES the same ticket instead of
# duplicating it; when a posture delta is supplied, resolved findings emit close
# events so stale tickets do not leak. Pure stdlib / JSON-serialisable dicts —
# preserves the offline, zero-dependency guarantee. Each builder returns a
# uniform envelope: {target, meta, items:[{op, dedup_key, body}]}, where `body`
# is the pristine native payload and `op` (create/update/reopen/resolve/upsert)
# tells the downstream poster which HTTP verb to use.

_TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SLA_HUMAN = {"P1": "24-72h", "P2": "7d", "P3": "30d", "P4": None}
# severity -> fallback tier when no prioritizer ran
_TIER_BY_SEV = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P4"}
# tier / severity -> Jira priority (name, id) on the default 5-level scheme
_JIRA_PRI_BY_TIER = {"P1": ("Highest", "1"), "P2": ("High", "2"),
                     "P3": ("Medium", "3"), "P4": ("Low", "4")}
_JIRA_PRI_BY_SEV = {"CRITICAL": ("Highest", "1"), "HIGH": ("High", "2"),
                    "MEDIUM": ("Medium", "3"), "LOW": ("Low", "4"), "INFO": ("Lowest", "5")}
# tier / severity -> ServiceNow (urgency, impact); 1=High 2=Medium 3=Low.
# NEVER set priority directly — the OOB data lookup derives it from urgency x impact.
_SN_UI_BY_TIER = {"P1": ("1", "1"), "P2": ("2", "1"), "P3": ("2", "2"), "P4": ("3", "3")}
_SN_UI_BY_SEV = {"CRITICAL": ("1", "1"), "HIGH": ("1", "2"), "MEDIUM": ("2", "2"),
                 "LOW": ("3", "2"), "INFO": ("3", "3")}
# tier / severity -> Splunk SOAR severity (only high/medium/low ship; case-sensitive)
_SOAR_SEV_BY_TIER = {"P1": "high", "P2": "high", "P3": "medium", "P4": "low"}
_SOAR_SEV_BY_SEV = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium",
                    "LOW": "low", "INFO": "low"}

_SCANNER_NAME = "FortiGate Security Scanner"
_VENDOR = "Krishcalin"


def _fp_string(rule_id: Any, entity: Any) -> str:
    """Reconstruct posture.finding_fingerprint's plain string form exactly:
    ``rule_id|entity`` when an entity exists, else ``rule_id``."""
    rule_id = str(rule_id or "")
    entity = str(entity or "")
    return f"{rule_id}|{entity}" if entity else rule_id


def _dedup_key(host: str, finding: Any) -> str:
    """Canonical cross-system idempotency key: ``sha1('host|rule_id[|entity]')[:16]``.
    Stable across scans and unique per (device, finding). Deliberately excludes
    volatile evidence (line_content) so a cosmetic value change is the SAME
    ticket, not resolve+recreate. Includes host so two devices' identical
    findings do not collapse into one ticket, and hashes so the value is
    label-safe (Jira rejects labels with spaces)."""
    try:
        from posture import finding_fingerprint
        fp = finding_fingerprint(finding)
    except Exception:  # pragma: no cover - posture is a core sibling
        fp = str(_g(finding, "rule_id", ""))
    return hashlib.sha1(f"{host}|{fp}".encode("utf-8")).hexdigest()[:16]


def _dedup_key_from_rec(host: str, rec: Dict[str, Any]) -> str:
    """Same key for a slim posture rec (resolved/carried), reconstructing the
    fingerprint identically so a closure matches its open ticket's key."""
    fp = _fp_string(rec.get("rule_id", ""), rec.get("entity", ""))
    return hashlib.sha1(f"{host}|{fp}".encode("utf-8")).hexdigest()[:16]


def _entity_of(finding: Any) -> str:
    try:
        from posture import finding_entity
        return finding_entity(str(_g(finding, "rule_id", "")),
                              str(_g(finding, "line_content", "")))
    except Exception:  # pragma: no cover
        return ""


def _tier_of(prio: Dict[str, Any], finding: Any) -> str:
    """Fused urgency tier: the prioritizer's tier if it ran, else derived from
    intrinsic severity so tier-based mapping/filtering still works offline."""
    if prio and prio.get("tier"):
        return str(prio["tier"])
    return _TIER_BY_SEV.get(str(_g(finding, "severity", "")).upper(), "P4")


def _tier_of_rec(rec: Dict[str, Any]) -> str:
    """Tier for a slim posture rec (resolved closure), MIRRORING _tier_of's
    severity fallback: a rec whose stored tier is empty (tracked while the
    prioritizer was unavailable) still resolves to the SAME severity-derived
    tier its ticket was created under — otherwise a stricter --soar-min-tier
    would gate the create in but the close out, leaking the ticket forever."""
    return rec.get("tier") or _TIER_BY_SEV.get(str(rec.get("severity", "")).upper(), "P4")


def _tier_ok(tier: Any, min_tier: str) -> bool:
    return _TIER_RANK.get(str(tier), 3) <= _TIER_RANK.get(str(min_tier).upper(), 3)


def _lifecycle(delta: Any, host: str):
    """(op_by_key, resolved) from a posture delta. ``op_by_key`` maps a dedup key
    to create/reopen/update for LIVE findings; ``resolved`` is [(key, rec), ...]
    for findings absent this scan (they must emit closures or stale tickets leak).
    ``host`` MUST be the same one used for live findings so the keys align."""
    if delta is None:
        return {}, []
    op: Dict[str, str] = {}
    for r in getattr(delta, "new", []) or []:
        op[_dedup_key_from_rec(host, r)] = "create"
    for r in getattr(delta, "reopened", []) or []:
        op[_dedup_key_from_rec(host, r)] = "reopen"
    for r in getattr(delta, "carried", []) or []:
        op[_dedup_key_from_rec(host, r)] = "update"
    resolved = [(_dedup_key_from_rec(host, r), r) for r in (getattr(delta, "resolved", []) or [])]
    return op, resolved


def _kb_detail(kb: Any, finding: Any) -> Dict[str, Any]:
    """Structured remediation for a finding. Prefer the RemediationKB (rich,
    with its own graceful fallback); if no KB was supplied (or it errored),
    synthesize the SAME finding-derived fallback here so a ticket's remediation
    is never empty."""
    if kb is not None:
        try:
            return kb.detail_for(finding)
        except Exception:  # pragma: no cover - defensive
            pass
    rec = str(_g(finding, "recommendation", "") or "")
    refs = [str(r) for r in (_g(finding, "cwe"), _g(finding, "cve")) if r]
    return {"risk": str(_g(finding, "description", "") or ""),
            "steps": [rec] if rec else [], "gui": "",
            "cli": str(_g(finding, "remediation_cmd", "") or ""),
            "verify": "", "rollback": "", "impact": "", "references": refs,
            "_detailed": False}


def _plan(findings: List[Any], host: str, prio_by_id, delta, min_tier: str):
    """Shared work planner. Returns (live, resolved):
      live:     [(finding, op, key, prio_dict)] for findings at/above min_tier
      resolved: [(rec, key)] closures for resolved findings at/above min_tier
    A live finding's op is its posture lifecycle (create/update/reopen) or
    'upsert' when no posture delta was supplied."""
    prio_by_id = prio_by_id or {}
    op_by_key, resolved_pairs = _lifecycle(delta, host)
    live = []
    for f in findings:
        prio = prio_by_id.get(id(f), {})
        if not _tier_ok(_tier_of(prio, f), min_tier):
            continue
        key = _dedup_key(host, f)
        live.append((f, op_by_key.get(key, "upsert"), key, prio))
    resolved = [(rec, key) for (key, rec) in resolved_pairs
                if _tier_ok(_tier_of_rec(rec), min_tier)]
    return live, resolved


def _envelope(target: str, host: str, scan_epoch: int, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "target": target,
        "meta": {"host": host, "scanner": _SCANNER_NAME, "vendor": _VENDOR,
                 "scan_epoch": int(scan_epoch or 0), "count": len(items)},
        "items": items,
    }


def _finding_summary(finding: Any, prio: Dict[str, Any]) -> Dict[str, Any]:
    """Raw finding + priority overlay, for traceability in a target's free-form
    data slot (Splunk container.data / artifact.data)."""
    return {
        "rule_id": _g(finding, "rule_id"), "name": _g(finding, "name"),
        "severity": _g(finding, "severity"), "category": _g(finding, "category"),
        "cve": _g(finding, "cve") or None, "cwe": _g(finding, "cwe") or None,
        "evidence": _g(finding, "line_content"),
        "compliance": _g(finding, "compliance") or {},
        "priority": {k: prio.get(k) for k in
                     ("tier", "priority_score", "kev", "epss", "internet_reachable")} if prio else {},
    }


# ---- remediation-KB flattening (plain text / ADF / structured) --------------

def _kb_lines(detail: Dict[str, Any]):
    out = []
    if detail.get("risk"):
        out.append(("Risk", str(detail["risk"])))
    steps = [s for s in (detail.get("steps") or []) if str(s).strip()]
    if steps:
        out.append(("Remediation steps", "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))))
    if detail.get("gui"):
        out.append(("GUI path", str(detail["gui"])))
    if detail.get("cli"):
        out.append(("CLI", str(detail["cli"])))
    if detail.get("verify"):
        out.append(("Verify", str(detail["verify"])))
    if detail.get("rollback"):
        out.append(("Rollback", str(detail["rollback"])))
    if detail.get("impact"):
        out.append(("Service impact", str(detail["impact"])))
    refs = [r for r in (detail.get("references") or []) if str(r).strip()]
    if refs:
        out.append(("References", "\n".join(f"- {r}" for r in refs)))
    return out


def _kb_text(detail: Dict[str, Any], limit: Optional[int] = None) -> str:
    text = "\n\n".join(f"{label}:\n{body}" for label, body in _kb_lines(detail))
    if limit and len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def _webhook_remediation(detail: Dict[str, Any]) -> Dict[str, Any]:
    if not detail:
        return {}
    return {
        "summary": detail.get("risk", ""),
        "steps": detail.get("steps", []),
        "gui": detail.get("gui", ""),
        "cli": detail.get("cli", ""),
        "verify": detail.get("verify", ""),
        "rollback": detail.get("rollback", ""),
        "service_impact": detail.get("impact", ""),
        "references": detail.get("references", []),
    }


# ---- Atlassian Document Format (ADF) helpers (Jira v3) -----------------------
# Every inline leaf MUST carry {"type":"text"}; an orderedList/bulletList must
# have at least one listItem (callers guard on non-empty lists).

def _adf_text(s: Any) -> Dict[str, Any]:
    return {"type": "text", "text": str(s)}


def _adf_para(s: Any) -> Dict[str, Any]:
    return {"type": "paragraph", "content": [_adf_text(s)]}


def _adf_heading(s: Any, level: int = 3) -> Dict[str, Any]:
    return {"type": "heading", "attrs": {"level": level}, "content": [_adf_text(s)]}


def _adf_code(s: Any, language: str = "shell") -> Dict[str, Any]:
    return {"type": "codeBlock", "attrs": {"language": language}, "content": [_adf_text(s)]}


def _adf_list(items: List[Any], ordered: bool = True) -> Dict[str, Any]:
    node = "orderedList" if ordered else "bulletList"
    return {"type": node, "content": [
        {"type": "listItem", "content": [_adf_para(it)]}
        for it in items if str(it).strip()
    ]}


def _adf_from_kb(detail: Dict[str, Any], header: str) -> Dict[str, Any]:
    content: List[Dict[str, Any]] = [_adf_para(header)]
    if detail.get("risk"):
        content += [_adf_heading("Risk"), _adf_para(detail["risk"])]
    steps = [s for s in (detail.get("steps") or []) if str(s).strip()]
    if steps:
        content += [_adf_heading("Remediation steps"), _adf_list(steps, ordered=True)]
    if detail.get("gui"):
        content += [_adf_heading("GUI path"), _adf_para(detail["gui"])]
    if detail.get("cli"):
        content += [_adf_heading("CLI"), _adf_code(detail["cli"])]
    if detail.get("verify"):
        content += [_adf_heading("Verify"), _adf_code(detail["verify"])]
    if detail.get("rollback"):
        content += [_adf_heading("Rollback"), _adf_code(detail["rollback"])]
    if detail.get("impact"):
        content += [_adf_heading("Service impact"), _adf_para(detail["impact"])]
    refs = [r for r in (detail.get("references") or []) if str(r).strip()]
    if refs:
        content += [_adf_heading("References"), _adf_list(refs, ordered=False)]
    return {"type": "doc", "version": 1, "content": content}


def _jira_labels(base_labels, severity: str, tier: str, key: str) -> List[str]:
    labels = list(base_labels)
    sev = str(severity or "").lower()
    if sev:
        labels.append(f"sev-{sev}")
    if tier:
        labels.append(f"tier-{str(tier).lower()}")
    labels.append(f"fw-fp-{key}")
    # Jira rejects labels with whitespace — collapse any into underscores.
    return ["_".join(str(l).split()) for l in labels]


# ---- the four builders ------------------------------------------------------

def build_jira(findings: List[Any], *, host: str, prio_by_id=None, kb=None, delta=None,
               min_tier: str = "P4", project_key: str = "SEC", issuetype: str = "Bug",
               api_version: int = 3, base_labels=("fortigate", "firewall-hardening"),
               set_priority: bool = True, scan_epoch: int = 0) -> Dict[str, Any]:
    """Jira create/update issue payloads (v3 ADF description by default; pass
    ``api_version=2`` for a plain-string description). Idempotency: the exporter
    embeds a stable ``fw-fp-<key>`` label + an ``fwFinding`` entity property; the
    downstream poster searches by that label (POST /rest/api/3/search/jql) and
    POSTs (create) or PUTs (update) accordingly."""
    live, resolved = _plan(findings, host, prio_by_id, delta, min_tier)
    v = 2 if str(api_version) == "2" else 3
    items: List[Dict[str, Any]] = []
    for f, op, key, prio in live:
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        name = str(_g(f, "name", "") or rid)
        tier = _tier_of(prio, f)
        detail = _kb_detail(kb, f)
        header = f"Finding {rid} on {host} — severity {sev}, priority tier {tier}."
        fields: Dict[str, Any] = {
            "project": {"key": project_key},
            "issuetype": {"name": issuetype},
            "summary": f"[FortiGate {host}] {name} ({rid})"[:255],
            "labels": _jira_labels(base_labels, sev, tier, key),
        }
        if set_priority:
            pname, pid = (_JIRA_PRI_BY_TIER.get(tier) if prio.get("tier")
                          else None) or _JIRA_PRI_BY_SEV.get(sev, ("Medium", "3"))
            fields["priority"] = {"name": pname, "id": pid}
        if v == 3:
            fields["description"] = _adf_from_kb(detail, header)
        else:
            fields["description"] = (header + "\n\n" + _kb_text(detail)).strip()
        prop = {
            "fingerprint": key, "host": host, "ruleId": rid, "entity": _entity_of(f),
            "severity": sev, "tier": tier, "cve": _g(f, "cve") or None,
            "cwe": _g(f, "cwe") or None, "kev": bool(prio.get("kev", False)),
            "epss": prio.get("epss"), "scanner": _SCANNER_NAME,
        }
        items.append({"op": op, "dedup_key": key,
                      "body": {"fields": fields,
                               "properties": [{"key": "fwFinding", "value": prop}]}})
    for rec, key in resolved:
        items.append({"op": "resolve", "dedup_key": key, "body": {
            "jql": f'project = {project_key} AND labels = "fw-fp-{key}"',
            "transition_hint": "Done",
            "comment": "No longer detected by the FortiGate scanner as of this scan.",
        }})
    return _envelope("jira", host, scan_epoch, items)


def build_servicenow(findings: List[Any], *, host: str, prio_by_id=None, kb=None, delta=None,
                     min_tier: str = "P4", category: str = "security", subcategory=None,
                     assignment_group_sysid=None, caller_sysid=None, cmdb_ci_sysid=None,
                     contact_type: str = "integration", scan_epoch: int = 0) -> Dict[str, Any]:
    """ServiceNow Incident (Table API) records. Sets urgency+impact (never
    priority — the OOB data lookup derives it) and a stable ``correlation_id``
    (fwscan:<key>) so a re-import coalesces onto the same incident (query-then-
    PATCH, or Import Set with coalesce=correlation_id)."""
    live, resolved = _plan(findings, host, prio_by_id, delta, min_tier)
    items: List[Dict[str, Any]] = []
    for f, op, key, prio in live:
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        name = str(_g(f, "name", "") or rid)
        tier = _tier_of(prio, f)
        urgency, impact = (_SN_UI_BY_TIER.get(tier) if prio.get("tier")
                           else None) or _SN_UI_BY_SEV.get(sev, ("2", "2"))
        detail = _kb_detail(kb, f)
        header = (f"Device: {host}\nRule: {rid}\nSeverity: {sev}   Priority tier: {tier}\n"
                  f"Category: {_g(f, 'category', '')}\nEvidence: {_g(f, 'line_content', '')}\n"
                  f"CVE: {_g(f, 'cve') or '-'}   CWE: {_g(f, 'cwe') or '-'}\n"
                  f"Compliance: {_compliance_flat(f)}")
        rec_body = {
            "short_description": f"{name} on {host} ({rid})"[:160],
            "description": (header + "\n\n" + _kb_text(detail))[:4000],
            "category": category,
            "urgency": urgency, "impact": impact,
            "contact_type": contact_type,
            "correlation_id": f"fwscan:{key}",
            "correlation_display": _SCANNER_NAME,
        }
        if subcategory:
            rec_body["subcategory"] = subcategory
        if assignment_group_sysid:
            rec_body["assignment_group"] = assignment_group_sysid
        if caller_sysid:
            rec_body["caller_id"] = caller_sysid
        if cmdb_ci_sysid:
            rec_body["cmdb_ci"] = cmdb_ci_sysid
        items.append({"op": op, "dedup_key": key, "body": rec_body})
    for rec, key in resolved:
        items.append({"op": "resolve", "dedup_key": key, "body": {
            "correlation_id": f"fwscan:{key}", "state": "6",
            "close_code": "Resolved by caller",
            "close_notes": "Finding no longer detected by the FortiGate scanner as of this scan.",
            "work_notes": "Auto-resolved by FortiGate Security Scanner.",
        }})
    return _envelope("servicenow", host, scan_epoch, items)


def build_splunk_soar(findings: List[Any], *, host: str, prio_by_id=None, kb=None, delta=None,
                      min_tier: str = "P4", label: str = "events", artifact_label: str = "event",
                      sensitivity: str = "amber", asset_id=None, scan_epoch: int = 0) -> Dict[str, Any]:
    """Splunk SOAR container+embedded-artifact payloads (one container per
    finding). Sets an explicit ``source_data_identifier`` on the container
    (fwscan:<key>) and each artifact (fwscan:<key>:<n>) so a re-ingest dedups;
    severity is lowercase high/medium/low (the only shipped names)."""
    live, resolved = _plan(findings, host, prio_by_id, delta, min_tier)
    items: List[Dict[str, Any]] = []
    for f, op, key, prio in live:
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        name = str(_g(f, "name", "") or rid)
        tier = _tier_of(prio, f)
        soar_sev = (_SOAR_SEV_BY_TIER.get(tier) if prio.get("tier")
                    else None) or _SOAR_SEV_BY_SEV.get(sev, "medium")
        detail = _kb_detail(kb, f)
        sdi = f"fwscan:{key}"
        cef = {
            "deviceHostName": host,
            "cs1Label": "ruleId", "cs1": rid,
            "cs2Label": "intrinsicSeverity", "cs2": sev,
            "cs3Label": "priorityTier", "cs3": tier,
            "msg": (str(_g(f, "description", "")) or name)[:1000],
        }
        if _g(f, "cve"):
            cef["cs4Label"] = "cve"
            cef["cs4"] = _g(f, "cve")
        if prio.get("priority_score") is not None:
            cef["cn1Label"] = "priorityScore"
            cef["cn1"] = prio.get("priority_score")
        container = {
            "name": f"Firewall finding: {name} ({host})"[:250],
            "label": label,
            "description": str(_g(f, "description", "")) or name,
            "severity": soar_sev,
            "sensitivity": sensitivity,
            "status": "new",
            "source_data_identifier": sdi,
            "tags": ["fortigate", rid, f"sev-{sev.lower()}", f"tier-{tier.lower()}"],
            "data": {"scanner_finding": _finding_summary(f, prio)},
            "artifacts": [{
                "name": name[:250],
                "label": artifact_label,
                "severity": soar_sev,
                "source_data_identifier": f"{sdi}:1",
                "cef": cef,
                "cef_types": {"deviceHostName": ["host name"]},
                "data": {"remediation": detail},
            }],
        }
        if asset_id is not None:
            container["asset_id"] = asset_id
        items.append({"op": op, "dedup_key": key, "body": container})
    for rec, key in resolved:
        items.append({"op": "resolve", "dedup_key": key, "body": {
            "source_data_identifier": f"fwscan:{key}", "status": "closed"}})
    return _envelope("splunk_soar", host, scan_epoch, items)


def build_webhook(findings: List[Any], *, host: str, prio_by_id=None, kb=None, delta=None,
                  min_tier: str = "P4", source_prefix: str = "/fortinet-scanner",
                  scan_epoch: int = 0, now_iso: str = "", tool_version: str = "",
                  dataschema: str = "https://github.com/Krishcalin/Fortinet-Network-Security/schemas/finding/1.0"
                  ) -> Dict[str, Any]:
    """Vendor-neutral CloudEvents 1.0 + OCSF/ECS-lite finding events. The record
    identity is ``data.dedup_key`` (NOT the per-emission CloudEvents ``id``);
    ``data.event`` carries the lifecycle (new/existing/reopened/resolved)."""
    live, resolved = _plan(findings, host, prio_by_id, delta, min_tier)
    _EVENT = {"create": "new", "update": "existing", "reopen": "reopened",
              "resolve": "resolved", "upsert": "new"}
    items: List[Dict[str, Any]] = []

    def _ce(key: str, event: str, data: Dict[str, Any]) -> Dict[str, Any]:
        ce = {
            "specversion": "1.0",
            "id": f"{key}-{int(scan_epoch or 0)}",
            "source": f"{source_prefix}/{host}",
            "type": f"com.krishcalin.fortinet.finding.{event}",
            "subject": key,
            "datacontenttype": "application/json",
            "dataschema": dataschema,
            "data": data,
        }
        if now_iso:
            ce["time"] = now_iso
        return ce

    for f, op, key, prio in live:
        event = _EVENT.get(op, "new")
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        tier = _tier_of(prio, f)
        detail = _kb_detail(kb, f)
        loc = f"{_g(f, 'file_path', '')}:{_g(f, 'line_num') or ''}".rstrip(":")
        data = {
            "dedup_key": key, "event": event, "rule_id": rid,
            "title": str(_g(f, "name", "") or rid), "severity": sev,
            "priority": {"tier": tier, "score": prio.get("priority_score"),
                         "label": prio.get("tier_label"), "sla": _SLA_HUMAN.get(tier)},
            "threat": {"kev": bool(prio.get("kev", False)), "kev_date": prio.get("kev_date"),
                       "epss": prio.get("epss"), "epss_percentile": prio.get("epss_pct"),
                       "ransomware": bool(prio.get("ransomware", False)),
                       "internet_reachable": bool(prio.get("internet_reachable", False))},
            "vulnerability": {"cve": _g(f, "cve") or None, "cwe": _g(f, "cwe") or None},
            "compliance": _g(f, "compliance") or {},
            "evidence": {"asset": host, "category": _g(f, "category"),
                         "location": loc, "snippet": _g(f, "line_content")},
            "remediation": _webhook_remediation(detail),
            "status": "open",
            "source_tool": {"name": _SCANNER_NAME, "vendor": _VENDOR, "version": str(tool_version or "")},
        }
        items.append({"op": op, "dedup_key": key, "body": _ce(key, event, data)})
    for rec, key in resolved:
        data = {
            "dedup_key": key, "event": "resolved", "rule_id": rec.get("rule_id"),
            "title": rec.get("name"), "severity": str(rec.get("severity", "")).upper(),
            "priority": {"tier": rec.get("tier"), "score": None, "label": None,
                         "sla": _SLA_HUMAN.get(rec.get("tier"))},
            "status": "resolved", "resolved_at": rec.get("resolved_at"),
            "source_tool": {"name": _SCANNER_NAME, "vendor": _VENDOR, "version": str(tool_version or "")},
        }
        items.append({"op": "resolve", "dedup_key": key, "body": _ce(key, "resolved", data)})
    return _envelope("webhook", host, scan_epoch, items)
