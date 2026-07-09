"""
Fortinet FortiGate — CVE Reachability Assessment
================================================
The CVE check (``_check_cves``) fires on firmware version math alone: if the box
runs an affected FortiOS train it reports the CVE, regardless of whether the
*vulnerable feature is even turned on*. That is correct for "am I running
vulnerable code", but it over-states urgency — five SSL-VPN RCEs should not all
sit at "Fix Now" on a device where SSL-VPN is disabled.

This module answers, from the parsed configuration only (stdlib, offline-safe),
a narrower question per CVE: *is the vulnerable component actually enabled, and
is it reachable from the internet on THIS device?* The verdict feeds the
Risk-Prioritization Engine, which **downranks** (never suppresses) findings whose
vulnerable feature is disabled or not internet-facing, and keeps the CISA-KEV
floor so a known-exploited bug is never buried.

Design principles (deliberately conservative — a wrong "disabled" verdict could
hide a real RCE, so the engine only ever downranks and the KEV floor still holds):
  * Only emit a decisive verdict when the config signal is unambiguous.
  * Anything uncertain -> INDETERMINATE (no change to the finding's priority).
  * Cross-product CVEs (FortiManager / FortiClient EMS) are always INDETERMINATE:
    a FortiGate .conf cannot prove another product's reachability.
  * Every decisive verdict carries a cited config-evidence string.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

# Verdicts (plain strings so risk_prioritizer can consume them without importing).
CONFIRMED_REACHABLE = "CONFIRMED_REACHABLE"      # feature enabled AND internet/mgmt reachable
CONFIGURED_NOT_EXPOSED = "CONFIGURED_NOT_EXPOSED"  # feature enabled but not internet-facing
FEATURE_DISABLED = "FEATURE_DISABLED"            # vulnerable feature not enabled on this device
INDETERMINATE = "INDETERMINATE"                  # cannot tell from config -> do not change priority


# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #

def _as_list(v: Any) -> List[dict]:
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    if isinstance(v, dict):
        return [v]
    return []


def _first_dict(v: Any) -> dict:
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return v[0]
    return v if isinstance(v, dict) else {}


def _access_tokens(iface: dict) -> set:
    aa = iface.get("allowaccess", "")
    if isinstance(aa, (list, tuple, set)):
        toks = [str(a) for a in aa]
    else:
        toks = str(aa).split()
    return {t.strip().lower() for t in toks if str(t).strip()}


def _names(v: Any) -> set:
    out = set()
    for x in (v if isinstance(v, list) else [v]):
        if isinstance(x, dict) and x.get("name"):
            out.add(x["name"])
        elif isinstance(x, str) and x:
            # The live API returns multi-value reference fields as a list of dicts,
            # but the offline parser space-joins them into one string ("wan1 wan2")
            # for fields outside REF_LIST_FIELDS — split so both shapes yield the
            # same set (interface/object names never contain spaces).
            out.update(t for t in x.split() if t)
    return out


# --------------------------------------------------------------------------- #
#  config view — one read of the endpoints the predicates need                 #
# --------------------------------------------------------------------------- #

def build_view(scanner: Any) -> Dict[str, Any]:
    """Read the handful of config sections the reachability predicates need,
    via the scanner's own ``_api_get`` (live HTTP or offline .conf — identical
    shape). Returns a plain dict so the predicates stay pure and testable."""
    def get(path, monitor=False):
        try:
            return scanner._api_get(path, monitor=monitor)
        except Exception:
            return None

    try:
        wan = set(scanner._wan_interfaces())
    except Exception:
        wan = set()
    fw_version = tuple(getattr(scanner, "_fw_version", ()) or ())

    ifaces = _as_list(get("system/interface"))
    # Any interface explicitly tagged role=wan is WAN even if _wan_interfaces()
    # (name/mode heuristics) missed it.
    for i in ifaces:
        if str(i.get("role", "")).lower() == "wan":
            nm = i.get("name", "")
            if nm:
                wan.add(nm)
    # Broaden further: the interface that owns the default route is internet-facing
    # even when its role is unset and it has a static IP — a common manual-setup
    # config _wan_interfaces() alone misses. Without this, an SSL-VPN/admin/IPsec
    # CVE on a genuinely internet-facing box would be mislabelled "not exposed".
    for r in _as_list(get("router/static")):
        dst = str(r.get("dst", "")).strip()
        gw = str(r.get("gateway", "")).strip()
        default_dst = dst in ("", "0.0.0.0/0", "0.0.0.0 0.0.0.0", "0.0.0.0/0.0.0.0")
        if default_dst and gw and gw not in ("0.0.0.0", "::"):
            wan |= _names(r.get("device") or r.get("interface"))
    # Whether we could positively identify ANY WAN interface. If not, the
    # internet-facing predicates must return INDETERMINATE rather than a decisive
    # "not exposed" (per this module's "uncertain -> INDETERMINATE" invariant).
    wan_known = bool(wan)

    iface_access = {i.get("name", ""): _access_tokens(i) for i in ifaces}
    wan_access: set = set()
    for i in ifaces:
        if i.get("name", "") in wan:
            wan_access |= _access_tokens(i)
    all_access: set = set()
    for toks in iface_access.values():
        all_access |= toks

    ssl = _first_dict(get("vpn.ssl/settings"))
    ssl_status = str(ssl.get("status", "")).lower() if ssl else ""
    ssl_srcintf = _names(ssl.get("source-interface")) if ssl else set()

    phase1 = _as_list(get("vpn.ipsec/phase1-interface"))
    ipsec_wan = any((_names(p.get("interface")) & wan) for p in phase1)

    cm = _first_dict(get("system/central-management"))
    cm_type = str(cm.get("type", cm.get("mode", ""))).lower() if cm else ""
    fmg_set = bool(cm.get("fmg")) if cm else False

    policies = _as_list(get("firewall/policy"))
    def _pol_has(key):
        for p in policies:
            v = p.get(key)
            if v and str(p.get("status", "enable")).lower() != "disable":
                return True
        return False
    def _pol_wan(key):
        """True if an enabled policy carrying ``key`` touches a WAN interface —
        i.e. the feature actually inspects internet-ingress/egress traffic."""
        for p in policies:
            v = p.get(key)
            if v and str(p.get("status", "enable")).lower() != "disable":
                if (_names(p.get("srcintf")) | _names(p.get("dstintf"))) & wan:
                    return True
        return False
    proxy_policies = any(str(p.get("inspection-mode", "")).lower() == "proxy" for p in policies)
    webproxy = _first_dict(get("web-proxy/explicit"))
    # Proxy inspection can be set VDOM-wide (config system settings / set
    # inspection-mode proxy) rather than per-policy; backups omit the per-policy
    # line when it inherits that default, so read the VDOM toggle too.
    sys_settings = _first_dict(get("system/settings"))
    vdom_proxy = str(sys_settings.get("inspection-mode", "")).lower() == "proxy"
    proxy_on = (proxy_policies or vdom_proxy
                or str(webproxy.get("status", "")).lower() in ("enable", "enabled"))

    caps_portal = any("captive-portal" in str(i.get("security-mode", "")).lower()
                      or str(i.get("security-mode", "")).lower() == "captive-portal"
                      for i in ifaces)

    ha = _first_dict(get("system/ha"))
    ha_mode = str(ha.get("mode", "")).lower() if ha else ""

    return {
        "fw_version": fw_version,
        "wan": wan,
        "wan_known": wan_known,
        "wan_access": wan_access,
        "all_access": all_access,
        "sslvpn_status": ssl_status,
        "sslvpn_present": bool(ssl),
        "sslvpn_srcintf": ssl_srcintf,
        "ipsec_count": len(phase1),
        "ipsec_wan": ipsec_wan,
        "fmg": fmg_set or "fortimanager" in cm_type,
        # Count actually-managed APs (wireless-controller/wtp — empty on wired-only
        # devices) + user-created VAPs, NOT the always-present default wtp-profiles,
        # so CAPWAP CVEs correctly reach FEATURE_DISABLED on non-wireless boxes.
        "wtp": len(_as_list(get("wireless-controller/wtp"))) + len(_as_list(get("wireless-controller/vap"))),
        "radius": len(_as_list(get("user/radius"))),
        "tacacs": len(_as_list(get("user/tacacs+"))),
        "ldap": len(_as_list(get("user/ldap"))),
        "fsso": len(_as_list(get("user/fsso"))),
        "ips_policies": _pol_has("ips-sensor"),
        "ips_policies_wan": _pol_wan("ips-sensor"),
        "dnsfilter_policies": _pol_has("dnsfilter-profile"),
        "proxy_on": proxy_on,
        "captive_portal": caps_portal,
        "ha_mode": ha_mode,
    }


# --------------------------------------------------------------------------- #
#  per-component predicates                                                    #
# --------------------------------------------------------------------------- #

def _mgmt_on_wan(v) -> bool:
    return bool(v["wan_access"] & {"http", "https"})


def _not_exposed(v, msg):
    """Emit CONFIGURED_NOT_EXPOSED only when we could positively identify a WAN
    interface; otherwise return INDETERMINATE. A blank WAN set means WAN could not
    be determined — claiming "not exposed" there would hide a real internet-facing
    RCE, violating this module's conservative "uncertain -> INDETERMINATE" rule."""
    if not v.get("wan_known", True):
        return INDETERMINATE, "WAN interface could not be determined from config — exposure unknown"
    return CONFIGURED_NOT_EXPOSED, msg


def _sslvpn_reach(v, note=""):
    """CONFIRMED vs CONFIGURED by whether the SSL-VPN source-interface is WAN."""
    src = v["sslvpn_srcintf"]
    if not src or ("any" in src) or (src & v["wan"]):
        return CONFIRMED_REACHABLE, ("SSL-VPN enabled with source-interface "
                                     + (", ".join(sorted(src)) or "unset") + " (internet-facing)" + note)
    return _not_exposed(v, ("SSL-VPN enabled but source-interface "
                            + ", ".join(sorted(src)) + " is not a WAN interface" + note))


def _sslvpn(v):
    if not v["sslvpn_present"]:
        return INDETERMINATE, "no vpn.ssl settings section in config"
    status = v["sslvpn_status"]
    # The `set status enable|disable` toggle only exists from FortiOS 7.4.1; on
    # earlier trains there is NO status field and SSL-VPN is in use whenever the
    # settings block is configured. So an ABSENT status must NOT be read as
    # disabled on <7.4.1 (that would falsely downrank the flagship SSL-VPN CVEs).
    has_toggle = tuple(v.get("fw_version") or ()) >= (7, 4, 1)
    if status in ("disable", "disabled"):
        return FEATURE_DISABLED, "vpn.ssl settings status=disable (SSL-VPN not enabled)"
    if status in ("enable", "enabled"):
        return _sslvpn_reach(v)
    # status field absent:
    if has_toggle:
        # 7.4.1+ default is disable; an enabled box carries an explicit
        # 'set status enable', so no status line means disabled-by-default.
        return FEATURE_DISABLED, ("vpn.ssl settings present but no 'set status enable' "
                                  "(FortiOS >=7.4.1 defaults SSL-VPN to disabled)")
    return _sslvpn_reach(v, note=" — FortiOS <7.4.1 (SSL-VPN enabled when configured)")


def _admin_gui(v):
    if _mgmt_on_wan(v):
        return CONFIRMED_REACHABLE, ("HTTP/HTTPS admin access allowed on a WAN interface (allowaccess="
                                     + ", ".join(sorted(v["wan_access"] & {"http", "https"})) + ")")
    return _not_exposed(v, "GUI/HTTPS management not permitted on any WAN interface (allowaccess)")


def _admin_ssh(v):
    if "ssh" in v["wan_access"]:
        return CONFIRMED_REACHABLE, "SSH admin access allowed on a WAN interface (allowaccess includes ssh)"
    return _not_exposed(v, "SSH management not permitted on any WAN interface")


def _admin_auth(v):
    # Post-authentication admin/CLI bugs: only internet-relevant if the admin
    # surface is reachable from the WAN; otherwise an attacker needs local/VPN access.
    if _mgmt_on_wan(v) or "ssh" in v["wan_access"]:
        return CONFIRMED_REACHABLE, "management plane (HTTPS/SSH) is reachable from a WAN interface"
    return _not_exposed(v, "requires authenticated admin access; management not exposed on any WAN interface")


def _rest_api(v):
    if "https" in v["wan_access"]:
        return CONFIRMED_REACHABLE, "REST API rides HTTPS, which is allowed on a WAN interface"
    return _not_exposed(v, "HTTPS (REST API transport) not permitted on any WAN interface")


def _fgfm(v):
    if "fgfm" in v["wan_access"]:
        return CONFIRMED_REACHABLE, "FGFM (FortiManager protocol) allowed on a WAN interface"
    if v["fmg"] or "fgfm" in v["all_access"]:
        return CONFIGURED_NOT_EXPOSED, "FGFM/central-management configured but not exposed on a WAN interface"
    return FEATURE_DISABLED, "no FGFM allowaccess and no FortiManager central-management configured"


def _ipsec(v):
    if v["ipsec_count"] == 0:
        return FEATURE_DISABLED, "no IPsec phase1-interface tunnels configured"
    if v["ipsec_wan"]:
        return CONFIRMED_REACHABLE, f"{v['ipsec_count']} IPsec tunnel(s), at least one bound to a WAN interface"
    return _not_exposed(v, f"{v['ipsec_count']} IPsec tunnel(s) configured (none clearly WAN-bound)")


def _capwap(v):
    if "capwap" in v["wan_access"]:
        return CONFIRMED_REACHABLE, "CAPWAP allowed on a WAN interface"
    if v["wtp"] > 0:
        return CONFIGURED_NOT_EXPOSED, f"{v['wtp']} managed-AP/VAP object(s) present (CAPWAP internal, not WAN)"
    return FEATURE_DISABLED, "no managed APs/VAPs and CAPWAP not on any WAN interface"


def _ips(v):
    if v.get("ips_policies_wan"):
        return CONFIRMED_REACHABLE, "IPS sensor on a policy touching a WAN interface (internet-ingress traffic inspected)"
    if v["ips_policies"]:
        # IPS attached, but only to non-WAN policies — the engine still parses that
        # traffic, yet it is not internet-ingress, so it is not confirmed-reachable.
        return _not_exposed(v, "IPS sensor attached only to non-WAN policies")
    return CONFIGURED_NOT_EXPOSED, "no IPS sensor attached to any policy"


def _proxy(v):
    if v["proxy_on"]:
        return CONFIGURED_NOT_EXPOSED, "proxy-mode policy or explicit web-proxy configured"
    return FEATURE_DISABLED, "no proxy-mode policies and explicit web-proxy not enabled"


def _radius(v):
    if v["radius"] > 0:
        return CONFIGURED_NOT_EXPOSED, f"{v['radius']} RADIUS server(s) configured"
    return FEATURE_DISABLED, "no RADIUS servers configured (user/radius empty)"


def _tacacs(v):
    if v["tacacs"] > 0:
        return CONFIGURED_NOT_EXPOSED, f"{v['tacacs']} TACACS+ server(s) configured"
    return FEATURE_DISABLED, "no TACACS+ servers configured (user/tacacs+ empty)"


def _ldap(v):
    if v["ldap"] > 0:
        return CONFIGURED_NOT_EXPOSED, f"{v['ldap']} LDAP server(s) configured"
    return FEATURE_DISABLED, "no LDAP servers configured (user/ldap empty)"


def _fsso(v):
    if v["fsso"] > 0:
        return CONFIGURED_NOT_EXPOSED, f"{v['fsso']} FSSO agent(s) configured"
    return FEATURE_DISABLED, "no FSSO agents configured (user/fsso empty)"


def _ha(v):
    if v["ha_mode"] in ("a-p", "a-a", "active-passive", "active-active"):
        return CONFIGURED_NOT_EXPOSED, f"HA mode={v['ha_mode']} (heartbeat is internal, not internet-facing)"
    return FEATURE_DISABLED, "HA not configured (standalone)"


def _dnsfilter(v):
    if v["dnsfilter_policies"]:
        return CONFIGURED_NOT_EXPOSED, "DNS filter profile attached to a policy"
    return FEATURE_DISABLED, "no DNS filter profile attached to any policy"


def _captive_portal(v):
    if v["captive_portal"]:
        return CONFIGURED_NOT_EXPOSED, "an interface has captive-portal security-mode"
    return FEATURE_DISABLED, "no interface uses captive-portal authentication"


# Ecosystem / undetectable components -> always INDETERMINATE (constant predicate).
def _indeterminate(reason):
    def _p(v):
        return INDETERMINATE, reason
    return _p


PREDICATES: Dict[str, Callable[[dict], Tuple[str, str]]] = {
    "sslvpn": _sslvpn,
    "admin-gui": _admin_gui,
    "admin-ssh": _admin_ssh,
    "admin-auth": _admin_auth,
    "rest-api": _rest_api,
    "fgfm": _fgfm,
    "ipsec": _ipsec,
    "capwap": _capwap,
    "ips": _ips,
    "proxy": _proxy,
    "radius": _radius,
    "tacacs": _tacacs,
    "ldap": _ldap,
    "fsso": _fsso,
    "ha": _ha,
    "dnsfilter": _dnsfilter,
    "captive-portal": _captive_portal,
    "ecosystem": _indeterminate("cross-product CVE (FortiManager/FortiClient) — a FortiGate .conf cannot prove its reachability"),
    "forticloud-sso": _indeterminate("FortiCloud SSO reachability is not determinable from the device config"),
    "bluetooth": _indeterminate("Bluetooth/BLE presence is a hardware trait not reliably shown in config"),
}


def assess(component: Optional[str], view: dict) -> Tuple[str, str]:
    """Return (verdict, evidence) for a component against a prebuilt config view.
    Unknown/None components -> INDETERMINATE (no priority change)."""
    pred = PREDICATES.get(component or "")
    if pred is None:
        return INDETERMINATE, ""
    try:
        return pred(view)
    except Exception:
        return INDETERMINATE, ""


def assess_cves(scanner: Any, cve_components: Dict[str, str],
                cve_id_to_cve: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Build the config view once and assess every tracked CVE.

    ``cve_components`` maps rule_id (FORTIOS-CVE-NNN) -> component.
    ``cve_id_to_cve`` maps rule_id -> CVE id (the key the prioritizer looks up).
    Returns {CVE-id: {verdict, evidence, component}}."""
    view = build_view(scanner)
    out: Dict[str, Dict[str, str]] = {}
    for rule_id, component in cve_components.items():
        cve = cve_id_to_cve.get(rule_id)
        if not cve:
            continue
        verdict, evidence = assess(component, view)
        out[cve] = {"verdict": verdict, "evidence": evidence, "component": component}
    return out
