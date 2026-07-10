"""
Fortinet FortiGate — Traffic-Aware Policy Engine
================================================
Answers the question a firewall audit / incident-responder actually asks —
"is 203.0.113.5 -> 10.0.0.10:3389 permitted, and by which rule?" — by resolving
address objects/groups to real IP intervals and services to (protocol, port)
sets (stdlib ``ipaddress`` only) and walking the enabled policies in first-match
order. It also upgrades shadow/redundancy detection from name-matching to true
CIDR/port-interval overlap, and simulates a proposed policy's impact before it
is deployed.

**Accuracy is the whole point, so this engine fails to OPAQUE, never to a
guess.** A confidently-wrong "permitted" verdict is worse than "I can't tell":
so any factor that a static config cannot reliably resolve — a VIP/DNAT on the
path, an FQDN / Internet-Service / geography / dynamic / wildcard address object,
an unknown service, IPv6, or a schedule restriction — yields an **OPAQUE**
verdict (or excludes the object from overlap analysis) with the exact reason,
rather than a definitive allow/deny. Interface scope is only evaluated when the
caller supplies the ingress/egress interfaces (``--via``); otherwise the verdict
is returned with an explicit "interface not verified" caveat.

Standard library only, so it runs in the offline/air-gapped scanner too.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

# ── verdicts ──
ALLOW = "ALLOW"
DENY = "DENY"
OPAQUE = "OPAQUE"

FULL_START, FULL_END = 0, (1 << 32) - 1


def _g(o: Any, key: str, default: Any = "") -> Any:
    if isinstance(o, dict):
        return o.get(key, default)
    return getattr(o, key, default)


def _names(v: Any) -> List[str]:
    out = []
    for x in (v if isinstance(v, list) else [v]):
        if isinstance(x, dict) and x.get("name"):
            out.append(str(x["name"]))
        elif isinstance(x, str) and x:
            out.append(x)
    return out


# --------------------------------------------------------------------------- #
#  IPv4 interval set                                                          #
# --------------------------------------------------------------------------- #

def ip4_to_int(s: str) -> Optional[int]:
    try:
        a = ipaddress.ip_address(str(s).strip())
    except (ValueError, TypeError):
        return None
    return int(a) if a.version == 4 else None


class IPSet:
    """A set of IPv4 addresses as a sorted, merged list of inclusive [lo, hi]
    integer intervals."""

    __slots__ = ("intervals",)

    def __init__(self, intervals: Optional[List[Tuple[int, int]]] = None):
        self.intervals = _merge(intervals or [])

    @classmethod
    def full(cls) -> "IPSet":
        return cls([(FULL_START, FULL_END)])

    @classmethod
    def from_cidr(cls, cidr: str) -> Optional["IPSet"]:
        try:
            net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        except (ValueError, TypeError):
            return None
        if net.version != 4:
            return None
        return cls([(int(net.network_address), int(net.broadcast_address))])

    @classmethod
    def from_subnet_field(cls, subnet: str) -> Optional["IPSet"]:
        """Parse a FortiOS 'subnet' field: '10.0.0.0 255.255.255.0' or '10.0.0.0/24'."""
        s = str(subnet).strip()
        if not s:
            return None
        if "/" in s:
            return cls.from_cidr(s)
        parts = s.split()
        if len(parts) == 2:
            ip, mask = parts
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except (ValueError, TypeError):
                return None
            if net.version != 4:
                return None
            return cls([(int(net.network_address), int(net.broadcast_address))])
        return cls.from_cidr(s)

    @classmethod
    def from_range(cls, start: str, end: str) -> Optional["IPSet"]:
        lo, hi = ip4_to_int(start), ip4_to_int(end)
        if lo is None or hi is None or hi < lo:
            return None
        return cls([(lo, hi)])

    def is_empty(self) -> bool:
        return not self.intervals

    def contains_ip(self, n: int) -> bool:
        return any(lo <= n <= hi for lo, hi in self.intervals)

    def union(self, other: "IPSet") -> "IPSet":
        return IPSet(self.intervals + other.intervals)

    def overlaps(self, other: "IPSet") -> bool:
        for lo, hi in self.intervals:
            for olo, ohi in other.intervals:
                if lo <= ohi and olo <= hi:
                    return True
        return False

    def covers(self, other: "IPSet") -> bool:
        """True iff every address in ``other`` is in ``self``."""
        for olo, ohi in other.intervals:
            pos = olo
            covered = False
            for lo, hi in self.intervals:      # intervals are sorted+merged
                if lo <= pos <= hi:
                    if hi >= ohi:
                        covered = True
                        break
                    pos = hi + 1
            if not covered and pos <= ohi:
                return False
        return True


def _merge(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    ivs = sorted((lo, hi) for lo, hi in intervals if lo <= hi)
    if not ivs:
        return []
    out = [ivs[0]]
    for lo, hi in ivs[1:]:
        plo, phi = out[-1]
        if lo <= phi + 1:
            out[-1] = (plo, max(phi, hi))
        else:
            out.append((lo, hi))
    return out


# --------------------------------------------------------------------------- #
#  service / port set                                                          #
# --------------------------------------------------------------------------- #

# A small bundled table of common FortiOS predefined services (dst ports).
# Unknown predefined names resolve to OPAQUE rather than being guessed.
PREDEFINED_SERVICES: Dict[str, List[Tuple[str, int, int]]] = {
    "ALL": [("*", 0, 65535)],
    "ALL_TCP": [("tcp", 1, 65535)], "ALL_UDP": [("udp", 1, 65535)],
    "ALL_ICMP": [("icmp", 0, 0)], "ALL_ICMP6": [("icmp6", 0, 0)],
    "PING": [("icmp", 0, 0)], "PING6": [("icmp6", 0, 0)], "TRACEROUTE": [("udp", 33434, 33535)],
    "HTTP": [("tcp", 80, 80)], "HTTPS": [("tcp", 443, 443)], "HTTP8080": [("tcp", 8080, 8080)],
    "SSH": [("tcp", 22, 22)], "TELNET": [("tcp", 23, 23)], "FTP": [("tcp", 21, 21)],
    "FTP_GET": [("tcp", 21, 21)], "FTP_PUT": [("tcp", 21, 21)], "TFTP": [("udp", 69, 69)],
    "DNS": [("tcp", 53, 53), ("udp", 53, 53)], "SMTP": [("tcp", 25, 25)], "SMTPS": [("tcp", 465, 465)],
    "POP3": [("tcp", 110, 110)], "POP3S": [("tcp", 995, 995)], "IMAP": [("tcp", 143, 143)],
    "IMAPS": [("tcp", 993, 993)], "NTP": [("udp", 123, 123)], "SNMP": [("udp", 161, 162)],
    "RDP": [("tcp", 3389, 3389)], "VNC": [("tcp", 5900, 5900)], "SMB": [("tcp", 445, 445)],
    "SAMBA": [("tcp", 139, 139)], "LDAP": [("tcp", 389, 389)], "LDAPS": [("tcp", 636, 636)],
    "KERBEROS": [("tcp", 88, 88), ("udp", 88, 88)], "MS-SQL": [("tcp", 1433, 1433)],
    "MYSQL": [("tcp", 3306, 3306)], "POSTGRES": [("tcp", 5432, 5432)], "ORACLE": [("tcp", 1521, 1521)],
    "RADIUS": [("udp", 1812, 1813)], "SYSLOG": [("udp", 514, 514)], "DHCP": [("udp", 67, 68)],
    "IKE": [("udp", 500, 500), ("udp", 4500, 4500)], "L2TP": [("udp", 1701, 1701)],
    "PPTP": [("tcp", 1723, 1723)], "WINS": [("tcp", 1512, 1512), ("udp", 1512, 1512)],
    "HTTPS-8443": [("tcp", 8443, 8443)], "SIP": [("udp", 5060, 5060), ("tcp", 5060, 5060)],
    "MGMT": [("tcp", 443, 443)], "WEBPROXY": [("tcp", 8080, 8080)],
    "NONE": [],
}


class PortSet:
    """A protocol/destination-port matcher. ``entries`` is a set of
    (proto, lo, hi); proto '*' means every protocol/port."""

    __slots__ = ("entries",)

    def __init__(self, entries: Optional[List[Tuple[str, int, int]]] = None):
        self.entries = set(entries or [])

    @classmethod
    def all(cls) -> "PortSet":
        return cls([("*", 0, 65535)])

    def is_empty(self) -> bool:
        return not self.entries

    def _all(self) -> bool:
        return ("*", 0, 65535) in self.entries

    def union(self, other: "PortSet") -> "PortSet":
        return PortSet(list(self.entries | other.entries))

    def matches(self, proto: str, port: int) -> bool:
        proto = (proto or "").lower()
        for p, lo, hi in self.entries:
            if p == "*":
                return True
            if p != proto:
                continue
            if p in ("icmp", "icmp6", "ip"):
                return True
            if lo <= port <= hi:
                return True
        return False

    def covers(self, other: "PortSet") -> bool:
        """True iff every (proto,port) matched by ``other`` is matched by self."""
        if self._all():
            return True
        if other._all():
            return False
        for p, lo, hi in other.entries:
            if p == "*":
                return False
            if p in ("icmp", "icmp6", "ip"):
                if not any(sp in (p, "*") for sp, _, _ in self.entries):
                    return False
                continue
            pos = lo
            ok = False
            for sp, slo, shi in sorted(e for e in self.entries if e[0] in (p, "*")):
                if slo <= pos <= shi:
                    if shi >= hi:
                        ok = True
                        break
                    pos = shi + 1
            if not ok:
                return False
        return True

    def overlaps(self, other: "PortSet") -> bool:
        if self._all() or other._all():
            return True
        for p, lo, hi in self.entries:
            for op, olo, ohi in other.entries:
                if p != op:
                    continue
                if p in ("icmp", "icmp6", "ip") or (lo <= ohi and olo <= hi):
                    return True
        return False


def _parse_portrange(proto: str, spec: str) -> List[Tuple[str, int, int]]:
    """FortiOS portrange: 'dst' or 'dst-lo-dst-hi' optionally ':src...'. We key on
    the DESTINATION port (before the ':')."""
    out = []
    for tok in str(spec).split():
        dst = tok.split(":", 1)[0]
        if "-" in dst:
            a, _, b = dst.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
        else:
            try:
                lo = hi = int(dst)
            except ValueError:
                continue
        out.append((proto, min(lo, hi), max(lo, hi)))
    return out


# --------------------------------------------------------------------------- #
#  object resolution (address / service) with OPAQUE tracking                  #
# --------------------------------------------------------------------------- #

_YES, _NO, _MAYBE = "YES", "NO", "MAYBE"

_OPAQUE_ADDR_TYPES = {
    "fqdn": "FQDN object", "geography": "geography object", "dynamic": "dynamic/SDN object",
    "wildcard": "wildcard (non-contiguous) object", "wildcard-fqdn": "wildcard-FQDN object",
    "interface-subnet": "interface-subnet object", "mac": "MAC address object",
    "device": "device object", "internet-service": "Internet-Service object",
}


class Addr:
    __slots__ = ("ipset", "opaque", "reason", "vip", "vip_info", "negated")

    def __init__(self, ipset, opaque=False, reason="", vip=False, vip_info=None, negated=False):
        self.ipset = ipset if ipset is not None else IPSet([])
        self.opaque = opaque
        self.reason = reason
        self.vip = vip
        self.vip_info = vip_info
        # A negated match (srcaddr-negate/dstaddr-negate) INVERTS membership: the
        # literal members are the addresses the rule EXCLUDES. We keep opaque=True
        # and this flag so the matcher never treats an in-set IP as a definite hit.
        self.negated = negated


class Svc:
    __slots__ = ("portset", "opaque", "reason", "negated")

    def __init__(self, portset, opaque=False, reason="", negated=False):
        self.portset = portset if portset is not None else PortSet([])
        self.opaque = opaque
        self.reason = reason
        self.negated = negated


def _extip_range(ext: str) -> Tuple[str, str]:
    ext = str(ext).strip()
    if "-" in ext:
        a, _, b = ext.partition("-")
        return a.strip(), b.strip()
    return ext, ext


class Resolver:
    def __init__(self, addr_objs, addr_grps, svc_custom, svc_grps, vips):
        self.addr = {a["name"]: a for a in addr_objs if isinstance(a, dict) and a.get("name")}
        self.addrgrp = {g["name"]: g for g in addr_grps if isinstance(g, dict) and g.get("name")}
        self.svc = {s["name"]: s for s in svc_custom if isinstance(s, dict) and s.get("name")}
        self.svcgrp = {g["name"]: g for g in svc_grps if isinstance(g, dict) and g.get("name")}
        self.vips = {v["name"]: v for v in vips if isinstance(v, dict) and v.get("name")}
        self.vip_extips: List[Tuple[IPSet, dict]] = []
        for v in self.vips.values():
            s = self._vip_extip_set(v)
            if s is not None:
                self.vip_extips.append((s, v))

    def _vip_extip_set(self, v: dict) -> Optional[IPSet]:
        ext = str(v.get("extip", "")).strip()
        if "-" in ext:
            return IPSet.from_range(*_extip_range(ext))
        s = IPSet.from_cidr(ext)
        if s:
            return s
        iv = ip4_to_int(ext)
        return IPSet([(iv, iv)]) if iv is not None else None

    def vip_for_dst(self, dst_int: int) -> Optional[dict]:
        for s, v in self.vip_extips:
            if s.contains_ip(dst_int):
                return v
        return None

    # ---- address ----
    def resolve_addr(self, name: str, _seen=None) -> Addr:
        _seen = _seen or set()
        if name in _seen:
            return Addr(IPSet([]), True, f"circular group reference '{name}'")
        if name in ("all", "All", "ALL"):
            return Addr(IPSet.full())
        if name in ("none", "None", "NONE"):
            return Addr(IPSet([]))
        if name in self.vips:
            v = self.vips[name]
            s = self._vip_extip_set(v)
            return Addr(s or IPSet([]), opaque=(s is None),
                        reason="VIP with unparsable extip", vip=True, vip_info=v)
        if name in self.addr:
            return self._resolve_addr_obj(self.addr[name])
        if name in self.addrgrp:
            _seen = _seen | {name}
            acc, opaque, vip, reasons, vinfo = IPSet([]), False, False, [], None
            for m in _names(self.addrgrp[name].get("member")):
                r = self.resolve_addr(m, _seen)
                acc = acc.union(r.ipset)
                if r.opaque:
                    opaque = True
                    reasons.append(r.reason or m)
                if r.vip:
                    vip = True
                    vinfo = r.vip_info
            return Addr(acc, opaque, "; ".join(sorted(set(reasons)))[:120], vip, vinfo)
        return Addr(IPSet([]), True, f"unknown address object '{name}'")

    def _resolve_addr_obj(self, obj: dict) -> Addr:
        t = str(obj.get("type", "ipmask")).lower()
        if t in _OPAQUE_ADDR_TYPES:
            return Addr(IPSet([]), True, _OPAQUE_ADDR_TYPES[t])
        if obj.get("subnet6") or obj.get("ip6") or obj.get("start-ip6"):
            return Addr(IPSet([]), True, "IPv6 object (not modelled)")
        if t == "iprange":
            s = IPSet.from_range(obj.get("start-ip", ""), obj.get("end-ip", ""))
            return Addr(s, s is None, "unparsable iprange" if s is None else "")
        s = IPSet.from_subnet_field(obj.get("subnet", ""))
        return Addr(s, s is None, "unparsable subnet" if s is None else "")

    def resolve_addr_list(self, refs, negate=False) -> Addr:
        acc, opaque, vip, reasons, vinfo = IPSet([]), False, False, [], None
        for n in _names(refs):
            r = self.resolve_addr(n)
            acc = acc.union(r.ipset)
            opaque = opaque or r.opaque
            if r.vip:
                vip = True
                vinfo = r.vip_info
            if r.opaque and r.reason:
                reasons.append(r.reason)
        if negate:
            opaque = True
            reasons.append("negated address match")
        return Addr(acc, opaque, "; ".join(sorted(set(reasons)))[:140], vip, vinfo, negated=negate)

    # ---- service ----
    def resolve_svc(self, name: str, _seen=None) -> Svc:
        _seen = _seen or set()
        if name in _seen:
            return Svc(PortSet([]), True, f"circular service group '{name}'")
        up = str(name).upper()
        if up in PREDEFINED_SERVICES:
            return Svc(PortSet(PREDEFINED_SERVICES[up]))
        if name in self.svc:
            return self._resolve_svc_obj(self.svc[name])
        if name in self.svcgrp:
            _seen = _seen | {name}
            acc, opaque, reasons = PortSet([]), False, []
            for m in _names(self.svcgrp[name].get("member")):
                r = self.resolve_svc(m, _seen)
                acc = acc.union(r.portset)
                if r.opaque:
                    opaque = True
                    reasons.append(r.reason or m)
            return Svc(acc, opaque, "; ".join(sorted(set(reasons)))[:120])
        return Svc(PortSet([]), True, f"unknown service '{name}' (custom/Internet-Service?)")

    def _resolve_svc_obj(self, obj: dict) -> Svc:
        # Port ranges are authoritative and present even when a 'show' omits the
        # default 'set protocol TCP/UDP/SCTP' line, so read them first.
        entries: List[Tuple[str, int, int]] = []
        for pr, key in (("tcp", "tcp-portrange"), ("udp", "udp-portrange"), ("sctp", "sctp-portrange")):
            spec = obj.get(key, "")
            if spec:
                entries += _parse_portrange(pr, spec)
        if entries:
            return Svc(PortSet(entries))
        proto = str(obj.get("protocol", "")).upper()
        if "ICMP6" in proto:
            return Svc(PortSet([("icmp6", 0, 0)]))
        if "ICMP" in proto:
            return Svc(PortSet([("icmp", 0, 0)]))
        if proto == "IP" or "PROTOCOL-NUMBER" in proto:
            return Svc(PortSet([("ip", 0, 0)]))
        if "TCP" in proto or "UDP" in proto or "SCTP" in proto:
            return Svc(PortSet([]), True, "TCP/UDP service with no port range")
        return Svc(PortSet([]), True, f"service protocol '{proto or '?'}' not modelled")

    def resolve_svc_list(self, refs, negate=False) -> Svc:
        acc, opaque, reasons = PortSet([]), False, []
        for n in _names(refs):
            r = self.resolve_svc(n)
            acc = acc.union(r.portset)
            opaque = opaque or r.opaque
            if r.opaque and r.reason:
                reasons.append(r.reason)
        if negate:
            opaque = True
            reasons.append("negated service match")
        return Svc(acc, opaque, "; ".join(sorted(set(reasons)))[:140], negated=negate)


# --------------------------------------------------------------------------- #
#  policy model — query, overlap, simulate                                    #
# --------------------------------------------------------------------------- #

class QueryResult:
    def __init__(self, verdict, policy=None, reason="", caveats=None):
        self.verdict = verdict          # ALLOW / DENY / OPAQUE
        self.policy = policy            # the deciding policy dict (or None)
        self.reason = reason
        self.caveats = caveats or []

    def to_dict(self):
        p = self.policy or {}
        return {"verdict": self.verdict,
                "policy_id": p.get("policyid"), "policy_name": p.get("name"),
                "action": p.get("action"), "reason": self.reason, "caveats": self.caveats}


class PolicyModel:
    def __init__(self, policies, resolver: Resolver, zones=None, known_ifaces=None):
        self.resolver = resolver
        # Preserve the CONFIG / API order — FortiOS evaluates in sequence order,
        # which is NOT policyid order (rules can be moved). Only drop disabled.
        self.policies = [p for p in policies if isinstance(p, dict)
                         and str(p.get("status", "enable")).lower() != "disable"]
        # zone name -> set of member interface names (lowercased); known physical
        # interface names, for zone-aware --via matching.
        self.zones = {str(k).lower(): {str(x).lower() for x in v} for k, v in (zones or {}).items()}
        self.known_ifaces = {str(n).lower() for n in (known_ifaces or set())}

    @classmethod
    def from_scanner(cls, scanner) -> "PolicyModel":
        def L(path):
            v = scanner._api_get(path)
            return v if isinstance(v, list) else []
        resolver = Resolver(L("firewall/address"), L("firewall/addrgrp"),
                            L("firewall.service/custom"), L("firewall.service/group"),
                            L("firewall/vip"))
        zones = {z.get("name"): _names(z.get("interface")) for z in L("system/zone")
                 if isinstance(z, dict) and z.get("name")}
        known = {i.get("name") for i in L("system/interface") if isinstance(i, dict) and i.get("name")}
        return cls(L("firewall/policy"), resolver, zones, known)

    # ---- zone-aware interface matching ----
    def _expand_ifaces(self, pol_ifaces):
        """Return (expanded_member_set, has_unclassifiable). A named interface that
        is neither a known physical interface nor a known zone can't be classified,
        so a mismatch against it must be OPAQUE, not a definite miss."""
        exp, unknown = set(), False
        for n in _names(pol_ifaces):
            nl = n.lower()
            if nl == "any":
                exp.add("any")
            elif nl in self.zones:
                exp |= self.zones[nl]
            elif nl in self.known_ifaces or not self.known_ifaces:
                exp.add(nl)
                if not self.known_ifaces:
                    unknown = True  # no interface data loaded -> can't be sure it isn't a zone
            else:
                exp.add(nl)
                unknown = True
        return exp, unknown

    def _iface_result(self, pol_ifaces, provided: str) -> str:
        exp, unknown = self._expand_ifaces(pol_ifaces)
        if "any" in exp or not exp:
            return _YES
        if provided.lower() in exp:
            return _YES
        return _MAYBE if unknown else _NO

    def _iface_covers_z(self, a_ifaces, b_ifaces) -> bool:
        a, _ = self._expand_ifaces(a_ifaces)
        if "any" in a or not a:
            return True
        b, _ = self._expand_ifaces(b_ifaces)
        if "any" in b or not b:
            return False
        return all(x in a for x in b)

    # ---- reachability query ----
    def query(self, src: str, dst: str, port: int, proto: str = "tcp",
              ingress: Optional[str] = None, egress: Optional[str] = None) -> QueryResult:
        proto = (proto or "tcp").lower()
        si, di = ip4_to_int(src), ip4_to_int(dst)
        if si is None or di is None:
            return QueryResult(OPAQUE, reason=f"non-IPv4 address in query ({src} -> {dst}); IPv6 not modelled")

        vip = self.resolver.vip_for_dst(di)
        if vip is not None:
            mapped = vip.get("mappedip")
            mapped = _names(mapped)[0] if isinstance(mapped, list) else vip.get("mappedip", "?")
            return QueryResult(OPAQUE, reason=(
                f"destination {dst} is the external IP of VIP '{vip.get('name')}' (DNAT to "
                f"{mapped}:{vip.get('mappedport', vip.get('extport', '?'))}); the translated flow is not "
                f"modelled — evaluate reachability to the mapped address/port instead"))

        for pol in self.policies:
            res, reason, caveats = self._match(pol, si, di, proto, port, ingress, egress)
            if res == _NO:
                continue
            if res == _MAYBE:
                return QueryResult(OPAQUE, pol, reason=(
                    f"policy {pol.get('policyid')} ('{pol.get('name')}') could match but contains "
                    f"unresolved factors: {reason}"), caveats=caveats)
            # definite match
            action = str(pol.get("action", "deny")).lower()
            verdict = ALLOW if action == "accept" else DENY
            return QueryResult(verdict, pol,
                               reason=f"first match: policy {pol.get('policyid')} ('{pol.get('name')}') action={action}",
                               caveats=caveats)
        return QueryResult(DENY, reason="no policy matches — implicit deny")

    def _match(self, pol, si, di, proto, port, ingress, egress):
        """Return (YES/NO/MAYBE, reason, caveats) for one policy against a flow."""
        caveats: List[str] = []
        maybe_reasons: List[str] = []
        # interface: only decisive when the caller supplies the path. Zone-aware;
        # an unclassifiable interface yields MAYBE, never a definite miss.
        if ingress is not None:
            r = self._iface_result(pol.get("srcintf"), ingress)
            if r == _NO:
                return _NO, "", caveats
            if r == _MAYBE:
                maybe_reasons.append(f"ingress {ingress} vs srcintf {_ifnames(pol.get('srcintf'))} (zone/interface unresolved)")
        elif not _iface_any(pol.get("srcintf")):
            caveats.append(f"ingress interface {_ifnames(pol.get('srcintf'))} not verified (pass --via)")
        if egress is not None:
            r = self._iface_result(pol.get("dstintf"), egress)
            if r == _NO:
                return _NO, "", caveats
            if r == _MAYBE:
                maybe_reasons.append(f"egress {egress} vs dstintf {_ifnames(pol.get('dstintf'))} (zone/interface unresolved)")
        elif not _iface_any(pol.get("dstintf")):
            caveats.append(f"egress interface {_ifnames(pol.get('dstintf'))} not verified (pass --via)")

        # Internet-Service (ISDB) matching replaces the srcaddr/dstaddr/service the
        # engine can see — the DB is not resolvable from a static config, so a
        # policy that uses it can never be definitively matched or excluded.
        if _isdb(pol):
            maybe_reasons.append("policy matches by Internet-Service (ISDB) database, not modelled from config")

        src = self.resolver.resolve_addr_list(pol.get("srcaddr"), _neg(pol, "srcaddr-negate"))
        dst = self.resolver.resolve_addr_list(pol.get("dstaddr"), _neg(pol, "dstaddr-negate"))
        svc = self.resolver.resolve_svc_list(pol.get("service"), _neg(pol, "service-negate"))

        sm = _addr_comp(src, si, maybe_reasons)
        if sm == _NO:
            return _NO, "", caveats
        dm = _addr_comp(dst, di, maybe_reasons)
        if dm == _NO:
            return _NO, "", caveats
        cm = _svc_comp(svc, proto, port, maybe_reasons)
        if cm == _NO:
            return _NO, "", caveats

        # schedule restriction makes the match time-dependent.
        sched = str(pol.get("schedule", "always")).lower()
        if sched and sched not in ("always", ""):
            maybe_reasons.append(f"time-restricted by schedule '{pol.get('schedule')}'")
        # a VIP referenced as a destination means DNAT on this path.
        if dst.vip:
            maybe_reasons.append(f"destination references VIP '{(dst.vip_info or {}).get('name','?')}' (DNAT)")

        if maybe_reasons:
            return _MAYBE, "; ".join(maybe_reasons), caveats
        return _YES, "", caveats

    # ---- CIDR-overlap shadow / redundancy ----
    def overlap_findings(self, cap: int = 250000):
        """True IP/port-interval shadow & redundancy — an earlier policy that
        fully COVERS a later one on interfaces + src + dst + service. Skips any
        policy with OPAQUE objects (never asserts coverage it cannot prove).
        Each result carries ``name_covered`` (the coarse name-based check would
        also flag this pair) so callers can avoid double-reporting. Returns
        (findings, truncated) so a silent cap is surfaced, not hidden."""
        norm = [n for n in (self._normalize(p) for p in self.policies) if n is not None]
        out: List[Dict[str, Any]] = []
        comparisons, truncated = 0, False
        for i, a in enumerate(norm):
            for b in norm[i + 1:]:
                comparisons += 1
                if comparisons > cap:
                    truncated = True
                    return out, truncated
                if (self._iface_covers_z(a["srcintf"], b["srcintf"])
                        and self._iface_covers_z(a["dstintf"], b["dstintf"])
                        and a["src"].covers(b["src"]) and a["dst"].covers(b["dst"])
                        and a["svc"].covers(b["svc"])):
                    same = a["action"] == b["action"]
                    out.append({
                        "kind": "redundant" if same else "shadowed",
                        "earlier": a["id"], "earlier_name": a["name"],
                        "later": b["id"], "later_name": b["name"],
                        "earlier_action": a["action"], "later_action": b["action"],
                        "name_covered": _name_covers(a, b),
                    })
        return out, truncated

    def _normalize(self, p) -> Optional[dict]:
        if _isdb(p):
            return None  # Internet-Service policy: coverage not resolvable
        src = self.resolver.resolve_addr_list(p.get("srcaddr"), _neg(p, "srcaddr-negate"))
        dst = self.resolver.resolve_addr_list(p.get("dstaddr"), _neg(p, "dstaddr-negate"))
        svc = self.resolver.resolve_svc_list(p.get("service"), _neg(p, "service-negate"))
        if src.opaque or dst.opaque or svc.opaque or src.vip or dst.vip:
            return None  # cannot assert coverage on opaque/VIP/negated objects
        return {"id": p.get("policyid"), "name": p.get("name"),
                "action": str(p.get("action", "deny")).lower(),
                "srcintf": _ifnames(p.get("srcintf")), "dstintf": _ifnames(p.get("dstintf")),
                "src": src.ipset, "dst": dst.ipset, "svc": svc.portset,
                # raw name-sets for the name-coverage (dedup) check
                "src_names": _names(p.get("srcaddr")), "dst_names": _names(p.get("dstaddr")),
                "svc_names": _names(p.get("service"))}

    # ---- pre-change simulation ----
    def simulate(self, proposed: dict) -> Dict[str, Any]:
        """Descriptive impact of inserting ``proposed`` (a policy dict). Reports
        shadow relationships and internet exposure — never asserts 'safe'."""
        # Insert the proposed policy by its policyid relative to existing rules
        # (existing order is preserved — see __init__).
        pid = _polid(proposed)
        merged = list(self.policies)
        insert_at = len(merged)
        for idx, p in enumerate(merged):
            if _polid(p) > pid:
                insert_at = idx
                break
        merged.insert(insert_at, proposed)
        model = PolicyModel(merged, self.resolver, self.zones, self.known_ifaces)
        rel, _trunc = model.overlap_findings()
        shadowed_by = [r for r in rel if r["later"] == proposed.get("policyid")
                       and r["kind"] == "shadowed"]
        redundant_under = [r for r in rel if r["later"] == proposed.get("policyid")
                           and r["kind"] == "redundant"]
        shadows = [r for r in rel if r["earlier"] == proposed.get("policyid")]
        # internet exposure: an accept rule from an any/WAN source to a broad dst
        src = self.resolver.resolve_addr_list(proposed.get("srcaddr"), _neg(proposed, "srcaddr-negate"))
        any_source = ("all" in [n.lower() for n in _names(proposed.get("srcaddr"))]) or \
                     (not src.opaque and src.ipset.covers(IPSet.full()))
        action = str(proposed.get("action", "deny")).lower()
        opaque = src.opaque or self.resolver.resolve_addr_list(proposed.get("dstaddr")).opaque or \
            self.resolver.resolve_svc_list(proposed.get("service")).opaque
        return {
            "action": action,
            "dead_on_arrival": bool(shadowed_by or redundant_under),
            "shadowed_by": shadowed_by, "redundant_under": redundant_under,
            "shadows_existing": shadows,
            "any_source_accept": bool(any_source and action == "accept"),
            "opaque_objects": opaque,
        }


# ── small helpers ──

def _polid(p) -> int:
    try:
        return int(p.get("policyid"))
    except (TypeError, ValueError):
        return 10 ** 9


def _neg(p, key) -> bool:
    return str(p.get(key, "")).lower() in ("enable", "enabled", "true")


def _ifnames(v) -> List[str]:
    return _names(v)


def _iface_any(v) -> bool:
    return "any" in [n.lower() for n in _names(v)] or not _names(v)


# Internet-Service (ISDB) matching flags — when any is enabled, the policy matches
# on the FortiGuard Internet-Service database, which is NOT resolvable from a
# static config, so such a policy can never be definitively matched or excluded.
_ISDB_FLAGS = ("internet-service", "internet-service-src", "internet-service6", "internet-service-src6")


def _isdb(p) -> bool:
    return any(_neg(p, k) for k in _ISDB_FLAGS)


def _name_covers(a: dict, b: dict) -> bool:
    """Coarse NAME-based coverage (mirrors the sibling name-based rule-base check),
    used only to avoid double-reporting: if this is True the name-based
    FORTIOS-RULEBASE-001/002 already flags the pair, so the interval check can skip
    it and report only the overlaps name-matching misses."""
    uni = {"all", "any"}

    def cov(an, bn):
        al = {x.lower() for x in an}
        return bool(al & uni) or {x.lower() for x in bn} <= al
    return (cov(a["src_names"], b["src_names"]) and cov(a["dst_names"], b["dst_names"])
            and cov(a["svc_names"], b["svc_names"]))


def _addr_comp(resolved: Addr, ip_int: int, maybe_reasons: List[str]) -> str:
    if resolved.negated:
        # Membership is INVERTED — we cannot assert match/no-match from the literal
        # set (an in-set IP is excluded, an out-of-set IP matches). Fail to MAYBE.
        maybe_reasons.append(resolved.reason or "negated address match")
        return _MAYBE
    if resolved.ipset.contains_ip(ip_int):
        return _YES                       # in the resolvable part -> definite hit
    if resolved.opaque:
        maybe_reasons.append(resolved.reason or "unresolved address object")
        return _MAYBE
    return _NO


def _svc_comp(resolved: Svc, proto: str, port: int, maybe_reasons: List[str]) -> str:
    if resolved.negated:
        maybe_reasons.append(resolved.reason or "negated service match")
        return _MAYBE
    if resolved.portset.matches(proto, port):
        return _YES
    if resolved.opaque:
        maybe_reasons.append(resolved.reason or "unresolved service object")
        return _MAYBE
    return _NO
