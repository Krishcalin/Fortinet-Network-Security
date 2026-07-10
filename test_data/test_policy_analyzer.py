"""
Tests for the traffic-aware policy engine: IP/port interval math, object
resolution with OPAQUE discipline, first-match reachability queries, true
CIDR/port-overlap shadow analysis, and pre-change simulation.

The load-bearing property under test is: the engine NEVER asserts a definitive
allow/deny across a factor it cannot resolve (VIP/DNAT, FQDN/ISDB/geo/wildcard,
IPv6, negation, schedule) — it returns OPAQUE instead.

Run:  python -m pytest test_data/test_policy_analyzer.py -v
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from policy_analyzer import (  # noqa: E402
    IPSet, PortSet, Resolver, PolicyModel, ALLOW, DENY, OPAQUE, ip4_to_int,
)


def _lst(v):
    return [{"name": n} for n in (v if isinstance(v, (list, tuple)) else [v])]


def pol(pid, action="accept", srcintf="any", dstintf="any", srcaddr="all",
        dstaddr="all", service="ALL", status="enable", **extra):
    p = {"policyid": pid, "action": action, "status": status,
         "srcintf": _lst(srcintf), "dstintf": _lst(dstintf), "srcaddr": _lst(srcaddr),
         "dstaddr": _lst(dstaddr), "service": _lst(service)}
    p.update(extra)
    return p


def model(policies, addrs=(), grps=(), svcs=(), svcgrps=(), vips=(),
          zones=None, known=("lan", "wan1", "wan2", "dmz", "internal", "port1", "port2")):
    return PolicyModel(policies, Resolver(list(addrs), list(grps), list(svcs), list(svcgrps), list(vips)),
                       zones=zones, known_ifaces=known)


# --------------------------------------------------------------- IPSet -------

def test_ipset_from_subnet_forms():
    a = IPSet.from_subnet_field("10.0.0.0 255.255.255.0")
    b = IPSet.from_cidr("10.0.0.0/24")
    assert a.intervals == b.intervals
    assert a.contains_ip(ip4_to_int("10.0.0.55"))
    assert not a.contains_ip(ip4_to_int("10.0.1.1"))


def test_ipset_range_and_cover_and_overlap():
    r = IPSet.from_range("10.0.1.5", "10.0.1.9")
    assert r.contains_ip(ip4_to_int("10.0.1.7")) and not r.contains_ip(ip4_to_int("10.0.1.10"))
    net = IPSet.from_cidr("10.0.0.0/16")
    assert net.covers(r) and not r.covers(net)
    assert net.overlaps(r) and IPSet.full().covers(net)


def test_ipset_merge_adjacent():
    s = IPSet([(0, 10), (11, 20), (30, 40)])
    assert s.intervals == [(0, 20), (30, 40)]


# -------------------------------------------------------------- PortSet ------

def test_portset_matches_and_covers():
    tcp443 = PortSet([("tcp", 443, 443)])
    assert tcp443.matches("tcp", 443) and not tcp443.matches("tcp", 80) and not tcp443.matches("udp", 443)
    assert PortSet.all().covers(tcp443) and not tcp443.covers(PortSet.all())
    rng = PortSet([("tcp", 1, 65535)])
    assert rng.covers(tcp443)


# ------------------------------------------------------------ resolution -----

def test_resolve_opaque_object_types():
    r = Resolver([{"name": "F", "type": "fqdn", "fqdn": "x.com"},
                  {"name": "G", "type": "geography", "country": "CN"},
                  {"name": "W", "type": "wildcard"},
                  {"name": "OK", "type": "ipmask", "subnet": "10.0.0.0 255.255.255.0"}], [], [], [], [])
    assert r.resolve_addr("F").opaque and r.resolve_addr("G").opaque and r.resolve_addr("W").opaque
    assert not r.resolve_addr("OK").opaque
    assert r.resolve_addr("does-not-exist").opaque   # unknown object -> opaque


def test_resolve_group_opaque_if_any_member_opaque():
    r = Resolver([{"name": "A", "subnet": "10.0.0.0/24"}, {"name": "F", "type": "fqdn"}],
                 [{"name": "GRP", "member": _lst(["A", "F"])}], [], [], [])
    g = r.resolve_addr("GRP")
    assert g.opaque and g.ipset.contains_ip(ip4_to_int("10.0.0.9"))  # resolvable part kept


def test_resolve_service_custom_and_unknown():
    r = Resolver([], [], [{"name": "WEB-8443", "tcp-portrange": "8443"}], [], [])
    s = r.resolve_svc("WEB-8443")
    assert not s.opaque and s.portset.matches("tcp", 8443)
    assert r.resolve_svc("HTTPS").portset.matches("tcp", 443)     # predefined
    assert r.resolve_svc("SomeISDBService").opaque                # unknown -> opaque


# ------------------------------------------------------------- query ---------

def test_query_first_match_allow_and_deny():
    m = model([pol(1, "accept", service="HTTPS"),
               pol(2, "deny", service="SSH")])
    assert m.query("1.1.1.1", "2.2.2.2", 443, "tcp").verdict == ALLOW
    assert m.query("1.1.1.1", "2.2.2.2", 22, "tcp").verdict == DENY   # p1 HTTPS no-match, p2 SSH deny
    assert m.query("1.1.1.1", "2.2.2.2", 80, "tcp").verdict == DENY   # implicit deny


def test_query_specific_addresses():
    m = model([pol(1, "accept", srcaddr="LAN", dstaddr="SRV", service="HTTPS")],
              addrs=[{"name": "LAN", "subnet": "192.168.1.0/24"},
                     {"name": "SRV", "type": "ipmask", "subnet": "10.0.0.10 255.255.255.255"}])
    assert m.query("192.168.1.5", "10.0.0.10", 443).verdict == ALLOW
    assert m.query("192.168.2.5", "10.0.0.10", 443).verdict == DENY   # src not in LAN


def test_query_vip_dst_is_opaque():
    m = model([pol(1, "accept", srcaddr="all", dstaddr="WEB-VIP", service="HTTPS")],
              vips=[{"name": "WEB-VIP", "extip": "203.0.113.5", "mappedip": "10.0.0.10",
                     "extport": "443", "mappedport": "8443"}])
    r = m.query("8.8.8.8", "203.0.113.5", 443)
    assert r.verdict == OPAQUE and "VIP" in r.reason


def test_query_opaque_when_deciding_policy_has_fqdn():
    # A flow that ONLY the FQDN policy could match -> OPAQUE (can't prove/deny)
    m = model([pol(1, "accept", srcaddr="all", dstaddr="EXT", service="HTTPS")],
              addrs=[{"name": "EXT", "type": "fqdn", "fqdn": "updates.example.com"}])
    r = m.query("192.168.1.5", "93.184.216.34", 443)
    assert r.verdict == OPAQUE and "FQDN" in r.reason


def test_query_ipv6_opaque():
    m = model([pol(1, "accept")])
    assert m.query("2001:db8::1", "2001:db8::2", 443).verdict == OPAQUE


def test_query_negation_opaque():
    m = model([pol(1, "accept", srcaddr="LAN", **{"srcaddr-negate": "enable"})],
              addrs=[{"name": "LAN", "subnet": "192.168.1.0/24"}])
    assert m.query("8.8.8.8", "1.1.1.1", 443).verdict == OPAQUE


def test_query_schedule_restricted_opaque():
    m = model([pol(1, "accept", service="HTTPS", schedule="business-hours")])
    r = m.query("1.1.1.1", "2.2.2.2", 443)
    assert r.verdict == OPAQUE and "schedule" in r.reason.lower()


def test_query_interface_via_decisive():
    m = model([pol(1, "accept", srcintf="lan", dstintf="wan1", service="HTTPS")])
    # matching interfaces -> clean ALLOW; wrong ingress -> no match -> implicit deny
    assert m.query("1.1.1.1", "2.2.2.2", 443, ingress="lan", egress="wan1").verdict == ALLOW
    assert m.query("1.1.1.1", "2.2.2.2", 443, ingress="dmz", egress="wan1").verdict == DENY
    # no --via -> still ALLOW but with an unverified-interface caveat
    r = m.query("1.1.1.1", "2.2.2.2", 443)
    assert r.verdict == ALLOW and any("not verified" in c for c in r.caveats)


def test_query_disabled_policy_skipped():
    m = model([pol(1, "accept", service="HTTPS", status="disable"),
               pol(2, "deny", service="HTTPS")])
    assert m.query("1.1.1.1", "2.2.2.2", 443).verdict == DENY


# ---- review regressions (false-verdict / OPAQUE-discipline) ----

def test_negated_address_is_opaque_not_false_allow():
    """Regression (HIGH): dstaddr-negate must NOT report an IP inside the negated
    set as a definite ALLOW."""
    m = model([pol(1, "accept", srcaddr="all", dstaddr="INTERNAL", service="ALL",
                   **{"dstaddr-negate": "enable"})],
              addrs=[{"name": "INTERNAL", "subnet": "10.0.0.0/8"}])
    # 10.0.0.20 IS in the negated set -> real FortiGate does NOT match -> engine must NOT say ALLOW
    assert m.query("10.0.0.5", "10.0.0.20", 445).verdict == OPAQUE


def test_negated_service_is_opaque_not_false_allow():
    m = model([pol(1, "accept", srcaddr="all", dstaddr="all", service="HTTPS",
                   **{"service-negate": "enable"})])
    assert m.query("1.1.1.1", "2.2.2.2", 443).verdict == OPAQUE   # 443 is the excluded port


def test_internet_service_policy_is_opaque():
    """Regression (HIGH): a policy that matches by Internet-Service (ISDB) can't be
    resolved from config -> OPAQUE, not a bypass."""
    m = model([pol(1, "accept", srcaddr="all", dstaddr="all", service="ALL",
                   **{"internet-service": "enable"})])
    r = m.query("1.1.1.1", "8.8.8.8", 443)
    assert r.verdict == OPAQUE and "Internet-Service" in r.reason


def test_first_match_preserves_config_order_not_policyid():
    """Regression (HIGH): FortiOS evaluates in sequence order, not policyid order.
    A deny placed FIRST in the list (higher policyid) must win."""
    m = model([pol(50, "deny", service="HTTPS"),      # sequence-first
               pol(2, "accept", service="HTTPS")])    # lower policyid, later in sequence
    r = m.query("1.1.1.1", "2.2.2.2", 443)
    assert r.verdict == DENY and r.policy["policyid"] == 50


def test_via_mismatch_opaque_without_interface_data():
    """Regression (HIGH-zone): with NO interface/zone data loaded, a --via that
    doesn't match a named interface is OPAQUE (could be a zone), not a false DENY."""
    m = model([pol(1, "accept", srcintf="corp-zone", dstintf="wan1", service="HTTPS")], known=())
    assert m.query("1.1.1.1", "2.2.2.2", 443, ingress="port5", egress="wan1").verdict == OPAQUE


def test_via_zone_member_matches():
    """A --via physical interface that is a MEMBER of a zone-scoped policy matches."""
    m = model([pol(1, "accept", srcintf="corp", dstintf="wan1", service="HTTPS")],
              zones={"corp": ["port3", "port4"]}, known=("port3", "port4", "wan1"))
    assert m.query("1.1.1.1", "2.2.2.2", 443, ingress="port3", egress="wan1").verdict == ALLOW
    assert m.query("1.1.1.1", "2.2.2.2", 443, ingress="port9", egress="wan1").verdict == DENY  # not a member


# ------------------------------------------------------------ overlap --------

def test_overlap_redundant_and_shadowed():
    # p1 broad accept covers p2 (redundant) and p3 deny (shadowed - dead)
    m = model([pol(1, "accept", srcaddr="all", dstaddr="all", service="ALL"),
               pol(2, "accept", srcaddr="LAN", dstaddr="all", service="HTTPS"),
               pol(3, "deny", srcaddr="LAN", dstaddr="all", service="SSH")],
              addrs=[{"name": "LAN", "subnet": "192.168.1.0/24"}])
    overlaps, _ = m.overlap_findings()
    kinds = {(o["later"], o["kind"]) for o in overlaps}
    assert (2, "redundant") in kinds and (3, "shadowed") in kinds


def test_overlap_skips_opaque_and_vip():
    m = model([pol(1, "accept", srcaddr="all", dstaddr="all", service="ALL"),
               pol(2, "accept", srcaddr="all", dstaddr="EXT", service="HTTPS"),
               pol(3, "accept", srcaddr="all", dstaddr="WEB-VIP", service="HTTPS")],
              addrs=[{"name": "EXT", "type": "fqdn"}],
              vips=[{"name": "WEB-VIP", "extip": "203.0.113.5"}])
    overlaps, _ = m.overlap_findings()
    laters = {o["later"] for o in overlaps}
    assert 2 not in laters and 3 not in laters   # FQDN + VIP policies excluded


def test_overlap_name_covered_dedup_flag():
    """name_covered marks pairs the coarse name-based check also catches (so the
    interval check can skip them); a CIDR-only overlap (different names) is False."""
    m = model([pol(1, "accept", srcaddr="all", dstaddr="all", service="ALL"),
               pol(2, "accept", srcaddr="LAN", dstaddr="all", service="HTTPS")],
              addrs=[{"name": "LAN", "subnet": "192.168.1.0/24"}])
    d = {(o["earlier"], o["later"]): o for o in m.overlap_findings()[0]}
    assert d[(1, 2)]["name_covered"] is True   # 'all' name-covers LAN
    m2 = model([pol(1, "accept", srcaddr="BIG", dstaddr="all", service="HTTP"),
                pol(2, "accept", srcaddr="SMALL", dstaddr="all", service="HTTP")],
               addrs=[{"name": "BIG", "subnet": "10.0.0.0/8"}, {"name": "SMALL", "subnet": "10.0.1.0/24"}])
    d2 = {(o["earlier"], o["later"]): o for o in m2.overlap_findings()[0]}
    assert (1, 2) in d2 and d2[(1, 2)]["name_covered"] is False   # CIDR overlap, names differ


def test_overlap_respects_interface_scope():
    # different, specific interfaces -> not shadowing (different paths)
    m = model([pol(1, "accept", srcintf="lan", dstintf="wan1", service="ALL"),
               pol(2, "accept", srcintf="dmz", dstintf="wan1", service="HTTPS")])
    overlaps, _ = m.overlap_findings()
    assert not overlaps


# ----------------------------------------------------------- simulate --------

def test_simulate_any_source_accept_flagged():
    m = model([pol(1, "accept", srcaddr="LAN", service="HTTPS")],
              addrs=[{"name": "LAN", "subnet": "192.168.1.0/24"}])
    s = m.simulate(pol(9, "accept", srcaddr="all", dstaddr="all", service="ALL"))
    assert s["any_source_accept"] is True


def test_simulate_dead_on_arrival():
    m = model([pol(1, "accept", srcaddr="all", dstaddr="all", service="ALL")])
    s = m.simulate(pol(9, "accept", srcaddr="all", dstaddr="all", service="HTTPS"))
    assert s["dead_on_arrival"] is True   # fully covered by the earlier broad accept


def test_simulate_shadows_existing():
    m = model([pol(5, "deny", srcaddr="LAN", dstaddr="all", service="SSH")],
              addrs=[{"name": "LAN", "subnet": "192.168.1.0/24"}])
    s = m.simulate(pol(1, "accept", srcaddr="all", dstaddr="all", service="ALL"))
    assert any(r["later"] == 5 for r in s["shadows_existing"])   # new broad rule kills the deny


# -------------------------------------------------- scanner integration ------

def test_offline_scan_emits_interval_overlap_finding():
    from fortinet_offline_scanner import OfflineFortinetScanner
    conf = os.path.join(os.path.dirname(__file__), "sample_policy.conf")
    s = OfflineFortinetScanner(conf)
    s.scan()
    ids = {f.rule_id for f in s.findings}
    assert "FORTIOS-RULEBASE-102" in ids   # redundant-by-overlap fired
