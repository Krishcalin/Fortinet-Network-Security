#!/usr/bin/env python3
"""Unit tests for the FortiGate offline .conf parser and the offline scanner
adapter. Run from the project root:

    python -m pytest test_data/test_offline_parser.py -v
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fortinet_offline_scanner import (
    FortiGateConfParser,
    OfflineFortinetScanner,
    REF_LIST_FIELDS,
)


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

def test_header_extracts_model_version_build():
    text = "#config-version=FGT60F-7.2.5-FW-build1517-230718:opmode=0:vdom=0\n"
    p = FortiGateConfParser(text)
    assert p.header_meta["model"] == "FGT60F"
    assert p.header_meta["version"] == "7.2.5"
    assert p.header_meta["build"] == "1517"


def test_header_falls_back_to_buildno_line():
    text = (
        "#config-version=FGT100F-7.4.1-FW-something:opmode=0\n"
        "#buildno=2463\n"
    )
    meta = FortiGateConfParser(text).header_meta
    assert meta["build"] == "2463"


def test_header_missing_returns_empty_meta():
    p = FortiGateConfParser("config system global\nset hostname \"x\"\nend\n")
    assert p.header_meta == {}


# ---------------------------------------------------------------------------
# Section -> API path mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section,expected", [
    (["system", "global"], "system/global"),
    (["firewall", "policy"], "firewall/policy"),
    (["vpn", "ssl", "settings"], "vpn.ssl/settings"),
    (["log", "fortianalyzer", "setting"], "log.fortianalyzer/setting"),
    (["vpn", "ipsec", "phase1-interface"], "vpn.ipsec/phase1-interface"),
    (["system", "snmp", "community"], "system.snmp/community"),
])
def test_section_to_api_path(section, expected):
    assert FortiGateConfParser._section_to_api_path(section) == expected


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------

def test_tokenize_handles_quoted_and_bare_tokens():
    toks = FortiGateConfParser._tokenize('set name "Allow All" enable')
    assert toks == ["set", "name", "Allow All", "enable"]


def test_tokenize_escaped_quote_in_value():
    toks = FortiGateConfParser._tokenize(r'set comment "He said \"hi\""')
    # The escape sequence stays in the captured group; what matters is that
    # the tokenizer treats the entire quoted region as one token.
    assert toks[0] == "set"
    assert toks[1] == "comment"
    assert len(toks) == 3


# ---------------------------------------------------------------------------
# Block / edit parsing
# ---------------------------------------------------------------------------

def test_simple_global_block_returns_dict_with_int_coercion():
    text = """\
config system global
    set hostname "FGT-A"
    set admintimeout 30
    set strong-crypto disable
end
"""
    result = FortiGateConfParser(text).parse()
    assert result["system/global"] == {
        "hostname": "FGT-A",
        "admintimeout": 30,          # coerced to int — critical for isinstance(x,int) checks
        "strong-crypto": "disable",
    }


def test_edit_block_uses_name_key_and_string_id_for_quoted_edits():
    text = """\
config system admin
    edit "admin"
        set accprofile "super_admin"
        set two-factor disable
    next
end
"""
    result = FortiGateConfParser(text).parse()
    assert result["system/admin"] == [
        {"name": "admin", "accprofile": "super_admin", "two-factor": "disable"},
    ]


def test_firewall_policy_uses_policyid_int_and_keeps_user_name():
    text = """\
config firewall policy
    edit 1
        set name "Allow-All"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
"""
    pol = FortiGateConfParser(text).parse()["firewall/policy"]
    assert pol[0]["policyid"] == 1
    assert pol[0]["name"] == "Allow-All"
    # reference field shaping
    assert pol[0]["srcaddr"] == [{"name": "all"}]
    assert pol[0]["dstaddr"] == [{"name": "all"}]
    assert pol[0]["service"] == [{"name": "ALL"}]


def test_numeric_edit_id_in_non_policy_section_sets_both_id_and_name():
    text = """\
config system snmp community
    edit 1
        set name "public"
        set status enable
    next
end
"""
    comm = FortiGateConfParser(text).parse()["system.snmp/community"]
    # 'name' set first from edit id, then overridden by `set name "public"`.
    assert comm[0]["name"] == "public"
    # 'id' set from numeric edit id so scanner's comm.get("id", "?") works.
    assert comm[0]["id"] == 1


def test_multi_token_unquoted_set_stays_space_joined_string():
    text = """\
config system interface
    edit "wan1"
        set allowaccess https ssh ping snmp
    next
end
"""
    iface = FortiGateConfParser(text).parse()["system/interface"][0]
    assert iface["allowaccess"] == "https ssh ping snmp"


def test_multi_value_reference_field_produces_list_of_name_dicts():
    text = """\
config firewall policy
    edit 1
        set srcaddr "internal" "dmz"
    next
end
"""
    pol = FortiGateConfParser(text).parse()["firewall/policy"][0]
    assert pol["srcaddr"] == [{"name": "internal"}, {"name": "dmz"}]


# ---------------------------------------------------------------------------
# Nested config blocks (e.g. config srcaddr inside an edit)
# ---------------------------------------------------------------------------

def test_nested_config_block_inside_edit_is_lifted_as_sub_property():
    text = """\
config firewall policy
    edit 1
        set name "via-config-block"
        config srcaddr
            edit "internal"
            next
        end
    next
end
"""
    pol = FortiGateConfParser(text).parse()["firewall/policy"][0]
    assert pol["srcaddr"] == [{"name": "internal"}]


# ---------------------------------------------------------------------------
# VDOM wrappers
# ---------------------------------------------------------------------------

def test_vdom_wrapper_lifts_inner_configs_to_top_level():
    text = """\
config system global
    set hostname "FGT-MULTIVDOM"
end
config vdom
edit "root"
    config firewall policy
        edit 1
            set name "from-root-vdom"
        next
    end
next
end
"""
    result = FortiGateConfParser(text).parse()
    assert result["system/global"]["hostname"] == "FGT-MULTIVDOM"
    assert result["firewall/policy"][0]["name"] == "from-root-vdom"


def test_global_wrapper_is_transparent():
    text = """\
config global
    config system dns
        set primary "8.8.8.8"
    end
end
"""
    result = FortiGateConfParser(text).parse()
    assert result["system/dns"]["primary"] == "8.8.8.8"


# ---------------------------------------------------------------------------
# Robustness — malformed input should not crash
# ---------------------------------------------------------------------------

def test_empty_config_block_is_handled():
    result = FortiGateConfParser("config system global\nend\n").parse()
    assert result["system/global"] == {}


def test_missing_end_returns_partial_block_without_crashing():
    text = """\
config system global
    set hostname "FGT-PARTIAL"
"""
    result = FortiGateConfParser(text).parse()
    assert result["system/global"]["hostname"] == "FGT-PARTIAL"


def test_comments_inside_block_are_skipped():
    text = """\
config system global
    # generated by Ansible 2026-01-01
    set hostname "FGT-CMT"
    # end of relevant settings
end
"""
    assert FortiGateConfParser(text).parse()["system/global"] == {"hostname": "FGT-CMT"}


def test_blank_lines_and_indentation_are_tolerated():
    text = "config system global\n\n   set hostname \"x\"\n\n\nend\n"
    assert FortiGateConfParser(text).parse()["system/global"] == {"hostname": "x"}


def test_unset_clears_value_to_empty_string():
    text = """\
config system global
    set hostname "x"
    unset hostname
end
"""
    assert FortiGateConfParser(text).parse()["system/global"] == {"hostname": ""}


# ---------------------------------------------------------------------------
# REF_LIST_FIELDS contains the names the scanner iterates as objects
# ---------------------------------------------------------------------------

def test_ref_list_fields_covers_known_policy_iterables():
    # These are the fields the live policy check does `[a["name"] for a in field]` on.
    must_be_refs = {"srcaddr", "dstaddr", "service", "srcintf", "dstintf"}
    assert must_be_refs.issubset(REF_LIST_FIELDS)


# ---------------------------------------------------------------------------
# OfflineFortinetScanner adapter
# ---------------------------------------------------------------------------

def test_offline_scanner_synthesises_system_status_from_header():
    text = (
        "#config-version=FGT60F-7.2.5-FW-build1234-230101:opmode=0\n"
        "config system global\n"
        '    set hostname "FGT-OFFLINE"\n'
        "end\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(text)
        path = fh.name
    try:
        scanner = OfflineFortinetScanner(path, verbose=False)
        status = scanner._synth_system_status()
        assert status["version"] == "v7.2.5"
        assert status["hostname"] == "FGT-OFFLINE"
        assert status["model"] == "FGT60F"
        assert status["build"] == 1234
        # monitor endpoints other than system/status return None
        assert scanner._api_get("system/ha-peer", monitor=True) is None
        assert scanner._api_get("license/status", monitor=True) is None
        # config endpoints come through
        assert scanner._api_get("system/global")["hostname"] == "FGT-OFFLINE"
        # missing endpoints return None (live checks already tolerate this)
        assert scanner._api_get("vpn.ssl/settings") is None
    finally:
        os.unlink(path)


def test_offline_scanner_runs_end_to_end_on_sample(tmp_path):
    """End-to-end smoke: a tiny insecure config triggers known findings without raising."""
    text = """\
#config-version=FGT60F-7.0.10-FW-build1234-230101:opmode=0
config system global
    set hostname "FGT-E2E"
    set admintimeout 30
    set admin-lockout-threshold 0
end
config firewall policy
    edit 1
        set name "any-any"
        set action accept
        set status enable
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set srcintf "lan"
        set dstintf "wan1"
    next
end
"""
    conf = tmp_path / "e2e.conf"
    conf.write_text(text)
    scanner = OfflineFortinetScanner(str(conf), verbose=False)
    scanner.scan()
    rule_ids = {f.rule_id for f in scanner.findings}
    # Any-to-any policy must fire
    assert "FORTIOS-POLICY-002" in rule_ids
    # CVE matching against 7.0.10 must fire (multiple 7.0.x CVEs are unpatched)
    assert any(rid.startswith("FORTIOS-CVE-") for rid in rule_ids)
    # admintimeout=30 (> 5 min) triggers a finding now that the value is int
    assert any("admintimeout" in (f.line_content or "").lower() for f in scanner.findings)
