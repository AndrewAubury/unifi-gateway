import json
import urllib.parse

import pfsense_sync
from collectors.pfsense_api import PfSenseAPIError

PORTS = [
    {"ifname": "eth0", "name": "WAN", "type": "wan", "realif": "wan"},
    {"ifname": "eth1", "name": "LAN", "type": "lan", "realif": "lan"},
]

UNIFI_CFG = {
    "port-forward": {
        "auto-firewall": "true",
        "hairpin-nat": "false",
        "lan-interface": "eth1",
        "wan-interface": "eth0",
        "rule": {
            "1": {
                "description": "web",
                "forward-to": {"address": "10.0.0.10", "port": "80"},
                "original-port": "80",
                "protocol": "tcp",
            },
            "2": {
                "description": "game range",
                "forward-to": {"address": "10.0.0.11"},
                "original-port": "6000:6002",
                "protocol": "both",
            },
        },
    },
    "firewall": {
        "WAN_IN": {
            "rule": {
                "2001": {
                    "action": "accept",
                    "description": "allow http",
                    "destination": {"port": "80"},
                    "protocol": "tcp",
                    "source": {"address": "1.2.3.4"},
                },
                "2002": {
                    "action": "drop",
                    "description": "block bad subnet",
                    "destination": {"address": "10.0.0.0/24"},
                    "source": {"address": "5.6.7.0/24"},
                },
                "2003": {
                    "action": "accept",
                    "description": "group rule",
                    "source": {"group": {"address-group": "BAD_GROUP"}},
                },
            },
        },
        "LAN_LOCAL": {
            "rule": {
                "1": {
                    "action": "reject",
                    "description": "lan thing",
                    "log": "enable",
                },
            },
        },
    },
}

# Mirrors the real structure pushed by UniFi Network 10.x as `system_cfg`
SYSTEM_CFG = {
    "firewall": {
        "group": {
            "address-group": {
                "guest_portal_address": {
                    "description": "guest portal address",
                    "address": ["10.0.0.62"],
                },
                "guest_restricted": {
                    "description": "restricted addresses for guests",
                    "address": ["192.168.0.0/16", "10.0.0.0/8"],
                },
                "authorized_guests": {"description": "authorized guests"},
            },
            "network-group": {
                "corporate_network": {
                    "description": "corporate subnets",
                    "network": ["10.0.0.0/23"],
                },
                "guest_network": {"description": "guest subnets"},
            },
            "port-group": {
                "guest_portal_ports": {
                    "description": "guest portal ports",
                    "port": [8880, 8843],
                },
            },
        },
        "ipv6-name": {
            "WANv6_IN": {
                "default-action": "drop",
                "rule": {"3001": {"action": "accept", "protocol": "ipv6-icmp"}},
            },
        },
        "name": {
            "WAN_IN": {
                "default-action": "drop",
                "rule": {
                    "1999": {
                        "action": "accept",
                        "description": "PortForward [Web port test]",
                        "destination": {"address": "10.0.0.62", "port": "8971"},
                        "protocol": "tcp",
                    },
                    "2000": {
                        "action": "accept",
                        "description": "Test",
                        "log": "enable",
                        "protocol": "all",
                    },
                    "2001": {
                        "action": "drop",
                        "description": "block corp from wan",
                        "destination": {
                            "group": {"network-group": "corporate_network"}
                        },
                        "source": {"address": "5.6.7.8"},
                    },
                    "2002": {
                        "action": "drop",
                        "description": "drop guest net",
                        "source": {"group": {"network-group": "guest_network"}},
                    },
                    "3001": {
                        "action": "accept",
                        "description": "allow established/related sessions",
                        "state": {"established": "enable"},
                    },
                    "3002": {
                        "action": "drop",
                        "description": "drop invalid state",
                        "state": {"invalid": "enable"},
                    },
                },
            },
            "WAN_LOCAL": {
                "default-action": "drop",
                "rule": {
                    "3001": {
                        "action": "accept",
                        "description": "allow established/related sessions",
                        "state": {"established": "enable"},
                    },
                },
            },
            "LAN_IN": {
                "default-action": "accept",
                "rule": {
                    "6001": {
                        "action": "accept",
                        "description": "Allow Network 10.0.0.0/23 Traffic",
                        "source": {"address": "10.0.0.0/23"},
                    },
                },
            },
            "GUEST_IN": {
                "default-action": "accept",
                "rule": {
                    "3005": {
                        "action": "drop",
                        "description": "Block Restricted Traffic",
                        "destination": {"group": {"address-group": "guest_restricted"}},
                    },
                },
            },
        },
        "options": {"mss-clamp": {"mss": "1452"}},
    },
    "port-forward": {
        "wan-interface": "eth0",
        "lan-interface": "eth1",
        "auto-firewall": "disable",
    },
    "interfaces": {},
}


class TestParseCfg:
    def test_plain_json(self):
        parsed = pfsense_sync.parse_cfg(json.dumps(UNIFI_CFG))
        assert parsed == UNIFI_CFG

    def test_urlencoded_json(self):
        encoded = urllib.parse.quote(json.dumps(UNIFI_CFG))
        assert pfsense_sync.parse_cfg(encoded) == UNIFI_CFG

    def test_passthrough_dict(self):
        assert pfsense_sync.parse_cfg(UNIFI_CFG) == UNIFI_CFG

    def test_invalid_raises(self):
        try:
            pfsense_sync.parse_cfg("this is not json {")
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")


class TestPortForwardExtraction:
    def test_translation(self):
        forwards = pfsense_sync.extract_port_forwards(UNIFI_CFG, PORTS)
        assert len(forwards) == 2
        web = next(f for f in forwards if f["descr"] == "unifi:web")
        assert web == {
            "interface": "wan",
            "ipprotocol": "inet",
            "protocol": "tcp",
            "source": "any",
            "source_port": None,
            "destination": "any",
            "destination_port": "80",
            "target": "10.0.0.10",
            "local_port": "80",
            "disabled": False,
            "natreflection": None,
            "associated_rule_id": "pass",
            "descr": "unifi:web",
        }
        game = next(f for f in forwards if f["descr"] == "unifi:game range")
        assert game["protocol"] == "tcp/udp"
        assert game["destination_port"] == "6000:6002"
        assert game["local_port"] == "6000"

    def test_system_cfg_port_forward_section_without_rules(self):
        assert pfsense_sync.extract_port_forwards(SYSTEM_CFG, PORTS) == []

    def test_no_port_forward_section(self):
        assert pfsense_sync.extract_port_forwards({}, PORTS) == []

    def test_rule_without_target_skipped(self):
        cfg = {
            "port-forward": {
                "rule": {
                    "1": {"description": "broken", "original-port": "80"},
                }
            }
        }
        assert pfsense_sync.extract_port_forwards(cfg, PORTS) == []


class TestAliasExtraction:
    def test_groups_to_aliases(self):
        aliases = pfsense_sync.extract_aliases(SYSTEM_CFG)
        by_name = {a["name"]: a for a in aliases}
        # empty groups (authorized_guests, guest_network) are excluded
        assert set(by_name) == {
            "guest_portal_address",
            "guest_restricted",
            "corporate_network",
            "guest_portal_ports",
        }
        corp = by_name["corporate_network"]
        assert corp["type"] == "network"
        assert corp["address"] == ["10.0.0.0/23"]
        assert corp["descr"].startswith("unifi:")
        # bare IPs must land in a host alias: pfSense rejects them in
        # network aliases ("not a valid CIDR, FQDN, or alias")
        portal = by_name["guest_portal_address"]
        assert portal["type"] == "host"
        assert portal["address"] == ["10.0.0.62"]
        ports = by_name["guest_portal_ports"]
        assert ports["type"] == "port"
        assert ports["address"] == ["8880", "8843"]

    def test_mixed_members_use_network_with_normalized_hosts(self):
        cfg = {
            "firewall": {
                "group": {
                    "address-group": {
                        "mixed": {
                            "description": "mixed",
                            "address": ["10.0.0.62", "10.0.0.0/23"],
                        },
                    }
                }
            }
        }
        aliases = pfsense_sync.extract_aliases(cfg)
        assert aliases == [
            {
                "name": "mixed",
                "type": "network",
                "address": ["10.0.0.62/32", "10.0.0.0/23"],
                "descr": "unifi:mixed",
            }
        ]

    def test_no_groups(self):
        assert pfsense_sync.extract_aliases({}) == []

    def test_alias_name_sanitized(self):
        # pfSense rejects hyphens in alias names (verified live: HTTP 400)
        cfg = {
            "firewall": {
                "group": {
                    "port-group": {
                        "unifi_controller_ports-tcp": {
                            "description": "tcp",
                            "port": [8080],
                        },
                    }
                }
            }
        }
        aliases = pfsense_sync.extract_aliases(cfg)
        assert aliases[0]["name"] == "unifi_controller_ports_tcp"

    def test_alias_name_collision_disambiguated(self):
        cfg = {
            "firewall": {
                "group": {
                    "address-group": {
                        "a-b": {"address": ["10.0.0.1"]},
                        "a_b": {"address": ["10.0.0.2"]},
                    }
                }
            }
        }
        names = [a["name"] for a in pfsense_sync.extract_aliases(cfg)]
        assert names == ["a_b", "a_b_2"]


# UniFi "Optionally restrict access to the forwarded ports..." (From field)
PFOR_CFG = {
    "port-forward": {
        "wan-interface": "eth0",
        "lan-interface": "eth1",
        "rule": {
            "1": {
                "description": "restricted single",
                "forward-to": {"address": "10.0.0.10", "port": "9000"},
                "original-port": "9000",
                "protocol": "tcp",
                "source": {"address": "81.2.100.4"},
            },
            "2": {
                "description": "restricted list",
                "forward-to": {"address": "10.0.0.11", "port": "9001"},
                "original-port": "9001",
                "protocol": "tcp",
                "source": {"address": "81.2.100.4,81.2.100.0/24"},
            },
            "3": {
                "description": "restricted range",
                "forward-to": {"address": "10.0.0.12", "port": "9002"},
                "original-port": "9002",
                "protocol": "tcp",
                "source": {"address": "81.2.100.10-81.2.100.20"},
            },
            "4": {
                "description": "group restricted",
                "forward-to": {"address": "10.0.0.13", "port": "9003"},
                "original-port": "9003",
                "protocol": "tcp",
                "source": {"group": {"address-group": "corporate_network"}},
            },
        },
    },
}


class TestPortForwardFromRestrictions:
    def test_restriction_modes(self):
        forwards = pfsense_sync.extract_port_forwards(
            PFOR_CFG,
            PORTS,
            alias_names={"corporate_network", "unifi_pfor_2", "unifi_pfor_3"},
        )
        by_name = {f["descr"][len("unifi:") :]: f for f in forwards}
        assert len(forwards) == 4
        # single IP or CIDR passes straight through
        assert by_name["restricted single"]["source"] == "81.2.100.4"
        # lists and dash ranges reference a derived alias
        assert by_name["restricted list"]["source"] == "unifi_pfor_2"
        assert by_name["restricted range"]["source"] == "unifi_pfor_3"
        # group references resolve to the synced alias
        assert by_name["group restricted"]["source"] == "corporate_network"

    def test_unknown_group_skips_forward(self):
        forwards = pfsense_sync.extract_port_forwards(PFOR_CFG, PORTS)
        assert all(f["descr"] != "unifi:group restricted" for f in forwards)

    def test_source_aliases_derived(self):
        aliases = pfsense_sync.extract_port_forward_source_aliases(PFOR_CFG)
        by_name = {a["name"]: a for a in aliases}
        assert set(by_name) == {"unifi_pfor_2", "unifi_pfor_3"}
        # mixed list: CIDR present -> network alias, bare IP normalized to /32
        assert by_name["unifi_pfor_2"]["type"] == "network"
        assert by_name["unifi_pfor_2"]["address"] == [
            "81.2.100.4/32",
            "81.2.100.0/24",
        ]
        # dash range -> host alias (pfSense host aliases accept ranges)
        assert by_name["unifi_pfor_3"]["type"] == "host"
        assert by_name["unifi_pfor_3"]["address"] == ["81.2.100.10-81.2.100.20"]
        assert all(a["descr"].startswith(pfsense_sync.MARKER) for a in aliases)

    def test_apply_flow_with_restrictions(self):
        fake = FakePfSense()
        stats = pfsense_sync.apply_config(fake, PFOR_CFG, PORTS)
        assert stats["aliases"]["created"] == 2
        # group-restricted forward skipped: corporate_network has no alias here
        assert stats["port_forwards"]["created"] == 3

        calls_after_first = len(fake.calls)
        stats = pfsense_sync.apply_config(fake, PFOR_CFG, PORTS)
        assert stats["port_forwards"]["created"] == 0
        assert stats["aliases"]["updated"] == 0
        assert stats["port_forwards"]["unchanged"] == 3
        mutations = [
            c
            for c in fake.calls[calls_after_first:]
            if c[0] in ("POST", "PATCH", "DELETE")
        ]
        assert mutations == []


class TestFirewallRuleExtraction:
    def test_translation(self):
        rules = pfsense_sync.extract_firewall_rules(UNIFI_CFG, PORTS)
        by_name = {r["descr"]: r for r in rules}
        # group-based rule without an alias is skipped
        assert len(rules) == 3
        assert by_name["unifi:WAN_IN - allow http"] == {
            "type": "pass",
            "interface": ["wan"],
            "ipprotocol": "inet",
            "protocol": "tcp",
            "source": "1.2.3.4",
            "source_port": None,
            "destination": "any",
            "destination_port": "80",
            "disabled": False,
            "log": False,
            "statetype": "keep state",
            "descr": "unifi:WAN_IN - allow http",
        }
        assert by_name["unifi:WAN_IN - block bad subnet"]["type"] == "block"
        assert by_name["unifi:LAN_LOCAL - lan thing"]["interface"] == ["lan"]
        assert by_name["unifi:LAN_LOCAL - lan thing"]["type"] == "reject"
        assert by_name["unifi:LAN_LOCAL - lan thing"]["log"] is True

    def test_baseline_rules_filtered(self):
        # state rules, auto "Allow Network ..." rules, GUEST_*/ipv6 rulesets,
        # group/ipv6-name/options keys: all filtered out
        alias_names = {
            "guest_portal_address",
            "guest_restricted",
            "corporate_network",
            "guest_portal_ports",
        }
        rules = pfsense_sync.extract_firewall_rules(
            SYSTEM_CFG, PORTS, alias_names=alias_names
        )
        # WAN_IN 2000 "Test" is an unrestricted WAN accept: skipped by default
        # WAN_IN 2002 references the empty guest_network group: skipped
        assert [r["descr"] for r in rules] == ["unifi:WAN_IN - block corp from wan"]
        rule = rules[0]
        assert rule["type"] == "block"
        assert rule["source"] == "5.6.7.8"
        assert rule["destination"] == "corporate_network"  # alias reference

    def test_unsafe_wan_pass_with_flag(self):
        alias_names = {
            "guest_portal_address",
            "guest_restricted",
            "corporate_network",
            "guest_portal_ports",
        }
        rules = pfsense_sync.extract_firewall_rules(
            SYSTEM_CFG, PORTS, alias_names=alias_names, allow_unsafe=True
        )
        by_name = {r["descr"]: r for r in rules}
        test_rule = by_name["unifi:WAN_IN - Test"]
        assert test_rule["type"] == "pass"
        assert test_rule["protocol"] is None
        assert test_rule["source"] == "any"
        assert test_rule["destination"] == "any"
        assert test_rule["log"] is True


class FakePfSense:
    """Emulates pfSense list/object-id semantics: `id` is the array index,
    renumbered after every mutation."""

    def __init__(self, port_forwards=None):
        self.port_forwards = port_forwards or []
        self.rules = []
        self.aliases = []
        self.calls = []
        self.applied = False

    def request(self, method, path, body=None, params=None):
        self.calls.append((method, path, body, params))
        if path == "/firewall/nat/port_forwards" and method == "GET":
            return [dict(r, id=i) for i, r in enumerate(self.port_forwards)]
        if path == "/firewall/nat/port_forward":
            if method == "POST":
                self.port_forwards.append(dict(body))
                return dict(body)
            if method == "PATCH":
                target = self.port_forwards[params["id"]]
                target.update(body)
                return target
            if method == "DELETE":
                self.port_forwards.pop(params["id"])
                return {}
        if path == "/firewall/rules" and method == "GET":
            return [dict(r, id=i) for i, r in enumerate(self.rules)]
        if path == "/firewall/rule":
            if method == "POST":
                self.rules.append(dict(body))
                return dict(body)
            if method == "PATCH":
                target = self.rules[params["id"]]
                target.update(body)
                return target
            if method == "DELETE":
                self.rules.pop(params["id"])
                return {}
        if path == "/firewall/aliases" and method == "GET":
            return [dict(a, id=i) for i, a in enumerate(self.aliases)]
        if path == "/firewall/alias":
            if method == "POST":
                self.aliases.append(dict(body))
                return dict(body)
            if method == "PATCH":
                target = self.aliases[params["id"]]
                target.update(body)
                return target
            if method == "DELETE":
                self.aliases.pop(params["id"])
                return {}
        if path == "/firewall/apply":
            if method == "GET":
                return {"applied": True, "pending_subsystems": []}
            if method == "POST":
                self.applied = True
                return {"applied": True, "pending_subsystems": []}
        raise AssertionError(f"unexpected {method} {path}")


def _forward(name, target="10.0.0.99", port="8080"):
    return {
        "interface": "wan",
        "ipprotocol": "inet",
        "protocol": "tcp",
        "source": "any",
        "source_port": None,
        "destination": "(self)",
        "destination_port": port,
        "target": target,
        "local_port": port,
        "disabled": False,
        "natreflection": None,
        "associated_rule_id": "pass",
        "descr": pfsense_sync.MARKER + name,
    }


class TestReconcile:
    def test_create_update_delete_and_native_untouched(self):
        fake = FakePfSense(
            port_forwards=[
                # a pfSense-native rule: must never be touched
                {
                    "interface": "wan",
                    "protocol": "tcp",
                    "target": "10.0.0.1",
                    "local_port": "443",
                    "destination_port": "443",
                    "descr": "pf-native",
                },
                # an old unifi rule that stays
                _forward("keep-me", port="9090"),
                # an old unifi rule that must be updated
                _forward("stale", target="10.0.0.50"),
                # an old unifi rule that must be deleted
                _forward("gone"),
            ]
        )
        desired = [
            _forward("keep-me", port="9090"),
            _forward("stale"),  # target differs from existing
            _forward("fresh"),  # new
        ]

        stats = pfsense_sync._reconcile(
            fake,
            "/firewall/nat/port_forwards",
            "/firewall/nat/port_forward",
            desired,
            pfsense_sync.PORT_FORWARD_FIELDS,
            "port forward",
        )

        assert stats["created"] == 1
        assert stats["updated"] == 1
        assert stats["deleted"] == 1

        names = [r["descr"] for r in fake.port_forwards]
        assert names == ["pf-native", "unifi:keep-me", "unifi:stale", "unifi:fresh"]
        # native rule untouched
        assert fake.port_forwards[0]["target"] == "10.0.0.1"
        # stale rule was updated to the desired target
        assert fake.port_forwards[2]["target"] == "10.0.0.99"
        # PATCH must carry the id in BOTH query and body: some RESTAPI
        # builds (v2.4.3 on pfSense 2.7.2, verified live) reject a PATCH
        # whose body lacks the id with "Field `id` is required"
        patches = [c for c in fake.calls if c[0] == "PATCH"]
        assert patches
        for _method, _path, body, params in patches:
            assert body["id"] == params["id"]

    def test_idempotent(self):
        fake = FakePfSense(port_forwards=[_forward("stable")])
        stats = pfsense_sync._reconcile(
            fake,
            "/firewall/nat/port_forwards",
            "/firewall/nat/port_forward",
            [_forward("stable")],
            pfsense_sync.PORT_FORWARD_FIELDS,
            "port forward",
        )
        assert stats["created"] == 0
        assert stats["updated"] == 0
        assert stats["deleted"] == 0
        assert stats["unchanged"] == 1

    def test_mutation_failure_stops_sync(self):
        class FailingPfSense(FakePfSense):
            def request(self, method, path, body=None, params=None):
                if method == "POST":
                    raise PfSenseAPIError("HTTP 403: forbidden", code=403)
                return super().request(method, path, body, params)

        fake = FailingPfSense()
        stats = pfsense_sync._reconcile(
            fake,
            "/firewall/nat/port_forwards",
            "/firewall/nat/port_forward",
            [_forward("new-rule")],
            pfsense_sync.PORT_FORWARD_FIELDS,
            "port forward",
        )
        assert stats["created"] == 0


class TestApplyConfig:
    def test_full_flow(self):
        fake = FakePfSense()
        stats = pfsense_sync.apply_config(fake, UNIFI_CFG, PORTS)
        assert stats["port_forwards"]["created"] == 2
        assert stats["firewall_rules"]["created"] == 3
        assert stats["aliases"]["created"] == 0
        assert len(fake.port_forwards) == 2
        assert all(
            r["descr"].startswith(pfsense_sync.MARKER) for r in fake.port_forwards
        )

    def test_system_cfg_flow(self):
        fake = FakePfSense()
        stats = pfsense_sync.apply_config(fake, None, PORTS, system_cfg=SYSTEM_CFG)
        assert stats["aliases"]["created"] == 4
        assert {a["name"] for a in fake.aliases} == {
            "guest_portal_address",
            "guest_restricted",
            "corporate_network",
            "guest_portal_ports",
        }
        # all aliases are tagged, so their descr carries the marker
        assert all(a["descr"].startswith(pfsense_sync.MARKER) for a in fake.aliases)
        # "Test" (unsafe WAN accept) skipped; only the group rule is created
        assert stats["firewall_rules"]["created"] == 1
        assert fake.rules[0]["descr"] == "unifi:WAN_IN - block corp from wan"
        assert fake.rules[0]["destination"] == "corporate_network"
        # no port-forward rules in system_cfg
        assert stats["port_forwards"]["created"] == 0
        # any change must trigger an explicit firewall reload
        assert fake.applied is True

    def test_system_cfg_idempotent(self):
        fake = FakePfSense()
        pfsense_sync.apply_config(fake, None, PORTS, system_cfg=SYSTEM_CFG)
        calls_after_first = len(fake.calls)
        stats = pfsense_sync.apply_config(fake, None, PORTS, system_cfg=SYSTEM_CFG)
        assert stats["aliases"]["created"] == 0
        assert stats["aliases"]["updated"] == 0
        assert stats["aliases"]["deleted"] == 0
        assert stats["aliases"]["unchanged"] == 4
        assert stats["firewall_rules"]["created"] == 0
        assert stats["firewall_rules"]["unchanged"] == 1
        mutations = [
            c
            for c in fake.calls[calls_after_first:]
            if c[0] in ("POST", "PATCH", "DELETE")
        ]
        assert mutations == []
        # no change -> no reload either
        assert all(c[1] != "/firewall/apply" for c in fake.calls[calls_after_first:])

    def test_no_changes_no_mutations(self):
        # Seed pfSense with exactly what apply_config would create
        forwards = pfsense_sync.extract_port_forwards(UNIFI_CFG, PORTS)
        rules = pfsense_sync.extract_firewall_rules(UNIFI_CFG, PORTS)
        fake = FakePfSense(port_forwards=[dict(f) for f in forwards])
        fake.rules = [dict(r) for r in rules]

        stats = pfsense_sync.apply_config(fake, UNIFI_CFG, PORTS)

        assert stats["port_forwards"]["created"] == 0
        assert stats["port_forwards"]["updated"] == 0
        assert stats["port_forwards"]["deleted"] == 0
        assert stats["firewall_rules"]["created"] == 0
        mutations = [c for c in fake.calls if c[0] in ("POST", "PATCH", "DELETE")]
        assert mutations == []
