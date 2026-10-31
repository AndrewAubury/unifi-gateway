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
            "destination": "(self)",
            "destination_port": "80",
            "target": "10.0.0.10",
            "local_port": "80",
            "disabled": False,
            "natreflection": None,
            "associated_rule_id": "pass",
            "descr": "unifi:web",
        }
        game = next(f for f in forwards if f["descr"] == "unifi:game range")
        # 'both' protocol maps to tcp/udp, missing forward-to port falls back
        # to the first port of the original range
        assert game["protocol"] == "tcp/udp"
        assert game["destination_port"] == "6000:6002"
        assert game["local_port"] == "6000"

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


class TestFirewallRuleExtraction:
    def test_translation(self):
        rules = pfsense_sync.extract_firewall_rules(UNIFI_CFG, PORTS)
        by_name = {r["descr"]: r for r in rules}
        # group-based rule is skipped
        assert len(rules) == 3
        assert by_name["unifi:allow http"] == {
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
            "descr": "unifi:allow http",
        }
        assert by_name["unifi:block bad subnet"]["type"] == "block"
        assert by_name["unifi:lan thing"]["interface"] == ["lan"]
        assert by_name["unifi:lan thing"]["type"] == "reject"
        assert by_name["unifi:lan thing"]["log"] is True


class FakePfSense:
    """Emulates pfSense list/object-id semantics: `id` is the array index,
    renumbered after every mutation."""

    def __init__(self, port_forwards=None):
        self.port_forwards = port_forwards or []
        self.rules = []
        self.calls = []

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
        if path == "/firewall/apply" and method == "GET":
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
        assert len(fake.port_forwards) == 2
        assert all(
            r["descr"].startswith(pfsense_sync.MARKER) for r in fake.port_forwards
        )

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
