"""One-way firewall sync: UniFi controller config -> pfSense REST API.

The UniFi controller pushes the gateway's config (EdgeOS JSON) in the `cfg`
key of a `mgmt_cfg` setparam. This module translates the parts we understand
(port forwards and simple firewall rules) into pfSense API objects.

Only objects whose `descr` starts with the MARKER prefix are managed —
rules created directly on pfSense are never touched, and UniFi-originated
rules are easy to identify in the pfSense UI.
"""

import json
import logging
import urllib.parse

logger = logging.getLogger("unifi-gateway")

MARKER = "unifi:"

PORT_FORWARD_FIELDS = (
    "interface",
    "ipprotocol",
    "protocol",
    "source",
    "source_port",
    "destination",
    "destination_port",
    "target",
    "local_port",
    "disabled",
    "natreflection",
    "associated_rule_id",
)

FIREWALL_RULE_FIELDS = (
    "type",
    "interface",
    "ipprotocol",
    "protocol",
    "source",
    "source_port",
    "destination",
    "destination_port",
    "disabled",
    "log",
    "statetype",
)


def parse_cfg(raw):
    """Parse the controller cfg value: raw JSON or URL-encoded JSON."""
    if isinstance(raw, dict):
        return raw
    text = raw.strip().strip('"')
    for candidate in (text, urllib.parse.unquote(text)):
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("cfg is not parseable JSON")


def _pfsense_if_for_unifi_if(ports, unifi_ifname):
    """Map a UniFi port (e.g. 'eth0') to its pfSense interface ID."""
    for port in ports:
        if port.get("ifname") == unifi_ifname:
            return port.get("realif")
    return None


def _normalize_protocol(protocol):
    if not protocol or str(protocol).lower() in ("all", "any"):
        return None  # pfSense: null = any protocol
    proto = str(protocol).lower()
    if proto in ("both", "tcp_udp", "tcp-udp"):
        return "tcp/udp"
    return proto


def _first_port(port_value):
    """'8080:8090' -> '8080'; '8080' -> '8080'."""
    if not port_value:
        return None
    return str(port_value).split(":")[0].split("-")[0].strip()


def extract_port_forwards(cfg, ports):
    """Translate UniFi `port-forward` rules into pfSense port forward payloads.

    UniFi/EdgeOS:
        port-forward.rule.<id> = {description, forward-to {address, port},
                                  original-port, protocol}
    """
    pf = cfg.get("port-forward") or {}
    rules = pf.get("rule") or {}
    if not isinstance(rules, dict):
        return []

    wan_interface = (
        _pfsense_if_for_unifi_if(ports, pf.get("wan-interface"))
        or _pfsense_if_for_unifi_if(ports, "eth0")
        or next((p["realif"] for p in ports if p["type"].lower() == "wan"), None)
    )
    if not wan_interface:
        logger.warning("pfSense sync: cannot map a WAN interface for port forwards")
        return []

    desired = []
    for rule_id, rule in rules.items():
        if not isinstance(rule, dict):
            continue
        description = str(rule.get("description") or f"rule {rule_id}").strip()
        forward_to = rule.get("forward-to") or {}
        target = forward_to.get("address")
        original_port = rule.get("original-port")
        if not target or not original_port:
            logger.warning(
                "pfSense sync: skipping port-forward %r (no target/port)", description
            )
            continue
        local_port = forward_to.get("port") or _first_port(original_port)
        desired.append(
            {
                "interface": wan_interface,
                "ipprotocol": "inet",
                "protocol": _normalize_protocol(rule.get("protocol")) or "tcp",
                "source": "any",
                "source_port": None,
                "destination": "(self)",
                "destination_port": str(original_port),
                "target": str(target),
                "local_port": str(local_port),
                "disabled": False,
                "natreflection": None,
                # UniFi's auto-firewall behaviour: pass matching traffic
                "associated_rule_id": "pass",
                "descr": MARKER + description,
            }
        )
    return desired


def extract_firewall_rules(cfg, ports):
    """Translate simple UniFi `firewall` rules into pfSense filter rules.

    UniFi/EdgeOS: firewall.<name>.rule.<id> where name is e.g. WAN_IN,
    WAN_LOCAL, LAN_IN. Groups and advanced options are not translated.
    """
    firewall = cfg.get("firewall") or {}
    wan_if = next((p["realif"] for p in ports if p["type"].lower() == "wan"), None)
    lan_if = next((p["realif"] for p in ports if p["type"].lower() == "lan"), None)

    desired = []
    for fw_name, fw_def in firewall.items():
        if not isinstance(fw_def, dict):
            continue
        prefix = str(fw_name).upper().split("_")[0]
        if prefix == "WAN" and wan_if:
            interface = wan_if
        elif prefix == "LAN" and lan_if:
            interface = lan_if
        else:
            logger.debug("pfSense sync: skipping firewall group %r", fw_name)
            continue

        rules = fw_def.get("rule") or {}
        if not isinstance(rules, dict):
            continue
        for rule_id, rule in rules.items():
            if not isinstance(rule, dict):
                continue
            description = str(rule.get("description") or f"{fw_name} {rule_id}").strip()
            action = {"accept": "pass", "drop": "block", "reject": "reject"}.get(
                str(rule.get("action") or "").lower()
            )
            source = rule.get("source") or {}
            destination = rule.get("destination") or {}
            if "group" in source or "group" in destination:
                logger.warning(
                    "pfSense sync: rule %r uses address groups, not translated",
                    description,
                )
                continue
            if not action:
                logger.warning(
                    "pfSense sync: rule %r has unmappable action %r",
                    description,
                    rule.get("action"),
                )
                continue
            desired.append(
                {
                    "type": action,
                    "interface": [interface],
                    "ipprotocol": "inet",
                    "protocol": _normalize_protocol(rule.get("protocol")),
                    "source": str(source.get("address") or "any"),
                    "source_port": source.get("port") or None,
                    "destination": str(destination.get("address") or "any"),
                    "destination_port": destination.get("port") or None,
                    "disabled": False,
                    "log": str(rule.get("log") or "").lower() == "enable",
                    "statetype": "keep state",
                    "descr": MARKER + description,
                }
            )
    return desired


def _field_equal(existing, desired, field):
    a = existing.get(field)
    b = desired.get(field)
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return str(a).lower() == str(b).lower()


def _reconcile(client, list_path, single_path, desired, compare_fields, label):
    """Make pfSense managed rules converge to `desired`.

    pfSense object ids are volatile array indexes (they shift on every
    mutation), so the list is re-fetched before each single mutation and
    objects are matched by their marked descr instead of id.
    """
    stats = {"created": 0, "updated": 0, "deleted": 0, "unchanged": 0}

    def marked_name(rule):
        descr = str(rule.get("descr") or "")
        return descr[len(MARKER) :] if descr.startswith(MARKER) else None

    desired_by_name = {d["descr"][len(MARKER) :]: d for d in desired}
    max_steps = 2 * (len(desired) + 16) + 8

    for _step in range(max_steps):
        current = client.request("GET", list_path) or []
        existing = {}
        for rule in current:
            name = marked_name(rule)
            if name is not None:
                existing[name] = rule

        action = None
        for name, rule in desired_by_name.items():
            if name not in existing:
                action = ("create", name, rule, None)
                break
        if action is None:
            for name, rule in desired_by_name.items():
                if name in existing and any(
                    not _field_equal(existing[name], rule, f) for f in compare_fields
                ):
                    action = ("update", name, rule, existing[name])
                    break
        if action is None:
            for name, existing_rule in existing.items():
                if name not in desired_by_name:
                    action = ("delete", name, existing_rule, existing_rule)
                    break
        if action is None:
            stats["unchanged"] = len(desired_by_name)
            return stats

        op, name, rule, existing_rule = action
        try:
            if op == "create":
                client.request("POST", single_path, body=rule)
                stats["created"] += 1
                logger.info("pfSense sync: created %s %r", label, name)
            elif op == "update":
                client.request(
                    "PATCH", single_path, body=rule, params={"id": existing_rule["id"]}
                )
                stats["updated"] += 1
                logger.info("pfSense sync: updated %s %r", label, name)
            elif op == "delete":
                client.request(
                    "DELETE", single_path, params={"id": existing_rule["id"]}
                )
                stats["deleted"] += 1
                logger.info("pfSense sync: deleted %s %r", label, name)
        # Broad catch is deliberate: sync failures must never break the
        # inform loop, whatever the underlying exception is.
        except Exception as e:  # noqa: BLE001
            logger.error("pfSense sync: failed to %s %s %r: %s", op, label, name, e)
            return stats

    logger.warning("pfSense sync: %s reconciliation did not converge", label)
    return stats


def apply_config(client, cfg, ports):
    """Translate + push controller cfg to pfSense. Returns a stats dict."""
    port_forwards = extract_port_forwards(cfg, ports)
    firewall_rules = extract_firewall_rules(cfg, ports)

    stats = {
        "port_forwards": {"found": len(port_forwards)},
        "firewall_rules": {"found": len(firewall_rules)},
    }

    stats["port_forwards"].update(
        _reconcile(
            client,
            "/firewall/nat/port_forwards",
            "/firewall/nat/port_forward",
            port_forwards,
            PORT_FORWARD_FIELDS,
            "port forward",
        )
    )
    stats["firewall_rules"].update(
        _reconcile(
            client,
            "/firewall/rules",
            "/firewall/rule",
            firewall_rules,
            FIREWALL_RULE_FIELDS,
            "firewall rule",
        )
    )

    if (
        stats["port_forwards"]["created"]
        + stats["port_forwards"]["updated"]
        + stats["port_forwards"]["deleted"]
        + stats["firewall_rules"]["created"]
        + stats["firewall_rules"]["updated"]
        + stats["firewall_rules"]["deleted"]
    ):
        try:
            pending = client.request("GET", "/firewall/apply") or {}
            if not pending.get("applied", True):
                client.request("POST", "/firewall/apply")
                logger.info("pfSense sync: firewall changes applied")
        # Same deliberate broad catch: apply is best-effort after a good sync
        except Exception as e:  # noqa: BLE001
            logger.warning("pfSense sync: firewall apply check failed: %s", e)

    return stats
