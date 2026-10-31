"""One-way firewall sync: UniFi controller config -> pfSense REST API.

The UniFi controller pushes the gateway's config (EdgeOS JSON) either in the
`cfg` key of a `mgmt_cfg` setparam or (on Network 10.x) as the `system_cfg`
setparam key. This module translates the parts we understand into pfSense API
objects:

- UniFi firewall groups (address/network/port) -> pfSense aliases
- UniFi port-forward rules                     -> pfSense NAT port forwards
- UniFi *user* firewall rules                  -> pfSense filter rules

UniFi's baseline plumbing (session-state rules, guest-portal rulesets,
auto-generated per-network rules) is deliberately NOT translated: pfSense
already state-matches and the user's pfSense policy must not be shadowed by
dozens of framework rules. Only rules visible as user intent in the UniFi UI
(Traffic & Firewall Rules) are synced.

Only objects whose `descr` starts with the MARKER prefix are managed —
rules/aliases created directly on pfSense are never touched, and
UniFi-originated objects are easy to identify in the pfSense UI.

Unrestricted accept rules on WAN (no source/destination restriction) are
skipped unless `allow_unsafe=True` — pfSense is the real firewall here, and a
misclicked "allow all" in the UniFi UI must not open it silently.
"""

import json
import logging
import re
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

ALIAS_FIELDS = ("name", "type", "address")

# UniFi rulesets that are pure baseline plumbing, never user intent
BASELINE_RULESET_PREFIXES = ("GUEST", "AUTHORIZED_GUESTS")

# Rule descriptions that identify auto-generated plumbing
BASELINE_RULE_HINTS = (
    "allow established/related sessions",
    "drop invalid state",
)

# firewall.<key> entries that are not rulesets
NON_RULESET_FIREWALL_KEYS = ("group", "ipv6-name", "options")

GROUP_TYPE_TO_ALIAS = {
    "address-group": "network",
    "network-group": "network",
    "ipv6-network-group": "network",
    "port-group": "port",
}

PORT_GROUP_TYPES = ("port-group",)
ADDRESS_GROUP_TYPES = ("address-group", "network-group", "ipv6-network-group")


def parse_cfg(raw):
    """Parse the controller cfg/system_cfg value: raw or URL-encoded JSON."""
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
    """Translate UniFi `port-forward` rules into pfSense port forward payloads."""
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
                # Auto-pass matching traffic: mirrors UniFi's auto-firewall
                "associated_rule_id": "pass",
                "descr": MARKER + description,
            }
        )
    return desired


def _alias_type_and_members(members, group_type):
    """Pick the pfSense alias type from the member content.

    pfSense rejects bare IPs in `network` aliases (they must be CIDRs) and
    CIDRs are unusual in `host` aliases, so:
      port-group               -> port
      any member has a CIDR /  -> network, bare IPs normalized to /32
      bare IPs/FQDNs only      -> host
    """
    members = [str(m) for m in members]
    if group_type == "port-group":
        return "port", members
    if any("/" in m for m in members):
        normalized = [m if "/" in m else f"{m}/32" for m in members]
        return "network", normalized
    return "host", members


def extract_aliases(system_cfg):
    """Translate UniFi firewall groups into pfSense alias payloads.

    Empty groups are skipped: the controller populates them dynamically
    (e.g. guest_network members) and pfSense aliases cannot be empty. Rules
    referencing skipped groups are skipped in turn.
    """
    group = ((system_cfg.get("firewall") or {}).get("group")) or {}
    aliases = []
    for group_type, groups in group.items():
        if group_type not in GROUP_TYPE_TO_ALIAS or not isinstance(groups, dict):
            continue
        for name, gdef in groups.items():
            if not isinstance(gdef, dict):
                continue
            members = (
                gdef.get("address") or gdef.get("network") or gdef.get("port") or []
            )
            if not members:
                logger.debug("pfSense sync: group %r is empty, no alias", name)
                continue
            if not re.fullmatch(r"[A-Za-z0-9_-]+", str(name)):
                logger.warning(
                    "pfSense sync: group name %r is not a valid alias name, skipped",
                    name,
                )
                continue
            alias_type, members = _alias_type_and_members(members, group_type)
            aliases.append(
                {
                    "name": str(name),
                    "type": alias_type,
                    "address": members,
                    "descr": MARKER
                    + str(gdef.get("description") or f"UniFi group {name}"),
                }
            )
    return aliases


def _resolve_group_ref(ref, alias_names, want_port=False):
    """Resolve an EdgeOS source/destination reference.

    Returns the address/port value ('any' for empty refs, an alias name for
    group refs, or a literal). Returns None when the rule should be skipped
    (group that has no alias because it is empty).
    """
    if not ref:
        return "any" if not want_port else None

    group = ref.get("group")
    if group:
        group_types = PORT_GROUP_TYPES if want_port else ADDRESS_GROUP_TYPES
        for group_type in group_types:
            group_name = group.get(group_type)
            if group_name:
                if group_name in alias_names:
                    return group_name
                # Group exists in UniFi but is empty (no alias was created)
                logger.warning(
                    "pfSense sync: rule references empty/unknown group %r, "
                    "rule skipped",
                    group_name,
                )
                return None
        return None  # group ref of an unsupported type for this half

    literal = ref.get("port") if want_port else ref.get("address")
    if want_port:
        return str(literal) if literal else None
    return str(literal) if literal else "any"


def _is_baseline_rule(rule):
    """True for UniFi's auto-generated plumbing rules."""
    description = str(rule.get("description") or "").lower()
    if "state" in rule:
        return True  # session-state plumbing (pf matches state implicitly)
    if any(hint in description for hint in BASELINE_RULE_HINTS):
        return True
    # auto-generated per-network rule
    return description.startswith("allow network ") and description.endswith("traffic")


def extract_firewall_rules(cfg, ports, alias_names=(), allow_unsafe=False):
    """Translate UniFi *user* firewall rules into pfSense filter rules.

    Baseline plumbing is filtered out; group references resolve to the
    pfSense aliases created by extract_aliases(). Unrestricted pass rules on
    WAN are skipped unless allow_unsafe=True (pfSense is the real firewall).
    """
    firewall = cfg.get("firewall") or {}
    wan_if = next((p["realif"] for p in ports if p["type"].lower() == "wan"), None)
    lan_if = next((p["realif"] for p in ports if p["type"].lower() == "lan"), None)
    alias_names = set(alias_names)

    # Normalise both layouts: canonical EdgeOS nests rulesets under
    # firewall.name.* (and ipv6-name.*); some pushes use firewall.<RULESET>
    # directly. IPv6 rulesets fall out below ("WANv6_IN" is unmappable).
    rulesets = {}
    for fw_name, fw_def in firewall.items():
        if fw_name in NON_RULESET_FIREWALL_KEYS or not isinstance(fw_def, dict):
            continue
        if fw_name in ("name", "ipv6-name"):
            for rs_name, rs_def in fw_def.items():
                if isinstance(rs_def, dict):
                    rulesets[rs_name] = rs_def
        else:
            rulesets[fw_name] = fw_def

    desired = []
    for fw_name, fw_def in rulesets.items():
        if any(fw_name.upper().startswith(p) for p in BASELINE_RULESET_PREFIXES):
            logger.debug("pfSense sync: skipping baseline ruleset %r", fw_name)
            continue

        prefix = str(fw_name).upper().split("_")[0]
        if prefix == "WAN" and wan_if:
            interface = wan_if
        elif prefix == "LAN" and lan_if:
            interface = lan_if
        else:
            logger.debug("pfSense sync: skipping unmappable ruleset %r", fw_name)
            continue

        rules = fw_def.get("rule") or {}
        if not isinstance(rules, dict):
            continue
        for rule_id, rule in rules.items():
            if not isinstance(rule, dict) or _is_baseline_rule(rule):
                continue
            description = str(rule.get("description") or f"{fw_name} {rule_id}").strip()
            action = {"accept": "pass", "drop": "block", "reject": "reject"}.get(
                str(rule.get("action") or "").lower()
            )
            if not action:
                logger.warning(
                    "pfSense sync: rule %r has unmappable action %r",
                    description,
                    rule.get("action"),
                )
                continue

            source = _resolve_group_ref(rule.get("source"), alias_names)
            destination = _resolve_group_ref(rule.get("destination"), alias_names)
            source_port = _resolve_group_ref(
                rule.get("source"), alias_names, want_port=True
            )
            destination_port = _resolve_group_ref(
                rule.get("destination"), alias_names, want_port=True
            )
            if source is None or destination is None:
                continue  # already warned inside _resolve_group_ref

            if (
                action == "pass"
                and interface == wan_if
                and source == "any"
                and destination == "any"
                and not allow_unsafe
            ):
                logger.warning(
                    "pfSense sync: SKIPPED unrestricted WAN accept rule %r "
                    "(enable [pfsense] sync_unsafe_rules to allow)",
                    description,
                )
                continue

            desired.append(
                {
                    "type": action,
                    "interface": [interface],
                    "ipprotocol": "inet",
                    "protocol": _normalize_protocol(rule.get("protocol")),
                    "source": source,
                    "source_port": source_port,
                    "destination": destination,
                    "destination_port": destination_port,
                    "disabled": False,
                    "log": str(rule.get("log") or "").lower() == "enable",
                    "statetype": "keep state",
                    "descr": MARKER + f"{fw_name} - {description}",
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
    if isinstance(a, (list, tuple)) or isinstance(b, (list, tuple)):
        a_set = {str(x) for x in a} if isinstance(a, (list, tuple)) else {str(a)}
        b_set = {str(x) for x in b} if isinstance(b, (list, tuple)) else {str(b)}
        return a_set == b_set
    return str(a).lower() == str(b).lower()


def _reconcile(
    client, list_path, single_path, desired, compare_fields, label, obj_name=None
):
    """Make pfSense managed objects converge to `desired`.

    pfSense object ids are volatile array indexes (they shift on every
    mutation), so the list is re-fetched before each single mutation and
    objects are matched by identity instead of id. `obj_name` extracts the
    identity of a managed object (or None for unmanaged); the default matches
    objects whose descr carries the MARKER.
    """
    stats = {"created": 0, "updated": 0, "deleted": 0, "unchanged": 0}

    if obj_name is None:

        def obj_name(obj):
            descr = str(obj.get("descr") or "")
            return descr[len(MARKER) :] if descr.startswith(MARKER) else None

    desired_by_name = {obj_name(d): d for d in desired}
    desired_by_name.pop(None, None)
    max_steps = 2 * (len(desired_by_name) + 16) + 8

    for _step in range(max_steps):
        current = client.request("GET", list_path) or []
        existing = {}
        for obj in current:
            name = obj_name(obj)
            if name is not None:
                existing[name] = obj

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


def _alias_obj_name(obj):
    descr = str(obj.get("descr") or "")
    name = obj.get("name")
    return str(name) if descr.startswith(MARKER) and name else None


def apply_config(client, cfg, ports, system_cfg=None, allow_unsafe=False):
    """Translate + push controller config to pfSense. Returns a stats dict.

    `cfg` is the classic mgmt_cfg `cfg` push; `system_cfg` is the Network
    10.x setparam push. Either may carry the full gateway config; where both
    would say the same thing, `cfg` wins.
    """
    configs = [c for c in (cfg, system_cfg) if c]
    if not configs:
        return {
            "aliases": {
                "found": 0,
                "created": 0,
                "updated": 0,
                "deleted": 0,
                "unchanged": 0,
            },
            "port_forwards": {
                "found": 0,
                "created": 0,
                "updated": 0,
                "deleted": 0,
                "unchanged": 0,
            },
            "firewall_rules": {
                "found": 0,
                "created": 0,
                "updated": 0,
                "deleted": 0,
                "unchanged": 0,
            },
        }

    aliases = extract_aliases(system_cfg or cfg or {})
    stats = {"aliases": {"found": len(aliases)}}
    stats["aliases"].update(
        _reconcile(
            client,
            "/firewall/aliases",
            "/firewall/alias",
            aliases,
            ALIAS_FIELDS,
            "alias",
            obj_name=_alias_obj_name,
        )
    )
    alias_names = {a["name"] for a in aliases}

    pf_source = next(
        (
            c
            for c in (cfg, system_cfg)
            if c and (c.get("port-forward") or {}).get("rule")
        ),
        None,
    )
    port_forwards = extract_port_forwards(pf_source, ports) if pf_source else []
    stats["port_forwards"] = {"found": len(port_forwards)}
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

    rules_source = cfg if (cfg or {}).get("firewall") else (system_cfg or {})
    firewall_rules = extract_firewall_rules(
        rules_source, ports, alias_names=alias_names, allow_unsafe=allow_unsafe
    )
    stats["firewall_rules"] = {"found": len(firewall_rules)}
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

    changed = sum(
        stats[key][op]
        for key in ("aliases", "port_forwards", "firewall_rules")
        for op in ("created", "updated", "deleted")
    )
    if changed:
        try:
            pending = client.request("GET", "/firewall/apply") or {}
            if not pending.get("applied", True):
                client.request("POST", "/firewall/apply")
                logger.info("pfSense sync: firewall changes applied")
        # Same deliberate broad catch: apply is best-effort after a good sync
        except Exception as e:  # noqa: BLE001
            logger.warning("pfSense sync: firewall apply check failed: %s", e)

    return stats
