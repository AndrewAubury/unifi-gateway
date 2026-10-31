"""Dev scratch: live read-only smoke test of PfSenseAPICollector + inform payload.

Reads PF_URL and PF_KEY from the environment. Read-only: GETs only.
"""

import configparser
import json
import os
import time

from collectors.pfsense_api import PfSenseAPICollector
from unifi_protocol import create_inform

cfg = configparser.ConfigParser()
cfg.read_dict(
    {
        "global": {"pid_file": "test.pid"},
        "gateway": {
            "ports": '[{"ifname":"eth0","name":"WAN","type":"wan","realif":"wan","speed":2500},'
            '{"ifname":"eth1","name":"LAN","type":"lan","realif":"igc1.102"}]',
            "is_adopted": "False",
            "device": "UCG-Ultra",
            "device_display": "Cloud Gateway Ultra",
            "firmware": "4.1.13",
            "lan_ip": "10.0.0.1",
            "lan_mac": "60:be:b4:03:5d:56",
            "url": "http://controller:8080/inform",
            "isp_name": "CityFibre",
        },
        "pfsense": {
            "url": os.environ["PF_URL"],
            "api_key": os.environ["PF_KEY"],
        },
    }
)

dc = PfSenseAPICollector(cfg)
print("first cycle OK, waiting 12s for a real bps delta...")
time.sleep(12)
dc.update()

print("speeds:       ", dc.data.get("speeds"))
print("uptime (s):   ", dc.data.get("uptime"))
print("system stats: ", dc.data.get("system_stats"))
print("nameservers:  ", dc.data.get("nameservers"))
print("leases:       ", len(dc.data.get("dhcp_leases", [])), "active")
print("host table:   ", len(dc.data.get("host_table", [])), "hosts")
print("ip:           ", json.dumps(dc.data.get("ip")))
eth0 = dc.data.get("ifstat", {}).get("eth0", {})
print(
    "eth0 counters: rx_bytes=%s tx_bytes=%s rx_bps=%s tx_bps=%s"
    % (
        eth0.get("rx_bytes"),
        eth0.get("tx_bytes"),
        eth0.get("rx_bps"),
        eth0.get("tx_bps"),
    )
)

cfg.set("gateway", "is_adopted", "True")
inform = json.loads(create_inform(cfg, dc))
print("--- inform payload ---")
print(
    "model:        ",
    inform["model"],
    "/",
    inform["model_display"],
    "/",
    inform["version"],
)
print("isp_name:     ", inform.get("isp_name"))
print(
    "if_table:     ",
    [
        (e["name"], e.get("speed"), e.get("isp_name"), e.get("gateways"))
        for e in inform["if_table"]
    ],
)
print("network_table:", [(e["name"], e.get("speed")) for e in inform["network_table"]])
print("leases:       ", len(inform["ipv4_active_leases"]))
print(
    "lan host_tbl: ",
    len(
        next(
            e.get("host_table", [])
            for e in inform["network_table"]
            if e["name"] == "eth1"
        )
    ),
)
print("uptime field: ", inform["uptime"], "| system-stats:", inform["system-stats"])

print("--- pfSense firewall state (read-only) ---")
try:
    pfs = dc.client.request("GET", "/firewall/nat/port_forwards")
    print("port_forwards on pfSense:", len(pfs or []))
except Exception as e:
    print("port_forwards read failed:", e)
try:
    rules = dc.client.request("GET", "/firewall/rules")
    print("firewall rules on pfSense:", len(rules or []))
except Exception as e:
    print("firewall rules read failed:", e)
