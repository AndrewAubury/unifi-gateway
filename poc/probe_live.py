"""Dev scratch: probe pfSense REST API v2 read-only endpoints. Key via argv, never persisted."""

import json
import ssl
import sys
import urllib.request

KEY = sys.argv[1] if len(sys.argv) > 1 else ""
BASE = "https://10.0.0.1"

ENDPOINTS = [
    "/api/v2/status/interfaces",
    "/api/v2/status/system",
    "/api/v2/status/dhcp_server/leases",
    "/api/v2/diagnostics/arp_table",
    "/api/v2/firewall/nat/port_forwards",
    "/api/v2/firewall/rules?limit=5",
    "/api/v2/system/version",
    "/api/v2/system/dns",
    "/api/v2/firewall/apply",
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def probe(path):
    req = urllib.request.Request(
        BASE + path,
        headers={"X-API-Key": KEY, "Accept": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        body = json.loads(resp.read())
        print(f"=== {path} -> {body.get('status')} ({body.get('code')}) ===")
        data = body.get("data")
        if isinstance(data, list):
            print(f"  [{len(data)} items]")
            for item in data[:3]:
                print(" ", json.dumps(item)[:600])
        else:
            print(" ", json.dumps(data)[:600])
    except Exception as e:
        print(f"=== {path} -> ERROR: {type(e).__name__} {e} ===")
    print()


for ep in ENDPOINTS:
    probe(ep)
