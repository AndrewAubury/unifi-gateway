"""Remote pfSense collector — pulls gateway stats from a pfSense box via the
REST API package (pfSense-pkg-RESTAPI, API v2).

This is for running the emulator OFF the router (e.g. in a Docker container
on another machine): instead of reading local psutil data, every inform
field is sourced from the pfSense API.

Requires the 'pfSense API' package on the router (System > Package Manager)
and an API key (System > REST API > Keys) or a local username/password.
"""

import base64
import json
import logging
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import BaseCollector

logger = logging.getLogger("unifi-gateway")

API_PREFIX = "/api/v2"


class PfSenseAPIError(Exception):
    def __init__(self, message, code=None):
        self.code = code
        super().__init__(message)


class PfSenseAPIClient:
    """Minimal REST API v2 client. Supports X-API-Key or JWT auth."""

    def __init__(self, config):
        section = "pfsense"
        self.base_url = (
            os.environ.get("UNIFI_GW_PFSENSE_URL")
            or (config.get(section, "url") if config.has_option(section, "url") else "")
        ).rstrip("/")
        self.api_key = os.environ.get("UNIFI_GW_PFSENSE_API_KEY") or (
            config.get(section, "api_key")
            if config.has_option(section, "api_key")
            else ""
        )
        self.username = (
            config.get(section, "username")
            if config.has_option(section, "username")
            else ""
        )
        self.password = (
            config.get(section, "password")
            if config.has_option(section, "password")
            else ""
        )

        self.verify_ssl = config.getboolean(section, "verify_ssl", fallback=False)
        self.timeout = config.getint(section, "timeout", fallback=30)

        if not self.base_url:
            raise ValueError("pfSense API url not configured ([pfsense] url)")
        if not self.api_key and not (self.username and self.password):
            raise ValueError(
                "pfSense API auth not configured: set [pfsense] api_key "
                "or username + password"
            )

        if self.verify_ssl:
            self._ssl_context = ssl.create_default_context()
        else:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

        self._jwt = None
        self._jwt_expiry = 0

    def _basic_auth(self):
        raw = f"{self.username}:{self.password}".encode()
        return f"Basic {base64.b64encode(raw).decode('ascii')}"

    def _fetch_jwt(self):
        """Fetch a fresh JWT via /auth/jwt (basic auth)."""
        req = urllib.request.Request(
            self.base_url + API_PREFIX + "/auth/jwt",
            data=b"",
            headers={
                "Authorization": self._basic_auth(),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        resp = urllib.request.urlopen(
            req, timeout=self.timeout, context=self._ssl_context
        )
        body = json.loads(resp.read())
        self._jwt = body.get("data", {}).get("token")
        # Refresh well before the typical 1h expiry
        self._jwt_expiry = time.time() + 50 * 60
        if not self._jwt:
            raise PfSenseAPIError("pfSense JWT response contained no token")

    def _auth_headers(self, refresh_jwt=False):
        if self.api_key:
            return {"X-API-Key": self.api_key}
        if refresh_jwt or not self._jwt or time.time() >= self._jwt_expiry:
            self._fetch_jwt()
        return {"Authorization": f"Bearer {self._jwt}"}

    def request(self, method, path, body=None, params=None):
        """Perform an API call and return the response `data` field.

        Raises PfSenseAPIError on any failure.
        """
        url = self.base_url + API_PREFIX + path
        if params:
            url += "?" + urllib.parse.urlencode(params)

        refresh_jwt = False
        for _attempt in (1, 2):
            headers = {
                "Accept": "application/json",
                **self._auth_headers(refresh_jwt=refresh_jwt),
            }
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"

            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                resp = urllib.request.urlopen(
                    req, timeout=self.timeout, context=self._ssl_context
                )
                payload = json.loads(resp.read())
                if payload.get("code") and payload["code"] >= 400:
                    raise PfSenseAPIError(
                        payload.get("message")
                        or payload.get("status", "unknown error"),
                        code=payload["code"],
                    )
                return payload.get("data")
            except urllib.error.HTTPError as e:
                message = ""
                try:
                    message = json.loads(e.read()).get("message", "")
                except (ValueError, OSError):
                    pass
                if e.code == 401 and not self.api_key and not refresh_jwt:
                    # JWT expired mid-flight: refresh once and retry
                    refresh_jwt = True
                    continue
                raise PfSenseAPIError(
                    f"HTTP {e.code}: {message or e.reason}", code=e.code
                ) from e
            except urllib.error.URLError as e:
                raise PfSenseAPIError(f"Connection failed: {e.reason}") from e
            except json.JSONDecodeError as e:
                raise PfSenseAPIError(f"Invalid JSON response: {e}") from e
        raise PfSenseAPIError("unreachable")


def _parse_uptime_seconds(text):
    """Parse pfSense uptime strings like '14 Days 12 Hours 21 Minutes 56 Seconds'."""
    if not text:
        return None
    total = 0
    for value, unit in re.findall(r"(\d+)\s*(day|hour|minute|second)", text, re.IGNORECASE):
        multiplier = {"day": 86400, "hour": 3600, "minute": 60, "second": 1}[
            unit.lower()
        ]
        total += int(value) * multiplier
    return total or None


def _parse_media_speed(media):
    """Parse pfSense media strings like '2500Base-T <full-duplex>' -> Mbps."""
    if not media:
        return None
    match = re.match(r"(\d+)\s*base", media, re.IGNORECASE)
    return int(match.group(1)) if match else None


class PfSenseAPICollector(BaseCollector):
    """Collector that reads all data from a remote pfSense REST API."""

    def __init__(self, config):
        self.client = PfSenseAPIClient(config)
        self._api_cache = {}
        self._api_cache_time = {}
        super().__init__(config)

    # ── API access with caching ─────────────────────────────────────────

    def _api_get(self, path, ttl=30):
        """GET an API endpoint, cached for `ttl` seconds. Returns last known
        data on failure (may be None if never fetched)."""
        now = time.time()
        if path in self._api_cache and (now - self._api_cache_time.get(path, 0)) < ttl:
            return self._api_cache[path]
        try:
            data = self.client.request("GET", path)
        except PfSenseAPIError as e:
            logger.warning("pfSense API call %s failed: %s", path, e)
            return self._api_cache.get(path)
        self._api_cache[path] = data
        self._api_cache_time[path] = now
        return data

    def _find_interface(self, realif):
        """Match a configured realif against pfSense interface data.

        Matches the pfSense interface ID ('wan', 'lan', 'opt1'), the hardware
        interface ('igc0', 'pppoe0', 'igc1.102') or the description.
        """
        # Short TTL: all calls within one update() cycle share one fetch,
        # the next inform cycle (>=10s later) fetches fresh counters.
        data = self._api_get("/status/interfaces", ttl=5)
        if not data or not realif:
            return None
        wanted = realif.lower()
        for entry in data:
            if wanted in (
                str(entry.get("name") or "").lower(),
                str(entry.get("hwif") or "").lower(),
                str(entry.get("descr") or "").lower(),
            ):
                return entry
        return None

    # ── Data collectors (override psutil-based base) ────────────────────

    def _get_ifstat(self):
        ret = {}
        now = time.time()
        for port in self.ports:
            ifname = port["ifname"]
            entry = self._find_interface(port["realif"])
            if entry is None:
                logger.debug(
                    "pfSense interface not found for %s (%s)", ifname, port["realif"]
                )
                continue

            info = {
                "rx_bytes": str(entry.get("inbytes") or 0),
                "rx_packets": str(entry.get("inpkts") or 0),
                "rx_errors": str(entry.get("inerrs") or 0),
                "rx_dropped": "0",
                "rx_fifo": "0",
                "rx_frame": "0",
                "rx_compressed": "0",
                "rx_multicast": "0",
                "tx_bytes": str(entry.get("outbytes") or 0),
                "tx_packets": str(entry.get("outpkts") or 0),
                "tx_errors": str(entry.get("outerrs") or 0),
                "tx_dropped": "0",
                "tx_fifo": "0",
                "tx_frame": "0",
                "tx_compressed": "0",
                "tx_multicast": "0",
            }

            rx_bytes = int(info["rx_bytes"])
            tx_bytes = int(info["tx_bytes"])
            prev = self._prev_io.get(ifname)
            if prev and self._prev_time:
                elapsed = now - self._prev_time
                if elapsed > 0:
                    # max(0, ..) guards against counter resets after a reboot
                    info["rx_bps"] = max(0, int((rx_bytes - prev[0]) / elapsed))
                    info["tx_bps"] = max(0, int((tx_bytes - prev[1]) / elapsed))
                else:
                    info["rx_bps"] = 0
                    info["tx_bps"] = 0
            else:
                info["rx_bps"] = 0
                info["tx_bps"] = 0
            self._prev_io[ifname] = (rx_bytes, tx_bytes)
            ret[ifname] = info

        self._prev_time = now
        return ret

    def _get_interface_macs(self):
        ret = {}
        for port in self.ports:
            entry = self._find_interface(port["realif"])
            mac = (entry or {}).get("macaddr")
            if mac:
                ret[port["ifname"]] = mac.replace("-", ":").lower()
            else:
                logger.debug(
                    "No MAC from pfSense for %s (%s)", port["ifname"], port["realif"]
                )
                ret[port["ifname"]] = "00:00:00:00:00:00"
        return ret

    def _get_interface_addresses(self):
        ret = {}
        for port in self.ports:
            entry = self._find_interface(port["realif"])
            if not entry:
                continue
            ip_addr = entry.get("ipaddr")
            netmask = entry.get("subnet")
            if not ip_addr or not netmask:
                continue
            entry_data = {"address": ip_addr, "netmask": netmask}
            if port["type"].lower() == "wan" and entry.get("gateway"):
                entry_data["gateway"] = entry["gateway"]
            ret[port["ifname"]] = entry_data
        return ret

    def _get_default_gateway(self):
        for port in self.ports:
            if port["type"].lower() == "wan":
                entry = self._find_interface(port["realif"])
                if entry and entry.get("gateway"):
                    return entry["gateway"]
        return None

    def _get_speeds(self):
        """Per-ifname link speeds in Mbps: config override > API media."""
        ret = {}
        for port in self.ports:
            ifname = port["ifname"]
            if port.get("speed"):
                ret[ifname] = int(port["speed"])
                continue
            entry = self._find_interface(port["realif"])
            speed = _parse_media_speed((entry or {}).get("media"))
            if speed:
                ret[ifname] = speed
        return ret

    def _get_dhcp_leases(self):
        data = self._api_get("/status/dhcp_server/leases", ttl=30)
        if not data:
            return []
        leases = []
        for lease in data:
            if lease.get("active_status") in ("expired", "released", "disabled"):
                continue
            entry = {"ip": lease["ip"], "mac": lease["mac"]}
            hostname = lease.get("hostname") or lease.get("descr")
            if hostname:
                entry["hostname"] = hostname
            if lease.get("ends"):
                entry["expiry"] = lease["ends"]
            leases.append(entry)
        return leases

    def _get_neighbors_raw(self):
        data = self._api_get("/diagnostics/arp_table", ttl=120)
        if not data:
            return []
        neighbors = []
        for row in data:
            mac = (
                (row.get("mac_address") or "").split()[0]
                if row.get("mac_address")
                else ""
            )
            # MACs can carry an HTML vendor suffix: '0c:...:53 <small>(...)</small>'
            mac = mac.strip().lower()
            ip = (row.get("ip_address") or "").strip()
            if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or not ip:
                continue
            entry = {"mac": mac, "ip": ip}
            hostname = (row.get("hostname") or "").strip()
            if hostname and hostname not in ("?", "*"):
                entry["hostname"] = hostname
            neighbors.append(entry)
        return neighbors

    def _get_nameservers(self):
        data = self._api_get("/system/dns", ttl=60)
        nameservers = (data or {}).get("dnsserver") or []
        if nameservers:
            return nameservers
        logger.warning("No nameservers from pfSense API, using fallback")
        return ["8.8.8.8", "8.8.4.4"]

    def _get_system_stats(self):
        data = self._api_get("/status/system", ttl=30)
        if not data:
            return {"cpu": "0", "mem": "0"}
        return {
            "cpu": str(int(data.get("cpu_usage") or 0)),
            "mem": str(int(data.get("mem_usage") or 0)),
        }

    def _get_uptime(self):
        data = self._api_get("/status/system", ttl=30)
        return _parse_uptime_seconds((data or {}).get("uptime"))

    def update(self):
        super().update()
        self.data["speeds"] = self._get_speeds()
        uptime = self._get_uptime()
        if uptime:
            self.data["uptime"] = uptime
