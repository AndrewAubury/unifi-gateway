import configparser
from unittest.mock import patch

import pytest

from collectors.pfsense_api import (
    PfSenseAPIClient,
    PfSenseAPICollector,
    _parse_media_speed,
    _parse_uptime_seconds,
)

INTERFACES = [
    {
        "name": "wan",
        "descr": "CITYFIBRE",
        "hwif": "pppoe0",
        "macaddr": None,
        "ipaddr": "81.2.121.238",
        "subnet": "255.255.255.255",
        "media": None,
        "gateway": "81.2.121.237",
        "inbytes": 615217605385,
        "outbytes": 294061598320,
        "inpkts": 1266101943,
        "outpkts": 1166961745,
        "inerrs": 0,
        "outerrs": 0,
    },
    {
        "name": "lan",
        "descr": "LAN",
        "hwif": "igc1.102",
        "macaddr": "60:be:b4:03:5d:56",
        "ipaddr": "10.0.0.1",
        "subnet": "255.255.254.0",
        "media": "2500Base-T <full-duplex>",
        "gateway": None,
        "inbytes": 204502017666,
        "outbytes": 513862621015,
        "inpkts": 418499198,
        "outpkts": 524438523,
        "inerrs": 0,
        "outerrs": 253,
    },
    {
        # extra interface that must NOT match any configured port
        "name": "opt1",
        "descr": "VIRGINMEDIA",
        "hwif": "igc1.101",
        "macaddr": "60:be:b4:03:5d:56",
        "ipaddr": None,
        "subnet": None,
        "media": "2500Base-T <full-duplex>",
        "gateway": None,
        "inbytes": 0,
        "outbytes": 0,
        "inpkts": 0,
        "outpkts": 0,
        "inerrs": 0,
        "outerrs": 0,
    },
]

SYSTEM = {
    "platform": "pfSense",
    "cpu_usage": 2,
    "mem_usage": 27,
    "uptime": "14 Days 12 Hours 21 Minutes 56 Seconds",
}

LEASES = [
    {
        "ip": "10.0.0.3",
        "mac": "78:8c:b5:bf:0d:da",
        "hostname": "c310",
        "if": "opt8",
        "active_status": "static",
        "online_status": "active/online",
        "descr": "",
    },
    {
        "ip": "10.0.0.4",
        "mac": "f4:12:fa:53:f9:64",
        "hostname": "",
        "if": "lan",
        "active_status": "active",
        "online_status": "active/online",
        "descr": "no-hostname-client",
        "ends": "2026/10/31 08:00:00",
    },
    {
        "ip": "10.0.0.5",
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "old-laptop",
        "if": "lan",
        "active_status": "expired",
        "online_status": "idle/offline",
        "descr": "",
    },
]

ARP = [
    {
        "hostname": "?",
        "ip_address": "10.0.0.170",
        "mac_address": "94:2a:6f:4e:aa:f3 <small>(Ubiquiti Networks)</small>",
        "interface": "LAN",
    },
    {
        "hostname": "fan-controller",
        "ip_address": "10.0.1.230",
        "mac_address": "f4:12:fa:53:f9:64",
        "interface": "LAN",
    },
    {"hostname": "", "ip_address": "", "mac_address": "broken-entry"},
]

DNS = {"dnsserver": ["1.0.0.1", "1.1.1.1"]}


class FakeClient:
    def __init__(self):
        self.responses = {
            "/status/interfaces": list(INTERFACES),
            "/status/system": dict(SYSTEM),
            "/status/dhcp_server/leases": list(LEASES),
            "/diagnostics/arp_table": list(ARP),
            "/system/dns": dict(DNS),
        }
        self.calls = []

    def request(self, method, path, body=None, params=None):
        self.calls.append((method, path, body, params))
        return self.responses.get(path)


@pytest.fixture
def pfsense_config():
    cfg = configparser.ConfigParser()
    cfg.read_dict(
        {
            "global": {"pid_file": "test.pid"},
            "gateway": {
                "ports": '[{"ifname":"eth0","name":"WAN","type":"wan","realif":"wan","speed":2500},'
                '{"ifname":"eth1","name":"LAN","type":"lan","realif":"igc1.102"}]',
                "is_adopted": "True",
                "platform": "pfsense-api",
            },
            "pfsense": {
                "url": "https://10.0.0.1",
                "api_key": "testkey123",
            },
        }
    )
    return cfg


@pytest.fixture
def collector(pfsense_config, base_patches):
    with patch("collectors.pfsense_api.PfSenseAPIClient") as client_cls:
        client_cls.return_value = FakeClient()
        dc = PfSenseAPICollector(pfsense_config)
    dc.update()
    return dc


class TestClientConfig:
    def test_config_values(self, pfsense_config):
        client = PfSenseAPIClient(pfsense_config)
        assert client.base_url == "https://10.0.0.1"
        assert client.api_key == "testkey123"
        assert client.verify_ssl is False
        assert client.timeout == 30

    def test_env_overrides_config(self, pfsense_config, monkeypatch):
        monkeypatch.setenv("UNIFI_GW_PFSENSE_URL", "https://192.168.9.1")
        monkeypatch.setenv("UNIFI_GW_PFSENSE_API_KEY", "envkey")
        client = PfSenseAPIClient(pfsense_config)
        assert client.base_url == "https://192.168.9.1"
        assert client.api_key == "envkey"

    def test_missing_url_raises(self):
        cfg = configparser.ConfigParser()
        cfg.read_dict(
            {
                "global": {"pid_file": "test.pid"},
                "gateway": {"ports": "[]"},
                "pfsense": {"api_key": "k"},
            }
        )
        with pytest.raises(ValueError):
            PfSenseAPIClient(cfg)

    def test_missing_auth_raises(self, pfsense_config):
        pfsense_config.remove_option("pfsense", "api_key")
        with pytest.raises(ValueError):
            PfSenseAPIClient(pfsense_config)

    def test_username_password_auth(self, pfsense_config):
        pfsense_config.remove_option("pfsense", "api_key")
        pfsense_config.set("pfsense", "username", "admin")
        pfsense_config.set("pfsense", "password", "secret")
        client = PfSenseAPIClient(pfsense_config)
        assert client.api_key == ""


class TestParsers:
    def test_uptime(self):
        assert (
            _parse_uptime_seconds("14 Days 12 Hours 21 Minutes 56 Seconds") == 1254116
        )
        assert _parse_uptime_seconds("2 Hours") == 7200
        assert _parse_uptime_seconds("") is None
        assert _parse_uptime_seconds(None) is None

    def test_media(self):
        assert _parse_media_speed("2500Base-T <full-duplex>") == 2500
        assert _parse_media_speed("1000baseT") == 1000
        assert _parse_media_speed("") is None
        assert _parse_media_speed(None) is None
        assert _parse_media_speed("autoselect") is None


class TestCollector:
    def test_interface_matching(self, collector):
        # 'wan' matches by pfSense ID, 'igc1.102' by hardware interface
        assert set(collector.data["macs"]) == {"eth0", "eth1"}

    def test_macs(self, collector):
        assert collector.data["macs"]["eth1"] == "60:be:b4:03:5d:56"
        # PPPoE WAN has no MAC: falls back to a placeholder (config lan_mac is
        # used for the inform identity separately)
        assert collector.data["macs"]["eth0"] == "00:00:00:00:00:00"

    def test_addresses(self, collector):
        assert collector.data["ip"]["eth0"] == {
            "address": "81.2.121.238",
            "netmask": "255.255.255.255",
            "gateway": "81.2.121.237",
        }
        assert collector.data["ip"]["eth1"]["address"] == "10.0.0.1"
        assert "gateway" not in collector.data["ip"]["eth1"]

    def test_default_gateway(self, collector):
        assert collector.data["ip"]["eth0"]["gateway"] == "81.2.121.237"
        assert collector._get_default_gateway() == "81.2.121.237"

    def test_ifstat(self, collector):
        ifstat = collector.data["ifstat"]
        assert ifstat["eth0"]["rx_bytes"] == "615217605385"
        assert ifstat["eth0"]["tx_bytes"] == "294061598320"
        assert ifstat["eth0"]["tx_errors"] == "0"
        assert ifstat["eth1"]["rx_errors"] == "0"
        assert ifstat["eth1"]["tx_errors"] == "253"

    def test_bps_delta(self, collector):
        import time

        interfaces = collector.client.responses["/status/interfaces"]
        wan = interfaces[0]
        wan["inbytes"] += 5000
        collector._api_cache = {}
        collector._api_cache_time = {}
        # Windows time.time() ticks at ~15.6ms: guarantee a measurable delta
        time.sleep(0.05)
        collector.update()
        assert collector.data["ifstat"]["eth0"]["rx_bps"] > 0

    def test_speeds(self, collector):
        # eth0: forced via "speed": 2500 config (PPPoE has no media)
        # eth1: parsed from '2500Base-T <full-duplex>'
        assert collector.data["speeds"] == {"eth0": 2500, "eth1": 2500}

    def test_system_stats(self, collector):
        assert collector.data["system_stats"] == {"cpu": "2", "mem": "27"}

    def test_uptime(self, collector):
        assert collector.data["uptime"] == 1254116

    def test_dhcp_leases(self, collector):
        leases = collector.data["dhcp_leases"]
        # expired lease filtered out
        assert {l["ip"] for l in leases} == {"10.0.0.3", "10.0.0.4"}
        by_ip = {l["ip"]: l for l in leases}
        assert by_ip["10.0.0.4"]["hostname"] == "no-hostname-client"
        assert by_ip["10.0.0.4"]["expiry"] == "2026/10/31 08:00:00"
        assert by_ip["10.0.0.3"]["hostname"] == "c310"

    def test_nameservers(self, collector):
        assert collector.data["nameservers"] == ["1.0.0.1", "1.1.1.1"]

    def test_neighbors_sanitized(self, collector, base_patches):
        neighbors = collector._get_neighbors_raw()
        assert neighbors == [
            {"mac": "94:2a:6f:4e:aa:f3", "ip": "10.0.0.170"},
            {
                "mac": "f4:12:fa:53:f9:64",
                "ip": "10.0.1.230",
                "hostname": "fan-controller",
            },
        ]

    def test_api_failure_keeps_last_data(self, collector):
        from collectors.pfsense_api import PfSenseAPIError

        class FailingClient:
            def request(self, method, path, body=None, params=None):
                raise PfSenseAPIError("Connection failed: unreachable")

        collector.client = FailingClient()
        collector._api_cache = {}
        collector._api_cache_time = {}
        # Must not raise; per-cycle fields fall back to safe defaults
        collector.update()
        assert collector.data["dhcp_leases"] == []
        assert collector.data["system_stats"] == {"cpu": "0", "mem": "0"}
        # MACs are only collected at init and survive as last-known data
        assert collector.data["macs"]["eth1"] == "60:be:b4:03:5d:56"
