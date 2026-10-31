# -*- coding: utf-8 -*-
"""Tests for UnifiGateway lifecycle — stop/restart must not require [gateway]."""

import importlib
import sys
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture
def _mock_daemon():
    """Replace Daemon base class with a stub that works on Windows."""

    class FakeDaemon:
        def __init__(self, pidfile="_.pid", **kw):
            self.pidfile = pidfile

        def stop(self):
            import os, time
            from signal import SIGTERM

            try:
                with open(self.pidfile, "r") as pf:
                    pid = int(pf.read().strip())
            except (IOError, FileNotFoundError):
                pid = None
            if not pid:
                return
            try:
                os.kill(pid, SIGTERM)
            except OSError:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)

        def restart(self):
            self.stop()
            self.start()

        def start(self):
            pass

    with patch.dict(sys.modules, {"daemon": MagicMock(Daemon=FakeDaemon)}):
        if "unifi_gateway" in sys.modules:
            del sys.modules["unifi_gateway"]
        import unifi_gateway

        yield unifi_gateway
    if "unifi_gateway" in sys.modules:
        del sys.modules["unifi_gateway"]


class TestStopWithoutGatewaySection:
    """The stop command only needs [global].pid_file to send SIGTERM.
    It must never touch the data collector or require [gateway]."""

    def test_init_without_gateway_section(self, tmp_path, _mock_daemon):
        conf = tmp_path / "minimal.conf"
        conf.write_text("[global]\npid_file = %s\n" % (tmp_path / "test.pid"))

        with patch.object(_mock_daemon, "CONFIG_FILE", str(conf)):
            gw = _mock_daemon.UnifiGateway()

        assert gw.datacollector is None
        assert gw._unhandled == {}

    def test_stop_reads_pidfile_and_kills(self, tmp_path, _mock_daemon):
        pid_file = tmp_path / "test.pid"
        conf = tmp_path / "minimal.conf"
        conf.write_text("[global]\npid_file = %s\n" % pid_file)
        pid_file.write_text("99999\n")

        with patch.object(_mock_daemon, "CONFIG_FILE", str(conf)):
            gw = _mock_daemon.UnifiGateway()

        with patch("os.kill") as mock_kill:
            mock_kill.side_effect = OSError("No such process")
            gw.stop()

        mock_kill.assert_called_once_with(99999, 15)  # SIGTERM = 15

    def test_restart_without_gateway_section(self, tmp_path, _mock_daemon):
        conf = tmp_path / "minimal.conf"
        conf.write_text("[global]\npid_file = %s\n" % (tmp_path / "test.pid"))

        with patch.object(_mock_daemon, "CONFIG_FILE", str(conf)):
            gw = _mock_daemon.UnifiGateway()

        with patch.object(gw, "start"):
            gw.restart()

        assert gw.datacollector is None


class TestRunInitializesCollector:
    """run() must initialize the collector before entering the inform loop."""

    def test_run_calls_init_collector(self, tmp_path, _mock_daemon):
        conf = tmp_path / "full.conf"
        conf.write_text(
            "[global]\npid_file = %s\n"
            "disable_broadcast = True\n"
            "[gateway]\n"
            "is_adopted = False\n"
            "ports = []\n"
            "firmware = 4.4.57.5578372\n" % (tmp_path / "test.pid")
        )
        with patch.object(_mock_daemon, "CONFIG_FILE", str(conf)):
            gw = _mock_daemon.UnifiGateway()

        assert gw.datacollector is None

        with patch.object(gw, "_init_collector") as mock_init:
            gw.run()

        mock_init.assert_called_once()


class TestSetParamHandling:
    """cfgversion and system_cfg setparam keys must be handled, not logged
    as unhandled TODOs."""

    def _make_gw(self, tmp_path, _mock_daemon):
        conf = tmp_path / "gw.conf"
        conf.write_text("[global]\npid_file = %s\n" % (tmp_path / "test.pid"))
        with patch.object(_mock_daemon, "CONFIG_FILE", str(conf)):
            return _mock_daemon.UnifiGateway(), conf

    def test_cfgversion_stored_not_unhandled(self, tmp_path, _mock_daemon):
        gw, conf = self._make_gw(tmp_path, _mock_daemon)
        with (
            patch.object(_mock_daemon, "CONFIG_FILE", str(conf)),
            patch.object(
                _mock_daemon, "UNHANDLED_LOG", str(tmp_path / "unhandled.json")
            ),
        ):
            gw._handle_response({"_type": "setparam", "cfgversion": "abc123"})
        assert gw.config.get("provisioned", "cfgversion") == "abc123"
        assert "setparam/cfgversion" not in gw._unhandled

    def test_system_cfg_parsed_and_dumped(self, tmp_path, _mock_daemon):
        import json

        gw, conf = self._make_gw(tmp_path, _mock_daemon)
        system_cfg = json.dumps(
            {
                "firewall": {
                    "all-ping": "enable",
                    "group": {
                        "network-group": {
                            "guest_network": {
                                "description": "guest",
                                "network": ["10.0.2.0/24"],
                            },
                        }
                    },
                },
                "system": {"timezone": "UTC"},
            }
        )
        with (
            patch.object(_mock_daemon, "CONFIG_FILE", str(conf)),
            patch.object(
                _mock_daemon, "UNHANDLED_LOG", str(tmp_path / "unhandled.json")
            ),
        ):
            gw._handle_response({"_type": "setparam", "system_cfg": system_cfg})

        assert "setparam/system_cfg" not in gw._unhandled
        assert gw._system_cfg["firewall"]["group"]["network-group"]["guest_network"]
        assert (tmp_path / "system_cfg.json").exists()

    def test_system_cfg_unparseable_recorded(self, tmp_path, _mock_daemon):
        gw, conf = self._make_gw(tmp_path, _mock_daemon)
        with (
            patch.object(_mock_daemon, "CONFIG_FILE", str(conf)),
            patch.object(
                _mock_daemon, "UNHANDLED_LOG", str(tmp_path / "unhandled.json")
            ),
        ):
            gw._handle_response({"_type": "setparam", "system_cfg": "not json {"})
        assert "setparam/system_cfg" in gw._unhandled
        assert gw._system_cfg is None
