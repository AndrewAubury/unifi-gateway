# UniFi Gateway Emulator  [![Build & Release](https://github.com/amd989/unifi-gateway/actions/workflows/release.yml/badge.svg)](https://github.com/amd989/unifi-gateway/actions/workflows/release.yml)

A Python 3 daemon that emulates a UniFi Cloud Gateway (UCG-Ultra) to a UniFi Controller. This allows non-Ubiquiti routers (OpenWRT, OPNSense, pfSense, or any Linux/FreeBSD router) to appear in the UniFi Controller UI and report network statistics.

> **Why a UCG-Ultra and not a USG?** UniFi Security Gateways (USG/UGW3) are deprecated: UniFi Network will not update past version 10.6 while a USG remains adopted. The emulator therefore identifies as a supported Cloud Gateway so your controller keeps updating. Model, display name, and firmware are all configurable (`device`, `device_display`, `firmware` in the config).

> **Controller never lists the emulated UCG as adoptable?** Some self-hosted deployments (e.g. UniFi Network 10.6 via UniFi OS/Podman-style install scripts) only register classic EdgeOS gateways via Layer-2 discovery + HTTP inform — UniFi OS models (UCG/UXG) use a different adoption handshake those installs don't serve. Symptoms: inform returns HTTP 404 for a fresh MAC and no pending device ever appears, even with broadcasts enabled. Workaround: adopt with the legacy identity (`device = UGW3`, `device_display = UniFi-Gateway-3`, `firmware = 4.4.18.5052168`) — note this reintroduces the controller's 10.6 update freeze. Also note that these controllers create the pending entry from the discovery broadcast (UDP 10001 multicast), not from the inform itself: the broadcast must be enabled (`disable_broadcast = False`) and the container needs `network_mode: host` to reach the LAN during adoption.

## How It Works

The daemon runs alongside your non-Ubiquiti router and periodically sends "inform" packets to your UniFi Controller — the same binary protocol that real UniFi devices use. The controller sees a Cloud Gateway and displays its stats (interfaces, traffic, connected clients, routes, etc.) in the dashboard. When running remotely (pfSense API mode), the daemon can live in a Docker container anywhere on your LAN and pull all stats from the router over its REST API.

Your UniFi APs, switches, and other devices continue connecting to the controller normally. This project fills the "gateway" slot so the controller has a complete view of your network topology.

```
┌──────────────────┐     inform (HTTP POST)     ┌───────────────────┐
│  This Daemon     │ ─────────────────────────► │  UniFi Controller │
│  (emulates UGW3) │                            │                   │
└────────┬─────────┘                            │  Sees complete    │
         │ reads stats from                     │  network topology │
┌────────▼─────────┐                            │                   │
│  Your Router     │     UniFi APs/Switches ──► │                   │
│  (OPNSense/etc)  │     also inform normally   └───────────────────┘
└──────────────────┘
```

## Requirements

- A running UniFi Controller (self-hosted or Cloud Key)
- Network access from the daemon to the controller's `/inform` endpoint

## Installation

### Debian / Ubuntu (apt)

```bash
curl -fsSL https://amd989.github.io/unifi-gateway/setup-apt.sh | sudo bash
sudo apt install unifi-gateway
```

### RHEL / Rocky / Fedora (dnf)

```bash
curl -fsSL https://amd989.github.io/unifi-gateway/setup-rpm.sh | sudo bash
sudo dnf install unifi-gateway
```

### OpenWRT

The OpenWRT packages ship pure Python source and depend on `python3`, `python3-psutil`, and `python3-pycryptodome` from the OpenWRT feeds — keeping the package tiny for flash-constrained devices.

```bash
# Auto-detects apk (25.12+) or opkg (older)
curl -fsSL https://amd989.github.io/unifi-gateway/setup-openwrt.sh | sh
```

Then install with whichever package manager your version uses:

```bash
# OpenWRT 25.12+ (apk)
apk add unifi-gateway

# OpenWRT pre-25.12 (opkg)
opkg install unifi-gateway
```

### FreeBSD / OPNSense / pfSense (pkg)

```bash
curl -fsSL https://amd989.github.io/unifi-gateway/setup-pkg.sh | sudo sh
sudo pkg install unifi-gateway
```

### Docker

```bash
docker pull ghcr.io/amd989/unifi-gateway:latest
docker compose up -d
```

See the [Docker section](#docker) below for details.

### Standalone Binaries

Pre-built binaries are also available from [Releases](https://github.com/amd989/unifi-gateway/releases) if you prefer manual installation.

| Platform | Binary |
|---|---|
| Linux x86_64 | `unifi-gateway-linux-amd64` |
| Linux ARM64 | `unifi-gateway-linux-arm64` |
| Linux ARMv7 | `unifi-gateway-linux-armhf` |
| FreeBSD x86_64 | `unifi-gateway-freebsd-amd64` |

### From Source

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

Copy the sample config and edit it:

```bash
cp conf/unifi-gateway.sample.conf conf/unifi-gateway.conf
```

Edit `conf/unifi-gateway.conf`:

```ini
[gateway]
# Map UniFi logical ports to your real system interfaces
ports = [ { "ifname": "eth0", "name": "WAN", "type": "wan", "realif": "eth0" }, { "ifname": "eth1", "name": "LAN", "type": "lan", "realif": "br-lan" } ]

# Your LAN-side IP and MAC (how the controller identifies this device)
lan_ip = 192.168.1.1
lan_mac = aa:bb:cc:dd:ee:ff
```

The `realif` values must match your actual system interface names (check with `ip link` on Linux or `ifconfig` on FreeBSD).

### 3. Adopt to controller

```bash
python unifi_gateway.py set-adopt -s http://your-controller:8080/inform
```

The first run sends a discovery inform. Go to the UniFi Controller UI, find the new "USG" device, and click **Adopt**. Then run `set-adopt` again to complete the handshake:

```bash
python unifi_gateway.py set-adopt -s http://your-controller:8080/inform
```

### 4. Run

```bash
# Foreground (recommended for initial testing)
python unifi_gateway.py run

# Background daemon (Linux only)
python unifi_gateway.py start

# Stop / restart
python unifi_gateway.py stop
python unifi_gateway.py restart
```

## Platform Setup

### OpenWRT

The daemon works with OpenWRT's default dnsmasq DHCP server. Typical interface mapping:

```ini
ports = [ { "ifname": "eth0", "name": "WAN", "type": "wan", "realif": "eth0" }, { "ifname": "eth1", "name": "LAN", "type": "lan", "realif": "br-lan" } ]
```

DHCP leases are auto-detected at `/tmp/dhcp.leases`.

### OPNSense (FreeBSD)

The daemon auto-detects FreeBSD and uses `arp -an` for the neighbor table, `netstat -rn` for routing. It supports KEA DHCP (OPNSense's default DHCP server) with auto-detection of the lease file at `/var/db/kea/kea-leases4.csv`.

Typical interface mapping (check your interfaces with `ifconfig`):

```ini
ports = [ { "ifname": "eth0", "name": "WAN", "type": "wan", "realif": "vmx0" }, { "ifname": "eth1", "name": "LAN", "type": "lan", "realif": "vmx1" } ]
dhcp_lease_file = /var/db/kea/kea-leases4.csv
dhcp_lease_format = kea
```

Recommended setup using a Python virtual environment:

```bash
python3 -m venv /opt/unifi-gateway/venv
/opt/unifi-gateway/venv/bin/pip install -r requirements.txt
/opt/unifi-gateway/venv/bin/python unifi_gateway.py set-adopt -s http://your-controller:8080/inform
/opt/unifi-gateway/venv/bin/python unifi_gateway.py run
```

### pfSense (FreeBSD)

Same as OPNSense but uses ISC dhcpd instead of KEA:

```ini
dhcp_lease_file = /var/dhcpd/var/db/dhcpd.leases
dhcp_lease_format = isc
```

### pfSense — remote via REST API (Docker)

If you'd rather NOT install anything on your pfSense box, run the emulator in a Docker container on another machine and pull all stats over pfSense's REST API. This requires the third-party [pfSense REST API package](https://github.com/pfrest/pfSense-pkg-RESTAPI) on the router:

1. Install the package on pfSense (see the [install docs](https://pfrest.org/INSTALL_AND_CONFIG/); pick the `.pkg` matching your pfSense version).
2. Create an API key: pfSense webConfigurator → **System → REST API → Keys → Add Key**. The key's privileges follow the creating user (an admin-created key is needed for the firewall sync below).
3. Configure the emulator with `platform = pfsense-api` and a `[pfsense]` section. `realif` values are pfSense interface IDs (`wan`, `lan`, `opt1`, ...) — you can also use hardware names (`igc0`, `igc1.102`) or descriptions:

```ini
[gateway]
platform = pfsense-api
ports = [ { "ifname": "eth0", "name": "WAN", "type": "wan", "realif": "wan", "speed": 2500 }, { "ifname": "eth1", "name": "LAN", "type": "lan", "realif": "lan" } ]
lan_ip = 10.0.0.1        ; your pfSense LAN IP
lan_mac = 60:be:b4:03:5d:56
isp_name = CityFibre     ; optional: WAN ISP name shown in the portal

[pfsense]
url = https://10.0.0.1
api_key = YOUR_API_KEY
verify_ssl = False       ; pfSense self-signed certificate
```

Notes:

- Interface counters, DHCP leases, ARP/neighbor tables, DNS servers, CPU/RAM, uptime, and link speeds are all read from the API (a few cached GETs per inform cycle; the last known data is kept if pfSense is briefly unreachable).
- The optional per-port `"speed"` (Mbps) overrides the reported link speed — useful for PPPoE WANs, where pfSense reports no media speed, or to force 2.5 Gb ports. Without it, the speed is parsed from the interface's media (e.g. `2500Base-T`).
- Credentials can also be provided via `UNIFI_GW_PFSENSE_URL` / `UNIFI_GW_PFSENSE_API_KEY` environment variables instead of the config file, and `username`/`password` is supported as an alternative to `api_key` (JWT is fetched and refreshed automatically).

#### Firewall / port-forwarding sync (UniFi → pfSense)

Port forwards and simple firewall rules you create in the UniFi UI are pushed to the gateway by the controller and **translated to pfSense** via the REST API:

- Only rules tagged with the `unifi:` description prefix are managed — rules you created directly on pfSense are never touched or removed.
- Enabled by default whenever `[pfsense]` is configured; disable with `sync_firewall = False` in the `[pfsense]` section.
- Port forwards map to pfSense NAT port forwards (`(self)` destination, auto-pass); simple accept/drop/reject firewall rules with source/destination/port translate to pfSense filter rules. Rules using UniFi address groups are currently skipped and logged.
- The full config UniFi pushes is dumped to `conf/controller_cfg.json` (gitignored) for inspection.

Note the limits of one-way sync: UniFi's UI always displays the rules stored in its own database, so port forwards created directly on pfSense keep working on the router but will not be listed inside UniFi.

### Generic Linux (Debian, Ubuntu, etc.)

Works out of the box. Uses `/proc/net/dev` for multicast counters, `/proc/net/route` for default gateway, and `/etc/resolv.conf` for nameservers.

## Docker

### Build and run

```bash
docker build -t unifi-gateway .
docker run -d --name unifi-gateway --network host \
  -v $(pwd)/conf:/app/conf \
  unifi-gateway
```

### Docker Compose

```bash
docker compose up -d
```

For automatic adoption on first start, set the `UNIFI_ADOPT_URL` environment variable in `docker-compose.yml`:

```yaml
environment:
  - UNIFI_ADOPT_URL=http://your-controller:8080/inform
```

**Note:** `network_mode: host` is only needed for LOCAL collectors that read the host's real network interfaces (Linux only). In pfSense remote mode (`platform = pfsense-api`) the daemon only talks HTTP, so plain bridge networking works fine and the compose file defaults to it.

## Service Management

Packages automatically install and enable the service. After configuring, just start it:

| Platform | Start | Logs |
|---|---|---|
| systemd (Debian/Ubuntu/RHEL) | `sudo systemctl start unifi-gateway` | `journalctl -u unifi-gateway -f` |
| rc.d (FreeBSD/OPNSense) | `sudo service unifi_gateway start` | `tail -f /var/log/unifi-gateway.log` |
| procd (OpenWRT) | `/etc/init.d/unifi-gateway start` | `logread -e unifi-gateway` |

Updates are handled by your package manager: `apt upgrade`, `dnf upgrade`, `opkg upgrade`, `apk upgrade`, or `pkg upgrade`.

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `UNIFI_GW_CONFIG` | `conf/unifi-gateway.conf` | Path to config file |
| `UNIFI_GW_LOG_LEVEL` | `DEBUG` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `UNIFI_GW_LOG_FILE` | *(stderr)* | Log to file instead of stderr |
| `UNIFI_ADOPT_URL` | *(none)* | Controller inform URL for automatic adoption on start |
| `UNIFI_ADOPT_KEY` | *(none)* | Auth key for auto-adoption (optional, rarely needed) |
| `UNIFI_GW_PFSENSE_URL` | *(none)* | Overrides `[pfsense]` url |
| `UNIFI_GW_PFSENSE_API_KEY` | *(none)* | Overrides `[pfsense]` api_key |
| `UNIFI_GW_VERIFY_CONTROLLER_SSL` | `True` | Verify TLS cert when the inform URL is `https://` (for self-signed controller certs set to `False`, or `verify_controller_ssl` in `[gateway]`) |

### Config File (`conf/unifi-gateway.conf`)

#### `[global]`

| Key | Default | Description |
|---|---|---|
| `pid_file` | `unifi-gateway.pid` | PID file path for daemon mode |
| `disable_broadcast` | `True` | Disable UDP multicast discovery |

#### `[gateway]`

| Key | Default | Description |
|---|---|---|
| `ports` | *(required)* | JSON list mapping UniFi ports to real interfaces; optional per-port `speed` (Mbps) overrides the reported link speed |
| `lan_ip` | *(required)* | LAN IP address |
| `lan_mac` | *(required)* | LAN MAC address |
| `firmware` | `4.1.13` | Reported firmware version |
| `device` | `UCG-Ultra` | Device model string |
| `device_display` | `Cloud Gateway Ultra` | Display name |
| `use_aes_gcm` | `False` | Use AES-GCM encryption (set by controller) |
| `hostname` | *(auto-detected)* | Override reported hostname |
| `isp_name` | *(none)* | WAN ISP name reported to the controller |
| `dhcp_lease_file` | *(auto-detected)* | Path to DHCP lease file |
| `dhcp_lease_format` | `dnsmasq` | Lease format: `dnsmasq`, `isc`, or `kea` |
| `ping_target` | `ping.ubnt.com` | Host for latency measurement |
| `speedtest_file` | `./speedtest.json` | Path to speedtest results JSON |
| `platform` | `auto` | Collector selection: `auto`, `linux`, `openwrt`, `freebsd`, `opnsense`, `pfsense` (local), or `pfsense-api` (remote REST API) |
| `discovery_platform` | `UNIFI-GW` | Platform string in UDP discovery broadcasts |

#### `[pfsense]` (remote mode)

| Key | Default | Description |
|---|---|---|
| `url` | *(none)* | pfSense base URL (e.g. `https://10.0.0.1`) |
| `api_key` | *(none)* | REST API key (`X-API-Key`; System → REST API → Keys) |
| `username` / `password` | *(none)* | Alternative auth (JWT fetched and auto-refreshed) |
| `verify_ssl` | `False` | Verify the pfSense TLS certificate |
| `sync_firewall` | `True` | Apply UniFi port-forward/firewall rules to pfSense |
| `timeout` | `30` | API request timeout (seconds) |

#### `[provisioned]`

Populated automatically by the controller after adoption. Do not edit manually.

## Speed Test

The controller can trigger speed tests. Install `speedtest-cli` for this to work:

```bash
pip install speedtest-cli
```

Results are saved to `speedtest.json` and reported in the next inform cycle.

## Architecture

| Module | Purpose |
|---|---|
| `unifi_gateway.py` | Entry point, inform loop, controller response handling, adoption, pfSense firewall sync wiring |
| `unifi_protocol.py` | TNBU binary protocol: AES-CBC/GCM encryption, zlib/snappy compression, JSON payload construction |
| `datacollector.py` | Backward-compat shim delegating to `collectors.create_collector()` |
| `collectors/` | Platform-aware data collection: psutil-based (Linux/FreeBSD/OpenWRT/OPNSense/pfSense) plus the remote `pfsense-api` REST API collector |
| `pfsense_sync.py` | One-way UniFi → pfSense firewall/port-forward sync over the pfSense REST API |
| `tools.py` | Helper functions for building `if_table` and `network_table` structures |
| `tlv.py` | TLV encoding for UDP discovery packets |
| `daemon.py` | Unix daemon (double-fork, PID file) |

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

This project builds upon and was inspired by:

- [stephanlascar/unifi-gateway](https://github.com/stephanlascar/unifi-gateway) — original UniFi Gateway emulator
- [qvr/unifi-gateway](https://github.com/qvr/unifi-gateway) — Python 3 port, FreeBSD support, AES-GCM encryption

Protocol documentation:

- [jk-5/unifi-inform-protocol](https://github.com/jk-5/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)
