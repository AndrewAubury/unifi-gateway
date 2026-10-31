# AGENTS.md

Guidance for AI coding agents working in this repo. See also `CLAUDE.md` (architecture reference with module map).

## Project

Python 3 daemon emulating a UniFi gateway (defaults to UCG-Ultra — USG/UGW3 is deprecated in UniFi Network, which freezes the controller at 10.6 while adopted). No package metadata files (no `pyproject.toml`); runtime deps are only `pycryptodome` + `psutil`.

## Commands

```bash
pip install -r requirements.txt        # runtime deps
pip install pytest                      # test deps (not in requirements.txt)

ruff check --exclude poc/ --exclude controller/ --ignore E401,E402 .   # exact CI lint command (no ruff config file exists)
python -m pytest tests/                # full suite
python -m pytest tests/test_factory.py::TestDetectPlatform::test_detects_openwrt   # single test

python unifi_gateway.py run            # run in foreground (works on any OS)
python unifi_gateway.py --help         # CLI smoke check (also run in CI)
```

- CI (`.github/workflows/ci.yml`) runs **ruff + an import check of every root module + `--help`** on Python 3.11–3.13. It does **not** run pytest — run tests locally.
- Tests are fully mocked (`tests/conftest.py` patches psutil/subprocess/filesystem), so they pass on any dev OS, including Windows. Collector tests use the `base_patches`/`bsd_patches` fixtures to fake platform behavior.

## Non-obvious architecture facts

- `datacollector.py` is a backward-compat shim delegating to `collectors.create_collector()`. **All new collector code goes in `collectors/`** (factory + platform auto-detection in `collectors/__init__.py`). Keep the shim importable — CI's import check exercises it, and `test_factory.py::TestBackwardCompat::test_datacollector_shim` guards it.
- Collector hierarchy: `BaseCollector` (psutil-based) → `LinuxCollector` / `FreeBSDCollector` → `OpenWRTCollector` / `OPNSenseCollector` / `PfSenseCollector`. Subclasses override `_get_default_gateway()` and `_get_neighbors_raw()`.
- `PfSenseAPICollector` (`collectors/pfsense_api.py`, platform `pfsense-api`) is the odd one out: it overrides **all** data collection to read a REMOTE pfSense via its REST API (for running the emulator in Docker off-router). Config section `[pfsense]`; API client supports `X-API-Key` or username/password (JWT auto-refresh). The collector caches API responses with short TTLs so one inform cycle costs ~4 GETs, and keeps last-known data when the API is down.
- pfSense firewall sync (`pfsense_sync.py`): the controller pushes the full EdgeOS-style gateway config in the mgmt_cfg `cfg` key or (Network 10.x) the `system_cfg` setparam key; `unifi_gateway.py` hands it to `pfsense_sync.apply_config()` which translates port-forwards + user firewall rules to pfSense and reconciles them. Firewall groups become `unifi:`-tagged pfSense aliases; UniFi baseline plumbing (state rules, guest rulesets, auto per-network rules) is filtered out; unrestricted accept-all WAN rules are skipped unless `[pfsense] sync_unsafe_rules = True`. Managed pfSense objects are tagged with the `unifi:` `descr` prefix — pfSense-native ones are never touched. **pfSense object ids are volatile array indexes** (they shift after every mutation), so the reconciler re-fetches the list before each single mutation. Dumps of the last controller cfg/system_cfg land in gitignored `conf/controller_cfg.json` / `conf/system_cfg.json` — inspect them when extending the translation.
- Config (`conf/unifi-gateway.conf`, INI) is **mutated at runtime** by controller responses and written back. The `[provisioned]` section is controller-owned — never hand-edit. The `ports` value is JSON embedded in an INI string (optional per-port `"speed"` in Mbps overrides the reported link speed; `isp_name` sets the WAN ISP shown in the portal).
- `conf/unifi-gateway.conf`, `conf/unhandled_commands.json`, and `conf/controller_cfg.json` are gitignored runtime files; the template is `conf/unifi-gateway.sample.conf`.
- `conf/unhandled_commands.json` (path via `UNIFI_GW_UNHANDLED_LOG`) is a living TODO of controller operations we don't act on (unknown response types, commands, setparam/mgmt_cfg keys). When you implement one, remove its entry from the log.
- Inform protocol (`unifi_protocol.py`): `TNBU` magic + flags that select AES-CBC vs AES-GCM and zlib vs snappy. Uses `MASTER_KEY` while unadopted, device-specific authkey after adoption.
- Adoption gotchas (verified on UniFi Network 10.6 self-hosted): modern controllers do **not** auto-register devices from an inform alone (unknown MAC → HTTP 404); the pending entry comes from the L2 discovery broadcast (UDP 10001 multicast), which needs `disable_broadcast = False` and, in Docker, `network_mode: host` for the adoption phase. UniFi OS models (UCG-Ultra, UXG) are NOT registrable via this classic path on some self-hosted installs (inform 404 regardless of MAC; their HTTPS inform endpoint often isn't published) — the UGW3 identity is the reliable fallback, at the cost of the controller's 10.6 update freeze. See the README troubleshooting note.
- Daemon commands `start`/`stop`/`restart` (double-fork `daemon.py`) are Unix-only; `run` works everywhere.

## Conventions & gotchas

- There is no ruff/formatter config file — the effective rules are whatever defaults the installed ruff ships. Modern ruff (0.17.x) enables far more than E/F by default (UP, I, BLE, PLW, RUF, ...), so the exact CI lint command currently reports **~90 pre-existing findings** on the tree. The only E/F-class issues are two unused imports (F401) in `tests/test_gateway_lifecycle.py`. Expect this noise when linting locally: don't mass-fix pre-existing findings in unrelated work, and don't add new ones.
- CI only triggers on pull requests to master and manual dispatch — **not on push** — so master's lint/test status isn't automatically checked.
- `poc/` is excluded from lint and packaging; don't treat it as production code.
- Env vars: `UNIFI_GW_CONFIG` (config path), `UNIFI_GW_LOG_LEVEL`, `UNIFI_GW_LOG_FILE`, `UNIFI_ADOPT_URL`/`UNIFI_ADOPT_KEY` (auto-adoption in Docker), `UNIFI_GW_UNHANDLED_LOG`, `UNIFI_GW_PFSENSE_URL`/`UNIFI_GW_PFSENSE_API_KEY` (override `[pfsense]` url/api_key).

## Release flow (`.github/workflows/release.yml`)

- Triggered by pushing a `v*` tag. Builds PyInstaller `--onefile` binaries → deb/rpm/FreeBSD pkg, plus a multi-arch Docker image, then publishes package repos to the `gh-pages` branch.
- **Exception: OpenWRT packages ship pure Python source** (depends on `python3-psutil`/`python3-pycryptodome` from the feeds) — never bundle a PyInstaller binary for OpenWRT. Both `opkg` (.ipk) and `apk` (.apk) formats are built via `pkg/openwrt/` scripts.
- Debian version is derived from the tag via sed on `debian/changelog` at build time — don't edit it manually for a release.
- FreeBSD builds run on a self-hosted runner (`scripts/setup-freebsd-runner.sh`).
