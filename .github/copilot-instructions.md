<!-- Copilot / AI agent instructions for the Texecom Connect Python repo -->
# Quick orientation

This repository implements a Python decoder and example client for the Texecom Connect alarm protocol. The core responsibility is a TCP client that speaks the Texecom binary protocol, decodes messages, and exposes callbacks that callers can register handlers on.

+ Core engine: [../texecomConnect.py](../texecomConnect.py) — protocol implementation, message framing, CRC, sequencing, site data management, and the main event loop.
+ Protocol constants: [../texecomDefines.py](../texecomDefines.py) — all command/message IDs and lookups used across the codebase.
+ Example/integration: [../alarm-monitor.py](../alarm-monitor.py) — a reference runner that registers callbacks on the engine and integrates with MQTT (paho-mqtt).
+ Models: [../zone.py](../zone.py), [../area.py](../area.py), [../user.py](../user.py) — lightweight domain objects and their state/save helpers.
+ Dev/runtime: [../requirements.txt](../requirements.txt), Dockerfile and docker-compose*.yaml (repo root) for containerized runs.

# Big-picture architecture (how data flows)

- The process connects to a Texecom ComIP/SmartCom over TCP (one connection only). The engine logs in, requests event messages, and enters an event loop that either receives unsolicited messages or responds to commands.
- Events are decoded in `texecomConnect` and dispatched via callback registration methods (for example `on_zone_event`, `on_area_event`, `on_zone_details`, etc.). `alarm-monitor.py` attaches those callbacks to publish MQTT topics.
- `alarm-monitor.py` uses environment variables to control connection parameters and MQTT configuration. It publishes Home Assistant autodiscovery messages under `MQTT_CONFIG_TOPIC` and state messages under `MQTT_ROOT_TOPIC`.

# Important repository-specific conventions

- Environment-driven configuration: the project is configured primarily through environment variables. Key vars used in `alarm-monitor.py`: `TEXHOST`, `TEXPORT`, `UDLPASSWORD`, `BROKER_URL`, `BROKER_PORT`, `BROKER_USER`, `BROKER_PASS`, `MQTT_ROOT_TOPIC`, `MQTT_CONFIG_TOPIC`, `MQTT_AREAS`, `MQTT_AREAMAPS`.
- Callbacks over inheritance: the engine exposes `on_*` registration functions rather than subclassing. When adding behaviour, register callbacks early (before `event_loop()`), matching the pattern in `alarm-monitor.py`.
- Queued arm/disarm: arm/disarm/reset requests are queued via the `requestArmAreas*` methods and processed on the engine thread — do not attempt to send commands directly from different threads.
- Networking expectations: code assumes a single persistent TCP socket and handles panel-initiated disconnects. Avoid concurrent socket writes from outside `TexecomConnect` APIs.

# Integration points & external dependencies

- paho-mqtt (used in `alarm-monitor.py`) for MQTT integration; configuration uses basic username/password auth.
- crcmod is used for CRC calculation; `hexdump.py` is included locally and used for debug prints.
- The code issues `os.system("./send-message.sh ...")` on connection loss/restore — CI or container runs may not have this script. Note or stub it when running in environments without it.

# How to run and debug locally

1. Install dependencies: `pip install -r requirements.txt` (or use the provided Dockerfile/docker-compose for reproducible runs).
2. Edit `alarm-monitor.py` or set ENV vars to point to your ComIP/SmartCom and your MQTT broker.
3. Run: `python alarm-monitor.py` — the script prints timestamped logs and publishes MQTT messages.
4. If debugging protocol frames, enable flags in `TexecomConnect` (`print_network_traffic`, `log_verbose`) or enable `TexecomMqtt.log_mqtt_traffic` in `alarm-monitor.py`.

# What to watch for when editing

- Keep protocol IDs and timings in `texecomDefines.py` in sync — many methods assume those constants and `CMD_TIMEOUT` values.
- Avoid changing how callbacks are registered or invoked — `alarm-monitor.py` depends on the `on_*` registration API.
- If you add threads, respect the engine's single-socket model and use the provided `requestArmAreas*` helpers to enqueue commands.

# Examples (copyable)

- Run with env vars (example):
  - `TEXHOST=192.168.0.2 UDLPASSWORD=MYUDL BROKER_URL=192.168.1.10 python alarm-monitor.py`
- Enable verbose protocol logging: set `TexecomConnect.print_network_traffic = True` in small local run or temporarily patch for debugging.

# Editing policy for AI agents

- Make only targeted, minimal changes required to implement a feature or fix a bug. Prefer adding small helper functions and tests over large refactors.
- Preserve public APIs in `TexecomConnect` (method names and callback signatures). If you must change them, update `alarm-monitor.py` and document the change in this file.

If anything in this guide is unclear or you want me to expand a section (examples for tests, Docker run steps, or more code references), tell me what to add and I will iterate.

## Protocol specification PDFs (NDA)

- There are two master Texecom protocol specification PDFs placed in this package's folder (same directory as `texecomConnect.py`). They are the authoritative source for framing, command/response layouts, CRC, and timing details.
- These PDFs are provided under NDA. Do not paste, reproduce, or publish textual excerpts from them in public outputs, commits, or issue bodies. If you need to quote short passages for debugging or code comments, ask the repository owner for explicit permission first.
- How AI agents should use them:
  - Use the PDFs to verify and implement protocol byte layouts, exact field lengths, sequence rules, and timeouts (cross-check against `texecomDefines.py` and `texecomConnect.py`).
  - Use them as authoritative reference for adding new commands or decoding new message types, but implement changes as minimal, well-tested code updates (preserve public APIs).
  - Do not include PDF content verbatim in generated code, docs, or PR descriptions; instead, summarize the change (e.g., "adjusted header length per spec") and reference the local PDF path.

