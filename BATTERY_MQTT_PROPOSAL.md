# Battery MQTT Proposal

This document proposes how to expose per-device battery state to Home Assistant via MQTT discovery and state topics, and outlines minimal code changes to implement it.

## Goals
- Expose a battery sensor for each device (panel, keypads, sounders, and sensors).
- Ensure Home Assistant associates battery sensors with the same `device` as existing binary sensors / alarm entities by using identical `device.identifiers`.
- Prefer percentage (0-100) when available; otherwise publish voltage and include conversion guidance.

## Topics and naming
- Config (Home Assistant discovery root) examples use `MQTT_CONFIG_TOPIC` env var (default in repo: `MQTT_CONFIG_TOPIC`).
- State topics use `MQTT_ROOT_TOPIC` env var (default: `MQTT_ROOT_TOPIC`).

Recommended topics (string examples):
- Discovery config for battery: `<CONFIG_ROOT>/sensor/<name>_battery/config`
- Battery state topic: `<ROOT>/sensor/<name>_battery/state`

Where `<name>` is the same normalized name used by existing code (lowercased `zone.text` with spaces -> underscores). This keeps naming consistent with `TexecomMqtt.zone_details_callback`.

## Discovery payload (battery sensor)
Example discovery JSON published retained=True to `<CONFIG_ROOT>/sensor/front_door_battery/config`:

```json
{
  "name": "front_door_battery",
  "state_topic": "alarm_unconfig/sensor/front_door_battery/state",
  "unit_of_measurement": "%",
  "device_class": "battery",
  "unique_id": "Premier168.front_door.battery",
  "device": {
    "name": "Texecom Premier168 168",
    "identifiers": ["texecom", "<panel_unique_id>"],
    "manufacturer": "Texecom",
    "model": "Premier168 168"
  }
}
```

- `device.identifiers` MUST match the `device.identifiers` used in the binary sensor / area discovery messages for HA to link entities to the same device. Replace the current hard-coded placeholder `"123456789"` with a stable identifier derived from the panel identification (see `get_panel_identification()`).

## State payloads
- Preferred: publish battery percent (integer 0-100) as plain payload to `<ROOT>/sensor/<name>_battery/state`, e.g. `87`.
- If only voltage is available, publish raw voltage (e.g. `3.02`) and set `unit_of_measurement` to `V` and `device_class` to `voltage` in discovery.

## Panel-level battery
- Publish a panel-level battery sensor with topic `.../sensor/panel_battery/` and `unique_id` like `<panelType>.panel.battery`.
- Populate panel battery from `get_system_power()` (already called during startup) and/or periodic polling.

## Per-device battery sources
- If the protocol provides explicit per-device battery percentage or voltage, publish it directly.
- If only a boolean 'low battery' flag exists for a device, either:
  - publish a binary `sensor` with device_class `problem` or
  - map boolean to percent (e.g. `100` / `10`) — document this choice.

## Voltage -> Percentage mapping (suggested helper)
- Use device-type-specific ranges. Example coin cell mapping:

```
def voltage_to_percent(v, min_v=2.6, max_v=3.3):
    p = 100 * (v - min_v) / (max_v - min_v)
    return max(0, min(100, int(round(p))))
```

- Panel (12V lead-acid) example: min_v=10.5, max_v=13.0.

## Minimal code changes (where to modify)
- `alarm-monitor.py` (`TexecomMqtt.zone_details_callback` / `area_details_callback`):
  - Build a canonical `device` dict once (use panel identification for `identifiers`).
  - Publish an additional retained discovery message for each device's battery sensor using the same `device` block.
  - Keep `unique_id` stable and append `.battery` for battery entities.

- `alarm-monitor.py` (`TexecomMqtt`):
  - Publish battery state messages to `<ROOT>/sensor/<name>_battery/state` when `texecomConnect` exposes battery info.
  - For panel battery, add a periodic publish using `get_system_power()` output.

- `texecomConnect.py`:
  - If battery data appears in event/log messages, add parsing in `handle_event_message` to extract per-device battery fields and call a callback to publish MQTT.
  - Optionally add a `on_battery_event(self, func)` registration method so `alarm-monitor.py` can register a publisher callback.

## Identifier / device metadata
- Replace the placeholder `identifiers` value in current discovery blocks with a stable list: `["texecom", "<panel_id>"]` where `<panel_id>` is derived from `get_panel_identification()` or `get_panel_identification()` output parsed to a short id.

## Publishing details
- Use `client.publish(topic, payload, retain=True)` for discovery config messages.
- Use `retain=True` or `retain=False` for state messages depending on whether you want HA to see last known value on reboot (recommended: retain state for panel and battery sensors).

## Examples
- Discovery topic: `homeassistant/sensor/front_door_battery/config` (example using default `MQTT_CONFIG_TOPIC`).
- State topic: `alarm_unconfig/sensor/front_door_battery/state` (example using default `MQTT_ROOT_TOPIC`).

## Edge cases & notes
- Only publish battery discovery for devices that can report battery data to avoid cluttering HA.
- Ensure `unique_id` values are stable across restarts and reconfigures.
- Keep discovery JSON small and include `device.identifiers` as the linking mechanism.

## Next steps I can implement
- Patch `alarm-monitor.py` to: build canonical `device` dict, publish battery discovery per zone/area, and publish panel battery periodically.
- Add a `on_battery_event` hook in `texecomConnect.py` and wire event parsing if battery data exists in protocol frames.

If you want, I can now implement the `alarm-monitor.py` changes and add a small battery helper module. Tell me to proceed and whether you want percentage or raw voltage as the primary published value.
