#!/usr/bin/env python
"""Offline tests for announcing the panel-event entity at startup.
No panel, no broker.

Before: the entity was announced from the heartbeat, and the first heartbeat
fires one second BEFORE the panel identifies itself, so the announce waited for
the second heartbeat - 5 minutes. HA rejects an event whose type the entity has
not been told about, so any new category was lost in that window.

Run:  python test_startup_announce.py
"""
import importlib.util
import json
import sys

from texecomConnect import TexecomConnect

FAILURES = []


def check(name, condition):
    print("{}  {}".format("PASS" if condition else "FAIL", name))
    if not condition:
        FAILURES.append(name)


# --- the library calls the hook once the site data is in --------------------
tc = TexecomConnect("127.0.0.1", 1, "x")
order = []
tc.get_all_areas = lambda: order.append("areas")
tc.get_all_zones = lambda: order.append("zones")
tc.get_all_users = lambda: order.append("users")
tc.get_site_data()
check("no hook registered: get_site_data still works", order == ["areas", "zones", "users"])

order[:] = []
seen = []
tc.panelType = "Elite"
tc.on_site_data(lambda: seen.append((list(order), tc.panelType)))
tc.get_site_data()
check("the hook runs AFTER areas, zones and users are read",
      seen == [(["areas", "zones", "users"], "Elite")])

tc.get_site_data()
check("it runs on every site data read (Site Data Changed, daily refresh)", len(seen) == 2)

# --- alarm-monitor wires the hook to the announce ----------------------------
spec = importlib.util.spec_from_file_location("alarm_monitor", "alarm-monitor.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
source = open("alarm-monitor.py").read()
check("alarm-monitor registers announce_event_entity on the site-data hook",
      "tc.on_site_data(TexecomMqtt.announce_event_entity)" in source)


class FakeClient:
    def __init__(self):
        self.published = []

    def publish(self, topic, payload, retain=False):
        self.published.append((topic, payload, retain))


class FakeTC:
    panelType = "Elite"
    numberOfZones = 48


mod.client = FakeClient()
mod.topic_root = "homeassistant"
mod.config_root = "homeassistant"
mod.tc = FakeTC()
mod.TexecomMqtt.event_entity_announced = False
mod.TexecomMqtt.announce_event_entity()
configs = [p for p in mod.client.published if p[0].endswith("/event/panel_event/config")]
check("the announce publishes the entity config, retained",
      len(configs) == 1 and configs[0][2] is True)
declared = json.loads(configs[0][1])["event_types"] if configs else []
check("the config declares the new categories",
      {"exit_error", "exit_error_cleared"} <= set(declared))
check("the config declares all 18 categories", len(declared) == 18)

mod.TexecomMqtt.announce_event_entity()
check("announced once per process, not on every site data read",
      len([p for p in mod.client.published if p[0].endswith("/config")]) == 1)

mod.TexecomMqtt.event_entity_announced = False
mod.client.published = []
mod.tc.panelType = None
mod.TexecomMqtt.announce_event_entity()
check("still refuses to announce before the panel is identified (backstop guard)",
      mod.client.published == [] and mod.TexecomMqtt.event_entity_announced is False)

print("")
if FAILURES:
    print("{:d} FAILED: {}".format(len(FAILURES), ", ".join(FAILURES)))
    sys.exit(1)
print("all tests passed")
