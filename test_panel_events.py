#!/usr/bin/env python
"""Offline tests for the structured panel-event publication. No panel, no broker.

Every log record below is built so that the EXISTING decoder renders the exact
line a real Elite 48 produced during a controlled alarm test: two interior
zones one second apart, confirmation, silence and a panel reset. The text is
asserted first; only then is the new structured output checked. That ties
these tests to observed panel output rather than to a reading of the decoder.

User, zone and area names come from test_fixtures.py and are SYNTHETIC -
nothing here depends on a particular name.

Run:  python test_panel_events.py
"""
import importlib.util
import json
import time

from texecomConnect import TexecomConnect
from user import User
from zone import Zone
from area import Area
from test_fixtures import USERS, ZONES, AREAS

FAILURES = []


def check(name, condition):
    print("{}  {}".format("PASS" if condition else "FAIL", name))
    if not condition:
        FAILURES.append(name)


def make_tc():
    """A TexecomConnect with a panel's tables loaded, but no connection."""
    tc = TexecomConnect("127.0.0.1", 1, "x")
    # The panel enumerates users from 00, which is always the engineer.
    for number, (name, code) in USERS.items():
        user = User()
        user.name = name
        user.passcode = code
        tc.users[number] = user
    engineer = User()
    engineer.name = "Engineer"
    tc.users[0] = engineer
    for number, text in ZONES.items():
        zone = Zone(number)
        zone.text = text
        tc.zones[number] = zone
    for number, text in AREAS.items():
        area = Area(number)
        area.text = text
        tc.areas[number] = area
    return tc


def logevent(event_type, group_type, parameter, areas, when,
             comm_delayed=False, communicated=False):
    """Build the wire payload for one MSG_LOGEVENT, 8-byte (Elite 48) form."""
    year, month, day, hours, minutes, seconds = when
    stamp = (seconds | (minutes << 6) | (month << 12) | (hours << 16)
             | (day << 21) | ((year - 2000) << 26))
    group_byte = group_type
    if comm_delayed:
        group_byte |= 0x40
    if communicated:
        group_byte |= 0x80
    return bytes([5, event_type, group_byte, parameter, areas]) + \
        stamp.to_bytes(4, "little")


def capture(tc, payload):
    """Return (text, event) for one message, event None if none was emitted."""
    got = []
    tc.on_panel_event(got.append)
    text = tc.handle_event_message(payload)
    return text, (got[0] if got else None)


# The eight log records of the 2026-09-20 confirmed alarm, with the exact
# text the panel produced for each.
ALARM = [
    (logevent(32, 16, 0, 1, (2026, 9, 20, 14, 17, 22)),
     "Log event message: 2026-09-20 14:17:22 Exit Started, Armed parameter: 0 areas: 1"),
    (logevent(42, 6, 3, 1, (2026, 9, 20, 14, 17, 32)),
     "Log event message: 2026-09-20 14:17:32 Remote Open/Close, Close parameter: 3 areas: 1"),
    (logevent(3, 3, 23, 1, (2026, 9, 20, 14, 18, 5)),
     "Log event message: 2026-09-20 14:18:05 Interior, Alarm parameter: 23 areas: 1"),
    (logevent(28, 0, 0, 1, (2026, 9, 20, 14, 18, 6)),
     "Log event message: 2026-09-20 14:18:06 Bell Active, Not Reported parameter: 0 areas: 1"),
    (logevent(27, 0, 0, 1, (2026, 9, 20, 14, 18, 6)),
     "Log event message: 2026-09-20 14:18:06 Alarm Active, Not Reported parameter: 0 areas: 1"),
    (logevent(3, 3, 15, 1, (2026, 9, 20, 14, 18, 7)),
     "Log event message: 2026-09-20 14:18:07 Interior, Alarm parameter: 15 areas: 1"),
    (logevent(120, 1, 0, 1, (2026, 9, 20, 14, 18, 8), communicated=True),
     "Log event message: 2026-09-20 14:18:08 Confirmed Intruder, Priority Alarm [communicated] parameter: 0 areas: 1"),
    (logevent(82, 3, 0, 1, (2026, 9, 20, 14, 18, 9)),
     "Log event message: 2026-09-20 14:18:09 Confirmed Alarm, Alarm parameter: 0 areas: 1"),
    (logevent(3, 4, 15, 1, (2026, 9, 20, 14, 18, 15), comm_delayed=True),
     "Log event message: 2026-09-20 14:18:15 Interior, Restore [comm delayed] parameter: 15 areas: 1"),
    (logevent(31, 0, 3, 1, (2026, 9, 20, 14, 18, 52)),
     "Log event message: 2026-09-20 14:18:52 User Code, Not Reported parameter: 3 areas: 1"),
    (logevent(45, 5, 7, 1, (2026, 9, 20, 14, 21, 12)),
     "Log event message: 2026-09-20 14:21:12 Reset After Alarm, Open parameter: 7 areas: 1"),
]

# ------------------------------------------------- the text must not change
tc = make_tc()
for payload, expected in ALARM:
    text, _ = capture(tc, payload)
    check("text unchanged: " + expected[19:60].strip(), text == expected)

# -------------------------------------------------------- arm, by the user
tc = make_tc()
_, ev = capture(tc, ALARM[1][0])
check("arm: category", ev["event_type"] == "arm")
check("arm: cause is the user the panel named",
      (ev["cause_kind"], ev["cause_number"], ev["cause"])
      == ("user", 3, USERS[3][0]))
check("arm: attributed by the panel", ev["cause_source"] == "panel")
check("arm: resolved", ev["cause_resolved"] is True)
check("arm: area named", ev["area_names"] == [AREAS[1]])
check("arm: panel time is the panel's, not ours", ev["panel_time"] == "2026-09-20T14:17:32")
check("arm: notifies", ev["notify"] is True)

# ---------------------------------------------------- trigger, by the zone
tc = make_tc()
_, ev = capture(tc, ALARM[2][0])
check("trigger: category", ev["event_type"] == "trigger")
check("trigger: cause is the zone the panel named",
      (ev["cause_kind"], ev["cause_number"], ev["cause"]) == ("zone", 23, ZONES[23]))
check("trigger: text reads for a human",
      ev["text"] == "Interior, Alarm - zone 23 {} ({})".format(ZONES[23], AREAS[1]))
check("trigger: notifies", ev["notify"] is True)

_, ev = capture(make_tc(), ALARM[5][0])
check("trigger: the second zone is named too", ev["cause"] == ZONES[15])

# ------------------------------------------------------------ confirmation
_, ev = capture(make_tc(), ALARM[6][0])
check("confirmed intruder: category", ev["event_type"] == "alarm_confirmed")
check("confirmed intruder: communicated flag", ev["communicated"] is True)
check("confirmed intruder: notifies", ev["notify"] is True)
_, ev = capture(make_tc(), ALARM[7][0])
check("confirmed alarm: category", ev["event_type"] == "alarm_confirmed")

# ------------------------------- Bell Active DOES notify: the siren is on
_, ev = capture(make_tc(), ALARM[3][0])
check("Bell Active: own category", ev["event_type"] == "bell")
check("Bell Active: notifies", ev["notify"] is True)
check("Bell Active: carries no cause, and does not invent one",
      ev["cause_kind"] == "none" and ev["cause"] is None)

# --------------------------------------- the noise that must NOT notify
_, ev = capture(make_tc(), ALARM[4][0])
check("Alarm Active: category alarm_aux", ev["event_type"] == "alarm_aux")
check("Alarm Active: does not notify", ev["notify"] is False)

_, ev = capture(make_tc(), ALARM[8][0])
check("zone restore: category restore", ev["event_type"] == "restore")
check("zone restore: does not notify", ev["notify"] is False)
check("zone restore: still names the zone", ev["cause"] == ZONES[15])

_, ev = capture(make_tc(), ALARM[9][0])
check("user code: category user_code", ev["event_type"] == "user_code")
check("user code: does not notify", ev["notify"] is False)
check("user code: names the user", ev["cause"] == USERS[3][0])

_, ev = capture(make_tc(), ALARM[0][0])
check("exit started: category exit", ev["event_type"] == "exit")
check("exit started: does not notify", ev["notify"] is False)
check("exit started: group 'Armed' does not make it an arm",
      ev["event_type"] != "arm")

# ------------------------------------------------------------------- reset
tc = make_tc()
_, ev = capture(tc, ALARM[10][0])
check("reset: category", ev["event_type"] == "reset")
check("reset: group 'Open' does not make it a disarm", ev["event_type"] != "disarm")
check("reset: parameter 7 is NOT called a user", ev["cause_kind"] == "none")
check("reset: the raw number is preserved", ev["cause_number"] == 7)
check("reset: no name is invented", ev["cause"] is None)
check("reset: attributed to the panel", ev["cause_source"] == "panel")

# reset requested through Home Assistant IS attributable
tc = make_tc()
tc.note_reset_request(3, USERS[3][0])
_, ev = capture(tc, ALARM[10][0])
check("reset via HA: named", (ev["cause_kind"], ev["cause_number"], ev["cause"])
      == ("user", 3, USERS[3][0]))
check("reset via HA: marked as OUR attribution, not the panel's",
      ev["cause_source"] == "ha")
check("reset via HA: text names the user",
      ev["text"] == "Reset After Alarm, Open - user 3 {} ({})".format(
          USERS[3][0], AREAS[1]))

# a request is consumed once - a later keypad reset is not credited to them
tc = make_tc()
tc.note_reset_request(3, USERS[3][0])
capture(tc, ALARM[10][0])
_, ev = capture(tc, ALARM[10][0])
check("reset: a second reset is not credited to the first requester",
      ev["cause_source"] == "panel" and ev["cause"] is None)

# a stale request is not credited either
tc = make_tc()
tc.note_reset_request(3, USERS[3][0])
tc.resetRequest = (time.time() - (tc.RESET_ATTRIBUTION_SECS + 1), 3, USERS[3][0])
_, ev = capture(tc, ALARM[10][0])
check("reset: a stale request is not credited", ev["cause_source"] == "panel")

# --------------------------------------------------- never invent a name
tc = make_tc()
_, ev = capture(tc, logevent(42, 6, 9, 1, (2026, 9, 20, 12, 0, 0)))
check("unknown user: kind is still user", ev["cause_kind"] == "user")
check("unknown user: number preserved", ev["cause_number"] == 9)
check("unknown user: no name invented", ev["cause"] is None)
check("unknown user: flagged unresolved", ev["cause_resolved"] is False)
check("unknown user: text says so",
      "user 9 (unidentified)" in ev["text"])

_, ev = capture(make_tc(), logevent(3, 3, 44, 1, (2026, 9, 20, 12, 0, 0)))
check("unknown zone: no name invented", ev["cause"] is None)
check("unknown zone: flagged unresolved", ev["cause_resolved"] is False)

_, ev = capture(make_tc(), logevent(42, 6, 0, 1, (2026, 9, 20, 12, 0, 0)))
check("user 0 is ambiguous (Engineer vs unattributed) and is NOT named",
      ev["cause"] is None and ev["cause_resolved"] is False)

# ------------------------------------------------------------ disarm/tamper
_, ev = capture(make_tc(), logevent(42, 5, 2, 1, (2026, 9, 20, 12, 0, 0)))
check("disarm: same event type as arm, split by group Open",
      ev["event_type"] == "disarm" and ev["cause"] == USERS[2][0])

_, ev = capture(make_tc(), logevent(68, 11, 10, 1, (2026, 9, 20, 12, 0, 0)))
check("zone tamper: category", ev["event_type"] == "tamper")
check("zone tamper: names the zone", ev["cause"] == ZONES[10])
check("zone tamper: notifies", ev["notify"] is True)

_, ev = capture(make_tc(), logevent(68, 12, 10, 1, (2026, 9, 20, 12, 0, 0)))
check("zone tamper restore: not reported as a tamper",
      ev["event_type"] == "tamper_restore" and ev["notify"] is False)

_, ev = capture(make_tc(), logevent(60, 11, 0, 1, (2026, 9, 20, 12, 0, 0)))
check("panel box tamper: category", ev["event_type"] == "tamper")

_, ev = capture(make_tc(), logevent(85, 33, 0, 1, (2026, 9, 20, 12, 0, 0)))
check("arm failed: category", ev["event_type"] == "arm_failed")
check("arm failed: notifies", ev["notify"] is True)

# --------------------------------------------------------- multi-area, misc
_, ev = capture(make_tc(), logevent(3, 3, 23, 3, (2026, 9, 20, 12, 0, 0)))
check("area bitmap decodes to both areas",
      ev["areas"] == [1, 2] and ev["area_names"] == [AREAS[1], AREAS[2]])

_, ev = capture(make_tc(), logevent(101, 3, 0, 1, (2026, 9, 20, 12, 0, 0)))
check("an unmapped event still classifies from its group",
      ev["event_type"] == "trigger" and ev["type"] == "Radio Jamming")

# ------------------------------------------- only log events emit an event
tc = make_tc()
for label, payload in (
    ("zone event", bytes([1, 23, 0])),
    ("area event", bytes([2, 1, 0])),
    ("output event", bytes([3, 0, 0])),
    ("user event", bytes([4, 3, 0])),
):
    _, ev = capture(tc, payload)
    check(label + " emits no panel event", ev is None)

# ------------------------------------ the MQTT payload must be serialisable
_, ev = capture(make_tc(), ALARM[2][0])
try:
    round_trip = json.loads(json.dumps(ev))
    check("event survives a JSON round trip", round_trip == ev)
except (TypeError, ValueError):
    check("event survives a JSON round trip", False)
check("event carries HA's required event_type key", "event_type" in ev)
# the discovery payload must declare every category the library can produce
spec = importlib.util.spec_from_file_location("alarm_monitor", "alarm-monitor.py")
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    declared = set(mod.TexecomMqtt.EVENT_TYPES)
except Exception:
    declared = set()
produced = set(TexecomConnect.LOG_CATEGORY_BY_EVENT.values()) \
    | set(TexecomConnect.LOG_CATEGORY_BY_GROUP.values()) \
    | {"tamper", "tamper_restore", "other"}
check("HA is told about every category the library can emit",
      produced <= declared)
check("every notifying category is a real category",
      set(TexecomConnect.LOG_CATEGORY_NOTIFY) <= produced)

print()
if FAILURES:
    print("{:d} FAILURES:".format(len(FAILURES)))
    for name in FAILURES:
        print("  " + name)
    raise SystemExit(1)
print("all checks passed")
