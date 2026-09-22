#!/usr/bin/env python
"""Offline tests for inferring an arm/disarm the panel log never delivered.
No panel, no broker.

Messages are fed through the real handle_event_message(), in the order the
panel sent them on 2026-09-21. A fake clock drives the 10 s window.

Run:  python test_inferred_events.py
"""
import json
import sys
import time as real_time

import texecomConnect as tcmod
from texecomConnect import TexecomConnect
from area import Area
from test_fixtures import AREAS

FAILURES = []

DISARMED, IN_EXIT, IN_ENTRY, ARMED, PART_ARMED, IN_ALARM = range(6)


def check(name, condition):
    print("{}  {}".format("PASS" if condition else "FAIL", name))
    if not condition:
        FAILURES.append(name)


class Clock:
    """Stands in for the time module inside texecomConnect."""
    now = 1_000_000.0

    def time(self):
        return self.now

    def strftime(self, fmt, t=None):
        return real_time.strftime(fmt, t or real_time.localtime(self.now))

    def localtime(self, secs=None):
        return real_time.localtime(self.now if secs is None else secs)

    def sleep(self, secs):
        self.now += secs


clock = Clock()
tcmod.time = clock


def logevent(event_type, group_type, parameter, areas, when=(2026, 9, 21, 20, 10, 14)):
    """Wire payload for one MSG_LOGEVENT, 8-byte (Elite 48) form."""
    year, month, day, hours, minutes, seconds = when
    stamp = (seconds | (minutes << 6) | (month << 12) | (hours << 16)
             | (day << 21) | ((year - 2000) << 26))
    return bytes([5, event_type, group_type, parameter, areas]) + \
        stamp.to_bytes(4, "little")


def area_event(area, state):
    return bytes([2, area, state])


USER_CODE = logevent(83, 0, 3, 1)       # Prox Tag, user 3
DISARM_RECORD = logevent(37, 5, 3, 1)   # Open/Close (Away Armed), Open
ARM_RECORD = logevent(37, 6, 3, 1)      # Open/Close (Away Armed), Close
ALARM_ABORT = logevent(41, 5, 3, 1)     # Open After Alarm


def make_tc(state):
    tc = TexecomConnect("127.0.0.1", 1, "x")
    tc.numberOfAreas = 2
    tc.areaBitmapSize = 7
    for number, text in AREAS.items():
        area = Area(number)
        area.text = text
        tc.areas[number] = area
    if state is None:
        tc.get_area(1).state = None   # as at startup, before any read
    else:
        tc.get_area(1).save_state(state)
    tc.get_area(2).save_state(DISARMED)
    tc.events = []
    tc.logged = []
    tc.log = lambda text: tc.logged.append(text)
    tc.on_panel_event(tc.events.append)
    return tc


def feed(tc, *payloads, gap=0.0):
    for payload in payloads:
        tc.handle_event_message(payload)
        clock.now += gap


def inferred(tc):
    return [ev for ev in tc.events if ev["cause_source"] == "inferred"]


# --- 2026-09-21 20:10: disarm record lost to a CRC failure -----------------
tc = make_tc(ARMED)
feed(tc, area_event(1, IN_ENTRY), USER_CODE, area_event(1, DISARMED))
start = clock.now
clock.now = start + 9
tc.service_pending_inferences()
check("20:10 replay: nothing inferred inside the 10 s window", inferred(tc) == [])
clock.now = start + 11
tc.service_pending_inferences()
got = inferred(tc)
check("20:10 replay: ONE disarm inferred after the window",
      len(got) == 1 and got[0]["event_type"] == "disarm")
ev = got[0] if got else {}
check("the inferred event says so, and names no user",
      ev.get("cause_source") == "inferred" and ev.get("cause") is None
      and ev.get("cause_kind") == "none" and "inferred" in ev.get("text", ""))
check("it carries the area", ev.get("areas") == [1] and ev.get("area_names") == [AREAS[1]])
check("its time is when the area event arrived, not when it was inferred",
      ev.get("panel_time") == real_time.strftime("%Y-%m-%dT%H:%M:%S",
                                                 real_time.localtime(start)))
check("it is logged", any("inferred disarm for area 1" in l for l in tc.logged))
tc.service_pending_inferences()
check("it is published once only", len(inferred(tc)) == 1)

real = make_tc(ARMED)
feed(real, area_event(1, DISARMED), DISARM_RECORD)
check("the inferred event has exactly the keys of a real one",
      set(ev) == set(real.events[-1]))
try:
    check("the inferred event survives a JSON round trip",
          json.loads(json.dumps(ev)) == ev)
except (TypeError, ValueError):
    check("the inferred event survives a JSON round trip", False)

# --- the normal cases must infer nothing ------------------------------------
tc = make_tc(ARMED)
feed(tc, area_event(1, IN_ENTRY), USER_CODE, area_event(1, DISARMED), DISARM_RECORD)
clock.now += 60
tc.service_pending_inferences()
check("10:58 replay: record AFTER the area event -> nothing inferred",
      inferred(tc) == [] and tc.pendingInferences == {})

tc = make_tc(IN_EXIT)
feed(tc, ARM_RECORD, area_event(1, ARMED))
clock.now += 60
tc.service_pending_inferences()
check("17:50 replay: record BEFORE the area event -> nothing inferred",
      inferred(tc) == [] and tc.pendingInferences == {})

tc = make_tc(ARMED)
feed(tc, area_event(1, DISARMED))
clock.now += 8
feed(tc, DISARM_RECORD)
clock.now += 60
tc.service_pending_inferences()
check("a record 8 s late still counts", inferred(tc) == [])

tc = make_tc(IN_ALARM)
feed(tc, area_event(1, DISARMED), ALARM_ABORT)
clock.now += 60
tc.service_pending_inferences()
check("after an alarm, 'Open After Alarm' (reset) accounts for the disarm",
      inferred(tc) == [])

tc = make_tc(IN_EXIT)
feed(tc, area_event(1, DISARMED))
clock.now += 60
tc.service_pending_inferences()
check("exit cancelled (in exit -> disarmed) expects no record",
      inferred(tc) == [] and tc.pendingInferences == {})

tc = make_tc(None)
feed(tc, area_event(1, DISARMED))
clock.now += 60
tc.service_pending_inferences()
check("first state after startup expects no record", inferred(tc) == [])

# --- states this app works out itself never expect a record -----------------
tc = make_tc(IN_ALARM)
maps = {21: bytes(8)}
for flag in TexecomConnect.AREA_FLAG_LIVE_ALARM:
    maps[flag] = bytes(8)
tc.clear_alarm_state_if_over(maps)
check("'alarm over' (worked out from flags) -> disarmed, but no expectation",
      tc.get_area(1).state == DISARMED and tc.pendingInferences == {})

# --- a lost ARM record is covered the same way ------------------------------
tc = make_tc(DISARMED)
feed(tc, area_event(1, IN_EXIT), area_event(1, ARMED))
clock.now += 11
tc.service_pending_inferences()
got = inferred(tc)
check("a lost arm record -> ONE arm inferred",
      len(got) == 1 and got[0]["event_type"] == "arm")

tc = make_tc(DISARMED)
feed(tc, area_event(1, IN_EXIT), area_event(1, PART_ARMED))
clock.now += 11
tc.service_pending_inferences()
check("part armed with no record -> arm inferred",
      [e["event_type"] for e in inferred(tc)] == ["arm"])

# --- scope and supersession --------------------------------------------------
tc = make_tc(ARMED)
feed(tc, area_event(1, DISARMED), logevent(37, 5, 3, 2))
clock.now += 11
tc.service_pending_inferences()
check("a disarm record for AREA 2 does not account for area 1",
      [e["areas"] for e in inferred(tc)] == [[1]])

tc = make_tc(ARMED)
feed(tc, area_event(1, DISARMED), ARM_RECORD)
clock.now += 11
tc.service_pending_inferences()
check("an ARM record does not account for a disarm",
      [e["event_type"] for e in inferred(tc)] == ["disarm"])

tc = make_tc(ARMED)
feed(tc, area_event(1, DISARMED))
clock.now += 3
feed(tc, area_event(1, IN_EXIT))
clock.now += 60
tc.service_pending_inferences()
check("a newer transition (disarmed -> in exit) drops the stale expectation",
      inferred(tc) == [])

print("")
if FAILURES:
    print("{:d} FAILED: {}".format(len(FAILURES), ", ".join(FAILURES)))
    sys.exit(1)
print("all tests passed")
