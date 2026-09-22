#!/usr/bin/env python
"""Offline tests for settling an area left 'in exit'. No panel, no broker.

Reproduces 2026-09-21 15:10: exit started, the arm failed, the panel sent no
area event, and Home Assistant showed 'arming' for 2 h 40 m.

Run:  python test_exit_state.py
"""
import sys

from texecomConnect import TexecomConnect

FAILURES = []

DISARMED = 0
IN_EXIT = 1
ARMED = 3
PART_ARMED = 4

T0 = 1_000_000.0          # exit started


def check(name, condition):
    print("{}  {}".format("PASS" if condition else "FAIL", name))
    if not condition:
        FAILURES.append(name)


def bitmap(areamask):
    return areamask.to_bytes(8, "little")     # one byte longer, as the panel sends


def exit_tc(flags=None, fail=0, exit_delay=30, areas=2):
    """Area 1 'in exit' since T0; the panel's flag reads are faked."""
    tc = TexecomConnect("127.0.0.1", 1, "x")
    tc.numberOfAreas = areas
    tc.areaBitmapSize = 7
    tc.published = []
    tc.reads = []
    tc.logged = []
    tc.log = lambda text: tc.logged.append(text)
    tc.on_area_event(lambda area: tc.published.append((area.number, area.state)))
    for n in range(1, areas + 1):
        area = tc.get_area(n)
        area.text = "area{:d}".format(n)
        area.exitDelay = exit_delay
        area.save_state(DISARMED)
    tc.get_area(1).save_state(IN_EXIT)
    tc.get_area(1).exitStartedAt = T0
    flags = flags or {}

    def fake_read(flagnums):
        tc.reads.append(list(flagnums))
        return {n: bitmap(flags.get(n, 0)) for n in flagnums}, fail

    tc.read_area_flags_individually = fake_read
    return tc


# --- the recorded failure: arm failed, every flag clear ---------------------
tc = exit_tc()
tc.saveAreasCurrentArmedState(bitmap(0), TexecomConnect.AREA_STATE_ARMED)
check("the existing flag-21 path still leaves 'in exit' alone (why it stuck)",
      tc.get_area(1).state == IN_EXIT and tc.published == [])

tc.resolve_stale_exit_state(now=T0 + 20)
check("inside the exit delay: nothing changes and the panel is NOT read",
      tc.get_area(1).state == IN_EXIT and tc.reads == [] and tc.published == [])

tc.resolve_stale_exit_state(now=T0 + 61)
check("2026-09-21 replay: overdue, all exit flags clear -> DISARMED published",
      tc.get_area(1).state == DISARMED and tc.published == [(1, DISARMED)])
check("the read covered Exit, Armed, Part Armed and Part Arming",
      tc.reads == [[19, 21, 23, 24]])
check("the change is logged with its reason",
      any("exit overdue" in line for line in tc.logged))

# --- a lost arm event is settled the same way -------------------------------
tc = exit_tc(flags={21: 0b0001})
tc.resolve_stale_exit_state(now=T0 + 61)
check("overdue with 21 Armed set -> ARMED",
      tc.get_area(1).state == ARMED and tc.published == [(1, ARMED)])

tc = exit_tc(flags={21: 0b0001, 23: 0b0001})
tc.resolve_stale_exit_state(now=T0 + 61)
check("overdue with 23 Part Armed set -> PART ARMED, not armed",
      tc.get_area(1).state == PART_ARMED)

# --- never guess ------------------------------------------------------------
tc = exit_tc(fail=1)
tc.resolve_stale_exit_state(now=T0 + 61)
check("a failed flag read decides nothing - stays 'in exit'",
      tc.get_area(1).state == IN_EXIT and tc.published == [])

tc = exit_tc(flags={19: 0b0001})
tc.resolve_stale_exit_state(now=T0 + 61)
check("panel still showing 19 Exit -> left 'in exit'",
      tc.get_area(1).state == IN_EXIT and tc.published == [])

tc = exit_tc(flags={24: 0b0001})
tc.resolve_stale_exit_state(now=T0 + 61)
check("panel still showing 24 Part Arming -> left 'in exit'",
      tc.get_area(1).state == IN_EXIT and tc.published == [])

# --- the grace follows the panel's own exit delay ---------------------------
tc = exit_tc(exit_delay=60)
tc.resolve_stale_exit_state(now=T0 + 45)
check("a 60 s exit delay is honoured: nothing at 45 s",
      tc.get_area(1).state == IN_EXIT and tc.reads == [])
tc.resolve_stale_exit_state(now=T0 + 61)
check("... and settled after 60 s", tc.get_area(1).state == DISARMED)

tc = exit_tc(exit_delay=None)
tc.resolve_stale_exit_state(now=T0 + 25)
check("unknown exit delay falls back to 30 s: nothing at 25 s",
      tc.get_area(1).state == IN_EXIT and tc.reads == [])
tc.resolve_stale_exit_state(now=T0 + 31)
check("... and settled after 30 s", tc.get_area(1).state == DISARMED)

# --- scope ------------------------------------------------------------------
tc = exit_tc(flags={21: 0b0010})
tc.resolve_stale_exit_state(now=T0 + 61)
check("decided per area: area 2's Armed bit does not arm area 1",
      tc.get_area(1).state == DISARMED and tc.get_area(2).state == DISARMED
      and tc.published == [(1, DISARMED)])

tc = exit_tc()
tc.get_area(1).save_state(ARMED)
tc.resolve_stale_exit_state(now=T0 + 600)
check("no area in exit -> no panel read at all",
      tc.reads == [] and tc.published == [])

tc = exit_tc()
tc.get_area(1).exitStartedAt = None
tc.resolve_stale_exit_state(now=T0 + 600)
check("'in exit' with no known start only starts the clock",
      tc.get_area(1).state == IN_EXIT and tc.get_area(1).exitStartedAt == T0 + 600
      and tc.reads == [])

# --- Area records when exit started -----------------------------------------
tc = exit_tc()
area = tc.get_area(2)
area.save_state(IN_EXIT)
first = area.exitStartedAt
area.save_state(IN_EXIT)
check("Area.save_state stamps the exit start once, not on a repeat",
      first is not None and area.exitStartedAt == first)

print("")
if FAILURES:
    print("{:d} FAILED: {}".format(len(FAILURES), ", ".join(FAILURES)))
    sys.exit(1)
print("all tests passed")
