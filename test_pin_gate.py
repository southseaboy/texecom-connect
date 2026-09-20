#!/usr/bin/env python
"""Offline tests for the PIN-gated arm/disarm path. No panel, no broker.

Run:  python test_pin_gate.py
"""
import importlib.util
import json
import sys
import time

from texecomConnect import TexecomConnect
from texecomDefines import TexecomDefines as D
from user import User
from test_fixtures import USERS, pick

# Synthetic throughout - see test_fixtures.py. No real code or name here.
U1_NAME, U1_CODE = USERS[1]
U2_NAME, U2_CODE = USERS[2]
U3_NAME, U3_CODE = USERS[3]
U5_NAME, U5_CODE = USERS[5]
WRONG_CODE = "9999"
assert WRONG_CODE not in (U1_CODE, U2_CODE, U3_CODE, U5_CODE)


def cmd(action, code):
    """A well formed command payload."""
    return json.dumps({"action": action, "code": code})

FAILURES = []


def check(name, condition):
    print("{}  {}".format("PASS" if condition else "FAIL", name))
    if not condition:
        FAILURES.append(name)


def load_monitor():
    spec = importlib.util.spec_from_file_location("alarm_monitor", "alarm-monitor.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeMessage:
    def __init__(self, payload, topic="homeassistant/alarm_control_panel/intruder/command"):
        self.payload = payload if isinstance(payload, bytes) else payload.encode()
        self.topic = topic


def make_tc(codes):
    """A TexecomConnect with a user table but no connection."""
    tc = TexecomConnect("127.0.0.1", 1, "x")
    users = {}
    for number, (name, code) in codes.items():
        user = User()
        user.name = name
        user.passcode = code
        users[number] = user
    engineer = User()
    engineer.name = "Engineer"
    users[0] = engineer
    tc.users = users
    return tc


# ---------------------------------------------------------------- matching
tc = make_tc(pick(1, 3, 5))

check("a correct code matches the right user",
      tc.find_user_by_code(U5_CODE) == ("match", 5, U5_NAME))
check("a wrong code matches nobody",
      tc.find_user_by_code(WRONG_CODE)[0] == "none")
check("a code of the wrong length does not match",
      tc.find_user_by_code(U5_CODE[1:])[0] == "none")
check("a leading zero is significant",
      U5_CODE.startswith("0") and
      tc.find_user_by_code(U5_CODE[1:])[0] == "none" and
      tc.find_user_by_code(U5_CODE)[0] == "match")
check("a non-numeric code is rejected",
      tc.find_user_by_code("abcd")[0] == "none")
check("an empty code is rejected",
      tc.find_user_by_code("")[0] == "none")
check("the engineer (user 0) can never be matched",
      all(n != 0 for n in (tc.find_user_by_code(c)[1] for c in ("", "0000")) if n))

dup = make_tc({2: ("A", "1234"), 4: ("B", "1234")})
check("a code matching two users is refused as ambiguous",
      dup.find_user_by_code("1234")[0] == "ambiguous")

blank = make_tc({2: ("Tag only", "")})
check("a user with no stored code never matches an empty code",
      blank.find_user_by_code("")[0] == "none")

# ------------------------------------------------------------ queue shapes
tc.arm_disarm_reset_queue = []
tc.requestArmAreasAsUser(3)
tc.requestDisArmAreasAsUser(3)
tc.requestResetAreas(bytes.fromhex("01000000000000"))
check("as-user requests queue with the 'user' tag and Cmd 29/30",
      tc.arm_disarm_reset_queue[0][:3] == ("user", D.CMD_ARMAREASASUSER, 3) and
      tc.arm_disarm_reset_queue[1][:3] == ("user", D.CMD_DISARMAREASASUSER, 3))
check("area requests still queue with the 'areas' tag",
      tc.arm_disarm_reset_queue[2][0] == "areas" and
      tc.arm_disarm_reset_queue[2][1] == D.CMD_RESETAREAS)
check("every queue entry has the 4 fields the dispatcher unpacks",
      all(len(e) == 4 for e in tc.arm_disarm_reset_queue))
check("arming as user 0 is refused before anything is sent",
      make_tc({}).arm_disarm_as_user(D.CMD_ARMAREASASUSER, 0) is False)

# ------------------------------------------------------------- user table
refresh = make_tc(pick(1))
refresh.numberOfUsers = 50
refresh.get_user = lambda n: None          # every read fails
before = dict(refresh.users)
refresh.get_all_users()
check("a failed refresh keeps the previous user table rather than emptying it",
      refresh.users == before)

rebuild = make_tc({})
rebuild.numberOfUsers = 4
built = {}
for n, (nm, cd) in pick(1, 2).items():
    u = User()
    u.name, u.passcode = nm, cd
    built[n] = u
rebuild.get_user = lambda n: built.get(n)
rebuild.next_user_refresh = 0
rebuild.get_all_users()
check("a good refresh replaces the table and re-arms the daily timer",
      set(rebuild.users) == {0, 1, 2} and rebuild.next_user_refresh > time.time())
check("the rebuilt table matches codes",
      rebuild.find_user_by_code(U2_CODE) == ("match", 2, U2_NAME))

# ------------------------------------------- Site Data Changed triggers it
ev = make_tc({})
ev.siteDataChanged = False
ev.handle_event_message(D.MSG_LOGEVENT + bytes([100, 0, 0, 1, 0, 0, 0, 0]))
check("a Site Data Changed log event asks for a site data re-read",
      ev.siteDataChanged is True)
ev.siteDataChanged = False
ev.handle_event_message(D.MSG_LOGEVENT + bytes([42, 0, 5, 1, 0, 0, 0, 0]))
check("an ordinary log event does not trigger a re-read",
      ev.siteDataChanged is False)

# --------------------------------------------------------- payload parsing
mon = load_monitor()
mon.topic_root = "homeassistant"
mon.config_root = "homeassistant"
mon.topic_subs = ["intruder"]
mon.topic_areamaps = ["01000000000000"]

check("a well formed command parses",
      mon.TexecomMqtt.parse_command(cmd("DISARM", U5_CODE).encode()) ==
      ("DISARM", U5_CODE))
check("a bare string carries no code and is not a command",
      mon.TexecomMqtt.parse_command(b"DISARM") == (None, None))
check("malformed JSON is not a command",
      mon.TexecomMqtt.parse_command(b'{"action":') == (None, None))
check("a JSON list is not a command",
      mon.TexecomMqtt.parse_command(b'["DISARM"]') == (None, None))
check("a command with no code is not a command",
      mon.TexecomMqtt.parse_command(b'{"action":"DISARM"}') == (None, None))
check("a numeric code is not accepted as a string code",
      mon.TexecomMqtt.parse_command(b'{"action":"DISARM","code":192}') == (None, None))
check("undecodable bytes are not a command",
      mon.TexecomMqtt.parse_command(b"\xff\xfe") == (None, None))

# ------------------------------------------------------- end to end routing
def fresh_route():
    mon.TexecomMqtt.failed_attempts = 0
    mon.TexecomMqtt.locked_until = 0.0
    routed = make_tc(pick(3, 5))
    routed.arm_disarm_reset_queue = []
    mon.tc = routed
    return routed

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("ARM_AWAY", U3_CODE)))
check("a valid code arms as that user",
      r.arm_disarm_reset_queue == [("user", D.CMD_ARMAREASASUSER, 3, None)])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", U5_CODE)))
check("a valid code disarms as that user",
      r.arm_disarm_reset_queue == [("user", D.CMD_DISARMAREASASUSER, 5, None)])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("reset", U3_CODE)))
check("reset is code gated and sent anonymously to the areas",
      len(r.arm_disarm_reset_queue) == 1 and
      r.arm_disarm_reset_queue[0][:2] == ("areas", D.CMD_RESETAREAS))

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage("DISARM"))
check("A6: a bare DISARM publish is refused - broker access alone is not enough",
      r.arm_disarm_reset_queue == [])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", WRONG_CODE)))
check("a wrong code sends nothing to the panel",
      r.arm_disarm_reset_queue == [])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("ARM_NIGHT", U3_CODE)))
check("an unimplemented action is dropped, but only after a valid code",
      r.arm_disarm_reset_queue == [])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage(
    cmd("DISARM", U5_CODE),
    topic="homeassistant/alarm_control_panel/somewhere_else/command"))
check("a command for an unknown area topic is ignored",
      r.arm_disarm_reset_queue == [])

# ------------------------------------------------------------------ lockout
r = fresh_route()
for _ in range(4):
    mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", WRONG_CODE)))
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", U5_CODE)))
check("4 failures do not lock out - a correct code still works",
      r.arm_disarm_reset_queue == [("user", D.CMD_DISARMAREASASUSER, 5, None)])
check("a success clears the failure count",
      mon.TexecomMqtt.failed_attempts == 0)

r = fresh_route()
for _ in range(5):
    mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", WRONG_CODE)))
check("the 5th failure starts a lockout",
      mon.TexecomMqtt.locked_until > time.time())
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", U5_CODE)))
check("a correct code is refused while locked out",
      r.arm_disarm_reset_queue == [])
check("the lockout is 15 minutes",
      894 < mon.TexecomMqtt.locked_until - time.time() <= 900)
mon.TexecomMqtt.locked_until = time.time() - 1
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", U5_CODE)))
check("once the lockout expires a correct code works again",
      r.arm_disarm_reset_queue == [("user", D.CMD_DISARMAREASASUSER, 5, None)])

r = fresh_route()
for _ in range(5):
    mon.TexecomMqtt.on_message(None, None, FakeMessage("DISARM"))
check("bare-string publishes also count toward the lockout",
      mon.TexecomMqtt.locked_until > time.time())

# --------------------------------------------------- discovery payload shape
published = {}


class FakeClient:
    @staticmethod
    def publish(topic, payload, retain=False):
        try:
            published[topic] = json.loads(payload)
        except (ValueError, TypeError):
            # state topics carry a bare string, not JSON
            published[topic] = payload


class FakeArea:
    text = "intruder"


mon.client = FakeClient
mon.TexecomMqtt.area_details_callback(FakeArea(), "Elite", 48)
cfg = published["homeassistant/alarm_control_panel/intruder/config"]
check("the entity offers Away plus the borrowed vacation button",
      cfg["supported_features"] == ["arm_away", "arm_vacation"])
check("vacation publishes 'reset', which on_message already implements",
      cfg["payload_arm_vacation"] == "reset")
check("no part arm button is offered",
      "arm_home" not in cfg["supported_features"] and
      "arm_night" not in cfg["supported_features"])
check("a code is required to arm and to disarm",
      cfg["code_arm_required"] is True and cfg["code_disarm_required"] is True)
check("HA is told to hand the code to us rather than check it itself",
      cfg["code"] == "REMOTE_CODE")
check("no code_format key - it is not in the MQTT alarm panel schema",
      "code_format" not in cfg)
check("the command template sends action and code as JSON",
      cfg["command_template"] == '{"action":"{{ action }}","code":"{{ code }}"}')
check("availability is still declared",
      cfg["availability_topic"] == "homeassistant/alarm_control_panel/state")

# ------------------------------------------------- area flags -> HA sensors
def flag_tc(areas=4):
    f = make_tc({})
    f.numberOfAreas = areas
    f.areaBitmapSize = 7
    f.panelType = "Elite"
    f.numberOfZones = 48
    for n in range(1, areas + 1):
        f.get_area(n).text = {1: "intruder", 2: "fire_co_alarms"}.get(
            n, "area{:d}".format(n))
    return f


def bitmap(areamask):
    return areamask.to_bytes(8, "little")     # one byte longer, as the panel sends


seen = []
f = flag_tc()
f.on_area_flags(lambda area, flagnum, isset: seen.append(
    (area.number, flagnum, isset)))

f.publish_area_flags({36: bitmap(0b0001)})
check("flag 36 set on area 1 only publishes True for area 1",
      seen == [(1, 36, True), (2, 36, False), (3, 36, False), (4, 36, False)])

seen[:] = []
f.publish_area_flags({36: bitmap(0b1010)})
check("the per-area bit is read, not just 'anything set'",
      [s for s in seen if s[2]] == [(2, 36, True), (4, 36, True)])

seen[:] = []
f.publish_area_flags({0: bitmap(0b1111), 21: bitmap(0b1111)})
check("a read that did not include flag 36 publishes nothing at all",
      seen == [])

seen[:] = []
f.publish_area_flags({})
check("an empty read publishes nothing rather than a false clear",
      seen == [])

seen[:] = []
f.publish_area_flags({36: bitmap(0b1111)})
check("the extra byte the panel returns does not bleed into the area bits",
      len([s for s in seen if s[2]]) == 4)

quiet = flag_tc()
quiet.publish_area_flags({36: bitmap(0b0001)})
check("publishing with no callback registered is a no-op, not a crash", True)

# ------------------------------------------------ the read-back after a reset
rb = make_tc({})
check("no flag read-back is pending to start with", rb.flagReadBackDue == [])
rb.schedule_flag_readback()
check("a reset schedules two flag re-reads, at +5s and +15s",
      len(rb.flagReadBackDue) == 2 and
      4 < rb.flagReadBackDue[0] - time.time() <= 5 and
      14 < rb.flagReadBackDue[1] - time.time() <= 15)
check("the re-reads are in order, so popping the first is correct",
      rb.flagReadBackDue[0] < rb.flagReadBackDue[1])

# ------------------------------- when is the alarm OVER (reworked 2026-09-19)
# Background: on a staged confirmed intruder alarm, flag 00 Alarm was CLEAR
# while the alarm was sounding and only went SET after the disarm. The old
# test keyed on flag 00 and so ended fast polling in the middle of the event.
live = flag_tc()

check("flag 00 is NOT a live-alarm flag - it is alarm memory",
      0 not in TexecomConnect.AREA_FLAG_LIVE_ALARM)
check("nor are 01/04/15, which latched the same way in the same run",
      not ({1, 4, 15} & set(TexecomConnect.AREA_FLAG_LIVE_ALARM)))
check("flag 15 Abort is in the alarm set, so a reset read-back can see it",
      15 in TexecomConnect.AREA_FLAG_ALARM_SET)
check("every live-alarm flag is also in the set that is actually polled",
      set(TexecomConnect.AREA_FLAG_LIVE_ALARM)
      <= set(TexecomConnect.AREA_FLAG_ALARM_SET))
check("every flag seen latched on 2026-09-19 is in the reset read-back set",
      {0, 1, 4, 15, 36} <= set(TexecomConnect.AREA_FLAG_ALARM_SET))
check("the reset read-back asks for the alarm set, not the 5-flag watchlist",
      '"after reset", self.AREA_FLAG_ALARM_SET'
      in __import__("inspect").getsource(TexecomConnect))

check("a live alarm flag set on one area means the alarm is not over",
      live.alarm_flag_set_anywhere({61: bitmap(0b0010)}) is True)
check("live flags all clear means the alarm IS over",
      live.alarm_flag_set_anywhere({61: bitmap(0), 28: bitmap(0)}) is False)

# The exact 2026-09-19 regression, as a test.
sounding = {0: bitmap(0), 61: bitmap(0b0001),
            28: bitmap(0b0001), 30: bitmap(0b0001)}
check("REGRESSION: flag 00 clear mid-alarm no longer ends the fast poll",
      live.alarm_flag_set_anywhere(sounding) is True)

# ...and the converse: the aftermath must not hold the poll open for ever.
aftermath = {0: bitmap(0b0001), 1: bitmap(0b0001), 4: bitmap(0b0001),
             15: bitmap(0b0001), 5: bitmap(0), 28: bitmap(0), 30: bitmap(0),
             44: bitmap(0), 61: bitmap(0), 62: bitmap(0)}
check("memory flags left set after the disarm do not hold the poll open",
      live.alarm_flag_set_anywhere(aftermath) is False)

check("a read with no live flag in it answers None, not 'over'",
      live.alarm_flag_set_anywhere({0: bitmap(0b1111)}) is None)
check("an empty read answers None, not 'over'",
      live.alarm_flag_set_anywhere({}) is None)
check("None is not False, so the caller's 'is False' test keeps polling",
      (live.alarm_flag_set_anywhere({}) is False) is False)

# ------------------- taking an area OUT of 'in alarm' (agreed 2026-09-19)
# The panel never reports an area leaving alarm, so HA sat at 'triggered'
# until a restart. Agreed definition: the alarm is over for an area when none
# of AREA_FLAG_LIVE_ALARM is set on THAT area.
IN_ALARM = 5      # AREA_STATE_INALARM
DISARMED = 0
ARMED = 3

def alarm_over_tc(states, live_mask=0, armed_mask=0, drop=()):
    """Areas in `states`; bitmaps for every watchlist flag unless dropped."""
    f = flag_tc()
    f.published = []
    f.on_area_event(lambda area: f.published.append((area.number, area.state)))
    for n, st in states.items():
        f.get_area(n).save_state(st)
    maps = {21: bitmap(armed_mask)}
    for flag in TexecomConnect.AREA_FLAG_LIVE_ALARM:
        maps[flag] = bitmap(live_mask)
    for flag in drop:
        maps.pop(flag, None)
    return f, maps

check("the watchlist carries every live-alarm flag, so the idle poll can decide",
      set(TexecomConnect.AREA_FLAG_LIVE_ALARM)
      <= set(TexecomConnect.AREA_FLAG_WATCHLIST))
check("the watchlist still carries 21 Armed, for the state it then publishes",
      21 in TexecomConnect.AREA_FLAG_WATCHLIST)

f, maps = alarm_over_tc({1: IN_ALARM})
f.clear_alarm_state_if_over(maps)
check("alarm over and not armed -> the area is published DISARMED",
      f.get_area(1).state == DISARMED and f.published == [(1, DISARMED)])

f, maps = alarm_over_tc({1: IN_ALARM}, armed_mask=0b0001)
f.clear_alarm_state_if_over(maps)
check("alarm over but still armed -> ARMED, not disarmed",
      f.get_area(1).state == ARMED and f.published == [(1, ARMED)])

# The whole point: an alarm raised while DISARMED keeps flag 21 clear, so a
# flag-21-only test would have cleared this one mid-alarm.
f, maps = alarm_over_tc({1: IN_ALARM}, live_mask=0b0001)
f.clear_alarm_state_if_over(maps)
check("REGRESSION: a live alarm flag set while disarmed keeps HA triggered",
      f.get_area(1).state == IN_ALARM and f.published == [])

f, maps = alarm_over_tc({1: IN_ALARM, 2: IN_ALARM}, live_mask=0b0010)
f.clear_alarm_state_if_over(maps)
check("it is decided PER AREA - area 1 leaves alarm, area 2 stays in it",
      f.get_area(1).state == DISARMED and f.get_area(2).state == IN_ALARM
      and f.published == [(1, DISARMED)])

f, maps = alarm_over_tc({1: ARMED, 2: DISARMED})
f.clear_alarm_state_if_over(maps)
check("an area that is not in alarm is never touched",
      f.get_area(1).state == ARMED and f.published == [])

f, maps = alarm_over_tc({1: IN_ALARM}, drop=(28,))
f.clear_alarm_state_if_over(maps)
check("a PARTIAL read cannot clear an alarm - one missing live flag aborts",
      f.get_area(1).state == IN_ALARM and f.published == [])

f, maps = alarm_over_tc({1: IN_ALARM}, drop=(21,))
f.clear_alarm_state_if_over(maps)
check("without flag 21 there is no state to publish, so nothing changes",
      f.get_area(1).state == IN_ALARM and f.published == [])

f, _ = alarm_over_tc({1: IN_ALARM})
f.clear_alarm_state_if_over({})
check("an empty read changes nothing rather than clearing the alarm",
      f.get_area(1).state == IN_ALARM and f.published == [])

f, maps = alarm_over_tc({1: IN_ALARM})
check("the extra byte the panel returns does not bleed across areas",
      not f.area_bit_set(bitmap(0b0010), 1)
      and f.area_bit_set(bitmap(0b0010), 2))

# ------------------------------------------------ the sensors HA is told about
published.clear()
mon.tc = flag_tc()
mon.TexecomMqtt.flag_sensors_announced = set()
for n in range(1, 5):
    mon.TexecomMqtt.area_flags_callback(mon.tc.get_area(n), 36, n == 1)

cfg1 = published["homeassistant/binary_sensor/reset_required_intruder/config"]
cfg2 = published["homeassistant/binary_sensor/reset_required_fire_co_alarms/config"]
check("every area gets a discovery config",
      sum(1 for t in published if t.endswith("/config")) == 4)
check("the intruder sensor is enabled - it is the area HA can command",
      cfg1["enabled_by_default"] is True)
check("the areas HA cannot command register disabled",
      cfg2["enabled_by_default"] is False)
check("the sensor reads as a problem, not a plain on/off",
      cfg1["device_class"] == "problem")
check("each sensor has its own unique_id",
      cfg1["unique_id"] != cfg2["unique_id"] and
      cfg1["unique_id"] == "Elite.areaflag.36.intruder")
check("the sensors join the existing Texecom device",
      cfg1["device"]["identifiers"] == "123456789")
check("availability is declared, so the sensors go unavailable with the app",
      cfg1["availability_topic"] == "homeassistant/alarm_control_panel/state")
check("the state payloads match what the config declares",
      published["homeassistant/binary_sensor/reset_required_intruder/state"] ==
      cfg1["payload_on"] == "True" and
      published["homeassistant/binary_sensor/reset_required_fire_co_alarms/state"] ==
      cfg1["payload_off"] == "False")

before = len(published)
mon.TexecomMqtt.area_flags_callback(mon.tc.get_area(1), 36, False)
check("a repeat publish updates the state without republishing discovery",
      len(published) == before and
      published["homeassistant/binary_sensor/reset_required_intruder/state"] == "False")

mon.TexecomMqtt.area_flags_callback(mon.tc.get_area(1), 21, True)
check("a flag with no sensor defined publishes nothing",
      "homeassistant/binary_sensor/reset_required_intruder" not in
      [t.rsplit("/", 1)[0] for t in published if "21" in t])

# ----------------------------------------------------- the audit line is stamped
lines = []
audit_tc = make_tc(pick(5))
audit_tc.on_log_event(lines.append)
mon.tc = audit_tc
audit_tc.arm_disarm_reset_queue = []
mon.TexecomMqtt.failed_attempts = 0
mon.TexecomMqtt.locked_until = 0.0
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", U5_CODE)))
check("the accept line reaches the log topic",
      any("DISARM accepted for user 5 '{}'".format(U5_NAME) in line
          for line in lines))
check("the accept line carries a timestamp",
      any(line[:2].isdigit() and line[4] == "-" and "DISARM accepted" in line
          for line in lines))
check("no line contains the code",
      not any(U5_CODE in line for line in lines))

lines[:] = []
mon.TexecomMqtt.on_message(None, None, FakeMessage(cmd("DISARM", WRONG_CODE)))
check("a rejection is timestamped and logged too, with no code in it",
      any("command rejected" in line for line in lines) and
      not any("9999" in line for line in lines))

print("")
if FAILURES:
    print("{:d} FAILED: {}".format(len(FAILURES), ", ".join(FAILURES)))
    sys.exit(1)
print("all tests passed")
