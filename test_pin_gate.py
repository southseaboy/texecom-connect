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
tc = make_tc({1: ("Master", "5678"), 3: ("Chris", "5112"), 5: ("test", "0192")})

check("a correct code matches the right user",
      tc.find_user_by_code("0192") == ("match", 5, "test"))
check("a wrong code matches nobody",
      tc.find_user_by_code("9999")[0] == "none")
check("a code of the wrong length does not match",
      tc.find_user_by_code("192")[0] == "none")
check("a leading zero is significant",
      tc.find_user_by_code("192")[0] == "none" and
      tc.find_user_by_code("0192")[0] == "match")
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
refresh = make_tc({1: ("Master", "5678")})
refresh.numberOfUsers = 50
refresh.get_user = lambda n: None          # every read fails
before = dict(refresh.users)
refresh.get_all_users()
check("a failed refresh keeps the previous user table rather than emptying it",
      refresh.users == before)

rebuild = make_tc({})
rebuild.numberOfUsers = 4
built = {}
for n, (nm, cd) in {1: ("Master", "5678"), 2: ("Mark", "2229")}.items():
    u = User()
    u.name, u.passcode = nm, cd
    built[n] = u
rebuild.get_user = lambda n: built.get(n)
rebuild.next_user_refresh = 0
rebuild.get_all_users()
check("a good refresh replaces the table and re-arms the daily timer",
      set(rebuild.users) == {0, 1, 2} and rebuild.next_user_refresh > time.time())
check("the rebuilt table matches codes",
      rebuild.find_user_by_code("2229") == ("match", 2, "Mark"))

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
      mon.TexecomMqtt.parse_command(b'{"action":"DISARM","code":"0192"}') ==
      ("DISARM", "0192"))
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
    routed = make_tc({3: ("Chris", "5112"), 5: ("test", "0192")})
    routed.arm_disarm_reset_queue = []
    mon.tc = routed
    return routed

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"ARM_AWAY","code":"5112"}'))
check("a valid code arms as that user",
      r.arm_disarm_reset_queue == [("user", D.CMD_ARMAREASASUSER, 3, None)])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"DISARM","code":"0192"}'))
check("a valid code disarms as that user",
      r.arm_disarm_reset_queue == [("user", D.CMD_DISARMAREASASUSER, 5, None)])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"reset","code":"5112"}'))
check("reset is code gated and sent anonymously to the areas",
      len(r.arm_disarm_reset_queue) == 1 and
      r.arm_disarm_reset_queue[0][:2] == ("areas", D.CMD_RESETAREAS))

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage("DISARM"))
check("A6: a bare DISARM publish is refused - broker access alone is not enough",
      r.arm_disarm_reset_queue == [])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"DISARM","code":"9999"}'))
check("a wrong code sends nothing to the panel",
      r.arm_disarm_reset_queue == [])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"ARM_NIGHT","code":"5112"}'))
check("an unimplemented action is dropped, but only after a valid code",
      r.arm_disarm_reset_queue == [])

r = fresh_route()
mon.TexecomMqtt.on_message(None, None, FakeMessage(
    '{"action":"DISARM","code":"0192"}',
    topic="homeassistant/alarm_control_panel/somewhere_else/command"))
check("a command for an unknown area topic is ignored",
      r.arm_disarm_reset_queue == [])

# ------------------------------------------------------------------ lockout
r = fresh_route()
for _ in range(4):
    mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"DISARM","code":"9999"}'))
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"DISARM","code":"0192"}'))
check("4 failures do not lock out - a correct code still works",
      r.arm_disarm_reset_queue == [("user", D.CMD_DISARMAREASASUSER, 5, None)])
check("a success clears the failure count",
      mon.TexecomMqtt.failed_attempts == 0)

r = fresh_route()
for _ in range(5):
    mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"DISARM","code":"9999"}'))
check("the 5th failure starts a lockout",
      mon.TexecomMqtt.locked_until > time.time())
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"DISARM","code":"0192"}'))
check("a correct code is refused while locked out",
      r.arm_disarm_reset_queue == [])
check("the lockout is 15 minutes",
      894 < mon.TexecomMqtt.locked_until - time.time() <= 900)
mon.TexecomMqtt.locked_until = time.time() - 1
mon.TexecomMqtt.on_message(None, None, FakeMessage('{"action":"DISARM","code":"0192"}'))
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
        published[topic] = json.loads(payload)


class FakeArea:
    text = "intruder"


mon.client = FakeClient
mon.TexecomMqtt.area_details_callback(FakeArea(), "Elite", 48)
cfg = published["homeassistant/alarm_control_panel/intruder/config"]
check("the entity offers Away only - no part arm button",
      cfg["supported_features"] == ["arm_away"])
check("a code is required to arm and to disarm",
      cfg["code_arm_required"] is True and cfg["code_disarm_required"] is True)
check("HA is told to hand the code to us rather than check it itself",
      cfg["code"] == "REMOTE_CODE")
check("the code format asks for 4 digits",
      cfg["code_format"] == r"^\d{4}$")
check("the command template sends action and code as JSON",
      cfg["command_template"] == '{"action":"{{ action }}","code":"{{ code }}"}')
check("availability is still declared",
      cfg["availability_topic"] == "homeassistant/alarm_control_panel/state")

print("")
if FAILURES:
    print("{:d} FAILED: {}".format(len(FAILURES), ", ".join(FAILURES)))
    sys.exit(1)
print("all tests passed")
