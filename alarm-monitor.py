#!/usr/bin/env python
#
# Decoder for Texecom Connect API/Protocol
#
# Copyright (C) 2018 Joseph Heenan
# Updates Jul 2020 Charly Anderson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import sys
import json
import time
import atexit

from texecomConnect import TexecomConnect

import paho.mqtt.client as paho


class TexecomMqtt:

    log_mqtt_traffic = False

    @staticmethod
    def on_connect(client, userdata, flags, rc):
        if len(topic_subs[0]) > 0:
            client.subscribe(topic_root + "/alarm_control_panel/+/command/#")

    # A command is only acted on if it carries the code of a user programmed
    # in the panel. Rejections are counted across the whole route rather than
    # per user - a wrong code matches nobody, so there is no-one to count it
    # against. The keypad is never affected by a lockout here.
    LOCKOUT_AFTER = 5
    LOCKOUT_SECONDS = 15 * 60
    failed_attempts = 0
    locked_until = 0.0

    @staticmethod
    def parse_command(payload):
        """Return (action, code) from a command payload, or (None, None).

        The returned code is for matching only and must never be logged,
        published or included in an error message.
        """
        try:
            text = payload.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            return (None, None)
        try:
            parsed = json.loads(text)
        except ValueError:
            return (None, None)
        if not isinstance(parsed, dict):
            return (None, None)
        action, code = parsed.get("action"), parsed.get("code")
        if not isinstance(action, str) or not isinstance(code, str):
            return (None, None)
        return (action, code)

    @staticmethod
    def reject(reason):
        """Count a rejected command and lock the route out on the fifth."""
        TexecomMqtt.failed_attempts += 1
        if TexecomMqtt.failed_attempts >= TexecomMqtt.LOCKOUT_AFTER:
            TexecomMqtt.locked_until = time.time() + TexecomMqtt.LOCKOUT_SECONDS
            TexecomMqtt.failed_attempts = 0
            print("command rejected ({}): {:d} failures, locking the Home Assistant "
                  "route for {:d} minutes - the keypad is unaffected".format(
                      reason, TexecomMqtt.LOCKOUT_AFTER,
                      TexecomMqtt.LOCKOUT_SECONDS // 60))
        else:
            print("command rejected ({}): {:d} more before a {:d} minute lockout".format(
                reason, TexecomMqtt.LOCKOUT_AFTER - TexecomMqtt.failed_attempts,
                TexecomMqtt.LOCKOUT_SECONDS // 60))

    @staticmethod
    def on_message(client, userdata, message):
        # Arm/Disarm/Reset. Every command must carry a code belonging to a
        # user programmed in the panel; the command is then sent AS that user,
        # so the panel's own log names them and the panel applies their rights.
        topic = message.topic
        topicbase = topic_root + "/alarm_control_panel/"
        if len(topic) <= len(topicbase):
            return
        idx = topic.find("/", len(topicbase))
        if idx < 0:
            return
        subtopic = topic[len(topicbase) : idx]
        if subtopic not in topic_subs:
            return
        subtopicIdx = topic_subs.index(subtopic)
        if len(topic_areamaps) < subtopicIdx:
            return
        area_bitmap = bytes.fromhex(topic_areamaps[subtopicIdx])

        # NB: the payload carries the code, so it is never printed - only the
        # action is, and only when traffic logging is on.
        action, code = TexecomMqtt.parse_command(message.payload)
        if TexecomMqtt.log_mqtt_traffic:
            print("topic: {} action: {}".format(topic, action or "(unparsable)"))

        now = time.time()
        if now < TexecomMqtt.locked_until:
            print("command refused: locked out for another {:d}s".format(
                int(TexecomMqtt.locked_until - now)))
            return
        if action is None or not code:
            # A bare string such as "DISARM" - the old behaviour, and anything
            # else publishing to this topic - lands here. It carries no code,
            # so it is refused: broker access alone no longer arms or disarms.
            TexecomMqtt.reject("payload carried no action and code")
            return

        status, usernumber, username = tc.find_user_by_code(code)
        if status == "ambiguous":
            TexecomMqtt.reject("code matches more than one user")
            return
        if status != "match":
            TexecomMqtt.reject("code did not match any user")
            return
        TexecomMqtt.failed_attempts = 0

        # The matched user IS logged: that is the audit trail this design
        # exists to produce. The code never is.
        if action == "ARM_AWAY":
            print("ARM_AWAY accepted for user {:d} '{}'".format(usernumber, username))
            tc.requestArmAreasAsUser(usernumber)
        elif action == "DISARM":
            print("DISARM accepted for user {:d} '{}'".format(usernumber, username))
            tc.requestDisArmAreasAsUser(usernumber)
        elif action == "reset":
            # The protocol has no reset-as-user, so this one is code-gated
            # here but anonymous in the panel's own log.
            print("reset accepted for user {:d} '{}' (anonymous at the panel)".format(
                usernumber, username))
            tc.requestResetAreas(area_bitmap)
        else:
            # Never drop an unknown action silently: a user could otherwise
            # press a mode, watch HA accept it, and leave believing the house
            # is armed when nothing was sent anywhere.
            print("action '{}' is not implemented - ignored (user {:d} '{}')".format(
                action, usernumber, username))

    @staticmethod
    def availability():
        # Declared to HA so that entities go 'unavailable' if this app or its
        # link to the panel dies. The topic is published 'online' on every
        # heartbeat (alive_event) and 'offline' by the MQTT LWT.
        return {
            "availability_topic": topic_root + "/alarm_control_panel/state",
            "payload_available": "online",
            "payload_not_available": "offline",
        }

    @staticmethod
    def zone_details_callback(zone, panelType, numberOfZones):
        if zone.zoneType == 1:
            HAZoneType = "door"
        elif zone.zoneType == 8:
            HAZoneType = "safety"
        else:
            HAZoneType = "motion"
        name = str.lower((zone.text).replace(" ", "_"))
        topicbase = topic_root + "/binary_sensor/" + name
        configtopic = config_root + "/binary_sensor/" + name + "/config"
        statetopic = topicbase + "/state"
        message = {
            "name": name,
            "device_class": HAZoneType,
            "state_topic": statetopic,
            "payload_on": "True",
            "payload_off": "False",
            "unique_id": ".".join([panelType, name]),
            "device": {
                "name": "Texecom " + panelType + " " + str(numberOfZones),
                "identifiers": "123456789",  # TODO panel serial number?
                "manufacturer": "Texecom",
                "model": panelType + " " + str(numberOfZones)
            }
        }
        message.update(TexecomMqtt.availability())
        if TexecomMqtt.log_mqtt_traffic:
            print("MQTT Update %s: %s" % (configtopic, json.dumps(message)))
        client.publish(configtopic, json.dumps(message), retain=True)
        return zone

    @staticmethod
    def area_details_callback(area, panelType, numberOfZones):
        name = str.lower((area.text).replace(" ", "_"))
        topicbase = topic_root + "/alarm_control_panel/" + name
        configtopic = config_root + "/alarm_control_panel/" + name + "/config"
        statetopic = topicbase + "/state"
        commandtopic = topicbase + "/command"
        message = {
            "name": name,
            "state_topic": statetopic,
            "command_topic": commandtopic,
            "unique_id": ".".join([panelType, "area", name]),
            # Every command must carry a panel user's code. REMOTE_CODE tells
            # HA to skip its own validation and pass the typed code through to
            # us; code_format gives the numeric keypad, without which HA
            # offers nowhere to type it. No PIN is stored in Home Assistant.
            "code": "REMOTE_CODE",
            "code_format": "^\\d{4}$",
            "code_arm_required": True,
            "code_disarm_required": True,
            "command_template": '{"action":"{{ action }}","code":"{{ code }}"}',
            # Advertise only the modes on_message() actually implements.
            # HA's default is all six, and an unimplemented mode is accepted
            # by the UI and then silently dropped here - a safety defect.
            # Part arm is NOT offered: Cmd 29 cannot express it, so a Home
            # button could only arm anonymously or under-arm the house.
            # NB: supported_features applies at entity SETUP, not on a
            # discovery update - the MQTT integration must be reloaded once
            # after this is first published or the entity keeps its old set.
            "supported_features": ["arm_away"],
            "device": {
                "name": "Texecom " + panelType + " " + str(numberOfZones),
                "identifiers": "123456789",  # TODO panel serial number?
                "manufacturer": "Texecom",
                "model": panelType + " " + str(numberOfZones)
            }
        }
        message.update(TexecomMqtt.availability())
        if TexecomMqtt.log_mqtt_traffic:
            print("MQTT Update %s: %s" % (configtopic, json.dumps(message)))
        client.publish(configtopic, json.dumps(message), retain=True)
        return area

    @staticmethod
    def zone_status_event(zone):
        topic = (
            topic_root
            + "/binary_sensor/"
            + str.lower((zone.text).replace(" ", "_"))
            + "/state"
        )
        if TexecomMqtt.log_mqtt_traffic:
            print("MQTT Update %s: %s" % (topic, zone.active))
        client.publish(topic, zone.active, retain=True)

    @staticmethod
    def area_status_event(area):
        area_state_str = [
            "disarmed",
            "arming",   # INEXIT  - exit delay running
            "pending",  # INENTRY - entry delay running
            "armed_away",
            "armed_night",
            "triggered",
        ][area.state]
        topic = (
            topic_root
            + "/alarm_control_panel/"
            + str.lower((area.text).replace(" ", "_"))
            + "/state"
        )
        if TexecomMqtt.log_mqtt_traffic:
            print("MQTT Update %s: %s" % (topic, area_state_str))
        client.publish(topic, area_state_str, retain=True)

    @staticmethod
    def alive_event():
        available = "online"
        topic = topic_root + "/alarm_control_panel/state"
        if TexecomMqtt.log_mqtt_traffic:
            print("MQTT Update %s: %s" % (topic, available))
        client.publish(topic, available, retain=True)

    @staticmethod
    def log_event(message):
        topic = topic_root + "/alarm_control_panel/log"
        if TexecomMqtt.log_mqtt_traffic:
            print("MQTT Update %s: %s" % (topic, message))
        client.publish(topic, message)

    @staticmethod
    def exiting():
        print("exiting")
        TexecomMqtt.log_event("Exiting alarm-monitor.")


# disable buffering to stdout when it's redirected to a file/pipe
# This makes sure any events appear immediately in the file/pipe,
# instead of being queued until there is a full buffer's worth.


class Unbuffered:
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


if __name__ == "__main__":
    # Texecom config
    texhost = os.getenv("TEXHOST", "192.168.0.2")
    texport = int(os.getenv("TEXPORT", 10000))
    # This is the default UDL password for a factory panel. For any real
    # installation, use wintex to set the UDL password in the panel to a
    # random 16 character alphanumeric string.
    udlpassword = os.getenv("UDLPASSWORD", "1234")
    # MQTT config
    broker_url = os.getenv("BROKER_URL", "192.168.1.1")
    broker_port = os.getenv("BROKER_PORT", 1883)
    broker_user = os.getenv("BROKER_USER", None)
    broker_pass = os.getenv("BROKER_PASS", None)
    topic_root = os.getenv("MQTT_ROOT_TOPIC", "homeassistant")
    config_root = os.getenv("MQTT_CONFIG_TOPIC", "homeassistant")
    # This is the name of your Areas for arm/disarm via mqtt. They are mapped onto the equivlent areamap.
    # example of MQTT_AREAS and MQTT_AREAMAPS below defines (in order) Area1-4 ('all'), Area1('ground_floor'), Area2('upstairs'), Area3('outside'), Area4('shed')
    topic_subs = os.getenv(
        "MQTT_AREAS", "all,ground_floor,upstairs,outside,shed"
    ).split(",")
    topic_areamaps = os.getenv(
        "MQTT_AREAMAPS",
        "0F000000000000,01000000000000,02000000000000,04000000000000,08000000000000",
    ).split(",")
 
    sys.stdout = Unbuffered(sys.stdout)

    # paho-mqtt 2.x defaults to the v2 callback API with a deprecation
    # warning; the callbacks in this file use the v1 signatures, so state
    # that explicitly rather than relying on the default.
    client = paho.Client(paho.CallbackAPIVersion.VERSION1)
    client.username_pw_set(broker_user, broker_pass)
    client.on_message = TexecomMqtt.on_message
    client.on_connect = TexecomMqtt.on_connect
    # retain=True: paho defaults it to False, so without this a HA restart
    # while this app is dead would not see the 'offline' LWT.
    client.will_set(
        topic_root + "/alarm_control_panel/state", "offline", retain=True
    )
    print("connecting to broker ", broker_url)
    client.connect(broker_url, broker_port)
    client.loop_start()

    tc = TexecomConnect(texhost, texport, udlpassword)
    tc.enable_output_events(False)
    tc.on_alive_event(TexecomMqtt.alive_event)
    tc.on_area_event(TexecomMqtt.area_status_event)
    tc.on_zone_event(TexecomMqtt.zone_status_event)
    tc.on_area_details(TexecomMqtt.area_details_callback)
    tc.on_zone_details(TexecomMqtt.zone_details_callback)
    tc.on_log_event(TexecomMqtt.log_event)

    atexit.register(TexecomMqtt.exiting)

    tc.event_loop()