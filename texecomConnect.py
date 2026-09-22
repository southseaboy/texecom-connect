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

import socket
import time
import os
import sys

import crcmod
import hexdump
import datetime
import re

from area import Area
from user import User
from zone import Zone

from texecomDefines import TexecomDefines


class TexecomConnect(TexecomDefines):
    def __init__(self, host, port, udl_password):
        self.host = host
        self.port = port
        self.udlpassword = udl_password.encode("ascii")
        self.crc8_func = crcmod.mkCrcFun(poly=0x185, rev=False, initCrc=0xFF)
        self.nextseq = 0

        self.print_network_traffic = False
        self.log_verbose = False
        self.alive_heartbeat_secs = 300
        self.time_last_heartbeat = 0
        self.last_command_time = 0
        self.last_received_seq = -1
        self.last_sequence = -1
        self.last_command = None
        self.panelType = None
        self.firmwareVersion = None
        self.alive_event_func = None
        self.area_event_func = None
        self.area_details_func = None
        self.zone_details_func = None
        self.zone_event_func = None
        self.log_event_func = None
        self.panel_event_func = None
        self.area_flags_func = None
        self.numberOfZones = None
        self.highestUsedZone = None
        self.numberOfUsers = None
        self.numberOfAreas = None
        self.areaBitmapSize = None
        # last logged area-flag text per area, and when we last forced a re-log
        self.lastAreaFlags = {}
        self.lastAreaFlagsLog = 0
        # fast flag polling while an area is in alarm
        self.alarmPollUntil = 0
        self.alarmPollNext = 0
        self.alarmPollSweepDone = False
        # timestamps at which to re-read the area flags after a reset
        self.flagReadBackDue = []
        self.zoneBitmapSize = None
        self.zoneNumSize = None
        self.zones = {}
        self.users = {}
        self.areas = {}
        self.arm_disarm_reset_queue = []
        # Backstop re-read of the user table. A code changed or deleted at the
        # keypad must stop working through Home Assistant without waiting for
        # a restart; the Site Data Changed log event covers the normal case
        # and this covers anything the panel does not announce.
        self.next_user_refresh = time.time() + self.USER_REFRESH_SECS
        self.requestPanelOutputEvents = True
        self.s = None
        # used to record which of our idle commands we last sent to the panel
        self.lastIdleCommand = 0
        # Set to true if the idle loop should reread the site data
        self.siteDataChanged = False
        # (time, usernumber, username) of the last reset accepted from Home
        # Assistant, so the panel's anonymous 'Reset After Alarm' can be
        # attributed. Rebound, never mutated: it is written from the MQTT
        # thread and read from the main thread.
        self.resetRequest = None

    ## texecom commands
    # in order of their command number

    def login(self):
        """CMD_LOGIN"""
        response = self.sendcommand(self.CMD_LOGIN, self.udlpassword)
        if response is None:
            self.log("sendcommand returned None for login")
            return False
        if response == self.CMD_RESPONSE_NAK:
            self.log("NAK response from panel")
            return False
        elif response != self.CMD_RESPONSE_ACK:
            self.log("unexpected ack payload: " + str(response))
            return False
        return True

    def get_zone_state(self, startZone, numZones):
        """CMD_GETZONESTATE"""
        if numZones > 168:
            numZones = 168
        body = bytes([startZone & 0xFF, numZones & 0xFF])
        details = self.sendcommand(self.CMD_GETZONESTATE, body)
        if details is None:
            return None
        if len(details) == numZones:
            for idx in range(0, numZones):
                newState = details[idx]
                zone = self.get_zone(startZone + idx)
                if zone.zoneType != zone.ZONETYPE_UNUSED:
                    if zone.state != newState:
                        zone.save_state(newState)
                        if self.zone_event_func is not None:
                            self.zone_event_func(zone)
                        self.log(
                            "zoneState: zone {:d} '{}' {}".format(
                                startZone + idx, zone.state_text, zone.text 
                            )
                        )
            return numZones
        else:
            self.log(
                "GETZONESTATE: response wrong length: {:d}/{:d} ".format(
                    len(details), numZones
                )
            )
            self.log("Payload: ")
            hexdump.hexdump(details)
            return None

    def get_zone_details(self, zone_number):
        """CMD_GETZONEDETAILS"""
        body = zone_number.to_bytes(self.zoneNumSize, "little")
        details = self.sendcommand(self.CMD_GETZONEDETAILS, body)
        if details is None:
            return None
        if len(details) == (33 + self.areaBitmapSize):
            zone = self.get_zone(zone_number)
            zone.zoneType = details[0]
            zone.zoneType_text = self.zone_types[zone.zoneType]
            zone.areaBitmap = details[1 : self.areaBitmapSize + 1]
            zone.text = details[(self.areaBitmapSize + 1) :].decode("ascii")
        else:
            self.log("GETZONEDETAILS: response wrong length")
            self.log("Payload: ")
            hexdump.hexdump(details)
            return None
        zonetext = zone.text.replace("\x00", " ")
        zonetext = re.sub(r"\W+", " ", zonetext)
        zonetext = zonetext.strip()
        if len(zonetext) > 0:
            zone.text = zonetext
        if zone.zoneType != zone.ZONETYPE_UNUSED:
            self.log(
                "zone {:d} type {} name '{}'".format(
                    zone.number, zone.zoneType_text, zone.text
                )
            )
            if self.zone_details_func is not None:
                self.zone_details_func(zone, self.panelType, self.numberOfZones)
        return zone

    USER_REFRESH_SECS = 24 * 60 * 60

    def arm_disarm_as_user(self, cmd, usernumber):
        """CMD_ARMAREASASUSER, CMD_DISARMAREASASUSER

        The command carries a user number and nothing else: the panel decides
        which areas and whether the arm is full or part, and it applies that
        user's own rights.

        The panel ACKs a command it then refuses to action - proven on this
        system 2026-09-18, when an "Arm Only" user's disarm was ACKed and the
        area stayed Full Armed with no log event for the refusal. An ACK here
        therefore means the frame was accepted, NOT that the panel did it.
        The only evidence of the outcome is the area state, which lags by
        several seconds.
        """
        if usernumber == 0:
            self.log("refusing to send as user 0: the protocol forbids it")
            return False
        if cmd == self.CMD_ARMAREASASUSER:
            cmdText = "arm as user"
        elif cmd == self.CMD_DISARMAREASASUSER:
            cmdText = "disarm as user"
        else:
            self.log("unexpected cmd for arm_disarm_as_user: 0x" + cmd.hex())
            return False
        response = self.sendcommand(cmd, bytes([usernumber]))
        if response is None:
            self.log("cmd {} {:d}: no response from panel".format(cmdText, usernumber))
            return False
        if response == self.CMD_RESPONSE_NAK:
            self.log("cmd {} {:d}: NAK - panel refused the command".format(cmdText, usernumber))
            return False
        if response != self.CMD_RESPONSE_ACK:
            self.log("cmd {} {:d}: unexpected response 0x{}".format(
                cmdText, usernumber, response.hex()))
            return False
        self.log("cmd {} {:d}: accepted by the panel (an ACK is not proof it was actioned)".format(
            cmdText, usernumber))
        return True

    def find_user_by_code(self, code):
        """Match a code typed in Home Assistant against the panel's user table.

        Returns (status, usernumber, name); status is "match", "none" or
        "ambiguous". The code itself is never logged, published or returned.

        The panel enforces what each user may actually do, so a match here is
        permission to *send* the command, not permission to arm or disarm -
        a user without disarm rights is refused by the panel.
        """
        if not code or not code.isdigit():
            return ("none", None, None)
        matches = []
        for usernumber, user in list(self.users.items()):
            # user 0 is the synthesised Engineer entry: it has no code, and
            # the protocol forbids arming or disarming as user 0
            if usernumber == 0:
                continue
            stored = user.passcode
            if not stored:
                continue
            if len(stored) == len(code) and stored == code:
                matches.append((usernumber, user.name))
        if len(matches) == 1:
            return ("match", matches[0][0], matches[0][1])
        if len(matches) > 1:
            return ("ambiguous", None, None)
        return ("none", None, None)

    def arm_disarm_reset_area(self, cmd, arm_type, area_bitmap):
        """CMD_ARMAREAS, CMD_DISARMAREAS, CMD_RESETAREAS"""
        if cmd == self.CMD_ARMAREAS:
            body = arm_type + area_bitmap[0 : self.areaBitmapSize]
        elif cmd == self.CMD_DISARMAREAS or cmd == self.CMD_RESETAREAS:
            body = area_bitmap[0 : self.areaBitmapSize]
        else:
            self.log("unexpected cmd for ARMAREAS: 0x" + cmd.hex())
            return False
        response = self.sendcommand(cmd, body)
        if response is None:
            self.log("sendcommand returned None for ARMAREAS")
            return False
        if response == self.CMD_RESPONSE_NAK:
            self.log("NAK response from panel for ARMAREAS")
            return False
        elif response != self.CMD_RESPONSE_ACK:
            self.log(
                "unexpected ack payload for ARMAREAS: 0x"
                + cmd.hex()
                + " response: "
                + str(response.hex())
            )
            return False
        if cmd == self.CMD_ARMAREAS:
            if arm_type == self.ARMING_TYPE_FULL:
                cmdText = "arm"
            else:
                cmdText = "part arm"
        elif cmd == self.CMD_DISARMAREAS:
            cmdText = "disarm"
        elif cmd == self.CMD_RESETAREAS:
            cmdText = "reset"
            self.schedule_flag_readback()
        else:
            cmdText = "unknown"
        self.log(
            "cmd {} areas: 0x{}".format(
                cmdText, area_bitmap[0 : self.areaBitmapSize].hex()
            )
        )
        return True

    def get_system_flags(self):
        """CMD_GETSYSTEMFLAGS"""
        details = self.sendcommand(self.CMD_GETSYSTEMFLAGS, None)
        if details is None:
            return None
        if len(details) == 8:
            for idx in range(0, 8):
                sysFlags = details[idx]
                self.log("systemFlags {:d}: {:d}".format(idx, sysFlags))
            return True
        else:
            self.log(
                "GETSYSTEMFLAGS: response wrong length: {:d}/{:d} ".format(
                    len(details), 8
                )
            )
            self.log("Payload: ")
            hexdump.hexdump(details)
            return None

    def get_area_flags(self, startAreaFlag, numAreaFlags):
        """CMD_GETAREAFLAGS"""
        if self.numberOfZones == 640 and numAreaFlags > 31:
            numAreaFlags = 31
        body = bytes([(startAreaFlag & 0xFF), (numAreaFlags & 0xFF)])
        details = self.sendcommand(self.CMD_GETAREAFLAGS, body)
        if details is None:
            return None
        expectedResultSize = self.areaBitmapSize * numAreaFlags
        if len(details) == expectedResultSize:
            outputAreaBitmaps = {}
            for outputArea in range(0, numAreaFlags):
                idx = self.areaBitmapSize * outputArea
                areaBitmap = details[idx : (idx + self.areaBitmapSize + 1)]
                outputAreaBitmaps[startAreaFlag + outputArea] = areaBitmap
                if self.log_verbose:
                    self.log(
                        "GETAREAFLAGS {:d}: 0x{}".format(
                            startAreaFlag + outputArea, areaBitmap.hex()
                        )
                    )
            return outputAreaBitmaps
        else:
            self.log(
                "GETAREAFLAGS: response wrong length: {:d}/{:d} ".format(
                    len(details), expectedResultSize
                )
            )
            self.log("Payload: ")
            hexdump.hexdump(details)
            return None

    def get_lcd_display(self):
        """CMD_GETLCDDISPLAY"""
        lcddisplay = self.sendcommand(self.CMD_GETLCDDISPLAY, None)
        if lcddisplay is None:
            return None
        if len(lcddisplay) != 32:
            self.log("GETLCDDISPLAY: response wrong length")
            self.log("Payload: ")
            hexdump.hexdump(lcddisplay)
            return None
        self.log("Panel LCD display: " + lcddisplay.decode("ascii"))
        return lcddisplay

    def get_log_pointer(self):
        """CMD_GETLOGPOINTER"""
        logpointerresp = self.sendcommand(self.CMD_GETLOGPOINTER, None)
        if logpointerresp is None:
            return None
        if len(logpointerresp) != 2:
            self.log("GETLOGPOINTER: response wrong length")
            self.log("Payload: ")
            hexdump.hexdump(logpointerresp)
            return None
        logpointer = logpointerresp[0] + (logpointerresp[1] << 8)
        self.log("Log pointer: {:d}".format(logpointer))
        return logpointer

    def get_panel_identification(self):
        """CMD_GETPANELIDENTIFICATION"""
        panelid = self.sendcommand(self.CMD_GETPANELIDENTIFICATION, None)
        if panelid is None:
            return None
        if len(panelid) != 32:
            self.log("GETPANELIDENTIFICATION: response wrong length")
            self.log("Payload: ")
            hexdump.hexdump(panelid)
            return None
        panelid = panelid.decode("ascii")
        self.log("Panel identification: " + panelid)
        return panelid

    def get_date_time(self):
        """CMD_GETDATETIME"""
        datetimeresp = self.sendcommand(self.CMD_GETDATETIME, None)
        if datetimeresp is None:
            return None
        if len(datetimeresp) < 6:
            self.log("GETDATETIME: response too short")
            self.log("Payload: ")
            hexdump.hexdump(datetimeresp)
            return None
        datetimeresp = bytearray(datetimeresp)
        datetimestr = "20{2:02d}-{1:02d}-{0:02d} {3:02d}:{4:02d}:{5:02d}".format(
            *datetimeresp
        )
        paneltime = datetime.datetime(
            2000 + datetimeresp[2],
            datetimeresp[1],
            datetimeresp[0],
            *datetimeresp[3:],
        )
        seconds = int((paneltime - datetime.datetime.now()).total_seconds())
        if seconds > 0:
            diff = " (panel is ahead by {:d} seconds)".format(seconds)
        else:
            diff = " (panel is behind by {:d} seconds)".format(-seconds)
        self.log("Panel date/time: " + datetimestr + diff)
        
        maxclockerror = int (os.getenv("MAXCLOCKERROR", 5)) # panel clock will be corrected to os clock if error > 5 secs
        if seconds > maxclockerror:
            # correct the clock
            boolresult = self.set_date_time()
            if boolresult:
                result = "success"
            else:
                result = "failed"    
            self.log("Trying to correct panel time: " + result )

        return datetimestr

    def set_date_time(self):
        """CMD_SETDATETIME"""
        now = datetime.datetime.now()
        datelist = [now.day,now.month,now.year-2000,now.hour,now.minute,now.second]
        nowbytes = bytes(datelist)

        response = self.sendcommand(self.CMD_SETDATETIME, nowbytes)
        if response is None:
            self.log("sendcommand returned None for set date-time")
            return False
        if response == self.CMD_RESPONSE_NAK:
            self.log("NAK response from panel")
            return False
        elif response != self.CMD_RESPONSE_ACK:
            self.log("unexpected ack payload: " + str(response))
            return False
        return True



    def get_system_power(self):
        """CMD_GETSYSTEMPOWER"""
        details = self.sendcommand(self.CMD_GETSYSTEMPOWER, None)
        if details is None:
            return None
        if len(details) != 5:
            self.log("GETSYSTEMPOWER: response wrong length")
            self.log("Payload: ")
            hexdump.hexdump(details)
            return None
        ref_v = details[0]
        sys_v = details[1]
        bat_v = details[2]
        sys_i = details[3]
        bat_i = details[4]
        system_voltage = 13.7 + ((sys_v - ref_v) * 0.070)
        battery_voltage = 13.7 + ((bat_v - ref_v) * 0.070)
        system_current = sys_i * 9
        battery_current = bat_i * 9
        self.log(
            "System power: system voltage {:.2f} battery voltage {:.2f} system current {:d} battery current {:d}".format(
                system_voltage, battery_voltage, system_current, battery_current
            )
        )
        return (system_voltage, battery_voltage, system_current, battery_current)

    def get_user(self, usernumber):
        """CMD_GETUSER"""
        body = usernumber.to_bytes(self.zoneNumSize, "little")
        details = self.sendcommand(self.CMD_GETUSER, body)
        if details is None:
            return None
        user = User()
        if len(details) == 23:
            username = details[0:8].decode("ascii")
            username = username.replace("\x00", " ")
            username = re.sub(r"\W+", " ", username)
            username = username.strip()
            user.name = username
            user.passcode = self.bcdDecodeBytes(details[8:11])
            user.areas = details[11]
            user.modifiers = details[12]
            user.locks = details[13]
            user.doors = details[14:17]
            user.tag = self.bcdDecodeBytes(details[17:21])  # last byte always 0xff
            user.config = details[21] + ((details[22]) << 8)
        else:
            # there are other lengths but I have no way to test
            self.log("GETUSER: unexpected response length {:d}".format(len(details)))
            self.log("Payload: ")
            hexdump.hexdump(details)
            return None
        if user.valid():
            self.log("user {:d} name '{}'".format(usernumber, user.name))
        return user

    def get_area_details(self, areaNumber):
        """CMD_GETAREADETAILS"""
        details = self.sendcommand(self.CMD_GETAREADETAILS, bytes([areaNumber]))
        if details is None:
            return None
        area = self.get_area(areaNumber)
        if len(details) == 25:
            # first byte is area number
            areatext = (details[1:17]).decode("ascii")
            areatext = areatext.replace("\x00", " ")
            areatext = re.sub(r"\W+", " ", areatext)
            areatext = areatext.strip()
            if len(areatext) > 0:
                area.text = areatext
            area.exitDelay = details[17] + (details[18] << 8)
            area.entry1Delay = details[19] + (details[20] << 8)
            area.entry2Delay = details[21] + (details[22] << 8)
            area.secondEntry = details[23] + (details[24] << 8)
            self.log(
                "area {:d} text '{}' exitDelay {:d} entry1 {:d} entry2 {:d} secondEntry {:d}".format(
                    areaNumber,
                    area.text,
                    area.exitDelay,
                    area.entry1Delay,
                    area.entry1Delay,
                    area.secondEntry,
                )
            )
            if self.area_details_func is not None:
                self.area_details_func(area, self.panelType, self.numberOfZones)
        return area

    def get_zone_changes(self):
        """CMD_GETZONECHANGES"""
        details = self.sendcommand(self.CMD_GETZONECHANGES, None)
        if details is None:
            self.log("GZC_none")
            return None
        if len(details) == self.zoneBitmapSize:  # was zoneBitmapSize + 2
            changedZonesBitmap = details
            if self.log_verbose:
                    self.log(
                        "GETZONECHANGES {:d}: 0x{}".format(
                            self.zoneBitmapSize, changedZonesBitmap.hex()
                        )
                    )
            return changedZonesBitmap
        else:
            self.log(
                "GETZONECHANGES: response wrong length: {:d}/{:d} ".format(
                    len(details), self.zoneBitmapSize
                )
            )
            self.log("Payload: ")
            hexdump.hexdump(details)
            return None

    def set_event_messages(self):
        """CMD_SETEVENTMESSAGES"""
        DEBUG_FLAG = 1
        ZONE_EVENT_FLAG = 1 << 1
        AREA_EVENT_FLAG = 1 << 2
        OUTPUT_EVENT_FLAG = 1 << 3
        USER_EVENT_FLAG = 1 << 4
        LOG_FLAG = 1 << 5
        events = (
            ZONE_EVENT_FLAG
            | AREA_EVENT_FLAG
            | USER_EVENT_FLAG
            | LOG_FLAG
        )
        if self.requestPanelOutputEvents:
            events |= OUTPUT_EVENT_FLAG
        body = events.to_bytes(2, "little")
        response = self.sendcommand(self.CMD_SETEVENTMESSAGES, body)
        if response == self.CMD_RESPONSE_NAK:
            self.log("NAK response from panel")
            return False
        elif response != self.CMD_RESPONSE_ACK:
            self.log("unexpected ack payload: " + str(response))
            return False
        return True

    ### Helpers for processing texecom data

    def get_number_zones(self):
        idstr = self.get_panel_identification()
        if idstr is None:
            return None
        self.panelType, numberOfZones, something, self.firmwareVersion = idstr.split()
        self.numberOfZones = int(numberOfZones)
        zone2NumberOfUsers = {
            12: 8,
            24: 25,
            48: 50,
            64: 50,
            88: 100,
            168: 200,
            640: 1000,
        }
        zone2NumberOfAreas = {12: 2, 24: 2, 48: 4, 64: 4, 88: 8, 168: 16, 640: 64}
        zone2AreaBitmapSize = {12: 1, 24: 1, 48: 1, 64: 1, 88: 1, 168: 2, 640: 8}
        zone2ZoneNumSize = {12: 1, 24: 1, 48: 1, 64: 1, 88: 1, 168: 1, 640: 2}
        self.numberOfUsers = zone2NumberOfUsers[self.numberOfZones]
        self.numberOfAreas = zone2NumberOfAreas[self.numberOfZones]
        self.areaBitmapSize = zone2AreaBitmapSize[self.numberOfZones]
        self.zoneBitmapSize = int(self.numberOfZones / 8)
        self.zoneNumSize = zone2ZoneNumSize[self.numberOfZones]

    def set_zone_state(self, zone, zone_bitmap):
        zone.state = zone_bitmap
        if (zone.state & 0x3) == 1:
            zone.active = True
        else:
            zone.active = False
        zone_str = ["secure", "active", "tamper", "short"][zone.state & 0x3]
        if zone.state & (1 << 2):
            zone_str += ", fault"
        if zone.state & (1 << 3):
            zone_str += ", failed test"
        if zone.state & (1 << 4):
            zone_str += ", alarmed"
            zone.armed = True
        else:
            zone.armed = False
        if zone.state & (1 << 5):
            zone_str += ", manual bypassed"
        if zone.state & (1 << 6):
            zone_str += ", auto bypassed"
        if zone.state & (1 << 7):
            zone_str += ", zone masked"
        zone.state_text = zone_str

    def get_zone(self, zone_number):
        if zone_number not in self.zones:
            self.zones[zone_number] = Zone(zone_number)
        return self.zones[zone_number]

    def get_area(self, areaNumber):
        if areaNumber not in self.areas:
            self.areas[areaNumber] = Area(areaNumber)
        return self.areas[areaNumber]

    def get_all_zones(self):
        for zoneNumber in range(1, self.numberOfZones + 1):
            zone = self.get_zone_details(zoneNumber)
            self.zones[zoneNumber] = zone
            if zone.zoneType != zone.ZONETYPE_UNUSED:
                self.highestUsedZone = zoneNumber
                self.associateZoneWithAreas(zone)

    def get_all_users(self):
        """Read the whole user table and swap it in atomically.

        Slot numbering, verified on this panel 2026-09-18: an UNPROGRAMMED
        slot returns a full 23-byte record with an empty code (so it is simply
        skipped), but slot `numberOfUsers` itself NAKs and makes get_user
        return None. The range below is therefore correct as written - do not
        "fix" it to numberOfUsers + 1, which would crash on every read.
        """
        if self.numberOfUsers is None:
            return
        users = {}
        for usernumber in range(1, self.numberOfUsers):
            user = self.get_user(usernumber)
            if user is not None and user.valid():
                users[usernumber] = user
        if not users and self.users:
            # A failed refresh must never empty the table: an empty table
            # matches no code and would silently disable arm and disarm from
            # Home Assistant until the next restart.
            self.log("user table refresh returned nothing; keeping the previous {:d} entries".format(
                len(self.users)))
            return
        engineer = User()
        engineer.name = "Engineer"
        users[0] = engineer
        # rebind rather than mutate: on_message reads this from the MQTT thread
        self.users = users
        self.next_user_refresh = time.time() + self.USER_REFRESH_SECS
        withcode = len([u for n, u in users.items() if n != 0 and u.passcode])
        self.log("user table loaded: {:d} users with a code".format(withcode))

    def get_all_areas(self):
        for areanumber in range(1, self.numberOfAreas + 1):
            area = self.get_area_details(areanumber)
            self.areas[areanumber] = area

    def get_all_zones_state(self):
        numZones = self.get_zone_state(1, self.highestUsedZone)
        if numZones is not None and numZones != self.highestUsedZone:
            self.log(
                "get_all_zones_state request {:d} zones, got {:d}".format(
                    self.highestUsedZone, numZones
                )
            )
        return numZones

    def get_changed_zones_state(self):
        changedZonesBitmap = self.get_zone_changes()
        if changedZonesBitmap is None:
            return None
        flags = int.from_bytes(changedZonesBitmap, "little")
        zoneNum = 1
        while zoneNum <= self.highestUsedZone:
            if (flags & 1) == 0:
                if flags == 0:
                    break
                flags = flags >> 1
                zoneNum += 1
            else:
                startZoneNum = zoneNum
                numZonesInBlock = 0
                while (flags & 1) == 1 and numZonesInBlock < 168:
                    flags = flags >> 1
                    zoneNum += 1
                    numZonesInBlock += 1
                respNumZone = self.get_zone_state(startZoneNum, numZonesInBlock)
                if respNumZone is None:
                    return None
        return True

    # Area flag names from the Texecom Connect Protocol Payload Specification
    # Rev N section 4.11.5. The list index IS the flag number used by
    # CMD_GETAREAFLAGS, so do not reorder it.
    AREA_FLAG_NAMES = [
        "Alarm",
        "Guard Alarm",
        "Guard Access Alarm",
        "Entry Alarm",
        "Confirmed Alarm",
        "24hr audible Alarm",
        "24hr Silent Alarm",
        "24hr Gas Alarm",
        "PA Alarm",
        "PA Silent Alarm",
        "Duress Alarm",
        "Fire Alarm",
        "Medical Alarm",
        "Auxiliary Alarm",
        "Tamper Alarm",
        "Abort",
        "Ready",
        "Entry",
        "Second Entry",
        "Exit",
        "Entry/Exit",
        "Armed",
        "Full Armed",
        "Part Armed",
        "Part Arming",
        "Force Armable",
        "Force Armed",
        "Arm Failed",
        "Bell SAB",
        "Bell SCB",
        "Strobe",
        "Detector Latch",
        "Detector Reset",
        "Walk Test",
        "Omitted",
        "24hr Omit",
        "Reset Required",
        "Door Strike",
        "Chime Mimic",
        "Chime Enabled",
        "Double Knock Active",
        "Beam Pair",
        "Zone on test",
        "Test Failed",
        "Internal Alarm",
        "Auto Arming",
        "Time Arming",
        "1st Code Entered",
        "2nd Code Entered",
        "Area Secured",
        "Part Arm 1",
        "Part Arm 2",
        "Part Arm 3",
        "Custom Alarm",
        "Zone Warning",
        "Arm Fail Warning",
        "Forced Entry",
        "Zones Locked Out",
        "All Armed",
        "Time Arm Disabled",
        "Armed/Alarm",
        "Intruder Alarm",
        "Speaker Mimic",
        "Full Armed/Exit",
        "Detector Fault",
        "Detector Masked",
        "Fault Present",
        "LED control",
        "Full Armed Entry",
        "Fire Sounder",
        "PA Confirmed",
        "Confirmed Intruder",
        "Seismic Alarm",
    ]

    # While an area is in alarm, poll this wider set every ALARM_POLL_INTERVAL
    # seconds. A real alarm here lasted 14 seconds from trigger to silence, so
    # the normal ~60 s poll would miss the entire event and show only the
    # aftermath.
    ALARM_POLL_INTERVAL = 5
    ALARM_POLL_WINDOW = 600
    AREA_FLAG_ALARM_SET = [
        0,   # Alarm
        1,   # Guard Alarm
        2,   # Guard Access Alarm
        3,   # Entry Alarm
        4,   # Confirmed Alarm
        5,   # 24hr audible Alarm
        13,  # Auxiliary Alarm
        14,  # Tamper Alarm
        15,  # Abort
        21,  # Armed
        28,  # Bell SAB
        29,  # Bell SCB
        30,  # Strobe
        36,  # Reset Required
        44,  # Internal Alarm
        53,  # Custom Alarm
        61,  # Intruder Alarm
        62,  # Speaker Mimic
    ]

    def start_alarm_flag_polling(self, areanumber):
        """Begin fast flag polling because an area has entered alarm."""
        self.alarmPollUntil = time.time() + self.ALARM_POLL_WINDOW
        self.alarmPollNext = 0
        self.alarmPollSweepDone = False
        self.log(
            "areaFlags: area {:d} in alarm - polling every {:d}s for up to {:d}s".format(
                areanumber, self.ALARM_POLL_INTERVAL, self.ALARM_POLL_WINDOW
            )
        )

    # The flags that mean "an alarm is happening NOW", as opposed to "an alarm
    # happened". Only these end the fast poll.
    #
    # Flag 00 Alarm is deliberately NOT here. Proven 2026-09-19 on a staged
    # confirmed intruder alarm: flag 00 was CLEAR at 09:56:04 while the alarm
    # was sounding and only went SET at 09:56:35, after the disarm. It is alarm
    # MEMORY, not alarm state, so the old flag-00 test ended fast polling in the
    # middle of the event. Flags 01 Guard Alarm, 04 Confirmed Alarm and 15 Abort
    # behaved the same way in the same run and are excluded for the same reason.
    AREA_FLAG_LIVE_ALARM = [
        5,   # 24hr audible Alarm
        28,  # Bell SAB
        30,  # Strobe
        44,  # Internal Alarm
        61,  # Intruder Alarm
        62,  # Speaker Mimic
    ]

    def alarm_flag_set_anywhere(self, bitmaps):
        """True/False if any LIVE alarm flag is set on any area, None if unknown.

        None means the question could not be answered - no live flag was read -
        and the caller must not treat that as "the alarm is over".
        """
        if not bitmaps:
            return None
        areamask = (1 << self.numberOfAreas) - 1
        answered = False
        for flagnum in self.AREA_FLAG_LIVE_ALARM:
            bitmap = bitmaps.get(flagnum)
            if bitmap is None:
                continue
            answered = True
            if (int.from_bytes(bitmap[: self.areaBitmapSize], "little") & areamask) != 0:
                return True
        return False if answered else None

    def area_bit_set(self, bitmap, areanumber):
        """True if the bit for this area is set in one flag's bitmap."""
        flags = int.from_bytes(bitmap[: self.areaBitmapSize], "little")
        return (flags >> (areanumber - 1)) & 1 == 1

    def clear_alarm_state_if_over(self, bitmaps):
        """Take an area out of 'in alarm' once no LIVE alarm flag is set on it.

        The panel reports an area ENTERING alarm as an event and never reports
        it leaving - not by area state, not by zone state, not by log event,
        not even on an engineer reset. Home Assistant therefore sat at
        'triggered' until the app was restarted, because the only code path
        that published a disarm was the startup enumeration, where area.state
        is still None.

        Definition agreed with the owner 2026-09-19: an area's alarm is over
        when none of AREA_FLAG_LIVE_ALARM is set on that area. Flag 21 Armed
        is NOT sufficient on its own - an alarm raised while the system is
        disarmed (24hr audible, internal, fire/CO, PA, tamper) leaves 21 clear
        throughout, so keying on it would publish 'disarmed' while the sounder
        was still running.

        The armed/disarmed state published afterwards is read from flag 21 in
        the SAME bitmaps, so it cannot disagree with the alarm test and costs
        no extra panel traffic.

        Deliberately only moves an area OUT of AREA_STATE_INALARM. Arming
        states arrive as events and are not second-guessed here.
        """
        if not bitmaps or 21 not in bitmaps:
            return
        if any(flag not in bitmaps for flag in self.AREA_FLAG_LIVE_ALARM):
            # A partial read cannot show that an alarm is over. Never guess.
            return
        for areanumber in range(1, self.numberOfAreas + 1):
            area = self.get_area(areanumber)
            if area.state != self.AREA_STATE_INALARM:
                continue
            if any(
                self.area_bit_set(bitmaps[flag], areanumber)
                for flag in self.AREA_FLAG_LIVE_ALARM
            ):
                continue
            newState = (
                self.AREA_STATE_ARMED
                if self.area_bit_set(bitmaps[21], areanumber)
                else self.AREA_STATE_DISARMED
            )
            area.save_state(newState)
            if self.area_event_func is not None:
                self.area_event_func(area)
            self.log(
                "areaState {:d} '{}': {:d} {} (alarm over - no live alarm flag set)".format(
                    areanumber, area.text, area.state, area.state_text
                )
            )

    # Flags that settle an area left 'in exit': 19 Exit, 21 Armed,
    # 23 Part Armed, 24 Part Arming.
    AREA_FLAG_EXIT_SET = [19, 21, 23, 24]

    # Used when the panel's exit delay for an area is not known.
    EXIT_GRACE_DEFAULT_SECS = 30

    def resolve_stale_exit_state(self, now=None):
        """Settle an area still 'in exit' after its exit delay has run out.

        After an Exit Error (arm failed) the panel sends no area event, so the
        area sat 'in exit' - Home Assistant showed 'arming' - until the next
        real arm. Seen 2026-09-21: 2 h 40 m. saveAreasCurrentArmedState()
        cannot catch it: it keeps a known state while flag 21 is clear.

        Rule agreed with the owner 2026-09-22: once the exit delay (30 s at
        the time) has passed, take the state from the panel's flags. Disarmed
        needs Exit, Armed, Part Armed and Part Arming all read clear; a failed
        read decides nothing. A set Armed / Part Armed flag settles a lost
        arm event the same way.

        Costs no panel traffic unless an area is overdue.
        """
        if now is None:
            now = time.time()
        overdue = []
        for areanumber in range(1, self.numberOfAreas + 1):
            area = self.get_area(areanumber)
            if area.state != self.AREA_STATE_INEXIT:
                continue
            if area.exitStartedAt is None:
                # In exit without a known start - start the clock now.
                area.exitStartedAt = now
                continue
            grace = getattr(area, "exitDelay", None) or self.EXIT_GRACE_DEFAULT_SECS
            if now - area.exitStartedAt > grace:
                overdue.append(area)
        if not overdue:
            return
        bitmaps, failed = self.read_area_flags_individually(self.AREA_FLAG_EXIT_SET)
        if failed:
            self.log(
                "areaFlags: {:d} of {:d} exit flags failed to read - exit state left as is".format(
                    failed, len(self.AREA_FLAG_EXIT_SET)
                )
            )
            return
        for area in overdue:
            if self.area_bit_set(bitmaps[19], area.number) or self.area_bit_set(
                bitmaps[24], area.number
            ):
                # Panel still says exit is running (e.g. a longer exit delay).
                continue
            if self.area_bit_set(bitmaps[23], area.number):
                newState = self.AREA_STATE_PARTARMED
            elif self.area_bit_set(bitmaps[21], area.number):
                newState = self.AREA_STATE_ARMED
            else:
                newState = self.AREA_STATE_DISARMED
            area.save_state(newState)
            if self.area_event_func is not None:
                self.area_event_func(area)
            self.log(
                "areaState {:d} '{}': {:d} {} (exit overdue {:.0f} s - from panel flags)".format(
                    area.number, area.text, area.state, area.state_text,
                    now - area.exitStartedAt
                )
            )

    def service_alarm_flag_polling(self):
        """One tick of fast polling. Caller guarantees no command is in flight."""
        self.alarmPollNext = time.time() + self.ALARM_POLL_INTERVAL
        bitmaps = self.log_all_area_flags(
            "alarm", self.AREA_FLAG_ALARM_SET, always=True
        )
        if not self.alarmPollSweepDone:
            # One full sweep after the first fast read, to catch anything the
            # alarm set above does not anticipate. Deliberately second, so the
            # quick read lands while the alarm is still sounding.
            self.alarmPollSweepDone = True
            self.log_all_area_flags(
                "alarm full sweep", list(range(len(self.AREA_FLAG_NAMES))), always=True
            )
        if self.alarm_flag_set_anywhere(bitmaps) is False:
            self.log(
                "areaFlags: no live alarm flag set on any area - ending fast poll"
            )
            self.alarmPollUntil = 0
        # Per-area, so area 1 can leave alarm while area 2 is still in it.
        self.clear_alarm_state_if_over(bitmaps)

    # Area flags published to Home Assistant as their own binary sensor.
    # Flag 36 is the panel's own "this area still needs a reset" state, and it
    # is the only evidence available that a reset did anything: the panel
    # reports no event when the condition clears (proven 2026-09-17).
    AREA_FLAGS_PUBLISHED = [36]

    # After a reset, re-read the flags rather than waiting up to a minute for
    # the idle poll. A reset that clears nothing is itself the finding, so it
    # must be visible promptly.
    FLAG_READBACK_DELAYS = [5, 15]

    def schedule_flag_readback(self):
        """Queue flag re-reads after a command that should change them."""
        now = time.time()
        self.flagReadBackDue = [now + delay for delay in self.FLAG_READBACK_DELAYS]

    def publish_area_flags(self, bitmaps):
        """Hand the published flags to the MQTT layer, one area at a time.

        A flag that failed to read is skipped entirely: leaving the last
        published value in place is right, whereas publishing a false 'clear'
        would say the panel is happy when we simply could not ask it.
        """
        if self.area_flags_func is None or not bitmaps:
            return
        for flagnum in self.AREA_FLAGS_PUBLISHED:
            if flagnum not in bitmaps:
                continue
            bitmap = bitmaps[flagnum][: self.areaBitmapSize]
            value = int.from_bytes(bitmap, "little")
            for areanumber in range(1, self.numberOfAreas + 1):
                area = self.get_area(areanumber)
                self.area_flags_func(
                    area, flagnum, bool(value & (1 << (areanumber - 1)))
                )

    # The flags worth reading on every poll. The panel refuses a bulk read, so
    # each one costs a round trip - keep this list short.
    #   00 Alarm, 05 24hr audible Alarm, 21 Armed, 36 Reset Required,
    #   61 Intruder Alarm
    # 0 Alarm and 36 Reset Required are watched because they are the panel's
    # own memory of an alarm; 21 Armed gives armed/disarmed; the rest are the
    # live-alarm flags, needed so the idle poll can tell when an alarm is over.
    AREA_FLAG_WATCHLIST = [0, 5, 21, 28, 30, 36, 44, 61, 62]

    def read_area_flags_individually(self, flagnums):
        """Read the given area flags one command at a time.

        `get_area_flags(N, 1)` is the only shape this panel honours. Asking for
        73 flags in one command returned a single byte and failed the length
        check ("response wrong length: 1/73") on Elite 48 firmware
        V4.02.01LS1, so the spec's count field is evidently not implemented as
        documented. Returns {flagnum: bitmap} for those that read, plus the
        number that failed.
        """
        bitmaps = {}
        failed = 0
        for flagnum in flagnums:
            result = self.get_area_flags(flagnum, 1)
            if result is None or flagnum not in result:
                failed += 1
            else:
                bitmaps[flagnum] = result[flagnum]
        return bitmaps, failed

    def probe_area_flag_batching(self):
        """One-off: log whether the panel honours ANY batched flag read.

        Costs a single command. Purely informational - if a batch of two ever
        works, the per-poll watchlist could be collapsed into fewer round
        trips. Nothing depends on the answer.
        """
        result = self.get_area_flags(0, 2)
        if result is None:
            self.log("areaFlags: batch probe (2 flags) NOT supported")
        else:
            self.log(
                "areaFlags: batch probe (2 flags) returned {:d} bitmaps".format(
                    len(result)
                )
            )

    def log_all_area_flags(self, reason, flagnums=None, always=False):
        """Log which area flags the panel holds, for each area.

        Diagnostic only: publishes no state and changes no area. It exists
        because the panel reports an area entering alarm as an event but never
        reports it leaving, so the flags are the only way to see when the panel
        itself considers the alarm over.

        `flagnums` defaults to the watchlist. The scope is written into every
        log line, because a line listing only the watchlist must never be read
        later as though it covered all 73 flags.
        """
        if flagnums is None:
            flagnums = self.AREA_FLAG_WATCHLIST
        scope = "{:d} flags".format(len(flagnums))
        bitmaps, failed = self.read_area_flags_individually(flagnums)
        if not bitmaps:
            # Never fail the caller on this - returning None into the
            # idle-command check would close the socket.
            self.log("areaFlags: read failed entirely ({}, {})".format(reason, scope))
            return None
        if failed:
            self.log(
                "areaFlags: {:d} of {:d} flags failed to read ({})".format(
                    failed, len(flagnums), reason
                )
            )
        now = time.time()
        forced = always or (now - self.lastAreaFlagsLog) > 600
        for areanumber in range(1, self.numberOfAreas + 1):
            mask = 1 << (areanumber - 1)
            setflags = []
            for flagnum in sorted(bitmaps):
                # get_area_flags() slices one byte more than areaBitmapSize,
                # so trim before testing rather than relying on the extra byte
                # landing above the area bits.
                bitmap = bitmaps[flagnum][: self.areaBitmapSize]
                if int.from_bytes(bitmap, "little") & mask:
                    setflags.append(
                        "{:d} {}".format(flagnum, self.AREA_FLAG_NAMES[flagnum])
                    )
            text = ", ".join(setflags) if setflags else "(none set)"
            key = (scope, areanumber)
            if forced or self.lastAreaFlags.get(key) != text:
                area = self.get_area(areanumber)
                self.log(
                    "areaFlags {:d} '{}' [{}, of {}]: {}".format(
                        areanumber, area.text, reason, scope, text
                    )
                )
                self.lastAreaFlags[key] = text
        if forced and not always:
            self.lastAreaFlagsLog = now
        self.publish_area_flags(bitmaps)
        return bitmaps

    def get_armed_area_state(self):
        # we just track armed state (not part arming or part armed etc)
        outputAreaBitmaps = self.get_area_flags(21, 1)
        if outputAreaBitmaps is None:
            return None
        return self.saveAreasCurrentArmedState(
            outputAreaBitmaps[21], self.AREA_STATE_ARMED
        )

    def saveAreasCurrentArmedState(self, areaBitmap, areaStateWhenTrue):
        # if its not alarm flag, assume its disarmed (any interim state should self correct on next event)
        flags = int.from_bytes(areaBitmap, "little")
        for areanumber in range(1, self.numberOfAreas + 1):
            area = self.get_area(areanumber)
            if (flags & 1) == 1:
                newState = areaStateWhenTrue
            else:
                if area.state == None:
                    newState = self.AREA_STATE_DISARMED
                else:
                    newState = area.state
            # If we know that the area is part armed, don't override that with fully armed
            # (since area flags only gives us a binary armed / disarmed and not part armed)
            if area.state != newState and area.state != self.AREA_STATE_PARTARMED and newState != self.AREA_STATE_ARMED:
                area.save_state(newState)
                if self.area_event_func is not None:
                    self.area_event_func(area)
                self.log(
                    "areaState {:d} '{}': {:d} {}".format(
                        areanumber, area.text, area.state, area.state_text
                        )
                )
            flags = flags >> 1
        return True

    def associateZoneWithAreas(self, zone):
        flags = int.from_bytes(zone.areaBitmap, "little")
        for areanumber in range(1, self.numberOfAreas + 1):
            area = self.get_area(areanumber)
            if (flags & 1) == 1:
                zone.areas[areanumber] = area
                area.zones[zone.number] = zone
                self.log(
                    "zone {:d} -> area {:d} ('{}' -> '{}')".format(
                        zone.number, areanumber, zone.text, area.text
                    )
                )
            else:
                if areanumber in zone.areas:
                    del zone.areas[areanumber]
                if zone.number in area.zones:
                    del area.zones[zone.number]
            flags = flags >> 1
        return True

    def alive(self):
        # call any alive callback
        self.time_last_heartbeat = time.time()
        self.log("alive ok")
        if self.alive_event_func is not None:
            self.alive_event_func()
        return True

    def get_site_data(self):
        self.get_all_areas()
        self.get_all_zones()
        self.get_all_users()

    def on_alive_event(self, alive_event_func):
        self.alive_event_func = alive_event_func

    def on_area_event(self, area_event_func):
        self.area_event_func = area_event_func

    def on_zone_event(self, zone_event_func):
        self.zone_event_func = zone_event_func

    def on_area_details(self, area_details_func):
        self.area_details_func = area_details_func

    def on_zone_details(self, zone_details_func):
        self.zone_details_func = zone_details_func

    def on_log_event(self, log_event_func):
        self.log_event_func = log_event_func

    def on_panel_event(self, panel_event_func):
        """Structured panel log events, for Home Assistant notifications.

        Separate from on_log_event, which carries every line this app
        prints - heartbeats, flag polls and all - as free text.
        """
        self.panel_event_func = panel_event_func

    def note_reset_request(self, usernumber, username):
        """Record who asked Home Assistant for a panel reset.

        The panel logs a reset anonymously, so this is the only place the
        requesting user is known. Consumed once, by the next 'Reset After
        Alarm' within RESET_ATTRIBUTION_SECS.
        """
        self.resetRequest = (time.time(), usernumber, username)

    def on_area_flags(self, area_flags_func):
        self.area_flags_func = area_flags_func

    def enable_output_events(self, yes):
        self.requestPanelOutputEvents = (yes == True)

    # Queue entries are tagged with their kind: "areas" commands carry an
    # area bitmap, "user" commands carry a user number and nothing else.
    def requestArmAreas(self, area_bitmap):
        """Queue arm areas request. Request is queued for processing by main thread"""
        self.arm_disarm_reset_queue.append(("areas", self.CMD_ARMAREAS, self.ARMING_TYPE_FULL, area_bitmap))

    def requestPartArmAreas(self, area_bitmap):
        """Queue part arm areas request. Request is queued for processing by main thread"""
        self.arm_disarm_reset_queue.append(("areas", self.CMD_ARMAREAS, self.ARMING_TYPE_PART1, area_bitmap))

    def requestDisArmAreas(self, area_bitmap):
        """Queue disarm areas request. Request is queued for processing by main thread"""
        self.arm_disarm_reset_queue.append(("areas", self.CMD_DISARMAREAS, None, area_bitmap))

    def requestResetAreas(self, area_bitmap):
        """Queue reset areas request. Request is queued for processing by main thread"""
        self.arm_disarm_reset_queue.append(("areas", self.CMD_RESETAREAS, None, area_bitmap))

    def requestArmAreasAsUser(self, usernumber):
        """Queue arm-as-user request. Request is queued for processing by main thread"""
        self.arm_disarm_reset_queue.append(("user", self.CMD_ARMAREASASUSER, usernumber, None))

    def requestDisArmAreasAsUser(self, usernumber):
        """Queue disarm-as-user request. Request is queued for processing by main thread"""
        self.arm_disarm_reset_queue.append(("user", self.CMD_DISARMAREASASUSER, usernumber, None))

    def set_area_state(self, area, area_state):
        area.state = area_state
        area.state_text = [
            "disarmed",
            "in exit",
            "in entry",
            "armed",
            "part armed",
            "in alarm",
        ][area.state]

    def handle_event_message(self, payload):
        msg_type, payload = payload[0:1], payload[1:]
        if msg_type == self.MSG_DEBUG:
            return "Debug message: " + payload.decode("ascii")
        elif msg_type == self.MSG_ZONEEVENT:
            if len(payload) == 2:
                zone_number = payload[0]
                zone_bitmap = payload[1]
            elif len(payload) == 3:
                zone_number = payload[0] + (payload[1] << 8)
                zone_bitmap = payload[2]
            else:
                return "unknown zone event payload length: {:d}".format(
                    len(payload)
                )
            zone = self.get_zone(zone_number)
            zone.save_state(zone_bitmap)
            if self.zone_event_func is not None:
                self.zone_event_func(zone)
            return "Zone event: zone {:d} '{}' {}".format(
                zone.number, zone.state_text, zone.text
            )
        elif msg_type == self.MSG_AREAEVENT:
            area_number = payload[0]
            area_state = payload[1]
            area = self.get_area(area_number)
            area.save_state(area_state)
            if area_state == self.AREA_STATE_INALARM:
                self.start_alarm_flag_polling(area_number)
            if self.area_event_func is not None:
                self.area_event_func(area)
            return "Area event: area {:d} {} {}".format(
                area.number, area.state_text, area.text
            )
        elif msg_type == self.MSG_OUTPUTEVENT:
            locations = [
                "Panel outputs",
                "Digi outputs",
                "Digi Channel low 8",
                "Digi Channel high 8",
                "Redcare outputs",
                "Custom outputs 1",
                "Custom outputs 2",
                "Custom outputs 3",
                "Custom outputs 4",
                "X-10 outputs",
            ]
            output_location = payload[0]
            output_state = payload[1]
            if output_location < len(locations):
                output_name = locations[output_location]
            elif (output_location & 0xF) == 0:
                output_name = "Network {:d} keypad outputs".format(output_location >> 4)
            else:
                output_name = "Network {:d} expander {:d} outputs".format(
                    output_location >> 4, output_location & 0xF
                )
            return "Output event message: location {:d}['{}'] now {:#04x}".format(
                output_location, output_name, output_state
            )
        elif msg_type == self.MSG_USEREVENT:
            user_number = payload[0]
            user_state = payload[1]
            user_state_str = ["code", "tag", "code+tag"][user_state]
            if user_number in self.users:
                name = self.users[user_number].name
            else:
                name = "unknown"
            return "User event message: logon by user '{}' {:d} {}".format(
                name, user_number, user_state_str
            )
        elif msg_type == self.MSG_LOGEVENT:
            if len(payload) == 8:
                parameter = payload[2]
                areas = payload[3]
                timestamp = payload[4:8]
            elif len(payload) == 9:
                # Premier 168 - longer message as 16 bits of area info
                parameter = payload[2]
                areas = payload[3] + (payload[8] << 8)
                timestamp = payload[4:8]
            elif len(payload) == 16:
                # Premier 640
                # I'm unsure if this is correct and I don't have a panel to test with
                parameter = payload[2] + (payload[3] << 8)
                areas = (
                    payload[4]
                    + (payload[5] << 8)
                    + (payload[6] << 16)
                    + (payload[7] << 24)
                )
                timestamp = payload[8:16]
            else:
                return "unknown log event message payload length"
            event_type = payload[0]
            group_type_msg = payload[1]
            timestamp_int = (
                timestamp[0]
                + (timestamp[1] << 8)
                + (timestamp[2] << 16)
                + (timestamp[3] << 24)
            )
            seconds = timestamp_int & 63
            minutes = (timestamp_int >> 6) & 63
            month = (timestamp_int >> 12) & 15
            hours = (timestamp_int >> 16) & 31
            day = (timestamp_int >> 21) & 31
            year = 2000 + ((timestamp_int >> 26) & 63)
            timestamp_str = "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(
                year, month, day, hours, minutes, seconds
            )
            if event_type == 100:
                # Site Data Changed: something was reprogrammed, at the keypad
                # or in Wintex. Re-read the site data so a changed or deleted
                # user code stops working without waiting for a restart.
                self.siteDataChanged = True
            if event_type in self.log_event_types:
                event_str = self.log_event_types[event_type]
            else:
                event_str = "Unknown log event type {:d}".format(event_type)
            group_type = group_type_msg & 0b00111111
            comm_delayed = group_type_msg & 0b01000000
            communicated = group_type_msg & 0b10000000

            if group_type in self.log_event_group_type:
                group_type_str = self.log_event_group_type[group_type]
            else:
                group_type_str = "Unknown log event group type {:d}".format(group_type)
            group_name = group_type_str

            if comm_delayed:
                group_type_str += " [comm delayed]"
            if communicated:
                group_type_str += " [communicated]"

            if self.panel_event_func is not None:
                self.panel_event_func(self.build_panel_event(
                    event_type, event_str, group_type, group_name,
                    parameter, areas, timestamp_str,
                    bool(comm_delayed), bool(communicated),
                ))

            return "Log event message: {} {}, {} parameter: {:d} areas: {:d}".format(
                timestamp_str, event_str, group_type_str, parameter, areas
            )
        else:
            return "unknown message type " + msg_type.hex() + ": 0x" + payload.hex()

    def message_event(self, payload):
        result = self.handle_event_message(payload)
        self.log(result)
        return None

    ### Main event loop
    def event_loop(self):
        lastConnectedAt = time.time()
        notifiedConnectionLoss = False
        connected = False
        while True:
            if connected:
                lastConnectedAt = time.time()
                connected = False
                notifiedConnectionLoss = False
                self.log("Connection lost")
            connectionLostTime = time.time() - lastConnectedAt
            if connectionLostTime >= 60 and not notifiedConnectionLoss:
                # send-message.sh has never existed in the image and
                # os.system() does not raise, so this notification was dead
                # code failing silently. Connection loss is now visible in HA
                # via the availability topic declared in the discovery payload.
                self.log("Connection lost for over 60 seconds")
                notifiedConnectionLoss = True
            try:
                self.connect()
            except socket.error as e:
                self.log("Connect failed - {}; sleeping for 5 seconds".format(e))
                time.sleep(5)
                continue
            if not self.login():
                self.log(
                    "Login failed - udl password incorrect, pre-v4 panel, or trying to connect too soon: closing socket, try again 5 in seconds"
                )
                time.sleep(5)
                self.closesocket()
                continue
            self.log("login successful")
            if not self.set_event_messages():
                self.log("Set event messages failed, closing socket")
                self.closesocket()
                continue
            connected = True
            if notifiedConnectionLoss:
                self.log("Connection regained")
            self.get_number_zones()
            self.get_date_time()
            self.get_system_power()
            self.get_log_pointer()
            self.get_site_data()
            self.get_all_zones_state()
            self.get_armed_area_state()
            self.probe_area_flag_batching()
            # one-off full sweep: every flag, one command each (~20 s)
            self.log_all_area_flags(
                "startup sweep", list(range(len(self.AREA_FLAG_NAMES)))
            )
            # self.get_system_flags()
            self.log("Got all areas/zones/users; waiting for events")
            while self.s is not None:
                try:
                    for zone in list(self.zones.values()):
                        zone.update()
                    if self.siteDataChanged:
                        self.siteDataChanged = False
                        self.get_site_data()
                    self.recvresponse()
                except socket.timeout:
                    # we didn't send any command, so a timeout is the expected result, continue our loop
                    continue

    ### Comms to texecom panel

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(self.CMD_TIMEOUT)
        self.s.connect((self.host, self.port))
        # if we send the login message to fast the panel ignores it; texecom
        # recommend 500ms, see:
        # http://texecom.websitetoolbox.com/post/show_single_post?pid=1303528828&postcount=4&forum=627911
        time.sleep(0.5)

    def closesocket(self):
        if self.s is not None:
            try:
                self.s.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            self.s.close()
            self.s = None

    def recvresponse(self):
        """Receive a response to a command. Automatically handles any messages that arrive first"""
        startTime = time.time()
        while True:
            if time.time() - startTime > self.CMD_TIMEOUT:
                # if we have had multiple event messages, we may get to the timeout time without the recv timing out
                raise socket.timeout
            assert self.last_command_time > 0
            time_since_last_command = time.time() - self.last_command_time
            if self.last_command is None and len(self.arm_disarm_reset_queue) > 0:
                # when no command waiting, drain any arm_disarm_reset queue
                request = self.arm_disarm_reset_queue.pop(0)
                if request[0] == "user":
                    self.arm_disarm_as_user(request[1], request[2])
                else:
                    self.arm_disarm_reset_area(request[1], request[2], request[3])
            elif (
                self.last_command is None
                and self.flagReadBackDue
                and time.time() >= self.flagReadBackDue[0]
            ):
                self.flagReadBackDue.pop(0)
                self.log_all_area_flags(
                    "after reset", self.AREA_FLAG_ALARM_SET, always=True
                )
            elif (
                self.last_command is None
                and time.time() < self.alarmPollUntil
                and time.time() >= self.alarmPollNext
            ):
                # Fast polling starves the 30 s idle commands for the duration
                # of the window; that is acceptable because these reads keep the
                # panel's 60 s timeout fed and zone changes still arrive as
                # events.
                self.service_alarm_flag_polling()
            elif time_since_last_command > 30:
                # get_changed_zones_state and get_armed_area_state to protect against any lost event messages for zone/area status
                # and to reset the panel's 60 second timeout
                # this ends up recursively calling recvresponse; however as our retry * timeout (3 * 2 == 6) is
                # far less than the 30 seconds between idle commands that won't be an issue
                if self.lastIdleCommand == 0:
                    result = self.get_changed_zones_state()
                else:
                    result = self.get_armed_area_state()
                    if result is not None:
                        self.clear_alarm_state_if_over(
                            self.log_all_area_flags("idle")
                        )
                        self.resolve_stale_exit_state()
                self.lastIdleCommand += 1
                if self.lastIdleCommand == 2:
                    self.lastIdleCommand = 0
                if result is None:
                    self.log("idle command failed; closing socket")
                    self.closesocket()
                    return None
                if time.time() >= self.next_user_refresh:
                    # Backstop for anything the panel does not announce as a
                    # Site Data Changed event. The main loop does the work.
                    self.next_user_refresh = time.time() + self.USER_REFRESH_SECS
                    self.log("daily user table refresh due")
                    self.siteDataChanged = True
            if time.time() - self.time_last_heartbeat > self.alive_heartbeat_secs:
                self.alive()
            #header = self.s.recv(self.LENGTH_HEADER)
            length = self.LENGTH_HEADER
            header = self.buffered_recv(length)
            if self.print_network_traffic:
                self.log("Received message header:")
                hexdump.hexdump(header)
            if header == b"+++":
                self.log(
                    "Panel has forcibly dropped connection, possibly due to inactivity"
                )
                self.closesocket()
                return None
            if header == b"+++A":
                self.log("Panel is trying to hangup modem; probably connected too soon")
                self.closesocket()
                return None
            if len(header) == 0:
                self.log("Panel has closed connection")
                self.closesocket()
                return None
            if len(header) < self.LENGTH_HEADER:
                self.log(
                    "Header received from panel is too short, only {:d} bytes, ignoring - contents:".format(
                        len(header)
                    )
                )
                hexdump.hexdump(header)
                continue
            msg_start, msg_type, msg_length, msg_sequence = (
                header[0:1],
                header[1:2],
                header[-2],
                header[-1],
            )
            if msg_start != b"t":
                self.log("unexpected msg start: 0x" + msg_start.hex())
                hexdump.hexdump(header)
                return None
            expected_len = msg_length - self.LENGTH_HEADER
            #payload = self.s.recv(expected_len)
            payload = self.buffered_recv(expected_len)
            if self.print_network_traffic:
                self.log("Received message payload:")
                hexdump.hexdump(payload)
            if len(payload) < expected_len:
                self.log(
                    "Ignoring message, payload shorter than expected - got {:d} bytes, expected {:d}".format(
                        len(payload), expected_len
                    )
                )
                print("header:")
                hexdump.hexdump(header)
                print("payload:")
                hexdump.hexdump(payload)
                continue
            payload, msg_crc = payload[:-1], payload[-1]
            expected_crc = self.crc8_func(header + payload)
            if msg_crc != expected_crc:
                self.log(
                    "crc: expected=" + str(expected_crc) + " actual=" + str(msg_crc)
                )
                return None
            if msg_type == self.HEADER_TYPE_RESPONSE:
                if msg_sequence != self.last_sequence:
                    self.log(
                        "incorrect response seq: expected="
                        + str(self.last_sequence)
                        + " actual="
                        + str(msg_sequence)
                    )
                    # recv again - either we receive the correct reply in the next packet, or we'll time out and retry the command
                    continue
            elif msg_type == self.HEADER_TYPE_MESSAGE:
                if self.last_received_seq != -1:
                    next_msg_seq = self.last_received_seq + 1
                    if next_msg_seq == 256:
                        next_msg_seq = 0
                    if msg_sequence == self.last_received_seq:
                        self.log(
                            "ignoring message, sequence number is the same as last message: expected="
                            + str(next_msg_seq)
                            + " actual="
                            + str(msg_sequence)
                        )
                        continue
                    if msg_sequence != next_msg_seq:
                        self.log(
                            "message seq incorrect - processing message anyway: expected="
                            + str(next_msg_seq)
                            + " actual="
                            + str(msg_sequence)
                        )
                        # process message anyway; perhaps we missed one or they arrived out of order
                self.last_received_seq = msg_sequence
            if msg_type == self.HEADER_TYPE_COMMAND:
                self.log("received command unexpectedly")
                return None
            elif msg_type == self.HEADER_TYPE_RESPONSE:
                return payload
            elif msg_type == self.HEADER_TYPE_MESSAGE:
                # FIXME: for "Site Data Changed" we should re-read the zone names etc - need to decode message
                # self.siteDataChanged = True
                self.message_event(payload)

    def sendcommand(self, cmd, body):
        if body is not None:
            body = cmd + body
        else:
            body = cmd
        self.sendcommandbody(body)
        self.last_command_time = time.time()
        retries = self.CMD_RETRIES
        response = None
        while retries > 0:
            retries -= 1
            try:
                response = self.recvresponse()
                break
            except socket.timeout:
                # NB: sequence number will be the same as last attempt
                if self.last_command is None:
                    return None
                self.log("Timeout waiting for response, resending last command")
                self.last_command_time = time.time()
                self.s.send(self.last_command)

        self.last_command = None
        if response is None:
            return None

        commandid, payload = response[0:1], response[1:]
        if commandid != cmd:
            if commandid == self.CMD_LOGIN and payload[0:1] == self.CMD_RESPONSE_NAK:
                self.log(
                    "Received 'Log on NAK' from panel - session has timed out and needs to be restarted"
                )
                return None
            self.log(
                "Got response for wrong command id: Expected 0x"
                + cmd.hex()
                + ", got 0x"
                + commandid.hex()
            )
            self.log("Payload:")
            hexdump.hexdump(payload)
            return None
        return payload

    def sendcommandbody(self, body):
        self.last_sequence = self.getnextseq()
        data = (
            self.HEADER_START
            + self.HEADER_TYPE_COMMAND
            + bytes([len(body) + 5, self.last_sequence])
            + body
        )
        data += bytes([(self.crc8_func(data))])
        if self.print_network_traffic:
            self.log("Sending command: 0x" + data.hex())
        self.s.send(data)
        self.last_command = data

    def getnextseq(self):
        if self.nextseq == 256:
            self.nextseq = 0
        nextseq = self.nextseq
        self.nextseq += 1
        return nextseq

    # buffered receive for DIY network comports
    def buffered_recv(self, length):
        buf = bytearray()
        while length:
            newbuf = self.s.recv(length)
            if not newbuf:
                self.log("Nothing in recv buffer for header, closing connection")
                self.closesocket
                return None
            buf.extend(newbuf)
            length -= len(newbuf)
        return buf



    ### General helpers

    def areas_from_bitmap(self, areas_bitmap):
        """(numbers, names) of the areas set in a log record's area bitmap."""
        numbers, names = [], []
        number, bit = 1, 1
        while bit <= areas_bitmap:
            if areas_bitmap & bit:
                numbers.append(number)
                area = self.areas.get(number)
                names.append(area.text if area is not None
                             else "Area{:d}".format(number))
            number += 1
            bit <<= 1
        return numbers, names

    def classify_log_event(self, event_type, group_type):
        """The category Home Assistant consumes.

        Group type wins for tamper, because it is the only thing that
        separates a tamper from its restore. Otherwise the event type is
        checked first: the group type alone misclassifies, e.g. 'Reset
        After Alarm' carries group 'Open' and would read as a disarm.
        """
        if group_type == 11:
            return "tamper"
        if group_type == 12:
            return "tamper_restore"
        if (event_type, group_type) in self.LOG_CATEGORY_BY_EVENT_GROUP:
            return self.LOG_CATEGORY_BY_EVENT_GROUP[(event_type, group_type)]
        if event_type in self.LOG_CATEGORY_BY_EVENT:
            return self.LOG_CATEGORY_BY_EVENT[event_type]
        if event_type in self.LOG_TAMPER_EVENTS:
            return "tamper"
        return self.LOG_CATEGORY_BY_GROUP.get(group_type, "other")

    def resolve_log_parameter(self, event_type, parameter):
        """(kind, number, name, resolved) for a log record's parameter.

        Names come from the panel's own tables, read at startup and
        refreshed on 'Site Data Changed'. NOTHING here is hand-maintained.

        A name is never invented. `resolved` is False only where the
        parameter is known to name something we could not name - so an
        unresolved cause can never be mistaken for an absent one.
        """
        if event_type in self.LOG_PARAM_USER:
            if parameter == 0:
                # Ambiguous on this panel: user 00 IS the Engineer, but the
                # panel also writes 0 for 'no user attributed'. Do not guess.
                return ("user", 0, None, False)
            user = self.users.get(parameter)
            if user is not None and user.name:
                return ("user", parameter, user.name, True)
            return ("user", parameter, None, False)
        if event_type in self.LOG_PARAM_ZONE:
            zone = self.zones.get(parameter)
            if zone is not None and zone.text:
                return ("zone", parameter, zone.text, True)
            return ("zone", parameter, None, False)
        # Not a parameter we can label: publish the number raw.
        return ("none", parameter, None, True)

    def build_panel_event(self, event_type, event_str, group_type, group_name,
                          parameter, areas_bitmap, timestamp_str,
                          comm_delayed, communicated):
        """Turn a decoded log record into the dict published to MQTT."""
        category = self.classify_log_event(event_type, group_type)
        kind, number, name, resolved = self.resolve_log_parameter(
            event_type, parameter
        )
        source = "panel"

        if event_type == 45 and self.resetRequest is not None:
            # 'Reset After Alarm' is anonymous at the panel. If Home
            # Assistant asked for this one, we know who asked.
            requested_at, usernumber, username = self.resetRequest
            if time.time() - requested_at <= self.RESET_ATTRIBUTION_SECS:
                kind, number, name, resolved = ("user", usernumber, username, True)
                source = "ha"
            # Consumed either way: a stale request must never be attached to
            # a later reset done at the keypad or in Wintex.
            self.resetRequest = None

        numbers, names = self.areas_from_bitmap(areas_bitmap)

        text = "{}, {}".format(event_str, group_name)
        if kind != "none":
            if name is not None:
                text += " - {} {:d} {}".format(kind, number, name)
            else:
                text += " - {} {:d} (unidentified)".format(kind, number)
        if names:
            text += " (" + ", ".join(names) + ")"

        return {
            # HA's MQTT event platform requires this key.
            "event_type": category,
            "panel_time": timestamp_str.replace(" ", "T"),
            "received": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "type_id": event_type,
            "type": event_str,
            "group_id": group_type,
            "group": group_name,
            "cause_kind": kind,
            "cause_number": number,
            "cause": name,
            "cause_resolved": resolved,
            "cause_source": source,
            "areas": numbers,
            "area_names": names,
            "comm_delayed": comm_delayed,
            "communicated": communicated,
            "notify": category in self.LOG_CATEGORY_NOTIFY,
            "text": text,
        }

    def log(self, string):
        timestamp = time.strftime("%Y-%m-%d %X")
        string = timestamp + ": " + string
        print(string)
        if self.log_event_func is not None:
            self.log_event_func(string)

    @staticmethod
    def bcdDecodeBytes(bcd):
        result = ""
        for char in bcd:
            for val in ((char >> 4), (char & 0xF)):
                if val <= 9:
                    result += str(val)
        return result
