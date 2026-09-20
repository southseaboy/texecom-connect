#!/usr/bin/env python
"""Fixtures for the offline test suites.

These are SYNTHETIC. No real user name, user code, zone name or area name
belongs in this file - it is committed to a public repository.

To run the suites against the real site's tables, put a `site_local.py`
next to this file defining any of USERS, ZONES or AREAS. That file is
listed in .gitignore and must never be committed. The suites pass either
way: nothing asserted below depends on a particular name or code, only on
the fixtures being used consistently.
"""

# number -> (name, code). User 5's leading zero is deliberate: a test in
# test_pin_gate.py proves that a leading zero is significant.
USERS = {
    1: ("User1", "1111"),
    2: ("User2", "2222"),
    3: ("User3", "3333"),
    5: ("User5", "0555"),
}

# number -> name
ZONES = {
    10: "Zone 10",
    15: "Zone 15",
    22: "Zone 22",
    23: "Zone 23",
}

AREAS = {
    1: "Area 1",
    2: "Area 2",
}

try:
    import site_local
except ImportError:
    pass
else:
    USERS = getattr(site_local, "USERS", USERS)
    ZONES = getattr(site_local, "ZONES", ZONES)
    AREAS = getattr(site_local, "AREAS", AREAS)


def pick(*numbers):
    """The fixture entries for the given user numbers."""
    return {number: USERS[number] for number in numbers}
