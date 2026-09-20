#!/usr/bin/env python3
"""Manage the local deny-list used by the pre-commit hook.

The list holds SALTED HASHES, never the words themselves, so it reveals
nothing at a glance and cannot turn into a second copy of the very strings
it exists to keep out of the repository. It lives OUTSIDE the working tree
so it can never be staged by accident.

    hooks/denylist.py init          create the list and its random salt
    hooks/denylist.py add           read words from stdin, one per line
    hooks/denylist.py status        how many entries, and where the file is
    hooks/denylist.py test          read words from stdin, say if each matches

Location: $TEXECOM_DENYLIST, else ~/.config/texecom-connect/denylist.sha256

Limitation, stated plainly: a single salted hash of a SHORT token - a
4-digit PIN, say - is brute-forceable by anyone who obtains this file. The
hashing keeps the words out of the repository and off the screen; it is not
a substitute for rotating a code that has already been exposed.
"""
import hashlib
import os
import re
import sys

DEFAULT = os.path.expanduser("~/.config/texecom-connect/denylist.sha256")
MIN_LEN = 3


def path():
    return os.environ.get("TEXECOM_DENYLIST", DEFAULT)


def tokens(text):
    """The comparable tokens in a piece of text."""
    return {t for t in re.findall(r"[A-Za-z0-9]+", text.lower())
            if len(t) >= MIN_LEN}


def load():
    """(salt, {hashes}). Raises IOError if the list does not exist."""
    salt = None
    hashes = set()
    with open(path(), "r") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("salt:"):
                salt = bytes.fromhex(line[5:])
            else:
                hashes.add(line)
    if salt is None:
        raise ValueError("no salt line in " + path())
    return salt, hashes


def digest(salt, token):
    return hashlib.sha256(salt + token.encode("utf-8")).hexdigest()


def cmd_init():
    target = path()
    if os.path.exists(target):
        print("already exists: " + target)
        return 0
    os.makedirs(os.path.dirname(target), exist_ok=True)
    salt = os.urandom(16)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write("# Salted hashes of words that must never be committed.\n")
        handle.write("# Managed by hooks/denylist.py - do not edit by hand.\n")
        handle.write("salt:" + salt.hex() + "\n")
    print("created " + target + " (mode 0600)")
    return 0


def cmd_add():
    salt, hashes = load()
    added = 0
    skipped = []
    new = []
    for line in sys.stdin:
        for token in tokens(line):
            value = digest(salt, token)
            if value not in hashes:
                hashes.add(value)
                new.append(value)
                added += 1
        for word in re.findall(r"[A-Za-z0-9]+", line.lower()):
            if len(word) < MIN_LEN:
                skipped.append(word)
    with open(path(), "a") as handle:
        for value in new:
            handle.write(value + "\n")
    # Never echo what was added.
    print("added {:d} new entries".format(added))
    if skipped:
        print("ignored {:d} token(s) shorter than {:d} characters".format(
            len(set(skipped)), MIN_LEN))
    return 0


def cmd_status():
    try:
        _, hashes = load()
    except (IOError, OSError):
        print("no deny-list at " + path() + " - run: hooks/denylist.py init")
        return 1
    print("{:d} entries in {}".format(len(hashes), path()))
    return 0


def cmd_test():
    salt, hashes = load()
    bad = 0
    for line in sys.stdin:
        hits = [t for t in tokens(line) if digest(salt, t) in hashes]
        if hits:
            bad += 1
            print("MATCH ({:d} token(s)): {}".format(len(hits), mask(hits)))
    print("no matches" if not bad else "{:d} line(s) would be blocked".format(bad))
    return 0


def mask(words):
    return ", ".join(w[0] + "*" * (len(w) - 1) for w in sorted(words))


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    actions = {"init": cmd_init, "add": cmd_add,
               "status": cmd_status, "test": cmd_test}
    if action not in actions:
        print(__doc__)
        raise SystemExit(2)
    try:
        raise SystemExit(actions[action]())
    except (IOError, OSError):
        print("no deny-list at " + path() + " - run: hooks/denylist.py init",
              file=sys.stderr)
        raise SystemExit(1)
