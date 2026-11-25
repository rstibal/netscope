"""
A Needs you card's Block: the card's own file, by the path the server saved.

Against the demo's blocker (an in-memory firewall and settings), so nothing
here can touch the real Windows Firewall. A card about a fake svchost.exe in
AppData must block that file, not be refused as "part of Windows"; the real
System32 svchost still is; a file that changed since the card is refused.
"""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, ROOT)

import netscope as N
from netscope_needs import NeedsYou

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)


class Resolver:
    local_ips = ("192.168.1.5",)


SHA = "ab" * 32
SYSROOT = os.environ.get("SystemRoot") or r"C:\Windows"
FAKE_SVCHOST = r"C:\Users\Alice\AppData\Roaming\svchost.exe"
REAL_SVCHOST = SYSROOT + r"\System32\svchost.exe"


def setup(enabled=True):
    b = N.make_blocker(Resolver(), demo=True)
    if enabled:
        b.set_enabled(True)
    return b, NeedsYou(None)


def card_for(needs, name, path, sha=SHA, reason="windows_name_misplaced"):
    return needs.add("program", name, {"name": name, "path": path, "sha256": sha,
                                       "reason": reason, "pid": 4242})


hashes = {FAKE_SVCHOST: SHA, REAL_SVCHOST: SHA}
hash_file = hashes.get

# ---- the misplaced svchost: its own file is blocked
b, needs = setup()
c = card_for(needs, "svchost.exe", FAKE_SVCHOST)
code, body, entry = N.block_card(b, needs, hash_file, c)
check("misplaced svchost card -> 200", code == 200, (code, body))
check("...blocks the card's AppData path",
      entry and entry["target"] == FAKE_SVCHOST and entry["kind"] == "program"
      and entry["name"] == "svchost.exe", entry)
check("...outbound, as a program block is", entry and entry.get("dir") == "out", entry)
check("...and the card is acted on", needs.get(c["id"])["state"] == "blocked")
check("...the block is listed", [e["target"] for e in b.entries()] == [FAKE_SVCHOST])

# ---- the real one is still refused
b, needs = setup()
c = card_for(needs, "svchost.exe", REAL_SVCHOST, reason="unchecked")
code, body, entry = N.block_card(b, needs, hash_file, c)
check("System32 svchost -> 400, part of Windows",
      code == 400 and "part of Windows" in body.get("error", ""), (code, body))
check("...the card stays open", needs.get(c["id"])["state"] == "open")
check("...and nothing was blocked", b.entries() == [])

# ---- the file changed since the card: 409, nothing blocked
b, needs = setup()
c = card_for(needs, "svchost.exe", FAKE_SVCHOST, sha="cd" * 32)
code, body, entry = N.block_card(b, needs, hash_file, c)
check("hash mismatch -> 409", code == 409 and "changed" in body.get("error", ""), (code, body))
check("...card open, nothing blocked",
      needs.get(c["id"])["state"] == "open" and b.entries() == [])

# ---- the file is gone: 409
b, needs = setup()
c = card_for(needs, "gone.exe", r"C:\Users\Alice\AppData\Local\gone.exe", reason="no_file")
code, body, entry = N.block_card(b, needs, hash_file, c)
check("a gone file -> 409", code == 409 and "gone" in body.get("error", ""), (code, body))
check("...card open", needs.get(c["id"])["state"] == "open")

# ---- a card with no path at all: 409
b, needs = setup()
c = needs.add("program", "nofile.exe", {"name": "nofile.exe", "path": None})
code, body, entry = N.block_card(b, needs, hash_file, c)
check("no path -> 409", code == 409, (code, body))

# ---- no sha256 on the card: the file only has to be there
b, needs = setup()
c = card_for(needs, "svchost.exe", FAKE_SVCHOST, sha=None)
code, body, entry = N.block_card(b, needs, hash_file, c)
check("no saved hash -> blocks the file that is there", code == 200, (code, body))

# ---- blocking switched off: 400, card stays
b, needs = setup(enabled=False)
c = card_for(needs, "svchost.exe", FAKE_SVCHOST)
code, body, entry = N.block_card(b, needs, hash_file, c)
check("blocking off -> 400", code == 400 and "switched off" in body.get("error", ""), (code, body))
check("...card open", needs.get(c["id"])["state"] == "open")

# ---- NetScope itself is always refused
b, needs = setup()
c = card_for(needs, os.path.basename(sys.executable), sys.executable)
code, body, entry = N.block_card(b, needs, {sys.executable: SHA}.get, c)
check("NetScope's own exe -> 400", code == 400 and "NetScope" in body.get("error", ""), (code, body))

# ---- the blocker's path entry point on its own
b, _ = setup()
for bad in ("", "relative\\x.exe", None):
    try:
        b.block_program_path(bad)
        check("block_program_path refuses %r" % (bad,), False)
    except N.BlockError:
        check("block_program_path refuses %r" % (bad,), True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
