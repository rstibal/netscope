"""Dry run: which of the programs in the alert log would now need the user?

Opens the real history database READ-ONLY, takes every distinct program that
ever raised a new_process alert, looks up its recorded path, runs the real
signature check and the real classifier, and prints one line per program and
the totals per pile. Writes nothing (no database write, no settings, no cache).

    python scripts/dryrun_needs.py [path-to-history.db]
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netscope_trust as trust  # noqa: E402


def db_path():
    # Same location as netscope_history.default_db_path(), without its mkdir.
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "NetScope", "history.db")
    return os.path.join(os.path.expanduser("~"), ".netscope", "history.db")


def main(argv):
    path = argv[1] if len(argv) > 1 else db_path()
    if not os.path.exists(path):
        print("no history database at", path)
        return 1
    uri = "file:" + path.replace("\\", "/").replace("?", "%3f") + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    names = [r[0] for r in db.execute(
        "SELECT DISTINCT process FROM alerts WHERE rule='new_process' "
        "AND process IS NOT NULL AND process <> '' ORDER BY process")]
    checker = trust.SignatureChecker()
    totals = {}
    for name in names:
        paths = [r[0] for r in db.execute(
            "SELECT path FROM program_paths WHERE name=?", (name.lower(),))]
        p = paths[0] if paths else ""
        sig = checker.check(p) if p else None
        if sig is not None and sig.status == "missing":
            # The live judge checks within seconds of first sighting, while the
            # program runs. A file gone weeks later (updated, versioned, removed,
            # unmounted) can't be judged after the fact: its own total.
            pile, reason = "gone since (can't judge after the fact)", "gone"
        else:
            v = trust.classify_program(name, p, sig)
            pile, reason = v.pile, v.reason
        totals.setdefault(pile, {}).setdefault(reason, 0)
        totals[pile][reason] += 1
        print("%-34s %-60s sig=%-9s %s (%s)" % (
            name[:34], (p or "-")[:60], sig.status if sig else "-", pile, reason))
    db.close()
    print()
    print("programs: %d" % len(names))
    for pile in sorted(totals):
        print("%s: %d  %s" % (pile, sum(totals[pile].values()), dict(totals[pile])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
