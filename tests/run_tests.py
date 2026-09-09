#!/usr/bin/env python3
"""
Run the NetScope test suite.

    python tests/run_tests.py              everything available
    python tests/run_tests.py --unit       decoder and logic tests only
    python tests/run_tests.py --ui         dashboard tests only
    python tests/run_tests.py -k conn      only tests whose name contains "conn"

Two halves, because they need different things.

*Unit* tests import the modules directly and need nothing but Python. They
cover the decoders, the connection table, alert rules and muting, filename
sanitising, pcap link types and the scheduled-task helpers.

*UI* tests drive the real dashboard in a real browser through Playwright,
against a demo server this script starts and stops. Nearly every UI bug in this
project's history was a layout or timing fault that only a browser could see —
a column that truncated, a view that drifted while rows were trimmed, a save
that gave no feedback — so they are worth the extra dependency:

    pip install playwright && playwright install chromium

If Playwright is missing the UI half is skipped and said so, rather than
failing.

A few unit tests open a real capture socket and need libpcap plus root, and
they create temporary adapters with `ip`, so they are Linux-only. They are
skipped elsewhere rather than reported as failures.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Need a live capture socket and `ip`, so they only run on Linux as root.
LINUX_CAPTURE_ONLY = {"test_drops.py", "test_stress.py", "test_ifaces.py"}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_demo(port):
    """Start a demo server and return (process, dashboard_url)."""
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "netscope.py"), "--demo",
         "--port", str(port), "--no-browser", "--no-history"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    url = None
    deadline = time.time() + 60
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        m = re.search(r"(http://127\.0\.0\.1:%d/\?t=\S+)" % port, line)
        if m:
            url = m.group(1)
            break
    if url:
        # The demo needs a moment to build up traffic; several tests wait for a
        # few hundred packets and a couple of finished conversations.
        time.sleep(20)
    return proc, url


def have_playwright():
    try:
        subprocess.run(["node", "-e", "require('playwright')"],
                       cwd=ROOT, capture_output=True, check=True)
        return True
    except Exception:
        return False


def run(cmd, cwd, timeout):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 1, "timed out"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit", action="store_true", help="unit tests only")
    ap.add_argument("--ui", action="store_true", help="dashboard tests only")
    ap.add_argument("-k", metavar="TEXT", default="",
                    help="only tests whose filename contains TEXT")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print each test's own output")
    args = ap.parse_args()
    do_unit = not args.ui
    do_ui = not args.unit

    passed, failed, skipped = [], [], []

    if do_unit:
        print("== unit ==")
        names = sorted(f for f in os.listdir(os.path.join(HERE, "unit"))
                       if f.startswith("test_") and f.endswith(".py"))
        for name in names:
            if args.k and args.k not in name:
                continue
            if name in LINUX_CAPTURE_ONLY and (
                    sys.platform != "linux" or os.geteuid() != 0):
                print("  SKIP  %-22s needs Linux + root for a live capture" % name)
                skipped.append(name)
                continue
            code, out = run([sys.executable, os.path.join("unit", name)],
                            HERE, 300)
            print("  %s  %s" % ("PASS " if code == 0 else "FAIL ", name))
            if args.verbose or code != 0:
                print("        " + out.strip().replace("\n", "\n        ")[:4000])
            (passed if code == 0 else failed).append(name)

    if do_ui:
        print("== dashboard ==")
        if not have_playwright():
            print("  SKIP  Playwright is not installed here.")
            print("        pip install playwright && playwright install chromium")
            skipped.append("all dashboard tests")
        else:
            port = free_port()
            proc, url = start_demo(port)
            if not url:
                print("  FAIL  the demo server did not start")
                failed.append("demo server")
            else:
                names = sorted(f for f in os.listdir(os.path.join(HERE, "ui"))
                               if f.endswith("_test.js"))
                for name in names:
                    if args.k and args.k not in name:
                        continue
                    code, out = run(["node", os.path.join("ui", name), url],
                                    HERE, 300)
                    ok = "FAILED: none" in out
                    print("  %s  %s" % ("PASS " if ok else "FAIL ", name))
                    if args.verbose or not ok:
                        print("        " + out.strip().replace("\n", "\n        ")[:4000])
                    (passed if ok else failed).append(name)
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                proc.kill()

    print()
    print("%d passed, %d failed, %d skipped" % (len(passed), len(failed), len(skipped)))
    if failed:
        print("failed: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
