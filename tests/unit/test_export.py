"""Text export on the server: CSV escaping, History totals, the alert log."""
import os, sys, tempfile, types
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope as N
from netscope_history import HistoryStore

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

# -- CSV ---------------------------------------------------------------------------
check("a formula from the network is defused", N.csv_cell('=HYPERLINK("http://x")') ==
      '"\'=HYPERLINK(""http://x"")"', N.csv_cell('=HYPERLINK("http://x")'))
for lead in "+-@":
    check("...as is one starting with " + lead, N.csv_cell(lead + "x") == "'" + lead + "x")
check("numbers stay numbers, negative ones too", N.csv_cell(-5) == "-5" and N.csv_cell(1.5) == "1.5")
check("None is empty", N.csv_cell(None) == "")
check("commas, quotes and newlines are quoted", N.csv_cell('a,"b"\nc') == '"a,""b""\nc"')
check("rows end in CRLF with a header", N.to_csv(["a", "b"], [{"a": 1}]) == "a,b\r\n1,\r\n")

# -- History totals and the alert log ------------------------------------------------
h = HistoryStore(path=os.path.join(tempfile.mkdtemp(), "h.db"))
h.record({"ts": 1_800_000_000.0, "process": "chrome.exe", "rhost": "github.com",
          "remote": "140.82.112.3", "dir": "out", "length": 1500})
h.record_alert({"ts": 1_800_000_001.0, "severity": "warn", "rule": "new_host",
                "title": "First contact", "detail": "=evil()", "process": "chrome.exe",
                "peer": "140.82.112.3", "subject": "github.com"})
app = types.SimpleNamespace(history=h, alerts=None)
cols, rows = N.export_rows(app, "history")
kinds = {(r["kind"], r["name"]) for r in rows}
check("History totals list programs and hosts", ("program", "chrome.exe") in kinds
      and ("host", "github.com") in kinds, rows)
check("...with readable times", all("T" in r["first_seen"] for r in rows), rows)
cols, rows = N.export_rows(app, "alerts")
check("the alert log is exported, oldest first, with a time",
      len(rows) == 1 and rows[0]["title"] == "First contact" and rows[0]["time"].startswith("20"), rows)
check("...and its CSV defuses what came off the wire", "'=evil()" in N.to_csv(cols, rows))
check("an unknown export is refused", N.export_rows(app, "settings") is None)

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
