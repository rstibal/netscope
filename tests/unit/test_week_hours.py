import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import shutil, tempfile
from datetime import datetime, timedelta
import netscope_history as H

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

tmp = tempfile.mkdtemp(prefix="ns-wh-")
h = H.HistoryStore(path=os.path.join(tmp, "h.db"))

def put(day, hour, bi, bo=0, proc="p.exe"):
    with h._db_lock:
        h._db.execute("INSERT INTO usage VALUES (?,?,?,?,?,?) ON CONFLICT(day,hour,process) "
                      "DO UPDATE SET bytes_in=bytes_in+excluded.bytes_in, "
                      "bytes_out=bytes_out+excluded.bytes_out",
                      (day.strftime("%Y-%m-%d"), hour, proc, bi, bo, 1))
        h._db.commit()

today = datetime.now().date()
w = h.week_hours(30)
check("an empty database gives an empty week, not an error",
      len(w["cells"]) == 7 and all(len(r) == 24 for r in w["cells"]) and
      sum(c[0] + c[1] for r in w["cells"] for c in r) == 0)

# Four weeks of data, every Monday at 09:00 and every Sunday at 23:00.
start = today - timedelta(days=27)
d = start
while d <= today:
    if d.weekday() == 0:
        put(d, 9, 1000, 100)
    if d.weekday() == 6:
        put(d, 23, 50, 0)
        put(d, 23, 30, 0, proc="q.exe")      # two programs in one hour add up
    d += timedelta(days=1)
w = h.week_hours(30)
mondays = w["counts"][0]
check("Monday comes first", w["cells"][0][9] == [1000, 100], w["cells"][0][9])
check("Sunday comes last (SQLite counts from Sunday)", w["cells"][6][23] == [80, 0], w["cells"][6][23])
check("it is an average per day, not a total",
      w["cells"][0][9][0] == 1000 and mondays == 4, (w["cells"][0][9], mondays))
check("nothing lands where there was nothing",
      sum(c[0] + c[1] for i, r in enumerate(w["cells"]) for j, c in enumerate(r)
          if (i, j) not in ((0, 9), (6, 23))) == 0)
first = min(x for x in (start + timedelta(days=i) for i in range(7)) if x.weekday() in (0, 6))
check("the counts cover only days since the first recorded one",
      sum(w["counts"]) == (today - first).days + 1, (w["counts"], first))

# One busy day long ago doesn't count against a 7-day view.
put(today - timedelta(days=60), 9, 10 ** 9)
w7 = h.week_hours(7)
check("a shorter range averages over fewer days", sum(w7["counts"]) == 7 and
      w7["cells"][0][9][0] == 1000, (w7["counts"], w7["cells"][0][9]))
w90 = h.week_hours(90)
check("...and a longer one over every day from the first record",
      sum(w90["counts"]) == 61, w90["counts"])

h._db.close()
shutil.rmtree(tmp, ignore_errors=True)
print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
