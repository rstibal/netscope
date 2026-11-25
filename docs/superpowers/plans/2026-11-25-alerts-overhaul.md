# Alerts Overhaul ("Needs you" / "Recorded") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split NetScope's alerts into a rare, toasting "Needs you" pile (unsigned programs in user-writable folders, misplaced Windows names, ARP impersonation) and a quiet "Recorded" pile, and rebuild the Alerts tab around the two.

**Architecture:** Two new pure-logic modules decide what needs Rob: `netscope_trust.py` judges a new program from its file (location, Authenticode signature) on a worker thread, and `netscope_arpwatch.py` tells a replaced device from an impersonated one. `netscope_needs.py` keeps the "Needs you" cards, persisted in the history database until acted on. `AlertEngine` tags every alert with a `pile`, toasts only `needs`, and the page draws the tab from that.

**Tech Stack:** Python 3 (stdlib, psutil, sqlite3), PowerShell `Get-AuthenticodeSignature` for signatures, the single-string page in `netscope_ui.py`, Node + Playwright UI tests.

**Spec:** `docs/superpowers/specs/2026-11-25-alerts-overhaul-design.md`

## Global Constraints

- Version becomes **1.53.0** (`VERSION` in `netscope.py`); README version history and a CLAUDE.md decision entry land in the last task.
- No new dependencies. No lookup leaves the machine. The signature check is local, with no revocation fetch.
- Nothing slow runs on the capture thread: signature checks, hashing and file reads happen on the judge's worker thread.
- Demo mode never touches the real machine. It uses a fake signature table and fake paths, never reads real files, and never toasts for real.
- Values from the spec: the ARP hold is **60 s** and the flip window **3600 s**. The signature cap is **5 s**. The admin-only folders are `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramW6432%` and `%SystemRoot%`, minus the user-writable folders under Windows (Task 1's list). The Windows-name home folders are `%SystemRoot%\System32`, `SysWOW64` and `WinSxS`.
- Old alert-log rows keep their severity. New rows keep each rule's existing severity, except `new_process` (Needs you → `high`, Recorded → `info`) and `arp_spoof` (Needs you → `high`, replaced → `info`).
- Mutes and trusted programs are always listed on the tab, with their count on the folded line (CLAUDE.md, "what is hidden is on screen").
- Follow CLAUDE.md throughout. The page must not redraw while the pointer is over it. The dashboard is one string, so syntax-check it with the command in CLAUDE.md after every page edit.
- Commits follow Rob's flow: a short-lived local branch, fast-forwarded into main at the end. Don't push.

## Review Focus

1. **Paths in odd forms.** A program path in mixed case, with forward slashes, with a `\\?\` prefix, or on another drive (`D:\Program Files\...`) is classified by its real location. `D:\Program Files` is user-writable; `C:\PROGRAM FILES\x.exe` is admin-only. (Task 1 test `odd_paths`.)
2. **A signature check that hangs, or PowerShell missing.** The card still arrives within the 5 s cap as "couldn't check", and the capture never waits. (Task 2 test `checker_timeout`.)
3. **A program that exits within a second.** Its path is still found from the resolver's or history's known paths. Only when no path is known at all does it become "file can't be found". (Task 6 test `locate_falls_back`.)
4. **A restart with an open card.** The card is back after restart, exactly once. Seeing the program again doesn't add a second card. (Task 3 test `dedup_and_reload`.)
5. **"It's mine" after the file changed or vanished.** A vanished file gets an error, not a trust of nothing. A changed file is trusted at its current hash, and the trust entry says so. (Task 6 test `trust_changed_or_gone`.)

---

### Task 1: Program verdict

**Files:**
- Create: `netscope_trust.py`
- Test: `tests/unit/test_trust_verdict.py`

**Interfaces:**
- Produces:
  - `Sig = namedtuple("Sig", "status signer")`. `status` is one of `"valid"`, `"unsigned"`, `"invalid"`, `"missing"` (no file) or `"unknown"` (check failed or timed out). `signer` is a str, `""` when none.
  - `Verdict = namedtuple("Verdict", "pile reason")`. `pile` is `"needs"` or `"recorded"`. `reason` is one of `"not_a_file"`, `"no_file"`, `"windows_name_misplaced"`, `"unchecked"`, `"signed"`, `"unsigned_admin"`, `"unsigned_writable"` or `"trusted"` (the last is set by Task 2).
  - `WINDOWS_NAMES: frozenset[str]` (lowercase): `svchost.exe lsass.exe csrss.exe smss.exe wininit.exe winlogon.exe services.exe explorer.exe rundll32.exe dllhost.exe taskhostw.exe conhost.exe spoolsv.exe sihost.exe ctfmon.exe dwm.exe regsvr32.exe powershell.exe cmd.exe wmiprvse.exe msiexec.exe searchindexer.exe`.
  - `norm_path(path: str) -> str`: lowercase, `/`→`\`, strip a `\\?\` prefix.
  - `admin_dirs(env: Mapping = os.environ) -> list[str]`: normalized with a trailing `\`.
  - `writable_under_windows(env) -> list[str]`: `%SystemRoot%` plus `Temp`, `Tasks`, `Tracing`, `Debug`, `ServiceProfiles`, `Registration\CRMLog`, `System32\Tasks`, `System32\spool`, `SysWOW64\Tasks`.
  - `system_dirs(env) -> list[str]`: System32, SysWOW64 and WinSxS under `%SystemRoot%`.
  - `classify_program(name: str, path: str | None, sig: Sig | None, env: Mapping = os.environ) -> Verdict`.

- [ ] **Step 1: Write the failing tests** in the house style (`check(name, cond)`, exit 1 on failure; copy `tests/unit/test_arp_spoof.py`'s header). Use a fixed env: `{"ProgramFiles": r"C:\Program Files", "ProgramFiles(x86)": r"C:\Program Files (x86)", "ProgramW6432": r"C:\Program Files", "SystemRoot": r"C:\Windows"}`. Cases, each `check(...)` on the returned Verdict:
  - `"System"` with any path → `("recorded", "not_a_file")`.
  - `"x.exe"` with path None, or with `Sig("missing","")` → `("needs","no_file")`.
  - `svchost.exe` at `C:\Users\Alice\AppData\Roaming\svchost.exe` with `Sig("valid","Microsoft Windows")` → `("needs","windows_name_misplaced")`; at `C:\Windows\System32\svchost.exe` with valid → `("recorded","signed")`.
  - Any `.exe` with `Sig("unknown","")` → `("needs","unchecked")`.
  - **Typical cases → recorded:** a signed vendor service under `C:\Program Files\Vendor Corporation\...` (valid); a signed updater under `C:\Users\Alice\.tool\downloads\...` (valid); a signed setup bootstrapper under `C:\Users\Alice\AppData\Local\Temp\x\...` (valid); `curl.exe` (`C:\Program Files\Git\mingw64\bin\curl.exe`, unsigned → `unsigned_admin`); `GetHelp.exe` (`C:\Program Files\WindowsApps\Microsoft.GetHelp_...\GetHelp.exe`, unsigned → `unsigned_admin`).
  - **Typical cases → needs (`unsigned_writable`):** an unsigned tool under `C:\Users\Alice\AppData\Local\Tool\bin`; an unsigned game installed to another drive (`E:\Games\SomeGame`); an unsigned exe in `C:\Windows\Temp\abc\setup.exe`.
  - `Sig("invalid", "...")` is treated as unsigned.
  - `odd_paths`: `C:/PROGRAM FILES/Foo/a.exe` unsigned → `unsigned_admin`; `\\?\C:\Program Files\Foo\a.exe` → `unsigned_admin`; `D:\Program Files\Foo\a.exe` unsigned → `unsigned_writable`; `C:\Program FilesX\a.exe` unsigned → `unsigned_writable` (a prefix match must stop at a folder boundary).

- [ ] **Step 2: Run it and watch it fail.** Run `python tests/run_tests.py -k trust_verdict`. Expected: FAIL, because there is no `netscope_trust` module yet.

- [ ] **Step 3: Implement the names above in `netscope_trust.py`.** Check these in order: not `.exe` → no path or `missing` → Windows name outside the system folders → `unknown` → `valid` → under an admin folder (and not under a writable Windows subfolder) → otherwise `unsigned_writable`. Every folder test is `norm_path(path).startswith(dir_with_trailing_backslash)`.

- [ ] **Step 4: Run it and see it pass.** Same command. Expected: PASS.

- [ ] **Step 5: Commit** with `git add netscope_trust.py tests/unit/test_trust_verdict.py` and the message `Alerts: classify a new program by its file and signature`.

### Task 2: Signature checker, trust list, and the program judge

**Files:**
- Modify: `netscope_trust.py`
- Test: `tests/unit/test_trust_judge.py`

**Interfaces:**
- Consumes: `Sig`, `Verdict` and `classify_program` from Task 1.
- Produces:
  - `file_sha256(path: str) -> str | None`. Returns None when the file can't be read.
  - `powershell_signature(path: str, timeout: float) -> Sig`. It runs `Get-AuthenticodeSignature -LiteralPath $env:NS_SIG_PATH` and prints `Status` and the signer's simple name as JSON. The path travels **only in the environment variable**, never in the script text: copy the reasoning and pattern from `DesktopNotifier.SCRIPT`. Status maps as follows: `Valid` → `valid`, `NotSigned` → `unsigned`, any other status → `invalid`. A missing file gives `missing`; a timeout or any error gives `unknown`.
  - `class SignatureChecker(run=powershell_signature, cap=5.0)` with `check(path) -> Sig`. Results are cached by `(norm_path, size, mtime)`. An `os.stat` failure gives `Sig("missing","")`.
  - `class TrustList(entries: list[dict] | None = None)` with these methods:
    - `add(name, path, sha256) -> dict`
    - `remove(path) -> bool`
    - `is_trusted(path, sha256) -> bool`
    - `entries() -> list[dict]`, each `{"name","path","sha256","ts"}`
  - `class ProgramJudge(checker, trust, locate, on_verdict, hash_file=file_sha256)`:
    - `locate(name: str, pid: int | None) -> tuple[str | None, str | None]` returns `(path, parent_name)`.
    - `on_verdict(name, rec, info: dict)` receives `info = {"path","parent","sig": Sig,"sha256","verdict": Verdict}`.
    - `submit(name, pid, rec)` puts the job on a queue.
    - `judge(name, pid, rec) -> dict` is the synchronous body; it returns `info` and also calls `on_verdict`.
    - `start()` starts one daemon worker thread named `program-judge`.
    - `last_ts: float | None` is the time of the last verdict.
    - When the path is trusted at its current hash, the verdict is `Verdict("recorded","trusted")` without a signature check.

- [ ] **Step 1: Write the failing tests.** Use a fake `run` that records calls and returns preset Sigs, and temp files written by the test. Cover these:
  - `cache`: the same file is checked twice and `run` is called once. Rewriting the file (a new mtime or size) calls it again.
  - `checker_timeout`: a fake `run` that sleeps past the cap makes `check()` return `Sig("unknown","")` within the cap plus 1 s. With `run` raising `FileNotFoundError` (no PowerShell), it also returns `unknown`.
  - Trust:
    - `add` followed by `is_trusted` at the same hash is True; at a different hash it is False.
    - `remove` returns True once, then False.
    - `entries()` round-trips through `TrustList(entries)`.
  - `judge`:
    - With `locate` returning a trusted path, the verdict is `("recorded","trusted")` and the checker isn't called.
    - With `locate` returning `(None, None)`, the verdict is `("needs","no_file")`.
    - `on_verdict` receives the same `info` that `judge` returns.
  - `submit`, then waiting up to 2 s for `on_verdict` (started worker), delivers the verdict exactly once.
  - The real `powershell_signature` is skipped unless `os.name == "nt"`. On Windows, `C:\Windows\System32\notepad.exe` (or `cmd.exe`) gives `valid` with a non-empty signer, and a temp file containing `b"x"` gives `unsigned`.

- [ ] **Step 2: Run it and watch it fail.** Run `python tests/run_tests.py -k trust_judge`. Expected: FAIL, with an ImportError for the new names.

- [ ] **Step 3: Implement the names above.** The worker is `queue.Queue` plus one thread. Every exception inside a job is caught, so the worker never dies. The checker enforces the cap with `subprocess.run(..., timeout=cap, creationflags=CREATE_NO_WINDOW)`.

- [ ] **Step 4: Run it and see it pass.** Same command. Expected: PASS, with the Windows-only check run on Windows.

- [ ] **Step 5: Commit** with the message `Alerts: signature checker, trust list and the program judge`.

### Task 3: The "Needs you" store, and the alert log's pile

**Files:**
- Create: `netscope_needs.py`
- Modify: `netscope_history.py` (the schema around line 103, the `ALTER TABLE` block around line 331, `record_alert` at line 521, `alert_log` at line 1134, and `wipe` at line 1230)
- Test: `tests/unit/test_needs.py`

**Interfaces:**
- Produces:
  - In `HistoryStore`:
    - a new table `needs_you(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, data TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open', acted REAL)`;
    - `needs_load() -> list[dict]`, which returns open rows only, with `data` JSON-decoded;
    - `needs_save(card: dict) -> int`, which inserts when `card["id"]` is None and updates otherwise, writes immediately (not batched: these are rare), and returns the id;
    - `alerts` gains a `pile TEXT` column (`ALTER TABLE` when it's missing). `record_alert` writes `alert.get("pile")`. `alert_log` rows carry `pile`, with NULL read as `"recorded"`;
    - `wipe()` does **not** empty `needs_you`, for the same reason the security record survives. Add a one-line comment saying so.
  - `class NeedsYou(history=None)`. It works in memory when `history` is None or disabled, and loads open cards from `history.needs_load()` at construction. Methods:
    - `add(kind: str, subject: str, data: dict) -> dict | None`. It returns None if an open card with the same `(kind, subject)` exists. `kind` is `"program"` or `"arp"`.
    - `open() -> list[dict]`, newest first; each card is `{"id","ts","kind","subject","data","state","acted"}`.
    - `get(id) -> dict | None`.
    - `act(id: int, state: str) -> dict | None`. `state` is one of `"trusted"`, `"blocked"`, `"dismissed"` or `"expected"`. It sets `acted`, persists, and the card leaves `open()`.
    - `update_talk(id: int, flows: dict, at: float)`, which merges into `data["talk"]` (see below) and sets `data["talk_at"] = at`. It persists at most once every 60 s per card.
  - `merge_talk(saved: dict, current: dict) -> dict`. Both are `{flow_key_str: {"host","in","out"}}`. Per key it keeps the larger `in` and `out`, and caps at 200 keys by bytes.
  - `talk_by_host(talk: dict) -> list[dict]`, which returns `[{"host","conns","in","out"}]`, sorted by `in+out` descending.
  - `flows_for(snapshot: dict, program: str) -> dict`. It takes `FlowTable.snapshot()` output and returns the flows whose `process` equals `program` (case-insensitive), keyed by `str(flow_key)`, with host `f["rhost"]` or else the remote address from the key.

- [ ] **Step 1: Write the failing tests:**
  - `dedup_and_reload`: on a `HistoryStore` at a temp file, `add` twice with the same kind and subject gives one card. A fresh `NeedsYou(HistoryStore(same path))` shows that one card. `act(id,"dismissed")` and then a reload shows none.
  - In-memory mode (`history=None`) works the same within a session.
  - `merge_talk`: a flow that later shrinks (pruned) keeps its larger figures. With 250 keys, the result is the 200 biggest.
  - `talk_by_host`: two flows to one host give `conns == 2` and summed bytes.
  - The alert log: `record_alert({... "pile":"needs"})`, then `flush()` and `alert_log()`, gives a row with `pile == "needs"`. An old database without the column gets it on open, and old rows read as `"recorded"`.
  - `wipe()` leaves an open card in place.

- [ ] **Step 2: Run it and watch it fail.** Run `python tests/run_tests.py -k needs`. Expected: FAIL.

- [ ] **Step 3: Implement the names above.** Guard every database call with `HistoryStore`'s existing `_db_lock` and `enabled` checks, as `note_path` does.

- [ ] **Step 4: Run it and see it pass.** Run the same command, then `python tests/run_tests.py --unit -k history` to check nothing around it regressed. Expected: PASS.

- [ ] **Step 5: Commit** with the message `Alerts: Needs you cards that survive a restart; pile in the alert log`.

### Task 4: Replaced or impersonated (ARP)

**Files:**
- Create: `netscope_arpwatch.py`
- Test: `tests/unit/test_arpwatch.py`

**Interfaces:**
- Produces `class ArpWatch(hold=60.0, flip_window=3600.0)`:
  - `observe(iface: str, ip: str, mac: str, now: float) -> list[tuple]`
  - `tick(now: float) -> list[tuple]`
  - Events:
    - `("replaced", iface, ip, old_mac, new_mac)`;
    - `("impersonated", iface, ip, {mac: last_seen_ts, ...})`, at most once per `(iface, ip)` until `clear()`.
  - `clear()`.
- State per `(iface, ip)`: the current MAC; a pending change `{mac, at}`; the last replacement `{mac: old, until}`; and the last-seen time per MAC. The first sighting is the baseline (no event), as today.
- Rules:
  - A different MAC with nothing pending becomes pending.
  - **During the hold**, the old MAC claiming again → `impersonated`.
  - `tick` after `hold` with the old MAC not seen since the pending change → `replaced`. The new MAC becomes current and `prev = {old, until: now + flip_window}`.
  - After a replacement, the old MAC claiming again before `until` → `impersonated`. After `until` it is treated as an ordinary new change.

- [ ] **Step 1: Write the failing tests:**
  - first sighting → `[]`;
  - same MAC again → `[]`;
  - a new MAC, then `tick(now+61)` → one `replaced` (a router swap);
  - a new MAC, then the old MAC at `+10 s` → one `impersonated` naming both MACs; further flips give no second event;
  - replaced, then the old MAC at `+1800 s` → `impersonated`, and at `+3700 s` → no event, just a new pending change;
  - the same IP on another adapter is separate;
  - `tick` before the hold → `[]`.

- [ ] **Step 2: Run it and watch it fail.** Run `python tests/run_tests.py -k arpwatch`. Expected: FAIL.

- [ ] **Step 3: Implement `ArpWatch`.** It is pure logic: no clock of its own and no threads.

- [ ] **Step 4: Run it and see it pass.** Same command. Expected: PASS.

- [ ] **Step 5: Commit** with the message `Alerts: tell a replaced device from an impersonated one`.

### Task 5: The alert engine sorts into piles

**Files:**
- Modify: `netscope_alerts.py` (`__init__` around line 364, `attach_settings` at line 457, `_fire` at line 587, `counts` at line 649, `clear` at line 656, the `new_process` branch of `_change_rules` at lines 778–786, and `_arp_rule` at line 1165)
- Modify: `tests/unit/test_arp_spoof.py`, cases 3 and 8, to the new behaviour
- Test: `tests/unit/test_alert_piles.py`

**Interfaces:**
- Consumes: `NeedsYou` (Task 3), `ArpWatch` (Task 4), and `ProgramJudge`, `Verdict` and `Sig` (Task 2).
- Produces:
  - Constants `NEEDS, RECORDED = "needs", "recorded"`.
  - `_fire(self, key, severity, rule, title, detail, rec=None, pile=RECORDED, data=None)`:
    - Every alert dict gains `"pile"`.
    - When `pile == NEEDS`, it also calls `self.needs.add(kind, subject_of(key), data)`, with kind `"program"` for `new_process` and `"arp"` for `arp_spoof`, and stores the card id on the alert as `"card"`.
    - **Toasts only when `pile == NEEDS`.**
  - `self.needs = NeedsYou(history)` is created in `__init__`; `self.arp = ArpWatch()`.
  - `attach_judge(judge: ProgramJudge)`. Without a judge, a new program fires as Recorded, as before, but with `pile=RECORDED`.
  - `on_program_verdict(name, rec, info)` is passed to the judge as `on_verdict`:
    - **Needs you** fires `("new_process", name)`, `HIGH`, `pile=NEEDS`. The title comes from the reason:
      - `unsigned_writable`: "Unsigned program in a folder anyone can write to"
      - `windows_name_misplaced`: "Program with a Windows name outside Windows"
      - `no_file`: "New program whose file can't be found"
      - `unchecked`: "New program whose signature couldn't be checked"

      Its `data` is `{"name","path","signer","sig","reason","parent","pid","sha256","first_seen": time,"talk": {}, "talk_at": None}`.
    - **Recorded** fires the same key, `INFO`, with the title "New program", and a detail of `"{name} · signed by {signer}"`, `"{name} · in Program Files, unsigned"` or `"{name} · trusted"`.
  - `tick(now=None)` passes ArpWatch events through `_arp_event`. The `CHECKIN_EVERY` beat in `netscope.py` calls it (Task 6).
  - `_arp_rule` feeds `self.arp.observe(iface, ip, mac, rec ts)` and handles events:
    - **replaced** fires `("arp_spoof", iface, ip)`, `INFO`, `RECORDED`, with the title "A device was replaced" and the detail `"{ip} on {iface} is a different device now ({old} → {new}), and has stayed so"`.
    - **impersonated** fires the same key, `HIGH`, `NEEDS`, with the title `"Another device is claiming {ip}"` and `data={"iface","ip","macs":[{"mac","last_seen"}]}`.
  - `counts()` adds `"needs": len(self.needs.open())`.
  - `clear()` leaves `needs` alone and calls `self.arp.clear()`.
  - The toast migration in `attach_settings`: if `stored.get("needs_toasts_on")` is falsy, set `notifier.enabled = True` and persist both `alert_toasts=True` and `needs_toasts_on=True`. Afterwards Rob's choice stands. A fresh install gets the same result: on.
  - The history-off branch ("Program started using the network", `INFO`) is **not** judged, and stays Recorded. Without history every program is "new" each session, so judging would toast after every restart.

- [ ] **Step 1: Write the failing tests** in `test_alert_piles.py`, with `AlertEngine(history=HistoryStore(temp path))`, a fake notifier that records `notify` calls, and a `ProgramJudge` built from Task 2 with a fake checker, called synchronously through `judge()`:
  - An unsigned program in `%LOCALAPPDATA%` gives one Needs you card, one toast, and an alert with `pile=="needs"` and `severity=="high"`.
  - A signed program gives no card, no toast, and `pile=="recorded"`.
  - The check-in, threshold, dns_resolver, port_scan and dhcp_rogue_server rules, driven as in their existing tests, all come out `pile=="recorded"` with **zero toasts**, even with the notifier enabled.
  - An ARP impersonation gives a card and a toast. An ARP replacement, driven through `tick(now+61)`, gives a Recorded alert and no toast.
  - `clear()` keeps the open card.
  - The toast migration: settings `{"alert_toasts": False}` leave the notifier enabled and save `needs_toasts_on`. Loading `{"alert_toasts": False, "needs_toasts_on": True}` leaves it disabled.

  Then update `test_arp_spoof.py`. Case 3 becomes "changed MAC → nothing until the hold, then *A device was replaced*". Case 8 becomes "alternation → one *Another device is claiming* alert".

- [ ] **Step 2: Run it and watch it fail.** Run `python tests/run_tests.py -k "alert_piles"`. Expected: FAIL.

- [ ] **Step 3: Implement the interfaces above.**

- [ ] **Step 4: Run all unit tests.** Run `python tests/run_tests.py --unit`. Expected: all PASS. Any other alert test that asserted a toast for a warn rule, or "ARP binding changed", is updated to the new behaviour, with its own one-line reason.

- [ ] **Step 5: Commit** with the message `Alerts: every alert in a pile; only Needs you toasts`.

### Task 6: Server, wiring and demo

**Files:**
- Modify: `netscope.py`:
  - imports;
  - `/api/alerts` at line 3257;
  - the `control` actions near line 3460;
  - `main()` wiring at lines 4085–4161;
  - `DemoEngine`: constants near line 1904, a new seed in the `_loop` seed tuple at line 2768, and the `late` list at line 2777.
- Test: `tests/unit/test_needs_api.py` (launches a demo server, following `tests/unit/test_demo_isolation.py`, with `sys.executable` and a scratch `LOCALAPPDATA`)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `locate_program(resolver, history, name, pid) -> (path, parent)`. It tries `psutil.Process(pid).exe()` if that process's name still equals `name` (and takes `.parent().name()` for the parent), then the newest existing file in `resolver.known_paths(name)`, then `history.known_paths(name)`. Otherwise it returns `(None, None)`.
  - In `main()`:
    - Build a `TrustList(settings_load().get("trusted_programs"))` and a `ProgramJudge(SignatureChecker(), trust, locate, alerts.on_program_verdict)`, start it, and call `alerts.attach_judge(judge)`.
    - Keep `trust` and `judge` on `App` as `app.trust` and `app.judge`.
    - Demo mode gets `SignatureChecker(run=DemoEngine.fake_signature)`, `locate=DemoEngine.program_file` and `hash_file=lambda p: "demo:" + p`.
  - A beat thread `watch_needs` running every `NEEDS_TALK_EVERY = 5` s. For each open program card, it calls `alerts.needs.update_talk(id, flows_for(store.flows.snapshot(), card["data"]["name"]), time.time())`. The existing check-in beat also calls `alerts.tick()`.
  - `/api/alerts` gains these fields:
    - `"needs"`: the open cards, each program card with `data["talk_hosts"] = talk_by_host(data["talk"])`;
    - `"trusted": app.trust.entries()`;
    - `"last_program_check": app.judge.last_ts`;
    - `"watching_since": alerts.started`.
  - `trust_card(trust, needs, hash_file, card) -> tuple[int, dict]` is a plain function so it can be tested without a server.
    - It hashes `card["data"]["path"]` now with `hash_file`.
    - If the file is gone, it returns `409, {"error": "The file is gone, so there is nothing to trust. Dismiss it instead."}`.
    - Otherwise it calls `trust.add(name, path, sha)`. If the hash differs from the card's, it sets `entry["changed"] = True`, and the Trusted list says "changed since the alert".
    - Then it calls `needs.act(id, "trusted")` and returns `200, {"trusted": entry}`.
  - Control actions:
    - `needs_act {id, act}`:
      - `act == "trust"`: call `trust_card(app.trust, alerts.needs, app.judge.hash_file, card)`, save `trusted_programs` on 200, and send its status and body.
      - `act == "block"`: run the existing program block (`blocker.block_program(pid=data.pid, name=data.name)`, through `_block_action`'s path, so the "Blocked" note and its errors behave as today). If that succeeds, `act(id,"blocked")`.
      - `act == "expected"` (ARP): `alerts.mute("arp_spoof", ip)`, then `act(id,"expected")`.
      - `act == "dismiss"`: `act(id,"dismissed")`.
    - `trust_remove {path}`: removes the entry and saves.
  - Demo:
    - `DemoEngine.fake_signature(path, timeout) -> Sig` gives:
      - `unsigned` for `SilentUpdater.exe`;
      - `missing` for `Vanished.exe`;
      - `valid` `"Example Corp"` for `CrashReporter.exe`;
      - `valid` `"Demo Vendor"` otherwise.
    - `DemoEngine.program_file(name, pid)` gives:
      - `(r"C:\Users\Demo\AppData\Local\Temp\su7\SilentUpdater.exe", "chrome.exe")` for `SilentUpdater.exe`;
      - `(r"C:\Program Files\Example\CrashReporter.exe", "services.exe")` for `CrashReporter.exe`;
      - `(r"C:\Users\Demo\Downloads\gone\Vanished.exe", None)` for `Vanished.exe`;
      - `(r"C:\Program Files\Demo\" + name, None)` otherwise.
    - The demo's `hash_file` is `lambda p: None if "\\gone\\" in p else "demo:" + p`.
    - `SilentUpdater.exe` moves from `late` into a new seed, `_seed_untrusted()`. At start, it runs one short conversation from SilentUpdater to `198.51.100.9`/`updates.vendor.example`, and one from `Vanished.exe` to `203.0.113.77`/`dl.example.org`. `CrashReporter.exe` stays late (it is signed, so it's Recorded).
    - A new seed, `_seed_arp_flip()`, emits ARP replies for `RESOLVER` (192.168.1.1), first from `MAC_GW`, then from `"de:ad:be:ef:13:37"`, then from `MAC_GW` again, so an impersonation card appears at start.

- [ ] **Step 1: Write the failing test** `test_needs_api.py`. It has two parts.

  **Without a server:**
  - `locate_falls_back`: with a fake resolver whose `known_paths` returns a temp file, and a pid that no longer exists, `locate_program` returns that path.
  - `trust_changed_or_gone` (calls `trust_card` directly):
    - a card for a temp file whose current hash differs from the card's `sha256` gives 200 and `entry["changed"] is True`;
    - a card whose file was deleted gives 409, the card is still open, and the trust list is unchanged.

  **Against a demo server:** start the demo, then poll `/api/alerts` (token in the `X-NetScope-Token` header) for up to 30 s. Check:
  - exactly three open cards:
    - `SilentUpdater.exe`, with reason `unsigned_writable` and parent `chrome.exe`;
    - `Vanished.exe`, with reason `no_file`;
    - an ARP card for `192.168.1.1`.
  - `counts.needs == 3`.
  - `needs_act trust` on SilentUpdater returns 200, the card is gone, and `trusted` lists its demo path.
  - `needs_act trust` on Vanished returns 409, and the card stays.
  - `needs_act dismiss` on the ARP card makes it go.
  - Nothing was written under the scratch `LOCALAPPDATA` (reuse the isolation check).

- [ ] **Step 2: Run it and watch it fail.** Run `python tests/run_tests.py -k needs_api`. Expected: FAIL.

- [ ] **Step 3: Implement the interfaces above.**

- [ ] **Step 4: Run the unit suite.** Run `python tests/run_tests.py --unit`. Expected: all PASS, including `test_demo_isolation.py`.

- [ ] **Step 5: Commit** with the message `Alerts: Needs you over the API, demo cards, live "talked to"`.

### Task 7: The Alerts tab

**Files:**
- Modify: `netscope_ui.py`:
  - CSS near the existing `.alert` rules;
  - `renderAlerts` from line 2816 (replace the body);
  - the alert-pane click handler at line 2788;
  - the badge at lines 5396–5399.
- Test: `tests/ui/needs_test.js` (new); fix `tests/ui/alert_test.js`, `alert_log_test.js`, `alert_menu_test.js`, `alert_draft_test.js` and `checkin_test.js` where they relied on the old layout.

**Interfaces:**
- Consumes: the `/api/alerts` fields and `needs_act`/`trust_remove` actions from Task 6, and `/api/alert_log` rows with `pile` from Task 3.
- Produces this DOM, which the UI tests rely on, top to bottom:
  1. `#needsSec`, with `<h4>Needs you · N</h4>` and one `.ncard[data-nid]` per card.
     - **Program cards** have rows for Program, Where (full path, monospace, wrapping), Signed (signer, or "not signed" in the high colour), Started by and First seen.
     - Then `.talk` rows from `talk_hosts`, as `host` and `"{conns} conn · {in} ▼ {out} ▲"`. When `now - talk_at > 60 s`, a line reads "as of HH:MM".
     - Then buttons `data-nact="block"` (only when blocking is enabled, as the existing menu decides), `"trust"` (hidden when `sig == "missing"` or `reason == "no_file"`), `"packets"` (sets the filter to `process == "<name>"` and shows the Table) and `"dismiss"`.
     - **ARP cards** have Adapter, Address, and each MAC with when it was last seen, then buttons `"packets"` (filter `arp`), `"expected"` and `"dismiss"`.
     - With no cards, `.nquiet` reads `Nothing needs you · last program checked HH:MM`, or `· watching since HH:MM` when nothing has been checked yet.
  2. `#recSec`, with `<h4>Recorded, nothing to do · today</h4>`. It has one `details.recline[data-kind]` per kind present today among the session alerts with `pile=="recorded"`, in this order:
     - `programs` (new_process): "New programs"
     - `devices` (arp_spoof): "Devices"
     - `checkins`: "Check-ins"
     - `bandwidth` (threshold): "Bandwidth"
     - `network` (dns_resolver, dhcp_rogue_server, rogue_ra, port_scan): "Network"
     - `insecure` (cleartext_proto, cleartext_creds, cert_problems): "Insecure traffic"
     - `hosts` (new_host): "New hosts"
     - `blocks` (block, unblock): "Blocks"

     The summary reads `Label · count`, then the first three subjects. Opening a line lists its alerts with today's per-alert controls: Mute, Mute 1h, Dismiss, the Unblock note, the "Don't record / Block…" menu, and "Why did this fire?". A devices item from a replacement also has `data-newrouter` "It's my new router", which dismisses it.
  3. `details#earlierSec` "Earlier days". It is folded, and on opening it loads `/api/alert_log` and groups it by local day, then by the same kinds. Rows with `pile=="needs"` are listed first within a day, marked "needed you".
  4. `details#mutedSec` ("Muted · N") and `details#trustedSec` ("Trusted programs · N", with a Remove button `data-untrust` per entry). Both are folded, with the count in the summary, and only drawn when N > 0.
  5. `details#rulesSec` "Rules and settings", folded, holding today's rule grid, threshold, toasts, reverse DNS, Apply and Clear alerts. The "This session / Past N days" switch is removed: the Earlier days section replaces it.
  - The badge `#nAlerts` shows `counts.needs` and gets the `high` class when it's above 0.
  - Open `details` stay open across the 2.5 s redraw, keyed by id or `data-kind`, the way `openWhy` does today. The pane still pauses its redraw under the pointer.

- [ ] **Step 1: Write the failing UI test** `needs_test.js` against the demo (copy the harness of `tests/ui/alert_test.js`). Wait up to 30 s for `.ncard` count 3, then check:
  - `#needsSec` is above `#recSec`;
  - the badge text is `3`;
  - the SilentUpdater card shows its path, "not signed", "chrome.exe" and at least one `.talk` row;
  - the Vanished card has no trust button;
  - clicking trust on SilentUpdater (move the pointer off the pane first, per CLAUDE.md) removes it, `#trustedSec` summary reads `Trusted programs · 1`, and the badge reads `2`;
  - **Clear alerts** inside `#rulesSec` leaves the 2 cards;
  - a page reload still shows 2;
  - a `recline` opens and stays open across a refresh;
  - Earlier days opens and lists rows;
  - no sideways scroll at 1680 and at the side panel's narrowest; no page errors.

- [ ] **Step 2: Run it and watch it fail.** Run `python tests/run_tests.py -k needs_test`. Expected: FAIL.

- [ ] **Step 3: Implement the tab.** Syntax-check with CLAUDE.md's `node --check` command after every edit.

- [ ] **Step 4: Run the alert UI tests, then everything.** Run `python tests/run_tests.py -k alert`, then `-k checkin`, then the full `python tests/run_tests.py`. Expected: all PASS. Fix the old alert tests to the new layout (for example, the rule grid is now inside `#rulesSec`, and the session list is under the recorded lines) without weakening what each checked.

- [ ] **Step 5: Look at it in the demo** in the Browser pane (`preview_start netscope-demo`), at the side panel's width and in light theme, and compare against option A in `.superpowers/brainstorm/1806-1795610231/content/alerts-layout.html`. Take a screenshot for the hand-over.

- [ ] **Step 6: Commit** with the message `Alerts tab: Needs you, Recorded, Earlier days`.

### Task 8: Measure against Rob's history, document, version

**Files:**
- Create: `scripts/dryrun_needs.py` (outside `tests/`, so the runner never picks it up)
- Modify: `netscope.py` (`VERSION`), `README.md` (the Alerts section and version history), `CLAUDE.md` (a new decision entry; amend the ARP/DHCP and toast lines it touches)

- [ ] **Step 1: Write `scripts/dryrun_needs.py`.** It opens the real history database **read-only** (`file:...?mode=ro`). For each distinct `process` in `alerts` where `rule='new_process'`, it takes `program_paths` for that name, runs the real `SignatureChecker` and `classify_program`, and prints one line per program (name, path, sig, verdict), then the totals per pile. It writes nothing.

- [ ] **Step 2: Run it.** Run `python scripts/dryrun_needs.py`. Expected: a handful of `needs`, from software Rob installed (unsigned tools in AppData, a game in a temp folder); programs with no recorded path show as `no_file`, which is reported separately. If `needs` is far above that, stop and report the list to Rob rather than adjust the rules unasked.

- [ ] **Step 3: Write the docs.**
  - Set `VERSION = "1.53.0"`.
  - README: rewrite the Alerts section for the two piles, and add a **1.53.0** version-history entry in the style of 1.52.0.
  - CLAUDE.md: add a decision entry, "Alerts are two piles (1.53)", covering:
    - why (a real 20-day log that was almost all routine);
    - the classifier's rule and Rob's choice of "unsigned and user-writable";
    - that only Needs you toasts;
    - the ARP hold and alternation test;
    - that cards persist in `needs_you` and survive Clear and wipe;
    - that history-off doesn't judge;
    - that a known program is never re-judged.

    Amend the "Alert mutes" and "Alerts have two stores" entries where the Earlier days section replaces the log switch.

- [ ] **Step 4: Run the full suite.** Run `python tests/run_tests.py`. Expected: all PASS (Linux-only skips aside).

- [ ] **Step 5: Commit** with the message `Alerts overhaul: dry run, docs (v1.53.0)`. Then fast-forward main from the branch, per Rob's flow, without pushing.

- [ ] **Step 6: List the live checks for Rob** in the hand-over, since they can't be automated here: a real toast from the tray build when a Needs you card appears, a real signature check on his machine (the dry run covers it), and Block from a card as administrator.
