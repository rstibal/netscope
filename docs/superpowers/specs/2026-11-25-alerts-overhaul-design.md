# Alerts tab overhaul: "Needs you" and "Recorded"

Date: 2026-11-25. Target version: 1.53.0 (minor: a feature change).

## Why

Rob opens the Alerts tab and finds "a wall of notes I don't act on". A
20-day log of a real machine, read on 2026-11-25, shows why:

- Dozens of alerts a day, most of them `warn` or `high`.
- At most one was worth a look, and it wasn't: an ARP change on the router's
  address was the router being swapped.
- Each rule fires on an ordinary setup, not on anything wrong:

| Rule | What it was |
|---|---|
| `checkin` | Many different pairs; much of it `System`, then browsers, sync clients, game launchers and vendor telemetry |
| `new_process` | One per program: installs and updates (game engines, driver setup, launchers) |
| `port_scan` (high) | `System` / `(no socket)`; Windows discovery, and a game launcher |
| `dns_resolver` | A VPN's DNS and the ISP's resolver |
| `threshold` | Mostly one streaming app (already excluded from History) |
| `dhcp_rogue_server` (high) | The home router and a second router on the LAN |
| `arp_spoof` (high) | The router swap |

Nothing had been muted and toasts were off, so the tab was the only way
anything got through, and it was all the same weight.

## What Rob wants (his words, in this conversation)

- To be interrupted for **"ARP changes and new programs I didn't install"**,
  and nothing else.
- Next to such an alert: **"which program it is, where it's installed, and
  what it talked to"**.
- Layout **A, "two piles"**: a "Needs you" section at the top, and under it
  what was recorded and needs nothing, one line per kind (mockup:
  `.superpowers/brainstorm/1806-1795610231/content/alerts-layout.html`,
  option A).
- **Toasts for "Needs you" only.**
- The ARP change from a router swap is fine and should not interrupt him.

## Goals

1. "Needs you" is empty on an ordinary day on Rob's machine. When it isn't,
   the card says enough to decide without leaving the tab.
2. Everything the rules notice today is still recorded and findable, one
   line per kind, without looking like a warning.
3. A "Needs you" alert reaches Rob as a Windows toast even when the
   dashboard is closed (he runs from the logon task / tray).

## Non-goals

- New detection rules beyond the two reclassifications below.
- Any lookup that leaves the machine (reputation services, VirusTotal,
  certificate revocation fetches). NetScope stays passive; reverse DNS is the
  one opt-in exception and stays that way.
- Re-judging programs the history already knows. A program known before the
  upgrade stays known.
- Rewriting old rows in the alert log. They keep the severity they were
  logged with.

## Anti-goals (would make this a failure even if it works)

- **A routine event in "Needs you".** That is the exact failure being fixed.
  When in doubt, a rule records rather than interrupts. Every routine case in
  the table above must land in "Recorded".
- **Anything going unseen.** Mutes stay listed on the tab. Recorded items are
  one click away. (Same principle as "what is hidden is on screen" in
  CLAUDE.md.)
- **Toasts for anything but "Needs you".**

## The two piles

Every alert gets one of two classes, replacing `info`/`warn`/`high` on the
tab:

- **Needs you**: shown as a full card, stays until acted on, toasts.
- **Recorded**: grouped one line per kind, never toasts.

Mapping:

| Rule | Class |
|---|---|
| `new_process` | **Needs you** if it fails the "didn't install" test below; otherwise Recorded ("New, signed: …") |
| `arp_spoof` | **Needs you** if it looks like impersonation (below); otherwise Recorded ("192.168.1.1 is a different device now") |
| `checkin`, `threshold`, `dns_resolver`, `port_scan`, `dhcp_rogue_server`, `rogue_ra`, `new_host`, `cert_problems`, `cleartext_proto`, `cleartext_creds`, `block`/`unblock` notes | Recorded |

The rules themselves (their logic, switches, mutes, baselines) are otherwise
unchanged.

## "A program I didn't install"

Applied when `new_process` would fire today: a named program, never seen in
history, not during baselining. Before deciding, NetScope looks at the
program's file (path from `ProcessResolver` / `program_paths`). It is
**Needs you** if any of these hold:

- it is **unsigned and in a folder a user can write to**. That means
  anywhere outside the admin-only install folders: `C:\Program Files`,
  `C:\Program Files (x86)`, `C:\Windows` and `C:\Program Files\WindowsApps`.
  "Unsigned" means no valid Authenticode signature. Rob chose this over a
  stricter test: see "Rob's decision";
- it has the **name of a Windows component** (`svchost.exe`, `lsass.exe`,
  `csrss.exe`, `explorer.exe`, `rundll32.exe` …) but is **outside**
  `C:\Windows\System32`, `SysWOW64` or `WinSxS`, signed or not;
- **its file can't be found or read.** This only applies to names ending in
  `.exe`; `System`, `Registry` and placeholder names are not files.

Otherwise it is Recorded, naming its signer, or "unsigned, in Program Files"
("New, signed: vendorsvc.exe · Vendor Corporation").

A **signed program is Recorded wherever it runs**, including Temp and
Downloads. Installers (Visual Studio, Office) and self-updating tools in the
user's profile run from there signed, and they are not news. An
**unsigned program in an admin-only folder is Recorded** too: writing there
already needs administrator rights.

Folder tests use the real locations (resolved through the environment and
known-folder paths), not folder names. A temp or `Program Files` folder on
another drive is user-writable.

Constraints:

- **The signature check never runs on the capture thread.** One check per
  new program, off-thread, cached by (path, size, mtime). The decision waits
  for the check, with a short cap (a few seconds). If the check can't finish,
  the program goes to Needs you saying "couldn't check its signature".
- The check is local only (WinVerifyTrust or equivalent; no revocation
  fetch).
- Demo mode uses a fake checker, as it already does for the firewall.

**"It's mine"** records that file. It's stored by path and a hash of the
file (SHA-256), in settings, and listed on the tab like mutes are.

A program is only judged the first time its name is seen (see Non-goals), so
later updates or replacements of a known program are not re-checked, trusted
or not. *(Final-review ruling: an earlier draft said a different file at the
same path would be judged again; nothing re-judges a known name, so the
wording was corrected rather than re-judging added.)*

## ARP: replaced vs impersonated

Today any MAC change for a known (adapter, IP) fires `high`. The new rule
keeps the same per-adapter binding but waits before deciding.

When a different MAC claims a known (adapter, IP), NetScope holds the change
for a short while (about a minute):

- **Impersonation → Needs you** if the address **changes hands at least
  three times within the hold** (old → new → old → new or more, any devices).
  This is the signature of ARP poisoning: the attacker keeps re-claiming the
  address while the real device keeps answering.
- **Contested → Recorded** for a single claim back by the old MAC, while held
  or within the following hour: "Two devices claimed <ip>", with both MACs.
  A Bonjour sleep proxy, a MAC-translating extender, a proxy-ARP hotspot and
  an overlapping router swap all do this once. A third device during the
  hold is one more change of hands, not an impersonation by itself.
  *(Final-review ruling: the first build made one flip back an
  impersonation, which put that routine LAN behaviour in Needs you.)*
- **Replacement → Recorded** if the new MAC holds the IP uncontested for the
  hold time: "192.168.1.1 is a different device now". It has an **"It's my
  new router"** button that marks it read; the binding has already moved.

*My call:* "the new MAC already belongs to another IP" was considered as a
second impersonation signal and left out. A router answering on two
addresses with one MAC is normal, and the alternating test catches the
classic attack.

ARP bindings stay in memory per session as today. A swap made while
NetScope was stopped is simply the new baseline.

## What a "Needs you" card shows

**For a program:**

- the name, the full path, the signature (signer or "not signed"/"invalid");
- what started it (parent process name via `psutil`, if still known);
- when it was first seen;
- **what it talked to**: hosts with connection count and bytes each way,
  from the Timeline's per-(program, host) totals, since first seen. It
  updates while the card is open.

*My call:* "what it talked to" is kept with the card, not read live. The
Timeline holds one hour in memory, and a card can outlive both. While the
card is open and the Timeline still has the program, the totals update from
it. They're saved with the card (host, connections, bytes each way), so after
an hour or a restart the card shows what was saved, marked "as of <time>".

Buttons: **Block** (a program block on the card's own file, by the path
saved with it; needs `blocking_enabled`, as now), **It's mine**, **Show packets** (sets the filter to that program),
**Dismiss**.

*My call,* on how a card leaves:

- **Block** blocks the program and removes the card. The block's note goes to
  Recorded.
- **It's mine** trusts the file and removes the card. When the file is gone
  (temp installers delete themselves), It's mine isn't offered.
- **Dismiss** removes the card without trusting anything. It's for a program
  already uninstalled, or one Rob has looked at and doesn't want to trust.
  The alert log keeps the entry.

**For ARP impersonation:**

- the adapter, the IP, both MACs (with their vendor where known), and when
  each was last seen claiming it.

Buttons: **Show packets** (filter `arp`), **It's expected** (mutes that
adapter+IP, through the existing mute list).

Cards in "Needs you" are **not** cleared by "Clear alerts" and **survive a
restart** until acted on. They're stored in the history database with an
acknowledged flag; with history off they last for the session. *My call:*
from the logon task, a card that vanished on reboot would never be seen.

## The tab

Top to bottom:

1. **Needs you · N**: cards as above. When there are none, a single line
   "Nothing needs you" with when the last program or ARP check ran.
2. **Recorded, nothing to do · today**: one line per kind, with a count and
   the top names. Opening a line lists its items as today's alerts do, with
   Mute and the existing "Don't record / Block…" menu.
3. **Earlier days** (folded): the same lines, from the history log (today's
   "Past N days" view, regrouped).
4. **Muted · N** and **Trusted programs · N**: listed, with undo. They're
   folded, but the count is on the folded line, as History's exclusions are.
5. **Rules and settings** (folded): today's rule grid, threshold, toasts,
   reverse DNS.

The tab badge counts **Needs you only**.

Existing behaviour to keep: the pane doesn't redraw under the pointer (see
CLAUDE.md, "The Alerts pane does not redraw while the pointer is over it").

## Toasts

- Only Needs you alerts toast.
- The toggle stays in Rules and settings. *My call:* it defaults to on for
  new installs, since it is now rare, and an existing setting is switched on
  once by the upgrade, because toasts are what Needs you is for.

## Testing

- **Unit:** the "didn't install" classifier with a fake signature checker
  and paths, covering each case above. Typical routine cases (signed vendor
  services, game launchers, signed tools under `%LOCALAPPDATA%`) must come
  out Recorded. Also
  the ARP state machine: replacement, alternation, flip after the hold.
- **Demo:** `DemoEngine` seeds one unsigned program from a temp folder and
  one ARP alternation, so the demo has a Needs you card. The rest of the demo
  traffic must land in Recorded.
- **UI** (`tests/ui/`): Needs you appears above Recorded. The badge counts
  only Needs you. "It's mine" removes the card and adds a Trusted entry.
  "Clear alerts" leaves Needs you. A card survives a reload. Recorded lines
  open and close.
- **Live, on Windows:** a real signature check, and a real toast from the
  tray build.
- **Against a real history:** a dry run of the classifier over the paths
  behind the `new_process` alerts in Rob's own history. The design expects a
  handful of Needs you, all software he installed (unsigned tools in AppData,
  a game unpacked to a temp folder). A result far above that means the test
  is wrong, not the machine. Run it locally only; it reads a real database,
  so it doesn't belong in the committed suite.

## Left to the builder

- How the signature and signer are read (ctypes WinVerifyTrust plus a
  certificate-name call, or PowerShell `Get-AuthenticodeSignature` off-thread),
  as long as it's local, off the capture thread and cached.
- Storage shape for acknowledged cards and trusted files.
- The exact hold time for ARP and the signature cap, within the bounds above.
- Wording of Recorded lines, following the mockup.
- README and CLAUDE.md entries, and the version bump to 1.53.0.


## Rob's decision

A builder check against Rob's real history found the first test as drafted
would have produced a Needs you card every couple of days, all his own
software. Some were unsigned (command-line tools, a language runtime, Store
apps, a game in a temp folder). Others were signed installers run from Temp
or Downloads, a self-updating tool on every update among them. Rob chose
**"unsigned and user-writable"** over keeping the strict four tests.
