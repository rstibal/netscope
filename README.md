# NetScope

**Version 1.11.1**

A live packet monitor for Windows with a browser dashboard. It captures every
frame going in and out of your machine and shows you which process sent it,
where it went, the decoded protocol, and the raw bytes in hex.

Think of it as a small, focused Wireshark that answers "what is my computer
actually talking to right now, and which program is doing it."

Since 1.1.0 it also answers "and *what* did it send" for unencrypted traffic:
it decodes Windows file-share activity so you see real filenames, rebuilds a
connection into a readable conversation, and reconstructs transferred files
so you can save them back out.

---

## What you need first

**1. Python 3.9 or newer** — https://www.python.org/downloads/windows/
Tick **"Add python.exe to PATH"** during install. You only need this to *build*
the .exe; once built, the .exe runs on its own.

**2. Npcap** — https://npcap.com
This is the capture driver, the same one Wireshark installs. Accept the default
options. If you already have Wireshark, you already have Npcap.

---

## Build it

Open a normal Command Prompt in this folder and run:

```
build.bat
```

That installs the dependencies, runs PyInstaller, and leaves you two files in
`dist\`, neither of which needs Python on the machine that runs it:

- **`NetScope.exe`** — the console build. Use it for `--list`, `--read`,
  `--task-status` and anything where you want to see output.
- **`NetScopeTray.exe`** — the same program built for the windows subsystem, so
  Windows never allocates a console for it. Double-click it and it goes
  straight to the notification area with no window at all, not even a flash. It
  implies `--tray`, so there is no flag to remember. With no console to print
  to, its startup output goes to `netscope.log` beside the history database.

First build takes a couple of minutes; each exe lands around 40 MB because
scapy's protocol dissectors come along for the ride.

---

## Run it

Double-click **`dist\NetScopeTray.exe`** for the everyday case: it goes
straight to the notification area with no window at all. Right-click the tray
icon for the dashboard.

For the console version, double-click `dist\NetScope.exe`. Either way Windows
prompts for administrator rights (both are built with `--uac-admin`, and
capture genuinely needs them). The console build prints a URL and opens the
dashboard in your browser:

```
NetScope 1.0.0
  Mode:      capturing on Wi-Fi
  Dashboard: http://127.0.0.1:8477/?t=xRsNy3NAVIV4ZRShoKMWHZze
```

Close the console window to stop capturing.

### Command line options

```
NetScope.exe --list                    list capture interfaces and exit
NetScope.exe --iface "Wi-Fi"           capture on a specific interface
NetScope.exe --iface all               every active adapter (the default)
NetScope.exe --iface auto              just the primary adapter
NetScope.exe --iface "Wi-Fi,Ethernet"  capture a specific set
NetScope.exe --filter "tcp port 443"   start with a BPF capture filter
NetScope.exe --port 9000               serve the dashboard on another port
NetScope.exe --demo                    synthetic traffic; no admin, no Npcap
NetScope.exe --no-browser              don't auto-open a browser
NetScope.exe --no-extract              capture only; don't rebuild files
NetScope.exe --read capture.pcap       analyse a saved capture, don't capture
NetScope.exe --toasts                  Windows desktop notifications for alerts
NetScope.exe --tray                    run in the tray (NetScopeTray.exe implies this)
NetScope.exe --db D:\netscope.db       history database somewhere else
NetScope.exe --no-history              don't record history to disk
NetScope.exe --retain-days 30          keep 30 days instead of 90
NetScope.exe --stress-drops 500        stall the capture, to test the drop warning
NetScope.exe --install-task            start in the tray at logon (elevated)
NetScope.exe --remove-task             undo that
NetScope.exe --task-status             is the logon task registered?
```

`--demo` is worth knowing about: it fabricates plausible traffic so you can see
what the dashboard does without capturing anything real. Useful for a look
around before you commit to installing Npcap.

**When the capture cannot keep up, it says so.** A Python capture path is slower
than a busy link, and when libpcap's kernel buffer fills the driver discards
frames without telling anybody. Every number here then undercounts — byte totals,
the attribution share, the connection table, and any alert whose packet went
missing — with nothing on screen to say so. NetScope reads the driver's own
counter and, when it is losing packets, puts **dropping N% of packets** in the
status line and a dropped count in the footer. Nothing appears when the capture
is clean, and nothing appears when the figure cannot be obtained, rather than
claiming a clean capture it has not verified.

---

## Using the dashboard

**The table** is the live packet list, newest at the bottom. Each row is one
frame: sequence number, timestamp to the millisecond, owning process, direction
(▲ out / ▼ in), source, destination, protocol, byte count, and a summary line.
Hostnames appear in place of IPs once NetScope has seen the DNS response that
resolved them.

**Click any row** to open it in the Packet panel: the full field breakdown
(TCP flags, sequence numbers, TLS record type and SNI, HTTP start line and
headers, DNS queries and answers, SMB commands and filenames) plus a hex +
ASCII dump of the raw bytes.

**Columns resize.** Drag the border between two headers to set a width.
Double-click a border to fit that column to its contents. Widths are remembered
between runs, and **Reset columns** in the filter bar puts them back.

**The table never scrolls sideways.** Info always takes whatever room is left,
so widening another column borrows from Info, and the drag stops before Info
would run out — the border reaches a limit instead of a scrollbar appearing.
Shrinking the window squeezes the columns proportionally; widening it again
restores exactly the widths you set. Any value too long for its column is still
readable in full by hovering it, and in the packet detail panel.

**Adapters that appear later are picked up on their own.** Started from a logon
task, NetScope is usually running before Wi-Fi has associated and before a VPN's
adapter exists. Those adapters used to stay invisible for the life of the
process — scapy enumerates once when it is imported and caches the answer, so
refreshing the dashboard just re-read a snapshot taken at boot, and only
restarting the whole app ever helped. The adapter list is now re-read from the
operating system, and a capture running on *all* interfaces attaches new ones as
they turn up, announcing each one. A capture you pointed at named adapters is
left alone: attaching one you did not ask for would be wrong.

**Capturing more than one adapter is the default.** NetScope captures every
adapter that has an address, merging them into one packet list — picking a
single adapter and hoping it is the busy one is how you end up watching an
empty capture while the traffic goes past on the other NIC. Choose a specific
adapter in the dropdown if you want one, and that choice is remembered for next
launch. `--iface auto` reverts to just the primary adapter. The
**Iface** column says where each packet was seen, and `iface` is a filter field
(`iface == Wi-Fi`). If one adapter fails to open, the others still capture and
the status line says which failed.

**Choosing columns.** Every column is shown by default. **Columns** in the
filter bar hides any of them except Info, which always stays because it takes
the leftover width. Your choice persists between runs.

**A note on the side panel:** only the Packet tab reflects the row you clicked.
Connections, Files, Streams and Talkers are session-wide — they show everything captured
since the app started, and they do not change with your selection. Clicking a
packet while one of them is open leaves it open; the Packet tab picks up the
frame number so you can see the click registered.

**The Files tab** lists everything NetScope has been able to rebuild from
unencrypted transfers — downloads and uploads both, with the real filename,
content type, size, the process that moved it, and the host it came from or
went to. **Save** writes the reconstructed file to disk, **Preview** shows it
inline (images render, text and JSON as text, anything else as hex), and
**Stream** jumps to the connection it came from. The tab label carries a count
so you can see it filling up from anywhere in the app.

**The Streams tab** lists every TCP connection with its process, endpoints,
protocol and byte totals. Click one — or hit **Follow this connection** at the
bottom of any packet's detail — to open the conversation viewer.

**The conversation viewer** stitches a connection's packets back into arrival
order and shows it top to bottom: client blocks in blue, server blocks in
green. Three modes:

- **Text** — the raw bytes as characters. Right for HTTP, SMTP, anything textual.
- **Strings** — just the readable runs, ASCII *and UTF-16*. This is the one for
  Windows protocols: SMB puts its filenames in UTF-16, which in Text mode
  looks like `v.a.c.a.t.i.o.n`, and Strings mode turns back into
  `vacation-2026.mp4`.
- **Hex** — full hex + ASCII dump.

Gaps in the capture and clipped output are flagged in the viewer, so you're
never quietly shown a partial reconstruction as if it were complete.

**The Connections tab** answers a different question from the packet list. The
packet list says what happened; this says what is open *right now* — one row per
connection, with the owning program, the remote host, the TCP state, bytes each
way and how long it has been up. Three views: **Open** is live connections,
**Listening** is sockets accepting inbound traffic on this machine (the "what
can be reached from outside" question), and **Just closed** keeps a connection
visible for 90 seconds after it goes away, because short connections vanish from
the socket table long before you finish reading the row. Click any row to filter
the packet list to that one conversation.

The rows are two sources joined on the connection's 5-tuple and the adapter it
was seen on. The OS socket table
knows what exists, what state it is in and which process owns it, but the kernel
exposes no per-socket byte counts. Flow accounting off the capture knows exactly
how many bytes moved each way, but only sees packets, so it cannot tell you a
socket is listening or merely idle. Neither is sufficient alone, which is why a
connection open since before the capture started shows real state and zero
bytes — nothing has crossed the wire since NetScope started watching.

Against a saved capture, or in demo mode, the socket table is deliberately left
out: those packets belong to a different machine or to no machine at all, and
pairing them with this one's live sockets would invite conclusions about
connections that do not exist.

**The Quality view**, the fourth filter in that tab, is the "why does this feel
slow" view. Four numbers per connection, all measured off the wire, so they work
against encrypted traffic just as well as plaintext — you cannot read a TLS
session but you can time its handshake and count its retransmissions:

- **RTT** — the TCP handshake, outbound SYN to the SYN/ACK that answers it. One
  clean round trip, measured before any application data muddies it.
- **TLS** — ClientHello to the first ApplicationData record: how long the
  session took to set up on top of that round trip.
- **Resent** — segments covering sequence ground already sent. Deliberately not
  called "retransmissions": telling a true retransmission from a reordered
  segment needs per-segment history and still only guesses, so this counts the
  honest thing and names it accordingly.
- **Dup** — duplicate ACKs, counted from the third identical one, which is the
  classic signal that a segment went missing.

Rows are ordered worst first, loss ahead of latency — a slow handshake is often
just distance, and loss rarely is. Connections with nothing measurable are left
out entirely rather than padding the list with blanks.

**Each connection is two lines**, not a row in a table: the program and the host
it is talking to on the first, and the numbers underneath — bytes each way, how
long it has been up, the protocol and TCP state, and the adapter when more than
one is in play. A table would need about 530px for the names alone and this panel
is 429px wide, which is why nothing here is a column.

**The activity mark** on the right of each open connection is 40 seconds of bytes
per second for that conversation — the shape, not the size. It is what tells a
steady transfer from a bursty one, and a connection that stalled thirty seconds
ago from one still working, neither of which a total and an age can say. Idle
connections draw a flat baseline rather than nothing, because "idle" and "no
data" are different states.

It is one ink, not the green/orange in-out split the footer chart uses: that pair
fails deuteranope separation on this dark surface, which is why the History charts
are blue and orange, and the byte counts on the line below already carry
direction. Each row is scaled to its own peak — a shared scale would flatten
every ordinary connection into a straight line beside one busy download — and
hovering says so, along with the peak rate and how many of the last 40 seconds
saw traffic. It appears only on open connections: a closed one's shape is
finished and a listener has none.

**The Talkers tab** ranks processes and remote hosts by total bytes moved, with
the in/out split for each — this is the "what is eating my bandwidth" view.

### Checking the capture is keeping up

Two states used to look identical: a capture with no drops, and one whose driver
cannot report drops at all. Both showed nothing. Hover the **packets** figure in
the footer and it now says which — either the driver's received and discarded
counts, or that statistics are unavailable on this machine.

To see the warning itself fire, either put the link under real load (a speed test
will usually do it) or make the capture deliberately slow:

```
NetScope.exe --stress-drops 500
```

That stalls the packet handler half a millisecond per packet, so libpcap's buffer
overflows under ordinary traffic and the status line shows **dropping N% of
packets**. It is a testing flag and nothing else — leave it off in normal use.
Measured on a controlled loopback load: the same traffic produced 0 drops without
the stall and 1,232 (33.9%) with it.

### Two filters, and the difference between them

**The display filter** is the wide box under the toolbar. It hides rows from
view without touching the capture, so nothing is lost and you can change your
mind instantly. Fields:

```
proto   process   src   dst   ip   host   port   sport   dport
bytes   payload   info  dir   pid  iface  stream seq
```

Operators are `==` `!=` `~` (contains) `!~` `>` `>=` `<` `<=`, combined with
`&&`, `||`, `!` and parentheses. String comparison is case-insensitive. `ip`
matches either address, `port` matches either port.

```
proto == QUIC
process ~ chrome && bytes > 1000
!(proto == TLS || proto == QUIC)          what isn't encrypted
port == 445                               file-share traffic
host ~ wpengine
dir == out && info ~ POST
```

The filter applies to the rows the browser is holding — up to 2,500. The
capture buffer holds far more, so when a filter is active and the buffer is
bigger than the table, a **Search buffer** button appears: it pulls the whole
ring down and filters all of it, which is how you find a handshake that has
scrolled out of the live view but is still captured. **← Live** goes back.

Type text with no operator and it falls back to a plain substring search across
every column, so `chrome` on its own does what you'd expect. A malformed
expression turns the box red and says what's wrong, leaving the previous filter
in force rather than dumping every packet back on screen. **Save** stores the
current expression as a named preset in the dropdown; presets persist between
runs. **?** shows a syntax reminder.

**The BPF capture filter** is the narrow box in the top toolbar. It is applied
down at the driver, so filtered traffic never reaches the app at all — cheaper,
but destructive: what it excludes is gone. Same syntax as Wireshark's *capture*
filters, not its display filters:

```
tcp port 443                  only HTTPS
host 192.168.1.50             only traffic with one machine
udp port 53                   only DNS
not port 22 and not arp       exclude the noise
tcp[tcpflags] & tcp-syn != 0  only connection openings
```

Press **Apply** after changing it.

**Keyboard:** `space` pauses the incoming feed (the capture keeps running),
`/` jumps to the filter box.

### Saving and opening captures

**Save ↓** writes everything currently buffered to a standard `.pcap` — real
Ethernet frames, microsecond timestamps, correct wire lengths for anything that
was snapped short. Wireshark, tcpdump and tshark all open it.

**Open ↑** loads a `.pcap` or `.pcapng` back in (or `--read file.pcap` from the
command line). NetScope switches to offline mode, stops capturing, and re-runs
the whole decoding path over the file: protocols, stream reassembly, file
extraction and alert rules all work exactly as they do live. The one thing that
cannot work offline is process attribution — the sockets are long gone, so
every packet shows `-`. The status line tells you the file you're looking at.

### Running it all the time

**Double-click `NetScopeTray.exe`** — that is the whole answer, and there is no
console involved. `NetScope.exe --tray` also works but, being a console build,
Windows gives it a console window before any of NetScope's own code runs, so it
flashes up briefly before being hidden. Launching the console build from an
existing shell leaves that shell's window alone — NetScope only hides a console
it created itself, never the terminal you typed into. To launch the console
build detached anyway:

```powershell
Start-Process -WindowStyle Hidden "C:\NetScope\NetScope.exe" -ArgumentList "--tray"
```

Tray mode puts NetScope in the notification area. The icon
shows state at a glance — blue idle, amber when a warning is outstanding, red
for a high-severity alert, grey when capture is paused — and its tooltip carries
the live rate, packet count and alert total. Right-click for open dashboard,
pause/resume, show console, and quit.

### Starting at logon

1. **Put the exe somewhere permanent first** — `C:\Tools\NetScope\`, say. The
   task records this exact path, so moving the file afterwards breaks it.
   NetScope refuses to register from a Temp or Downloads folder.
2. Open a Command Prompt **as administrator** and run:

```
NetScope.exe --install-task
```

3. Check it with `NetScope.exe --task-status`, or test immediately without
   rebooting: `schtasks /Run /TN NetScope`.

`--remove-task` deletes it again. That scheduled task is the only thing NetScope
writes outside its own database.

**Why a scheduled task and not the Run key.** NetScope's manifest requests
administrator, and Windows will not silently elevate anything started from
`HKCU\...\Run` — you get a UAC consent prompt at every logon, or nothing starts.
A task registered with `HighestAvailable` launches with a full token and no
prompt, which is the only arrangement that actually works unattended.

The task is written from XML rather than `schtasks` flags so two defaults can be
corrected: the execution time limit is removed (the flag form kills the task
after 72 hours) and the battery rules are disabled, so it keeps running on a
laptop. It fires 20 seconds after logon, giving the network stack and Npcap time
to come up.

`--autostart-registry` still writes the old Run-key entry, and
`--remove-autostart-registry` removes it. That path only makes sense for a build
without `--uac-admin`, running unelevated — fine for the dashboard and offline
pcap analysis, but live capture needs the task.

### History

Everything else in NetScope lives in memory and dies when you close it. History
does not. It records hourly per-process rollups, first-seen and last-seen for
every program and host, the alert log, and one row per session, into a SQLite
database at `%LOCALAPPDATA%\NetScope\history.db` (override with `--db`, disable
with `--no-history`).

The History tab shows totals as a KPI row, daily traffic as a stacked column
chart over 7, 30 or 90 days, per-program and per-host breakdowns, hosts first
contacted in the last week, the alert log and recent sessions. Every chart has
a table view underneath it, so no value is only reachable by hovering.

Writes never touch the capture path: packets accumulate in memory and a writer
thread flushes to disk every ten seconds. If the database can't be opened,
NetScope says so at startup and keeps capturing without it.

Old data is pruned hourly — 90 days of usage and 30 days of alerts by default,
adjustable with `--retain-days`. **Erase all history** in the History tab wipes
the database outright.

A note on the chart colours: the History charts use blue for received and orange
for sent, rather than the green and orange used for direction everywhere else in
the app. Green against orange fails deuteranope separation on the dark surface
(ΔE 5.7, under the floor) while blue against orange clears it comfortably in
both themes (ΔE 26.8 dark, 24.7 light). The ▼ and ▲ glyphs appear in the legend,
tooltip and table, so direction never depends on colour alone.

**First seen now means first seen ever.** With history recording, the
"new program on the network" and "first contact with a host" alerts check the
database rather than just this session — so they fire when something genuinely
new turns up, and are promoted from a note to a warning when it does.

### Alerts

The Alerts tab is both the log and the control panel. Each rule has a switch:

- **New program on the network** — something that hasn't used the network this
  session just did. Suppressed for the first few seconds, otherwise every
  program on the machine would fire at once.
- **First contact with a host** — off by default; on a busy machine it is very
  chatty.
- **Bandwidth threshold** — a program crosses N MB in a session. Default 500.
- **Credentials in the clear** — HTTP Basic auth, a password field posted over
  plain HTTP, FTP `USER`/`PASS`, IMAP `LOGIN`, POP3 and SMTP auth.
- **Unencrypted protocols** — FTP, Telnet, POP3, IMAP, TFTP, the r-commands.
- **Certificate problems** — expired, expiring within two weeks, self-signed, or
  signed with MD5/SHA-1. Only visible on TLS 1.2 and below: TLS 1.3 encrypts the
  Certificate message, so on a modern connection there is nothing to inspect.
- **Unexpected DNS resolver** — queries going somewhere other than the resolver
  the rest of the machine uses.

Repeat alerts fold into a count rather than filling the list. **Windows desktop
notifications** sends warnings and high-severity alerts as toasts (Windows only,
rate-limited to one every few seconds).

---

**Muting.** Any alert can be silenced for its own subject — the host, program or
resolver it is about — either indefinitely or for an hour, using the buttons on
the alert. The rule stays on and keeps watching everything else, which is the
distinction that matters: a rule is usually right to look and wrong about one
subject. Muted subjects are listed above the alert list with an Unmute button so
a mute is always visible and always reversible, they persist across restarts, and
they survive **Clear alerts**. Each alert also carries a **Why did this fire?**
disclosure stating what its rule compares, and **Dismiss** drops a single alert
without touching the rest.

Rule switches, the bandwidth threshold and the notification toggle are remembered
between runs, which matters most when NetScope starts from a logon task and
nobody is watching it be reconfigured.


## Can it see filenames, images, documents?

Short version: **filenames often, whole files sometimes, and nothing at all
over HTTPS.** In detail:

**Plain HTTP** — yes to both. The path is in the request line, so
`GET /reports/q3-invoice.pdf` shows up in the packet list as it happens, and
the file itself is reconstructed into the Files tab where you can save it.
Uploads too: a `multipart/form-data` POST gives up the original filename and
the bytes.

**Windows file shares (SMB)** — filenames yes, contents no. Windows *signs*
SMB by default but does not *encrypt* it, so filenames travel in the clear.
NetScope decodes SMB2, so copying something off a NAS shows as
`CREATE \\NAS\Media\vacation-2026.mp4 [read]` followed by the READ operations
and their sizes. What it does not do is reassemble the file content out of
those READs — that would mean tracking SMB file handles across the whole
transfer, which is a bigger job than the HTTP path. If the share negotiated
SMB3 encryption, even the names are gone, and NetScope says so rather than
showing you noise.

**FTP, TFTP, NFS, IPP print jobs, plain IMAP/POP3/SMTP** — filenames and
commands are readable in the conversation viewer. They aren't specially
decoded, so you'll be reading them as text rather than as tidy fields.

**QUIC / HTTP-3** — hostnames yes, contents no. A browser's ClientHello is too
big for one Initial packet (post-quantum key shares push it to two or three
kilobytes), so it arrives split across several. NetScope buffers the CRYPTO
fragments per connection ID and reports the hostname on the packet that
completes the message, the way Wireshark attributes a reassembled message to
its last fragment. Earlier Initials in the same handshake are marked
"ClientHello continues…". A large share of current traffic
is QUIC over UDP/443: Chrome, YouTube, most Google properties, anything behind
Cloudflare. QUIC's Initial packet is protected with keys derived from a
*published* salt and the client's own connection ID, so anyone on the wire can
decrypt it — the protection exists to stop middleboxes ossifying the handshake,
not to keep it private. NetScope derives those keys, decrypts the Initial,
reassembles the CRYPTO frames and reads the ClientHello, which gives you the
hostname and the ALPN. Everything after the handshake uses keys that were never
sent, and stays opaque.

**Anything over TLS** — no. HTTPS downloads, Google Drive, Dropbox, OneDrive,
Slack, email over TLS: you get the hostname from SNI, the byte counts, and the
timing. You can tell that 40 MB went to Dropbox at 2:15pm. You cannot tell what
it was, and no packet sniffer can — that is what TLS is for. Reading the bodies
of HTTPS requests needs an intercepting proxy like mitmproxy or Fiddler, which
installs its own root certificate and terminates TLS itself. Worth remembering
that such a certificate is a real security surface — install it for a debugging
session, remove it afterwards.

### How file reconstruction works, and where it stops

A background scanner re-parses each connection every few seconds, walks the
HTTP in it, and emits a file once its body has fully arrived — so a download
still in flight is simply picked up on the next pass rather than saved
half-finished. `Content-Length` and chunked encoding are both handled, and
gzip/deflate bodies are decompressed. Names come from
`Content-Disposition` when the server sends one, otherwise from the request
path, with an extension inferred from the content type as a last resort.

Limits, all deliberate so a big transfer can't eat the machine: 8 MB kept per
direction per connection, 400 connections, 300 extracted files, 96 MB of file
data total, 32 MB per single file. Oldest entries are dropped first. Nothing is
written to disk unless you click Save. `--no-extract` turns the whole thing off.

If packets were missed — capture started mid-connection, or the driver dropped
some under load — the reconstruction has holes. The conversation viewer counts
those gaps and says so at the top rather than pretending the result is
complete.

**Process attribution is best-effort.** NetScope polls the Windows socket table
once a second and remembers what it saw for two minutes, so long-lived
connections (browser tabs, a database client, anything streaming) are named
reliably. A connection that opens and closes between two polls — a one-shot DNS
lookup from a short-lived process, say — can show up as `-`. Getting this
perfect requires ETW kernel tracing, which is a much heavier lift than this app
takes on.

---

## Tests

```
python tests/run_tests.py            everything available
python tests/run_tests.py --unit     no browser needed
python tests/run_tests.py -k conn    only matching filenames
```

`tests/unit/` imports the modules directly and needs only Python. `tests/ui/`
drives the real dashboard in a real browser through Playwright, against a demo
server the runner starts and stops — `pip install playwright && playwright
install chromium`, and it is skipped with a message if absent. Three unit tests
open a live capture socket and need Linux and root, and skip elsewhere.

Almost every bug this project has had was a layout or timing fault only a
browser could see: a column that truncated, a view that drifted as rows were
trimmed, a save that gave no feedback, a socket closed out from under a reading
thread. Prefer adding to `tests/ui/` over reasoning about the DOM.

---

## Notes on safety and privacy

The dashboard binds to `127.0.0.1` only and requires a random token that's
generated fresh at startup and printed in the console — so another program on
your machine can't quietly read your traffic through it, and nothing is exposed
to your network. Nothing is written to disk and nothing leaves your machine;
the packet buffer lives in memory (the last 20,000 frames, with the first 2 KB
of each retained for the hex view) and vanishes when you close the app.

This is a diagnostic tool for a machine you own. Capturing traffic on networks
or devices that aren't yours is a different matter entirely, and generally not
a legal one.

---

## Files

```
netscope.py         capture engine, decoders, HTTP API
netscope_smb.py     SMB2 decoding — share paths, filenames, read/write sizes
netscope_streams.py TCP reassembly and HTTP file extraction
netscope_quic.py    QUIC decoding, Initial-packet key derivation, SNI recovery
netscope_alerts.py  alert rules and Windows toast notifications
netscope_conn.py    connection table — flow accounting joined to the socket table
netscope_pcap.py    .pcap writing and reading
netscope_history.py SQLite history — rollups, first-seen records, alert log
netscope_tray.py    tray icon, console hiding, start-on-login
netscope_ui.py      the dashboard page (HTML/CSS/JS, no external assets)
requirements.txt    scapy, psutil, cryptography, pystray, pillow
build.bat           one-shot PyInstaller build
```

Two dependencies are optional at runtime. `cryptography` is needed for QUIC
hostname recovery and certificate checks; `pystray`/`pillow` for tray mode.
Without either, everything else still works and NetScope says so at startup
rather than silently dropping the feature.

Both Python files are plain and readable — worth a skim before you run
something with administrator rights and a packet driver behind it.

---

## Troubleshooting

**"Scapy could not load" / no interfaces listed** — Npcap isn't installed, or
it's installed without the WinPcap compatibility layer. Reinstall from
npcap.com with the default options.

**Capture starts but no packets arrive** — you're probably on the wrong
interface. Use the dropdown in the header, or run `NetScope.exe --list` to see
what's available with IPs attached, then pick the one carrying your traffic.

**Every process shows as `-`** — the app isn't elevated. Right-click →
Run as administrator.

**The browser shows 403** — you opened `http://127.0.0.1:8477/` without the
`?t=...` token. Copy the whole URL from the console window.

**Port 8477 is in use** — `NetScope.exe --port 9000`.

**The Files tab stays empty** — almost certainly because everything you're
doing is over HTTPS, which is normal and expected. Try `--demo` to confirm the
feature works, then test against a plain-HTTP resource.

**SMB traffic shows as plain TCP** — the share negotiated SMB3 encryption, or
the SMB message was split across TCP segments (NetScope decodes SMB per packet,
which covers the small control messages where filenames live but not every
case). The conversation viewer in Strings mode will usually still show the
names.

---

## Version history

**1.11.1** — The test suite now lives in the repository.

Every test written for this project had been sitting in a scratch directory on a
machine that gets reclaimed — around 300 assertions across 12 Python files and 8
browser files, each one written after a bug was found by hand, none of them
surviving the session that produced them. They are now `tests/`, with a runner
that starts a demo server, runs both halves against it and tears it down.

Three of the older browser scripts printed measurements without asserting
anything. They were useful while hunting the column bugs and useless as a guard
afterwards — a suite that cannot fail is not a suite — so they were rewritten as
one test that actually asserts what they were watching: bounded columns do not
truncate after an auto-fit, the table never scrolls sideways at four widths, a
hidden column keeps ten cells in its row, and a drag does not jump on its first
pixel.

Running it from its new home immediately caught a real defect: a 26-character
hostname in the Connections list was clipped by two pixels, because the activity
mark's fixed 52px slot left the identity line just short. The mark is 44px now
and scales to whatever it is given. That is the assertion the two-line layout
exists to satisfy, and it had been quietly false.

Also added `CLAUDE.md`, recording the decisions that cost the most to reach —
why the packet table never scrolls sideways, why hidden columns are zero-width
rather than `display:none`, why Connections is not a table, why the charts avoid
green-on-orange, why capture sockets must outlive the sniffer thread — so they
are not undone by someone reasonable who has not read the history.

**1.11.0** — Adapters that appear after launch are found and captured, instead
of being invisible until the app is restarted.

Scapy enumerates network interfaces once when it is imported and caches the
result in `conf.ifaces` forever. NetScope never re-read it. Started from a logon
task twenty seconds after logon — which is how it is meant to run — it saw
whatever adapters existed at that moment and nothing else, so Wi-Fi associating a
minute later, or a VPN connecting, was invisible. Refreshing the dashboard did
not help, because the page was asking the server and the server was faithfully
re-reading a snapshot taken at boot. Restarting the app worked only because it
re-imported scapy.

Reproduced and then verified directly: bring an adapter up and scapy's list is
unchanged; call `conf.ifaces.reload()` and it appears, and removals are noticed
too.

Two fixes. The adapter list is re-read from the OS, rate-limited because the
dropdown asks on every poll, and forced when the dashboard explicitly asks —
that endpoint exists to answer "what is attached right now", and a cached answer
was the whole problem. And listing them is not enough when what you want is them
*captured*, so a capture running on all interfaces now watches for adapters
turning up and attaches a sniffer to each, reaping any whose thread has died.
Each new adapter is announced in the dashboard, and the dropdown refreshes
itself rather than only at page load — though never while you have it open,
which would shut the menu under your cursor.

A capture pointed at specific adapters is deliberately left alone. Attaching
something the user did not ask for would be wrong, and there is a test for it.

**1.10.1** — Made the drop warning verifiable, which 1.10.0 shipped without.

Two states looked identical: a clean capture, and one whose driver cannot report
statistics at all. Both displayed nothing, so there was no way to tell a working
alarm from an absent one — the warning was untestable on the machine that needed
it. Hovering the packets figure in the footer now always says which, giving the
driver's received and discarded counts or stating plainly that statistics are
unavailable here.

And drops only occur when the handler cannot drain libpcap's buffer, which on a
quiet link never happens, so `--stress-drops US` stalls the handler on purpose.
Measured on a controlled loopback load: identical traffic, 0 drops without the
stall and 1,232 — 33.9% — at 500us. It is a testing flag and does nothing unless
asked for.

Also fixed a test that depended on leftover state: mutes persist by design, and
repeated runs of the alerts test had silenced every alert it needed to find. It
clears them first now.

**1.10.0** — The capture now reports what it lost.

NetScope counted nothing about dropped packets, which meant it could be
discarding most of the traffic on a busy link and still show a confident,
completely wrong set of numbers. That is a worse failure than missing a feature:
a monitoring tool that under-reports silently teaches you to trust figures that
are not true.

libpcap keeps the answer — `ps_recv`, `ps_drop`, `ps_ifdrop` — and scapy exposes
no stats method of its own, but it bundles the libpcap bindings and its socket
keeps the raw handle, so the counter is one call away. This was verified rather
than assumed: against a real capture with nothing draining the buffer, 102,882
packets seen and 102,672 reported dropped.

Reaching it needed one structural change. AsyncSniffer keeps its sockets local to
its own run loop, so a socket it opened cannot be reached afterwards; NetScope now
opens each capture socket itself and passes it in, falling back to the old
behaviour (and simply having no statistics) if that fails, rather than not
capturing.

That change introduced a crash, which the test for it caught: a socket passed in
with `opened_socket=` is ours to close, and closing a pcap handle while the
sniffer thread is still blocked reading it frees memory out from under a running
thread. The process segfaults and there is nothing for Python to catch.
AsyncSniffer used to own these sockets and closed them only after its thread had
exited; taking ownership meant taking on that ordering too. Sockets are now
closed on a background thread once their sniffer has let go, references are
dropped before anything is freed, and reading the counter takes the same lock
that guards start and stop.

**1.9.1** — The Connections tab is two lines per connection instead of a
seven-column table, because the table never fit and never could.

A readable text column needs roughly 90px. The side panel is 429px. Seven
columns need about 530px for the process names and hostnames alone, so every
previous revision of this view was the same losing arithmetic: shave the
percentages, drop Proto, then drop State, abbreviate a header to "Dup", shorten
"PIA OpenVPN WinTUN Adapter" to "PIA". Those were not design decisions, they were
symptoms, and there were five different column arrangements in the file to prove
it.

Files and Streams solved this in the same panel a long time ago and this view
should have followed them: the identity gets its own full-width line, the numbers
go underneath in dim text and read as a sentence. Nothing truncates. Protocol and
state come back for free, and the byte counts, age, adapter and quality figures
all fit without argument, because there are no column widths left to argue about.
Rows are 46px, so about sixteen are visible at once rather than thirty
unreadable ones — the right way round.

Two things fall out of it. "via <adapter>" only appears when more than one
adapter is in play, rather than announcing "via Wi-Fi" on every row of a
single-NIC machine. And the activity sparkline stays Open-view only, sitting at
the right of the identity line.

**1.9.0** — An activity sparkline per connection, and a demo that can actually
show it.

The Connections table could say how much a connection had moved and how long it
had been up, but not what it was doing — steady or bursty, working or stalled
thirty seconds ago with the socket still open. The Open view now carries 40
seconds of bytes-per-second per row.

Some deliberate choices. One ink rather than the footer chart's green/orange
in-out split: that pair fails deuteranope separation on this surface (measured
when the History charts were built, which is why those are blue and orange), and
In and Out sit two cells away carrying direction numerically. A filled area
rather than a line, because at this size a hairline across forty points is noise
while a silhouette reads at a glance. Scaled per row, since a shared scale
flattens every ordinary connection next to one busy download and magnitude is
already in the columns beside it. No axis, no gridline, no labels — it is a mark,
not a chart. And only in the Open view, where the question is live.

Storage is a sparse dict of second-to-bytes per flow, expanded to a dense series
at read time: an idle connection costs two entries instead of an array of forty
zeros, and the silence is reconstructed where it is needed rather than stored.

**The demo needed two fixes to represent any of this.** It emitted each
conversation in one tight loop, so every connection lived a fraction of a second
— the sparkline was a single needle and the age column never left zero. The data
phase now runs in real time across several seconds, on its own thread so one
conversation playing out does not stall every other kind of traffic. And demo
mode deliberately ignores this machine's real socket table, which left the whole
Connections tab empty; it now invents sockets for the conversations it invents.
Fake sockets for fake flows is consistent — it was mixing the two that would have
misled.

**1.8.0** — Alert tuning: mute one subject without disabling the rule, dismiss
one alert without clearing them all, and settings that survive a reboot.

**Settings now persist.** Rule switches, the bandwidth threshold and the toast
toggle were set in memory and never written anywhere, so anyone running NetScope
from a logon task — the case it is built for — had all seven rules silently
restored to defaults at every reboot. They are stored beside the history
database now and reloaded at startup. That was a defect, not a missing feature.

**Muting is per subject.** The only control before was turning a whole rule off,
which is the wrong grain: a rule is usually right to look and wrong about one
subject, and silencing the rule to silence the subject means going blind to
everything else it would have caught. Any alert can now be muted for its own
subject — a host, a program, a resolver — indefinitely or for an hour, and the
rule keeps watching everything else. Muted subjects are listed above the alerts
with an Unmute button, because a mute you cannot see is indistinguishable from a
rule that has stopped working. Mutes persist, and deliberately survive **Clear
alerts**: clearing means "I have read these", not "forget what I told you to
ignore".

**Dismiss one alert.** Clear was all or nothing, so reading one alert meant
throwing away the ones you had not.

**Every rule explains itself.** Each alert carries a "Why did this fire?"
disclosure stating what the rule actually compares. Finding that out previously
meant reading the source.

Two things surfaced while building it. `subject_of()` takes the last element of
an alert's key, and two rules had put the peer in the middle — so they would
have offered to mute a username, or the literal word "password", rather than the
host involved. And the muted-subject row let the rule name take precedence in
the layout, which crushed a hostname down to `2.` — the subject is the point of
that row, so it now wins the space and the rule name truncates instead.

**1.7.0** — A Quality view in the Connections tab: handshake RTT, TLS setup
time, resent segments and duplicate ACKs, per connection.

This turns NetScope from "what is my machine saying" into "why is this
connection bad", and every number comes from what is already visible in
plaintext — the TCP handshake and the TLS record headers — so it works on
encrypted traffic, which is nearly all of it. Rows sort worst first, loss ahead
of latency, and connections with nothing to report are left out.

The accounting lives in the flow record, so it shares one key and one lookup
with the byte counters, and it is deliberately cheap: a few comparisons per
packet and no per-segment history. That is also why "Resent" is named for what
it measures — segments covering ground already sent — rather than claiming to
distinguish a retransmission from a reordered segment, which needs memory
proportional to the window and still only guesses.

The demo generator needed fixing to show any of this. It emitted independent
packets with a fresh random port each time, which fills a packet list but means
no two packets ever belong to the same conversation — so nothing that measures a
*connection* had anything to work on, and the Quality view would have been
permanently empty in `--demo`. It now also emits coherent connections: a real
handshake with a chosen round trip, TLS setup, data, and occasional loss.

**1.6.1** — Fixes to the connection table, found by running 1.6.0 against a
machine with a VPN up.

**Unconnected UDP sockets matched nothing.** The matcher required a socket's
full 5-tuple, but an unconnected UDP socket has no remote address at all — one
socket carries many conversations. Every such conversation therefore matched no
socket and fell through to "recently closed", while being attributed to the
right process everywhere else in the app. That is not a VPN problem: it covered
DNS, mDNS, NTP, DHCP and a VPN's own tunnel socket. Flows are now indexed by
each endpoint and by port, so an unconnected socket claims every conversation
that used its local end, and a wildcard bind (`0.0.0.0`) falls back to the port
— which is what process attribution keys on anyway.

**The adapter is now part of a flow's identity.** A VPN puts the same data on
the wire twice: the real conversation on the tunnel adapter, and its
encapsulated copy on the physical NIC. Those are two conversations, and the key
ignored the adapter, so anything appearing on two adapters merged into one row
with doubled byte counts. Where more than one adapter is in play the table grows
a **Via** column naming it — State gives way to it, since eight columns do not
fit and in the Open view the state is ESTABLISHED on nearly every row.

**Same-port-both-ends flows were indexed twice.** mDNS (5353), NTP (123) and
OpenVPN in its usual configuration all have identical ports at both ends, and
the endpoint index listed those flows once per end, so they appeared twice.

**A class name collision.** The process cell was given `class="pr"`, which is
the packet table's protocol-*badge* style — `display:inline-block` with a
`min-width` — so it stopped being a table cell and its text painted over the
next column. It has no class now, and the test that would have caught it checks
computed `display` rather than geometry: a Range's rect ignores overflow
clipping and cannot tell a correctly ellipsised cell from an escaping one.

**Mixed-link-type pcap export.** A `.pcap` file declares one link type for the
whole file, and the exporter hard-coded Ethernet. A tunnel adapter can hand up
bare IP with no Ethernet header, and Wireshark would then read the first 14
bytes of each IP header as MAC addresses — silent nonsense. Records now carry
the link layer scapy actually saw, the exporter picks `LINKTYPE_RAW` when every
frame is bare IP, and normalises only a genuinely mixed capture to Ethernet by
prefixing a zeroed header — zeroed deliberately, because an invented MAC that
looked plausible would be worse than one that is obviously not real.

**1.6.0** — A Connections tab: what is open right now, rather than what just
went past.

The packet list has always been a firehose, and Talkers only ever showed
aggregate volume per process and per host. Neither answers the question you
usually have, which is "what is my machine talking to at this moment, and which
program is doing it". The new tab gives one row per connection — process, remote
host, TCP state, bytes each way, age — with Open / Listening / Just closed views,
and clicking a row filters the packet list to that conversation.

It works by joining two sources that are each insufficient alone. The OS socket
table is authoritative about what exists, its state and its owning PID, but the
kernel hands out no per-socket byte counts. Flow accounting off the capture knows
the byte counts exactly, but only sees packets, so it cannot see a listening or
idle socket. They are joined on the connection's 5-tuple, normalised so both
directions land in one row rather than appearing twice with half the bytes each.

New module `netscope_conn.py` (`FlowTable`, `SocketTable`, `build_view`) and a
`/api/connections` endpoint. Flow accounting hangs off `PacketStore.add()`, the
one choke point every record passes through, so live capture, demo, `--read` and
an imported pcap all populate it. The socket table is enumerated on demand with
a one-second cache rather than on a timer — it is expensive, and nothing needs it
unless the tab is open. Records now carry `transport` alongside `proto`, since
`proto` is the application protocol the decoders named and DNS may be either TCP
or UDP; where the transport is genuinely unknown the flow is keyed `?` rather
than assumed to be TCP, which would merge two different conversations.

Also fixed while in here: `.btn-sm:hover` set an accent foreground over the
accent background `button.on` paints, so hovering any selected small button —
the History day-range and Files buttons included — turned it into an empty
coloured box.

**1.5.9** — `--install-task` and `--task-status` now say when the logon task is
the console build.

The task action already prefers `NetScopeTray.exe` whenever it sits next to
`NetScope.exe` — it is built for the windows subsystem, so nothing flashes up at
logon. But when the twin is missing it fell back to the console build in silence,
and a task registered that way is indistinguishable from a correct one until the
next reboot puts a console window on screen. The path is also fixed at creation
time, so a task registered before the tray build existed keeps launching the
console build forever, however many times you rebuild.

Both commands now name the problem. `--install-task` prints a note when it had to
register the console build, giving the path it looked for and what to do about
it. `--task-status` checks the command already registered and, if it is the
console build, says so and whether `NetScopeTray.exe` is available to switch to.
Neither refuses to proceed: registering the console build is a legitimate choice,
it just should not be a silent one.

**1.5.8** — Saving a file now tells you it happened, and a double-click can no
longer produce two of them.

`Save ↓` built an anchor, clicked it, and changed nothing on the page. With the
browser's download shelf hidden there was no evidence the click had registered,
so the reasonable response was to click again — and because the export names
itself from the clock at request time, two clicks inside one second produced two
files with the same name, seconds apart, for no visible reason.

A transient confirmation now names the file that was saved and where it went,
and a repeat of the *same* save inside 1.8s is refused with "already saved
<name>" rather than silently duplicating it. Two *different* files can still be
saved back to back. The message cannot live in the status text, which every poll
overwrites, so it is its own element above the footer. The same treatment covers
the Save button on rebuilt files in the Files tab, which had the identical
problem. The pcap's filename is now chosen client-side rather than left to
`Content-Disposition`, so the confirmation states the real name instead of
guessing at it.

Hardening found on the way: a rebuilt file's name comes from the server that
sent it, and it was going into a `Content-Disposition` header unescaped. A quote
or a CRLF in that name ends the header early and lets the rest be supplied by
whoever sent the file; a path separator aims the save somewhere other than the
download folder. `safe_filename()` now strips both, plus the characters Windows
rejects in a filename, and the dashboard applies the same rule client-side.

**1.5.7** — The footer sparkline no longer slides sideways once a second.

It sat after the counters, so anything that changed the width of "rate" or
"named" pushed it along — a chart that twitches every poll is hard to read and
harder to ignore. It is now the first thing in the footer, where nothing
upstream of it can move it.

The counters themselves were doing the shoving, so they are pinned too:
`font-variant-numeric: tabular-nums` stops digits changing width (a proportional
face gives "1" less room than "8"), and each counter reserves room in `ch` units
for the longest value it can reach, so going from "9 B/s" to "1.2 MB/s" costs no
layout. Footer height and wrapping are unchanged.

**1.5.6** — Turning off "follow" now actually holds your place, and pause is a
button instead of an undocumented keystroke.

The follow checkbox was doing its job — nothing scrolled the table when it was
off. The movement came from the ring buffer. Once 2,500 rows are on screen every
poll trims the oldest ones off the top, which shortens the content *above* the
viewport; `scrollTop` is an offset from the top, so with the same offset against
less content everything you were reading slides upward and off the screen. No
code scrolled, and the rows walked away anyway. poll() now measures the height it
removed and subtracts it from `scrollTop`, so the rows under your eyes stay put.
The table also sets `overflow-anchor: none`: browsers try to compensate for this
themselves, inconsistently, and two corrections are worse than one.

The other half of the complaint was that data kept arriving, which follow never
controlled. Pausing existed but was bound to the spacebar with no button, no
label, and no feedback beyond the status text dimming — so the only visible
control that sounded like it might stop the table was the wrong one. There is now
a Pause/Resume button next to it, the filter bar says when you are paused, and
both controls carry tooltips saying which does what: pause stops rows arriving,
follow stops the view chasing them. The spacebar still works and keeps the button
in sync.

**1.5.5** — Fixed a false positive in the "DNS to an unexpected resolver" rule
that fires on any machine with two live adapters.

The rule counted DNS destinations in one machine-wide tally and complained about
whichever resolver was in the minority. Since 1.4.0 captures every interface at
once, that was wrong by construction: Windows' smart multi-homed name resolution
deliberately sends the same query out every adapter, each to its own configured
resolver, so a PC on Wi-Fi and Ethernet at the same time tripped the rule
forever — reporting a correctly configured second resolver as suspicious.

Two changes. Counting is now per interface, so one adapter's normal resolver is
never judged against another's. And the rule now asks the OS which resolvers are
actually configured (`Get-DnsClientServerAddress` on Windows, `/etc/resolv.conf`
elsewhere, re-read every five minutes off the capture path) — a server on that
list is expected however rarely it is used, which also stops a configured
secondary resolver from alerting, and a server *not* on it is worth flagging
however ordinary it looks. When the OS cannot be asked, it falls back to the old
statistical test, now per interface. Alerts name the interface, since that is the
first thing you want to know.

**1.5.4** — Column sizing fixes, all of them the same mistake: guessing at a
rendered width instead of asking the browser for it.

Double-clicking a column border auto-fits it, but the measurement used a canvas
`measureText()` in one font plus a flat 20px for padding. That is right only
where a cell is plain monospace text. The Proto cell holds a badge with its own
10px sans face, letter-spacing, 6px of padding and a 1px border, so the estimate
came out short and the column stayed truncated after a double-click. Auto-fit
now clones the sampled cells into a hidden one-column table with
`table-layout: auto` and no clipping, and reads the width the browser gives
them — badge chrome, per-cell fonts and padding all included.

The drag handle's line was drawn 4px inside the header cell, so it read as a
stray rule crowding the label rather than as the border it controls. It now sits
on the cell's right edge, which with `border-collapse` is the column boundary,
and the grab area is 10px instead of 8.

Two default widths were simply too small for their contents and shipped
ellipsised: Time (88px for a 12-character timestamp that needs ~103) and
Direction (22px, where the cell's own 16px of side padding left the arrow 6px).
Proto's minimum is now 74px, the width of the badge itself — below that the
proportional squeeze at narrow windows clipped the chip, which looks broken in a
way ellipsised text does not.

**1.5.3** — The horizontal scrollbar is gone for good, this time by removing
the cause rather than the symptom. It was a timing problem: column widths were
committed against the container's width while the table was still empty, and
the moment rows filled it, the vertical scrollbar appeared and took about 15px
away — leaving the columns sized for a container that no longer existed. That
is why resizing a column fixed it and refreshing brought it back. Three
changes: `scrollbar-gutter: stable` reserves the scrollbar's width from the
start so the usable width never changes; the table is always sized at 100%
rather than a pixel width measured at one instant; and a `ResizeObserver`
re-fits the columns whenever the container actually changes, instead of
trusting a single measurement. The table wrapper is also `overflow-x: hidden`,
so it cannot produce one under any circumstances.

**1.5.2** — Capturing every active adapter is now the default rather than
something to select each time, and whichever interface you pick is remembered
between launches in `settings.json` beside the history database. Also fixes a
horizontal scrollbar that came back at middling window widths: it was the
*page* overflowing, not the table. A CSS grid item defaults to `min-width:auto`
and will not shrink below its content's minimum, so the side panel's six-tab
strip forced that column wider than its declared size and pushed the layout
past the viewport. The panel now has `min-width:0` and the tabs wrap.

**1.5.1** — A second executable, `NetScopeTray.exe`, built for the windows
subsystem so there is no console window at all — double-click it and it goes
straight to the tray. The console build could only hide its console *after*
Windows had already shown it. Its output goes to `netscope.log` instead, since
a windowed build has no stdout. The logon task prefers this executable when it
is present. Also fixes `hide_console()`, which used `GetConsoleWindow()`
without checking whether the console was ours: launched from an existing
PowerShell or cmd prompt it would have hidden the user's own terminal. It now
only hides a console this process is alone in.

**1.5.0** — ICMP is named rather than numbered: `Destination unreachable ·
port unreachable` instead of `type=3 code=3`, for both ICMPv4 and ICMPv6, plus
IGMP. Frames that are not IP, IPv6 or ARP are identified instead of showing as
`?  ?  OTHER` — spanning tree, LLDP, CDP, EAPOL, VLAN tags, PPPoE, Wake-on-LAN
and the rest, with real MAC addresses and named multicast destinations.
Packets with no owning process now say why — `(kernel)`, `(link layer)`,
`(broadcast)` or `(no socket)` — separating "nothing to attribute" from "failed
to attribute", and the footer reports what share of packets is tied to a
program. An unattributable packet also triggers an immediate socket-table
refresh, catching short-lived connections that open and close between polls.

Also fixes a column bug from 1.4.0: the Iface column was hidden with
`display:none` when only one adapter was captured, which removes the cell from
the row and shifts every later cell onto the wrong `<col>` — so resize handles
moved the neighbouring column. Hidden columns are now squeezed to zero width
instead, and every column is shown by default with a **Columns** chooser rather
than the app guessing.

**1.4.0** — Capture every active interface at once instead of picking one.
`--iface all`, `--iface "a,b"`, or **All active interfaces** in the dropdown;
one sniffer per adapter, merged into a single packet list, each packet tagged
with where it was seen. An Iface column appears only when more than one adapter
is in play, and `iface` is a new filter field. A partially failed start reports
which adapters could not be opened rather than silently capturing less than you
asked for. This removes the failure mode we hit while testing 1.3.2, where the
traffic was on the adapter that wasn't selected.

**1.3.5** — The packet table no longer scrolls horizontally, ever. Horizontal
scroll was the original bug — it is what pushed the Info column off-screen —
and 1.3.3 reintroduced it as the behaviour for widening a column, which put the
same problem back as a feature. It was never necessary: Info is the flex column
and cannot be dragged, so the only way to give Info more room is to shrink
something else. Widening a column now borrows from Info and the drag is clamped
before Info hits its minimum, so a border reaches a limit rather than a
scrollbar appearing. Shrinking the window squeezes columns proportionally
without discarding the widths you chose.

**1.3.4** — Column dragging no longer jumps. Starting a drag switched the table
from auto-fit to custom widths while the stored widths were still the
placeholder defaults, so every column snapped to a different size under the
cursor on the first pixel of movement. The on-screen widths are now snapshotted
the moment you press, measured from the header cells rather than the `<col>`
elements (which have no box in some browsers), and the Info column absorbs the
slack so only the border you are dragging moves. Resizing is also throttled to
one relayout per frame.

**1.3.3** — Resizable packet-table columns: drag a border, double-click to
auto-fit, widths persist, Reset columns restores them. 1.3.2 stopped the table
overflowing by clipping cells instead, which just traded a scrollbar for
truncated data with no way to get it back — now the defaults fit the window and
you can size any column yourself, with the table scrolling once you widen one.
Also removed the width breakpoints that used to hide the Bytes and Source
columns at narrow widths, since guessing which column you can spare is the
user's call, and added hover tooltips carrying the full value on every
truncatable cell.

**1.3.2** — Four fixes found by testing against a real Windows machine and a
real browser. **QUIC hostnames now work against actual browsers:** the
ClientHello is reassembled across Initial packets, where before only the first
packet was parsed, so a truncated ClientHello silently yielded no SNI — every
synthetic test passed because generated ClientHellos fit in one packet and
Chrome's does not. The interface dropdown re-syncs with the interface actually
being captured instead of only being set at page load. The packet table no
longer pushes the Info column off-screen at narrow window widths, and the
header stays on one row. The display filter can now search the entire capture
buffer rather than only the rows loaded in the browser.

**1.3.1** — Start-at-logon now registers a Task Scheduler logon task with
highest privileges instead of an HKCU Run entry. The Run key cannot silently
elevate a program whose manifest requests administrator, so the 1.3.0 flag
produced a UAC prompt at every logon. The task is created from XML so the
72-hour execution limit and the battery rules can be turned off.
`--install-task` / `--remove-task` / `--task-status`, with the old flag names
kept as aliases, the Run-key method available as `--autostart-registry`, a
refusal to register from a temporary folder, and the current state shown in the
History tab.

**1.3.0** — Persistent history in SQLite: hourly per-process rollups, first-seen
records for programs and hosts, the alert log and a session log, with hourly
retention pruning and a writer thread that keeps disk I/O off the capture path.
A History tab with a KPI row, a 7/30/90-day stacked column chart, per-program
and per-host breakdowns, recently-first-contacted hosts, and a table view under
every chart. The first-seen alerts now consult the database, so "new" means new
to the machine rather than new to the session. Tray mode with a state-coloured
icon and live tooltip, console hiding, and opt-in start-on-login via a single
removable HKCU Run entry.

**1.2.0** — PCAP export and import (Save/Open in the toolbar, `--read` on the
command line, full re-decode of loaded files). A display-filter expression
language with saved presets, separate from the BPF capture filter. QUIC/HTTP-3
decoding including Initial-packet decryption for hostname and ALPN recovery.
An alert engine with seven rules covering new programs, new hosts, bandwidth
thresholds, cleartext credentials, unencrypted protocols, certificate problems
and unexpected DNS resolvers, with optional Windows toasts. Demo mode now
generates genuine Ethernet frames, real QUIC Initials and deliberately insecure
traffic so every feature has something to show.

**1.1.1** — Clicking a packet no longer forces the side panel back to the
Packet tab. Files, Streams and Talkers are session-wide views, so they now stay
open while you click through the packet list; the Packet tab shows the selected
frame number so you can see the selection registered.

**1.1.0** — SMB2 decoding (share paths, filenames, read/write sizes); TCP
stream reassembly with a Follow-connection viewer in Text/Strings/Hex; HTTP
file extraction into a Files tab with save and preview; `--no-extract`.

**1.0.0** — Initial release: live capture, per-process attribution, DNS/TLS/HTTP
decoding, packet detail with hex, talkers ranking, BPF filters.
