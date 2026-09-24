# NetScope — working notes

A live packet monitor for Windows: Python + scapy capture, a browser dashboard
served from `127.0.0.1`, packaged with PyInstaller into two .exe files. Full
user documentation and the version history are in `README.md`.

## Layout

```
netscope.py           capture engine, decoders, HTTP API, DemoEngine, CLI
netscope_ui.py        the entire dashboard as one PAGE_HTML string
netscope_conn.py      connection table: flow accounting joined to the socket table
netscope_alerts.py    alert rules, muting, Windows toasts
netscope_history.py   SQLite history and the settings file
netscope_streams.py   TCP reassembly and HTTP/FTP file extraction
netscope_smb.py       SMB2 decoding (share paths, filenames)
netscope_ftp.py       FTP control-channel parsing, data-connection correlation
netscope_quic.py      QUIC Initial decryption for SNI/ALPN
netscope_l2.py        ICMP and link-layer description
netscope_pcap.py      .pcap reading and writing
netscope_tray.py      tray icon, console hiding, the logon task
tests/                see below
build.bat             PyInstaller: NetScope.exe (console) + NetScopeTray.exe (no console)
```

## Conventions

**Semver, deliberately.** Patch for fixes, minor for features. This differs from
the plain patch increments used on Activity Monitor, and that was a considered
choice — do not "correct" it.

**Bump `VERSION` in `netscope.py` and the zip filename together** on every
delivered build.

**The dashboard is one string.** `netscope_ui.py` holds the whole page in
`PAGE_HTML`. To syntax-check the JavaScript:

```
python -c "import re;s=open('netscope_ui.py').read();open('/tmp/ns.js','w').write(re.search(r'<script>(.*?)</script>',s,re.S).group(1))" && node --check /tmp/ns.js
```

## Tests

```
python tests/run_tests.py            everything available
python tests/run_tests.py --unit     no browser needed
python tests/run_tests.py -k conn    just the matching files
```

`tests/unit/` imports the modules directly and needs only Python.
`tests/ui/` drives the real dashboard through Playwright against a demo server
the runner starts and stops. The tests are Node scripts, so they need the
*npm* package — `npm install --no-save playwright && npx playwright install
chromium` in the project root; pip's `playwright` does not help. Skipped with
a message if absent. Three unit tests open a real
capture socket and create adapters with `ip`, so they are Linux+root only and
skip elsewhere.

Almost every bug in this project's history was a layout or timing fault that
only a browser could see. Prefer adding to `tests/ui/` over reasoning about the
DOM.

## Decisions worth not re-litigating

Each of these was reached the hard way; changing one without reading the reason
will reintroduce a bug that took a while to find.

**The tray icon is static: blue running, grey stopped, nothing else.**
Alert-state coloring (idle/warn/high) and a throughput-driven animation
(signal-strength bars, then a growing/pulsing dot) were each built, tried
live, and rejected — the moving parts read as noise rather than signal.
Don't reintroduce either without trying them live first.

**The packet table never scrolls sideways.** Info absorbs the remainder and
drags are clamped. Horizontal scroll was tried and rejected — it pushed the most
useful column off-screen.

**Hidden columns are zero-width, never `display:none`.** Removing a cell from a
row shifts every later cell onto the wrong `<col>`.

**The Connections tab is two-line items, not a table.** A readable text column
needs ~90px and the side panel is 429px; seven columns need ~530px. Five
different column arrangements were tried before the arithmetic was done. Files
and Streams use the same two-line pattern.

**Chart hues are blue/orange, not the app's green/orange.** Green vs orange
fails deuteranope separation on the dark surface — measured, not guessed. The
per-connection activity mark is a single ink for the same reason.

**The flow key includes the adapter.** A VPN puts the same conversation on the
wire twice, and a frame seen on two adapters would otherwise be counted once
with doubled bytes.

**Unconnected UDP sockets match flows by local endpoint, not the 5-tuple.**
They have no remote address; requiring the full tuple silently orphaned all
DNS, mDNS, NTP and VPN tunnel traffic.

**FTP data connections are only extracted once `closed`.** Unlike HTTP there
is no `Content-Length` to say a file is complete — the data connection
closing is the only signal FTP gives. Extracting earlier means shipping a
truncated file with no way to tell it was truncated.

**FTP uploads (`STOR`) are tracked but never armed for extraction.**
`FTPCorrelator` deliberately only arms a data connection after a `RETR`, so
an upload's data connection gets no hint and falls through to plain TCP —
downloads-only was a scope decision, not an oversight, so a `STOR` data
connection silently going unextracted is expected, not a bug to fix in
isolation.

**FTP negotiates the data port before it names the file.** RFC 959 order is
`PASV`/`EPSV` (or `PORT`/`EPRT`) first, then `RETR`. `FTPCorrelator` holds an
unnamed negotiation per control connection until the `RETR` arrives; any
other transfer command (`LIST`, `STOR`, ...) spends it. The original code and
its tests had the order reversed, which meant real downloads were missed or
mislabelled while every test passed — write FTP tests in the order a real
client sends.

**The port-scan rule counts connection attempts, not packets.** Inbound TCP
counts only a bare SYN; inbound UDP only when it isn't a reply to a datagram
this machine sent to that (peer, port) recently. Counting every packet made
each DNS reply (a fresh ephemeral port each time) look like a probe from the
router. Outbound fan-out ignores ports 80/443: one page load opens
connections to dozens of hosts, which is indistinguishable from a scan by
shape alone.

**Alert mutes are per (rule, subject) and survive `Clear alerts`.** Disabling a
whole rule to silence one subject is the wrong grain. Clearing means "I have
read these", not "forget my tuning".

**Capture sockets are opened by `CaptureEngine`, not `AsyncSniffer`.** The
sniffer keeps its sockets local to its run loop, and the drop counter lives on
the socket's pcap handle. They must be closed only after the sniffer thread has
exited — closing a pcap handle out from under a reading thread segfaults, with
no exception to catch.

**Adapters are re-enumerated, never trusted from cache.** scapy fills
`conf.ifaces` once at import and keeps it forever; started from a logon task,
NetScope would otherwise never see Wi-Fi or a VPN that came up afterwards.

**The dashboard server binds with `SO_EXCLUSIVEADDRUSE`, not the default
`SO_REUSEADDR`.** On Windows, `SO_REUSEADDR` (which `HTTPServer` sets by
default) lets a second NetScope silently bind the same port a first instance
is still listening on — no error, and every request keeps going to whichever
one bound first. The second process still prints and opens its own URL with
its own, different token, which the process actually serving requests never
recognises: a "bad token" 403 with nothing pointing at the real cause. This
is what a second launch of the tray build looks like when NetScope is already
running from the logon task. `DashboardServer` in `netscope.py` turns that
into an immediate, explained failure instead.

**ARP bindings and seen routers are tracked per adapter, DHCP servers are
not.** `arp_spoof` and `rogue_ra` both key their "seen before" state on
`(iface, subject)` — a VPN or a second NIC can legitimately show the same
private IP, or run its own router, without anything being wrong. DHCP
servers (`seen_dhcp_servers`) are deliberately tracked machine-wide instead:
a DHCP OFFER/ACK is already scoped to the interface it arrived on by the
capture itself, and a second adapter genuinely getting a lease from the same
router (common — one physical LAN, two adapters) is not a second server. If
a future rule needs multi-adapter DHCP-server tracking, that is a deliberate
change, not a bug to "fix" by copying the ARP/RA shape blindly.

**NBNS naming only ever comes from a Name Registration/Refresh or a
positive Name Query Response, never a plain query.** `netscope_nbns.parse()`
decodes every NBNS packet for display, but a broadcast query ("who has this
name?") says nothing trustworthy about who sent it — anyone can ask about
any name. Only the two unambiguous shapes call `store.note_host()`, and that
decision is made by the caller in `netscope.py`, not inside `parse()`
itself, the same separation `netscope_dhcp.parse()` keeps from
`DhcpTracker`'s lease correlation. This means NBNS naming fires less often
than mDNS/LLMNR in practice, since most real NBNS traffic is the ambiguous
broadcast queries — that's an honest trade, not a shortfall to "fix" by
attributing names from queries too.

**Building a scapy `DNS()` for a response, without also silencing the
question, leaks a phantom `www.example.com` query.** `DNS()`'s `qd` field
defaults to one `DNSQR()` (query section count 1) even when you only set
`an=...`, so a hand-built mDNS/LLMNR *response* needs `qdcount=0, qd=None`
explicitly, or the decoded `queries` list carries a fake entry that shows up
in the info line. Cost a debugging pass in the demo-mode mDNS seed
(`DemoEngine._seed_mdns`) before the LLMNR seed, built with an explicit
`qd`, happened to dodge it.

**Reverse DNS is the one naming source that is opt-in and off by default.**
Every other one (DNS, DHCP, mDNS/LLMNR/NBNS, TLS/QUIC SNI) only labels an IP
because something on the wire already announced a name — NetScope stays
purely passive. `ReverseResolver` in `netscope.py` is different: it sends
PTR-style queries out via the OS resolver for whatever stays unlabeled.
Defaulting it on would quietly turn a "just watching" tool into one that
originates its own traffic, and on a busy capture full of public IPs that
is a steady stream of queries leaving the machine — worth a deliberate
choice, not a default. `App.reverse` is `None`-safe everywhere it's read
(`CaptureEngine` never queues work against it in demo mode) so the toggle
existing does not imply demo mode does anything with it.

**Reverse DNS's lifetime attempt cap is a safety net, not a budget meant to
be hit.** It was originally 2,000 and got raised to 20,000 after a real
tray-mode run, left going since early morning, silently exhausted it with
no way to tell — every subsequently-seen IP just stayed unlabeled and looked
identical to "has no PTR record", which is the common, expected case. The
Alerts tab now shows attempted/resolved/cap-reached (`ReverseResolver.stats()`)
so that distinction is visible without reading the source. If this cap ever
needs raising again, add to the stats line too — a cap nobody can see being
hit is worse than no cap at all. It counts *distinct IPs*, not lookups (since
1.21.3): counting every lookup meant each retry after the 10-minute negative
cache spent budget too, so a few hundred long-lived unnamed IPs would still
exhaust 20,000 in under a day — the same failure the raise was meant to fix.
Retrying an IP already tried is free at the cap.

**An imported .pcap is offline: no history, no live attribution.**
`CaptureEngine.ingest_file()` sets `_offline` so imported packets are not
written to the history database (they are another machine's traffic, or
this one's from another time) and are not matched against the live socket
table (a port some process owns now says nothing about when the file was
captured). Direction is still computed, since it only compares addresses.

## Environment

Needs Npcap and administrator rights to capture. `cryptography` is optional
(QUIC hostnames, certificate checks) and so are `pystray`/`pillow` (tray mode);
NetScope says so at startup rather than silently dropping the feature.
`--demo` fabricates traffic and needs neither Npcap nor admin.

Unverifiable in a Linux container, so test on Windows: PyInstaller output, Npcap
capture, UAC elevation, real SMB shares, toast notifications, the tray icon and
the logon task.
