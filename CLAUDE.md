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
the runner starts and stops (`pip install playwright && playwright install
chromium`; skipped with a message if absent). Three unit tests open a real
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

## Environment

Needs Npcap and administrator rights to capture. `cryptography` is optional
(QUIC hostnames, certificate checks) and so are `pystray`/`pillow` (tray mode);
NetScope says so at startup rather than silently dropping the feature.
`--demo` fabricates traffic and needs neither Npcap nor admin.

Unverifiable in a Linux container, so test on Windows: PyInstaller output, Npcap
capture, UAC elevation, real SMB shares, toast notifications, the tray icon and
the logon task.
