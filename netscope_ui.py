# -*- coding: utf-8 -*-
"""The NetScope dashboard: one self-contained HTML page, no external assets."""

PAGE_HTML = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScope</title>
<style>
:root{
  --bg:#0e1116; --panel:#151a21; --panel2:#1b222b; --line:#242c37;
  --fg:#dbe3ee; --dim:#8b97a8; --faint:#5d6878;
  --accent:#4da3ff; --out:#f0883e; --in:#3fb950;
  --tcp:#4da3ff; --udp:#a371f7; --dns:#39c5cf; --tls:#3fb950;
  --http:#e3b341; --icmp:#f0883e; --arp:#8b97a8; --other:#6e7681; --smb:#db61a2;
  --quic:#56d4dd;
  --mono:"Cascadia Mono","JetBrains Mono",Consolas,"SF Mono",Menlo,monospace;
  --sans:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;
}
html[data-theme="light"]{
  --bg:#f6f8fa; --panel:#ffffff; --panel2:#f0f3f6; --line:#d8dee4;
  --fg:#1f2328; --dim:#59636e; --faint:#8c959f;
  --accent:#0969da; --out:#bc4c00; --in:#1a7f37;
  --tcp:#0969da; --udp:#8250df; --dns:#1b7c83; --tls:#1a7f37;
  --http:#9a6700; --icmp:#bc4c00; --arp:#6e7781; --other:#8c959f; --smb:#bf3989;
  --quic:#1b7c83;
}
*{box-sizing:border-box}
html,body{height:100%;overflow:hidden;max-width:100%}
body{
  margin:0;background:var(--bg);color:var(--fg);font:13px/1.45 var(--sans);
  display:flex;flex-direction:column;overflow:hidden;
}

/* ---------- top bar ---------- */
header{
  display:flex;align-items:center;gap:12px;padding:9px 14px;
  background:var(--panel);border-bottom:1px solid var(--line);flex:0 0 auto;flex-wrap:wrap;
}
.brand{display:flex;align-items:center;gap:8px;font-weight:650;letter-spacing:.2px}
.brand svg{display:block}
.badge{font:600 10px/1 var(--sans);padding:3px 6px;border-radius:4px;
  background:var(--panel2);color:var(--dim);border:1px solid var(--line);letter-spacing:.4px}
.badge.demo{background:#f0883e22;color:var(--out);border-color:#f0883e55}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);flex:0 0 auto}
.dot.live{background:var(--in);box-shadow:0 0 0 3px #3fb95033;animation:pulse 2s infinite}
.dot.err{background:#f85149;box-shadow:0 0 0 3px #f8514933}
@keyframes pulse{50%{box-shadow:0 0 0 6px #3fb95000}}
.status{color:var(--dim);font-size:12px;display:flex;align-items:center;gap:7px;min-width:0}
.status b{color:var(--fg);font-weight:600}
.spacer{flex:1 1 auto}
select,input[type=text]{
  background:var(--panel2);color:var(--fg);border:1px solid var(--line);
  border-radius:6px;padding:5px 8px;font:12px var(--sans);outline:none;
  min-width:0;
}
/* Let these shrink rather than shoving the buttons onto a second row. */
header #iface{flex:0 1 260px}
header #bpf{flex:1 1 120px}
header button{flex:0 0 auto}
@media(max-width:1320px){
  header{gap:8px;padding:7px 10px}
  header #iface{flex:0 1 170px}
  header .badge:not(.demo){display:none}
  header button{padding:5px 8px}
}
@media(max-width:1150px){
  header .status{display:none}
  header #bpf{flex:1 1 90px}
}
input[type=text]{font-family:var(--mono)}
select:focus,input:focus{border-color:var(--accent)}
button{
  background:var(--panel2);color:var(--fg);border:1px solid var(--line);
  border-radius:6px;padding:5px 11px;font:600 12px var(--sans);cursor:pointer;
}
button:hover{border-color:var(--accent);color:var(--accent)}
button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
button.danger:hover{border-color:#f85149;color:#f85149}
label.chk{display:flex;align-items:center;gap:5px;color:var(--dim);font-size:12px;cursor:pointer;user-select:none}

/* ---------- layout ---------- */
main{flex:1 1 auto;display:grid;grid-template-columns:1fr 430px;min-height:0}
@media(min-width:1750px){main{grid-template-columns:1fr 600px}}
@media(max-width:1400px){main{grid-template-columns:1fr 360px}}
@media(max-width:1100px){main{grid-template-columns:1fr}#side{display:none}}

/* Columns are sized by the <colgroup> and are user-resizable — no media
   queries guessing which column you can live without. */
#left{display:flex;flex-direction:column;min-width:0;min-height:0}
/* min-width:0 matters: a grid item defaults to min-width:auto and will not
   shrink below its content's minimum, so the six-tab strip was forcing this
   column wider than its declared size and pushing the whole page past the
   viewport — a horizontal scrollbar on the document, not the table. */
#side{border-left:1px solid var(--line);background:var(--panel);
  display:flex;flex-direction:column;min-height:0;min-width:0}

/* ---------- packet table ---------- */
.tablewrap{flex:1 1 auto;overflow-y:auto;overflow-x:hidden;min-height:0}
/* Scroll anchoring off: once the buffer is full the poll trims rows off the
   top, and the browser's own anchoring compensates for that inconsistently —
   it needs an anchor node it likes, and gives up in cases it does not
   document. poll() measures the removed height and adjusts scrollTop itself,
   which is exact; leaving anchoring on as well would double-count it. */
.tablewrap{overflow-anchor:none}
/* Reserve the vertical scrollbar's width from the start, so the usable width
   does not change the moment the first rows arrive. */
.tablewrap{scrollbar-gutter:stable}
/* table-layout:fixed is what stops the Info column being pushed off-screen:
   with auto layout the fixed pixel widths added up to more than a narrow
   window could give, so the table grew and the last column — the most useful
   one — ended up behind a horizontal scrollbar. Fixed layout shrinks the
   columns instead and lets text ellipsise. */
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px;
  table-layout:fixed}
thead th{
  position:sticky;top:0;z-index:2;background:var(--panel);color:var(--dim);
  text-align:left;font:600 11px var(--sans);letter-spacing:.3px;text-transform:uppercase;
  padding:7px 8px;border-bottom:1px solid var(--line);white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;
}
tbody td{padding:3px 8px;border-bottom:1px solid var(--line);white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}

/* ---------- column resizing ---------- */
thead th{position:sticky}
/* The grab area hugs the right edge of the <th>, and its line sits *on* that
   edge — which, with border-collapse, is the column boundary. Drawn a few
   pixels inside it instead, it read as a stray rule crowding the header
   label rather than as the cell border it controls. */
thead th .rz{
  position:absolute;top:0;right:0;width:10px;height:100%;cursor:col-resize;
  z-index:3;user-select:none;touch-action:none;
}
thead th .rz::after{
  content:"";position:absolute;top:5px;bottom:5px;right:0;width:1px;
  background:var(--line);
}
thead th .rz:hover::after,thead th .rz.on::after{
  background:var(--accent);width:2px;right:0;top:0;bottom:0;
}
body.rzing{cursor:col-resize;user-select:none}
body.rzing *{cursor:col-resize !important}

/* Off-screen ruler for double-click auto-fit. Cells are cloned into it and
   the browser is asked how wide they really are — see autoFit(). The wrapper
   is a zero-height clipped strip so nothing shows and nothing scrolls, but it
   is viewport-wide, because a shrink-to-fit table inside a zero-width box
   collapses to its minimum instead of its content width. */
#fitwrap{position:fixed;left:0;top:0;width:100vw;height:0;overflow:hidden;
  visibility:hidden;pointer-events:none;z-index:-1}
#fitmeter{position:absolute;left:0;top:0;table-layout:auto;
  width:max-content;max-width:none}
#fitmeter th,#fitmeter td{position:static;overflow:visible;text-overflow:clip;
  max-width:none;border-bottom:0}
tbody tr{cursor:pointer}
tbody tr:hover{background:var(--panel2)}
tbody tr.sel{background:#4da3ff22;outline:1px solid var(--accent);outline-offset:-1px}
td.num{text-align:right;color:var(--dim)}
td.info{color:var(--dim)}
.arrow{font-weight:700}
.arrow.out{color:var(--out)}
.arrow.in{color:var(--in)}
.pr{display:inline-block;min-width:44px;text-align:center;padding:1px 6px;border-radius:4px;
  font:700 10px var(--sans);letter-spacing:.4px;border:1px solid transparent}
.pr.TCP{color:var(--tcp);background:#4da3ff1a;border-color:#4da3ff33}
.pr.UDP{color:var(--udp);background:#a371f71a;border-color:#a371f733}
.pr.DNS{color:var(--dns);background:#39c5cf1a;border-color:#39c5cf33}
.pr.TLS{color:var(--tls);background:#3fb9501a;border-color:#3fb95033}
.pr.HTTP{color:var(--http);background:#e3b3411a;border-color:#e3b34133}
.pr.ICMP{color:var(--icmp);background:#f0883e1a;border-color:#f0883e33}
.pr.ARP{color:var(--arp);background:#8b97a81a;border-color:#8b97a833}
.pr.SMB2,.pr.SMB{color:var(--smb);background:#db61a21a;border-color:#db61a233}
.pr.QUIC{color:var(--quic);background:#56d4dd1a;border-color:#56d4dd33}
.pr.DHCP{color:var(--udp);background:#a371f71a;border-color:#a371f733}
/* Hidden columns are squeezed to zero width rather than display:none —
   removing a cell from the row shifts every later cell onto the wrong <col>,
   so the colgroup widths and the resize handles end up applying to the
   neighbouring column. The rules themselves are generated into #colhide. */
.colmenu{position:absolute;z-index:40;background:var(--panel);
  border:1px solid var(--line);border-radius:8px;padding:8px 10px;
  box-shadow:0 10px 30px rgba(0,0,0,.4);display:none}
.colmenu.on{display:block}
.colmenu label{display:flex;align-items:center;gap:7px;padding:3px 2px;
  color:var(--dim);font-size:12px;cursor:pointer;white-space:nowrap}
.colmenu label:hover{color:var(--fg)}
.hint{color:var(--faint);font-size:10.5px;margin-top:6px}
.colmenu .hint{color:var(--faint);font-size:10.5px;margin-top:6px;
  padding-top:6px;border-top:1px solid var(--line)}
/* Right-click on a packet row: hide it from view, or keep it out of History. */
.rowmenu{position:fixed;z-index:45;background:var(--panel);
  border:1px solid var(--line);border-radius:8px;padding:4px;
  box-shadow:0 10px 30px rgba(0,0,0,.4);display:none;min-width:220px;max-width:380px}
.rowmenu.on{display:block}
.rowmenu button{display:block;width:100%;text-align:left;border:none;background:none;
  padding:5px 8px;border-radius:5px;font:12px var(--sans);color:var(--fg);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rowmenu button:hover,.rowmenu button:focus{background:var(--panel2);color:var(--fg);outline:none}
.rowmenu .sep{height:1px;background:var(--line);margin:4px 2px}
.rowmenu .hint{padding:0 8px 4px;margin:0}
.pr.FTP{color:var(--http);background:#e3b3411a;border-color:#e3b34133}
.pr.ICMPv6{color:var(--icmp);background:#f0883e1a;border-color:#f0883e33}
.pr.IGMP{color:var(--icmp);background:#f0883e1a;border-color:#f0883e33}
/* Infrastructure chatter — present, named, but visually recessive. */
.pr.STP,.pr.LLDP,.pr.CDP,.pr.DTP,.pr.EAPOL,.pr.LLC,.pr.SNAP,.pr.VLAN,
.pr.PPPoE,.pr.RARP,.pr.PTP,.pr.LACP,.pr.WoL,.pr.SRP,.pr.Loop,
.pr.HomePlug,.pr.OSI,.pr.IPX,.pr.NetBIOS{
  color:var(--faint);background:transparent;border-color:var(--line)}
/* A category, not a program name. */
.proc.sys{color:var(--faint);font-style:italic}
.pr.OTHER{color:var(--other);background:#6e76811a;border-color:#6e768133}
.proc{color:var(--fg)}
.host{color:var(--accent)}

/* ---------- timeline view ----------
   The same capture as the table, drawn as one lane per program (or host)
   against time. Its job is rhythm: what checks in every minute, what woke up
   when, what talks at 3 a.m. The table can't show any of that. */
.viewsw{display:inline-flex;flex:0 0 auto}
.viewsw .btn-sm{border-radius:0}
.viewsw .btn-sm:first-child{border-radius:5px 0 0 5px}
.viewsw .btn-sm:last-child{border-radius:0 5px 5px 0;margin-left:-1px}
/* The table stays laid out at full width while the timeline is shown, only
   zero height: display:none would report a zero width to the column fitting,
   and rows keep arriving underneath either way. */
body.tlmode #tw{flex:0 0 0;height:0;overflow:hidden}
body.tlmode #colsBtn,body.tlmode #resetCols,body.tlmode #searchAll{display:none !important}
#tlview{flex:1 1 auto;display:flex;flex-direction:column;min-height:0;min-width:0;
  position:relative}
.tlbar{display:flex;align-items:center;gap:10px;padding:6px 14px;flex:0 0 auto;
  flex-wrap:wrap;border-bottom:1px solid var(--line);min-width:0}
.tlbar .legend{margin:0}
.tlnote{color:var(--dim);font-size:11.5px;min-width:0}
.tlnote.warn{color:var(--http)}
/* Axis and lanes share one grid, and both reserve the scrollbar's width, so
   a tick sits exactly above the moment it labels. */
.tlaxis,.tlscroll{display:grid;grid-template-columns:var(--tl-lw,290px) minmax(0,1fr);
  scrollbar-gutter:stable;overflow-x:hidden}
.tlaxis{flex:0 0 auto;overflow-y:hidden;border-bottom:1px solid var(--line);height:22px}
.tlscroll{flex:1 1 auto;overflow-y:auto;min-height:0;align-content:start}
#tlAxis,#tlCanvas{display:block;width:100%}
#tlAxis{height:22px}
#tlLabels{min-width:0}
.ln{display:flex;align-items:center;gap:6px;width:100%;height:26px;padding:0 8px 0 14px;
  border:0;border-bottom:1px solid var(--line);border-radius:0;background:none;
  color:var(--fg);font:12px var(--mono);text-align:left;cursor:pointer;min-width:0}
.ln:hover,.ln:focus-visible{background:var(--panel2);color:var(--fg);outline:none}
.ln .nm{flex:0 0 auto;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ln.sys .nm{color:var(--dim)}
.ln .tot{flex:0 0 auto;margin-left:auto;padding-left:4px;color:var(--faint);font-size:10.5px}
/* The box gives way before the name does: which program it is matters more
   than which host it checks in with, and the box's title has it in full. */
.ln .rg{flex:0 3 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font:700 9.5px var(--sans);color:var(--accent);
  border:1px solid var(--accent);border-radius:3px;padding:0 4px;letter-spacing:.2px}
.ln .rg:hover{background:var(--accent);color:#fff}
/* "(broadcast)", "(no socket)" and the like run on timers by nature, and the
   check-in alert skips them; the box is still true, just not news. */
.ln.sys .rg{opacity:.55}
#tlEmpty{grid-column:1 / -1}

/* ---------- footer stats ---------- */
footer{
  flex:0 0 auto;display:flex;align-items:center;gap:18px;padding:7px 14px;
  background:var(--panel);border-top:1px solid var(--line);font-size:12px;color:var(--dim);
  flex-wrap:wrap;
}
footer b{color:var(--fg);font-family:var(--mono);font-weight:600}
.kv{display:flex;align-items:center;gap:6px;white-space:nowrap}
#spark{flex:0 0 auto;border:1px solid var(--line);border-radius:4px;background:var(--bg)}

/* Every counter in here is rewritten once a second, and a value that changes
   width shoves everything after it along. Moving the chart to the front stops
   it being shoved; these stop the shoving. Tabular figures fix the digits —
   proportional fonts give "1" less room than "8" — and a min-width sized in
   `ch` against the monospace face reserves room for the longest value each
   counter can reach, so growing from "9 B/s" to "1.2 MB/s" costs no layout. */
footer b{font-variant-numeric:tabular-nums;display:inline-block}
#sPk{min-width:10ch}                 /* 9,999,999 */
#sIn,#sOut{min-width:9ch}            /* 999.9 KB  */
#sRate{min-width:11ch}               /* 999.9 KB/s */
#sAttr{min-width:5ch}                /* 100%      */
#sDrop{min-width:7ch;color:var(--out)}

/* ---------- side panel ---------- */
.tabs{display:flex;flex-wrap:wrap;gap:1px;padding:8px 8px 0;
  border-bottom:1px solid var(--line);min-width:0}
/* The strip must take the same number of lines with or without badges, or
   the first badge (clicking a packet) wraps a tab and every pane jumps down a
   row. With badges capped in width (tabCount(), frameBadge()) that holds at
   every panel width, but from opposite sides:
   - 600px panel, one line: the widest badges must still fit its 583px. At
     5px sides they need 557; at the old 10px, even the first badge wrapped.
   - 430 and 360px panels, two lines: the bare strip must NOT fit on one. At
     5px it measures 413 — exactly the 430 panel's room — so it takes 8px
     there, 461. Either margin is kept at 16px+ so a Windows 10 font (plain
     Segoe UI) or another browser's metrics can't tip it; tabs_test checks. */
.tab{padding:6px 8px;border-radius:6px 6px 0 0;color:var(--dim);cursor:pointer;
  font:600 12px var(--sans);border:1px solid transparent;border-bottom:none;
  white-space:nowrap;display:flex;align-items:center;gap:4px}
@media(min-width:1750px){.tab{padding:6px 5px}}
.tab.on{background:var(--panel2);color:var(--fg);border-color:var(--line)}
.tab .n{font:700 10px var(--mono);background:var(--accent);color:#fff;
  border-radius:8px;padding:1px 5px;min-width:16px;text-align:center}
.tab .n:empty,.tab .n.zero{display:none}
.pane{flex:1 1 auto;overflow:auto;padding:12px;display:none;min-height:0}
.pane.on{display:block}
.empty{color:var(--faint);text-align:center;padding:40px 12px;font-size:12px}
h4{margin:0 0 8px;font:600 11px var(--sans);letter-spacing:.5px;text-transform:uppercase;color:var(--dim)}
.sec{margin-bottom:16px}
.sechead{display:flex;justify-content:space-between;align-items:baseline;
  gap:10px;margin-bottom:8px}
.sechead h4{margin:0}
.row{display:flex;justify-content:space-between;gap:10px;padding:3px 0;
  font-family:var(--mono);font-size:11.5px;border-bottom:1px solid var(--line)}
.row span:first-child{color:var(--dim);flex:0 0 auto}
.row span:last-child{text-align:right;word-break:break-all}
.hex{font-family:var(--mono);font-size:11.5px;line-height:1.6;white-space:pre;
  background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto}
.hex .off{color:var(--faint)}
.hex .as{color:var(--dns)}
.bar{height:4px;border-radius:2px;background:var(--panel2);overflow:hidden;margin-top:3px}
.bar i{display:block;height:100%;background:var(--accent)}
/* ---------- connections ---------- */
.cfilter{display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap}
.chint{color:var(--dim);font-size:11px;margin:2px 0 10px}

/* Two lines per connection, like Files and Streams. No column widths: the
   identity takes the full panel on line one, the numbers read as a sentence
   underneath. A seven-column table needed ~530px in a 429px panel, which is
   why every earlier revision of this view was shaving percentages. */
.citem{padding:5px 8px;border:1px solid var(--line);border-radius:6px;
  margin-bottom:4px;background:var(--panel2);cursor:pointer}
.citem:hover{border-color:var(--accent)}
.citem.dim{opacity:.62}
.citem .l1{display:flex;align-items:baseline;gap:6px;min-width:0}
.citem .who{font:600 12px/1.35 var(--mono);color:var(--fg);flex:0 1 auto;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:45%}
.citem .ar{color:var(--faint);flex:0 0 auto;font-size:11px}
.citem .peer{font:12px/1.35 var(--mono);color:var(--accent);flex:1 1 auto;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* 44, not 52: at 52 a long hostname on the identity line was clipped by a
   couple of pixels, and the identity is what the row is for. The mark scales
   to whatever it is given. */
.citem .spw{flex:0 0 44px;width:44px;line-height:0;align-self:center}
.citem .l2{color:var(--dim);font:11px/1.35 var(--mono);margin-top:2px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.citem .l2 b{color:var(--fg);font-weight:600}
.citem .l2 b.warn{color:var(--out)}
.citem .l2 .sx{color:var(--faint)}
.citem .l2 .dn{color:var(--in)}
.citem .l2 .up{color:var(--out)}

/* The activity mark. One ink, no axis, no labels — it is a mark, not a chart. */
.spk{display:block;width:100%;height:14px}
.spk-fill{fill:var(--dim)}
.spk-base{fill:var(--line)}

.tlist{font-family:var(--mono);font-size:11.5px}
.tlist .t{padding:5px 0;border-bottom:1px solid var(--line)}
.tlist .t .top{display:flex;justify-content:space-between;gap:8px}
.tlist .t .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tlist .t .by{color:var(--dim);flex:0 0 auto}
.io{font-size:10.5px;color:var(--faint);margin-top:2px}
.io .u{color:var(--out)}
.io .d{color:var(--in)}
.err{background:#f8514915;border:1px solid #f8514955;color:#f85149;
  padding:8px 10px;border-radius:6px;font-size:12px;margin:10px 14px}
code.k{color:var(--accent);font-family:var(--mono)}

/* ---------- streams + files lists ---------- */
.item{padding:7px 8px;border:1px solid var(--line);border-radius:6px;margin-bottom:6px;
  cursor:pointer;background:var(--panel2)}
.item:hover{border-color:var(--accent)}
.item .l1{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
.item .nm{font:600 12px var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.item .sz{color:var(--dim);font:11px var(--mono);flex:0 0 auto}
.item .l2{color:var(--faint);font:11px var(--mono);margin-top:3px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tagx{display:inline-block;font:700 9.5px var(--sans);padding:1px 5px;border-radius:3px;
  letter-spacing:.3px;margin-right:5px;border:1px solid transparent}
.tagx.dl{color:var(--in);background:#3fb9501a;border-color:#3fb95033}
.tagx.up{color:var(--out);background:#f0883e1a;border-color:#f0883e33}
.btn-sm{padding:3px 9px;font:600 11px var(--sans);border-radius:5px;
  background:var(--panel);border:1px solid var(--line);color:var(--fg);cursor:pointer}
/* Not on the active button: `button.on` paints the background accent, and an
   accent foreground on top of it is an invisible label. Hovering the selected
   filter made it look like an empty blue box. */
.btn-sm:not(.on):hover{border-color:var(--accent);color:var(--accent)}
.rowbtns{display:flex;gap:6px;margin-top:6px;flex-wrap:wrap}
/* Muted subjects and the why-it-fired disclosure. */
.mute{display:flex;align-items:center;gap:8px;padding:5px 0;
  border-bottom:1px solid var(--line);font:11.5px var(--mono)}
.mute .s{flex:1 1 auto;min-width:90px;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
/* The subject is the point of the row; the rule name yields space to it
   rather than the other way round, which crushed a host down to "2.". */
.mute .r{color:var(--dim);flex:0 1 auto;min-width:0;font-size:11px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.why{margin-top:5px;color:var(--dim);font-size:11px}
.why summary{cursor:pointer;color:var(--accent);width:max-content}
.why[open]{padding-bottom:3px}

/* ---------- stream viewer overlay ---------- */
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:50;
  display:none;align-items:center;justify-content:center;padding:24px}
#overlay.on{display:flex}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  width:min(1180px,94vw);height:min(860px,90vh);display:flex;flex-direction:column;
  box-shadow:0 24px 60px rgba(0,0,0,.45);overflow:hidden}
.modal header{background:var(--panel2);flex-wrap:wrap}
.modal .body{flex:1 1 auto;overflow:auto;padding:14px;background:var(--bg)}
.convo{font-family:var(--mono);font-size:12px;line-height:1.55;white-space:pre-wrap;
  word-break:break-word;margin:0}
.blk{padding:8px 10px;border-radius:6px;margin-bottom:8px;border-left:3px solid;
  font-family:var(--mono);font-size:12px;line-height:1.55;
  white-space:pre-wrap;word-break:break-word}
.blk.c{border-color:var(--accent);background:#4da3ff0d}
.blk.s{border-color:var(--in);background:#3fb9500d}
.blk .who{font:700 10px var(--sans);letter-spacing:.4px;margin-bottom:5px;opacity:.85}
.blk.c .who{color:var(--accent)}
.blk.s .who{color:var(--in)}
.np{color:var(--faint)}
.modal .meta{color:var(--dim);font:12px var(--mono)}
.warnbar{background:#e3b34115;border:1px solid #e3b34155;color:var(--http);
  padding:6px 10px;border-radius:6px;font-size:12px;margin-bottom:10px}
.previewimg{max-width:100%;border:1px solid var(--line);border-radius:6px;background:#fff}

/* ---------- filter bar ---------- */
#filterbar{display:flex;align-items:center;gap:8px;padding:6px 14px;flex:0 0 auto;
  flex-wrap:wrap;min-width:0;
  background:var(--panel2);border-bottom:1px solid var(--line)}
#filterbar .flabel{color:var(--faint);font:600 10px var(--sans);letter-spacing:.6px;
  text-transform:uppercase}
#find{flex:1 1 auto;min-width:0;font-family:var(--mono);font-size:12px;
  background:var(--bg);border:1px solid var(--line);color:var(--fg);
  border-radius:6px;padding:5px 9px;outline:none}
#find:focus{border-color:var(--accent)}
#find.bad{border-color:#f85149;color:#f85149}
.fcount{color:var(--dim);font:11px var(--mono);white-space:nowrap;min-width:96px;text-align:right}
#fhelpbox{padding:9px 14px;background:var(--panel);border-bottom:1px solid var(--line);
  color:var(--dim);font-size:11.5px;line-height:1.8;flex:0 0 auto}
#fhelpbox b{color:var(--fg);font-size:10.5px;text-transform:uppercase;letter-spacing:.4px;
  margin-right:3px}
#fhelpbox code.k{background:var(--panel2);padding:1px 5px;border-radius:3px;
  border:1px solid var(--line)}

/* ---------- alerts ---------- */
.alert{border:1px solid var(--line);border-left-width:3px;border-radius:6px;
  padding:7px 9px;margin-bottom:6px;background:var(--panel2)}
.alert.high{border-left-color:#f85149;background:#f8514910}
.alert.warn{border-left-color:var(--http);background:#e3b34110}
.alert.info{border-left-color:var(--accent);background:#4da3ff10}
.alert .t{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
.alert .ti{font:600 12px var(--sans)}
.alert.high .ti{color:#f85149}
.alert.warn .ti{color:var(--http)}
.alert.info .ti{color:var(--accent)}
.alert .when{color:var(--faint);font:10.5px var(--mono);flex:0 0 auto}
.alert .d{color:var(--dim);font:11.5px var(--mono);margin-top:3px;line-height:1.5}
.alert .rl{color:var(--faint);font:10px var(--mono);margin-top:3px}
.rulegrid{display:grid;grid-template-columns:1fr;gap:4px;margin-bottom:6px}
.rulegrid label{display:flex;align-items:center;gap:7px;color:var(--dim);
  font-size:11.5px;cursor:pointer}
.rulegrid input[type=number]{width:70px;background:var(--bg);border:1px solid var(--line);
  color:var(--fg);border-radius:4px;padding:2px 5px;font:11px var(--mono)}
.tab .n.high{background:#f85149}

/* ---------- history / charts ----------
   Chart hues are the validated categorical slots 1 and 2, not the green/orange
   used for in/out elsewhere in the app: green vs orange fails deuteranope
   separation on the dark surface (ΔE 5.7, below the floor), while blue vs
   orange clears it comfortably in both modes (ΔE 26.8 dark / 24.7 light).
   Direction is still carried by the ▼/▲ glyphs in the legend and table, so
   identity never rests on colour alone. */
.viz{
  --series-in:  #2a78d6;
  --series-out: #eb6834;
  --grid: #d8dee4;
}
:root:not([data-theme="light"]) .viz{ --series-in:#3987e5; --series-out:#d95926;
  --grid:#242c37; }
:root[data-theme="dark"] .viz{ --series-in:#3987e5; --series-out:#d95926;
  --grid:#242c37; }
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]) .viz{ --series-in:#3987e5; --series-out:#d95926;
    --grid:#242c37; }
}

.kpirow{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));
  gap:8px;margin-bottom:14px}
.kpi{background:var(--panel2);border:1px solid var(--line);border-radius:7px;
  padding:8px 10px}
.kpi .k{color:var(--dim);font:600 9.5px var(--sans);letter-spacing:.5px;
  text-transform:uppercase}
.kpi .v{font:600 17px/1.25 var(--mono);color:var(--fg);margin-top:3px}
.kpi .s{color:var(--faint);font:10.5px var(--mono);margin-top:1px}

.legend{display:flex;gap:14px;align-items:center;margin:2px 0 8px;
  color:var(--dim);font-size:11.5px}
.legend i{display:inline-block;width:11px;height:11px;border-radius:2px;
  margin-right:5px;vertical-align:-1px}
.chartwrap{position:relative;margin-bottom:6px}
.chartwrap svg{display:block;width:100%;overflow:visible}
.axlbl{fill:var(--faint);font:10px var(--mono)}
.gridline{stroke:var(--grid);stroke-width:1;shape-rendering:crispEdges}
.hitrect{fill:transparent;cursor:pointer}
.hitrect:hover ~ .colgroup rect, .colgroup.hot rect{filter:brightness(1.18)}
.tip{position:absolute;pointer-events:none;z-index:20;background:var(--panel);
  border:1px solid var(--line);border-radius:6px;padding:7px 9px;
  box-shadow:0 6px 18px rgba(0,0,0,.32);font:11.5px var(--mono);
  white-space:nowrap;opacity:0;transition:opacity .08s}
.tip.on{opacity:1}
/* Busy-hours heatmap. Empty hours are drawn, faintly, so "nothing" reads as
   a measured nothing rather than a gap in the chart. */
.hm-empty{fill:var(--grid)}
.hm-cell{fill:var(--series-in)}
.hm-hit{fill:transparent;cursor:crosshair}
/* Outlined while hovered, or focused from the keyboard. Not after a click:
   a square that stays outlined reads as selected, and nothing is. */
.hm-hit:hover,.hm-hit:focus-visible{stroke:var(--fg);stroke-width:1}
.hm-hit:focus{outline:none}
.hmkey{display:flex;align-items:center;gap:3px;color:var(--faint);font:10.5px var(--mono);
  margin:2px 0 8px}
.hmkey i{display:inline-block;width:12px;height:10px;border-radius:2px;background:var(--series-in)}

/* Transient confirmation. Downloads used to happen in complete silence — the
   anchor is clicked, the browser takes over, and nothing in the page changes.
   With the download shelf hidden there is no evidence the click registered, so
   the natural response is to click again and end up with two identical files.
   This cannot live in the status text, which every poll overwrites. */
#flash{
  /* Clear of the footer, which is two lines tall once the protocol badges
     wrap — a confirmation sitting on top of the counters reads as damage. */
  position:fixed;left:50%;bottom:92px;z-index:60;
  transform:translateX(-50%) translateY(6px);
  background:var(--panel);border:1px solid var(--line);border-radius:6px;
  padding:8px 12px;font:12px var(--mono);color:var(--fg);
  box-shadow:0 8px 22px rgba(0,0,0,.35);
  opacity:0;pointer-events:none;transition:opacity .14s,transform .14s;
}
#flash.on{opacity:1;transform:translateX(-50%) translateY(0)}
.tip .th{color:var(--fg);font-weight:600;margin-bottom:4px}
.tip .tr{display:flex;justify-content:space-between;gap:14px;color:var(--dim)}
.tip .tr b{color:var(--fg);font-weight:600}
.tip .sw{display:inline-block;width:10px;height:2px;vertical-align:3px;
  margin-right:5px}
.hbar{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;
  padding:3px 0;font:11.5px var(--mono)}
.hbar .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--fg)}
.hbar .track{grid-column:1/-1;height:9px;background:var(--panel2);border-radius:2px;
  overflow:hidden;display:flex;gap:2px;position:relative}
.hbar .track i{display:block;height:100%}
.hbar .track i:first-of-type{border-radius:2px 0 0 2px}
.hbar .track i:last-of-type{border-radius:0 2px 2px 0}
/* The cut in a bar that was shortened: the track's own colour, slanted, so
   it reads as a gap in the bar rather than a mark on it. */
.hbar .track b{position:absolute;top:-1px;bottom:-1px;left:86%;width:7px;
  background:var(--panel2);transform:skewX(-25deg)}
.dayrange{display:flex;gap:6px;align-items:center;margin-bottom:10px}
.dayrange button{padding:3px 10px;font:600 11px var(--sans)}
.dayrange button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.dayrange a{color:var(--faint);font:11px var(--mono)}
.exrow{align-items:center}
.exrow span:first-child{flex:1 1 auto;color:var(--fg);word-break:break-all}
.exrow .kind{color:var(--faint);font:10.5px var(--sans);margin-left:8px}
.exadd{display:flex;gap:6px;margin-top:8px}
.exadd input{flex:1 1 auto}
table.tv{width:100%;border-collapse:collapse;font:11px var(--mono);margin-top:6px}
table.tv th{text-align:left;color:var(--dim);font:600 9.5px var(--sans);
  letter-spacing:.4px;text-transform:uppercase;padding:4px 6px;
  border-bottom:1px solid var(--line)}
table.tv td{padding:3px 6px;border-bottom:1px solid var(--line)}
table.tv td.n{text-align:right}
details.tvw{margin-top:8px}
details.tvw summary{cursor:pointer;color:var(--dim);font-size:11.5px;
  padding:4px 0;user-select:none}
details.tvw summary:hover{color:var(--accent)}
</style>
</head>
<body>

<header>
  <div class="brand">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
      <path d="M3 12h4l3-8 4 16 3-8h4" stroke="#4da3ff"/>
    </svg>
    NetScope
  </div>
  <span class="badge" id="ver">v-</span>
  <span class="badge demo" id="demoBadge" style="display:none">DEMO</span>

  <div class="status"><span class="dot" id="dot"></span><span id="statusText">starting…</span></div>

  <div class="spacer"></div>

  <select id="iface" title="Capture interface"></select>
  <input type="text" id="bpf" placeholder="BPF filter — e.g. tcp port 443" size="26"
         title="Capture filter applied at the driver, Wireshark syntax">
  <button id="apply">Apply</button>
  <button id="toggle">Stop</button>
  <button id="clear" class="danger">Clear</button>
  <button id="pause" title="Stop adding new rows to the table. The capture keeps
running and the buffer keeps filling — use Search buffer to see what arrived
while you were paused. Shortcut: space.">Pause</button>
  <label class="chk" title="Keep the newest row in view. Turn it off to read
back through the table while the capture continues."><input type="checkbox"
    id="follow" checked> follow</label>
  <button id="savePcap" title="Save the buffered packets as a .pcap Wireshark can open">Save ↓</button>
  <button id="openPcap" title="Load a .pcap or .pcapng for offline analysis">Open ↑</button>
  <input type="file" id="pcapFile" accept=".pcap,.pcapng,.cap" style="display:none">
  <button id="theme" title="Toggle theme">◐</button>
</header>

<div id="filterbar">
  <span class="viewsw" role="group" aria-label="View">
    <button id="vTable" class="btn-sm on" aria-pressed="true">Table</button>
    <button id="vTime" class="btn-sm" aria-pressed="false"
            title="One lane per program or host against time: what runs when, and what checks in on a schedule">Timeline</button>
  </span>
  <span class="flabel">filter</span>
  <input type="text" id="find" spellcheck="false"
         placeholder="proto == QUIC &amp;&amp; process ~ chrome   —   or just type text to search">
  <button id="findClear" class="btn-sm" title="Clear filter" style="display:none">✕</button>
  <span id="fcount" class="fcount"></span>
  <button id="searchAll" class="btn-sm" style="display:none"
          title="Filter every packet still in the capture buffer, not just the rows loaded here">Search buffer</button>
  <button id="backLive" class="btn-sm" style="display:none">← Live</button>
  <select id="presets" title="Saved filters"><option value="">presets…</option></select>
  <button id="savePreset" class="btn-sm">Save</button>
  <button id="delPreset" class="btn-sm danger">Del</button>
  <button id="colsBtn" class="btn-sm" title="Choose which columns to show">Columns</button>
  <button id="resetCols" class="btn-sm" style="display:none"
          title="Put the packet-table columns back to their default widths">Reset columns</button>
  <button id="fhelp" class="btn-sm" title="Filter syntax">?</button>
</div>
<style id="colhide"></style>
<div class="colmenu" id="colmenu"></div>
<div class="rowmenu" id="rowmenu" role="menu"></div>
<div id="fhelpbox" style="display:none">
  <b>Fields</b> proto · process · src · dst · ip · host · port · sport · dport ·
  bytes · info · dir · pid · iface · stream · seq
  &nbsp;&nbsp;<b>Operators</b> <code class="k">==</code> <code class="k">!=</code>
  <code class="k">~</code> (contains) <code class="k">!~</code>
  <code class="k">&gt; &gt;= &lt; &lt;=</code>
  &nbsp;&nbsp;<b>Logic</b> <code class="k">&amp;&amp;</code> <code class="k">||</code>
  <code class="k">!</code> and parentheses
  <br>
  <b>Examples</b>
  <code class="k">proto == QUIC</code> ·
  <code class="k">process ~ chrome &amp;&amp; bytes &gt; 1000</code> ·
  <code class="k">!(proto == TLS || proto == QUIC)</code> ·
  <code class="k">port == 445</code> ·
  <code class="k">host ~ wpengine</code> ·
  <code class="k">dir == out &amp;&amp; info ~ POST</code>
  <br>
  Text with no operator is a plain substring search across every column.
</div>

<div id="errBox" class="err" style="display:none"></div>

<main>
  <div id="left">
    <div class="tablewrap" id="tw">
      <table id="ptable">
        <colgroup id="cg">
          <col><col><col><col><col><col><col><col><col><col>
        </colgroup>
        <thead><tr id="hrow">
          <th>#<i class="rz" data-c="0"></i></th>
          <th>Time<i class="rz" data-c="1"></i></th>
          <th class="ifcol">Iface<i class="rz" data-c="2"></i></th>
          <th>Process<i class="rz" data-c="3"></i></th>
          <th><i class="rz" data-c="4"></i></th>
          <th>Source<i class="rz" data-c="5"></i></th>
          <th>Destination<i class="rz" data-c="6"></i></th>
          <th>Proto<i class="rz" data-c="7"></i></th>
          <th>Bytes<i class="rz" data-c="8"></i></th>
          <th>Info</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
      <div class="empty" id="emptyMsg">Waiting for packets…</div>
    </div>
    <div id="tlview" class="viz" style="display:none">
      <div class="tlbar">
        <span class="viewsw" id="tlWin" role="group" aria-label="Time window">
          <button class="btn-sm" data-w="60">1 min</button><button class="btn-sm" data-w="300">5 min</button><button class="btn-sm" data-w="900">15 min</button><button class="btn-sm" data-w="3600">1 hour</button>
        </span>
        <span class="viewsw" id="tlGroup" role="group" aria-label="One lane per">
          <button class="btn-sm" data-g="process">Programs</button><button class="btn-sm" data-g="host">Hosts</button>
        </span>
        <span class="tlnote" id="tlNote"></span>
        <span class="spacer"></span>
        <div class="legend"><span><i style="background:var(--series-out)"></i>▲ sent</span><span><i style="background:var(--series-in)"></i>▼ received</span></div>
      </div>
      <div class="tlaxis"><span></span><canvas id="tlAxis" height="22"></canvas></div>
      <div class="tlscroll" id="tlScroll">
        <div id="tlLabels"></div><canvas id="tlCanvas"></canvas>
        <div class="empty" id="tlEmpty" style="display:none"></div>
      </div>
      <div class="tip" id="tlTip"></div>
    </div>
    <footer>
      <!-- The chart goes first so nothing upstream of it can move it. It used
           to sit after the counters, and every poll that changed the width of
           "rate" or "named" slid it sideways. -->
      <canvas id="spark" width="240" height="26"></canvas>
      <div class="kv" id="kvPk" title="Packets NetScope has decoded."><span>packets</span><b id="sPk">0</b></div>
      <div class="kv"><span style="color:var(--in)">▼ in</span><b id="sIn">0 B</b></div>
      <div class="kv"><span style="color:var(--out)">▲ out</span><b id="sOut">0 B</b></div>
      <div class="kv"><span>rate</span><b id="sRate">0 B/s</b></div>
      <div class="kv" title="Share of packets tied to a specific program. The rest are kernel, link-layer or broadcast traffic that has no owning process."><span>named</span><b id="sAttr">—</b></div>
      <div class="kv" id="kvDrop" style="display:none" title="Packets the capture driver received but had to discard because nothing drained its buffer fast enough. Every other number on this page undercounts by roughly this much."><span>dropped</span><b id="sDrop">0</b></div>
      <div class="spacer"></div>
      <div class="kv" id="sProto"></div>
    </footer>
  </div>

  <div id="side">
    <div class="tabs">
      <div class="tab" data-p="detail">Packet <span class="n zero" id="nPkt"></span></div>
      <div class="tab on" data-p="history">History</div>
      <div class="tab" data-p="alerts">Alerts <span class="n zero" id="nAlerts"></span></div>
      <div class="tab" data-p="files">Files <span class="n zero" id="nFiles"></span></div>
      <div class="tab" data-p="conns" title="What is open right now, per program">Connections</div>
      <div class="tab" data-p="streams">Streams</div>
      <div class="tab" data-p="dhcp">DHCP <span class="n zero" id="nDhcp"></span></div>
      <div class="tab" data-p="talkers">Talkers</div>
    </div>
    <div class="pane" id="p-detail"><div class="empty">Click a packet to inspect it.</div></div>
    <div class="pane viz on" id="p-history"><div class="empty">Loading history…</div></div>
    <div class="pane" id="p-alerts"><div class="empty">No alerts.</div></div>
    <div class="pane" id="p-files"><div class="empty">No files rebuilt yet.</div></div>
    <div class="pane" id="p-conns"><div class="empty">Loading connections…</div></div>
    <div class="pane" id="p-streams"><div class="empty">No TCP connections yet.</div></div>
    <div class="pane" id="p-dhcp"><div class="empty">No DHCP leases seen yet.</div></div>
    <div class="pane" id="p-talkers"><div class="empty">No traffic yet.</div></div>
  </div>
</main>

<div id="overlay">
  <div class="modal">
    <header>
      <div class="brand" style="font-size:13px">Follow stream <span id="mId"></span></div>
      <div class="meta" id="mMeta"></div>
      <div class="spacer"></div>
      <button id="mText" class="on">Text</button>
      <button id="mStr" title="Readable strings, including UTF-16 (Windows protocols)">Strings</button>
      <button id="mHex">Hex</button>
      <button id="mClose" class="danger">Close</button>
    </header>
    <div class="body" id="mBody"></div>
  </div>
</div>

<div id="flash" role="status" aria-live="polite"></div>

<div id="fitwrap" aria-hidden="true">
  <table id="fitmeter"><thead><tr id="fithead"></tr></thead>
  <tbody id="fitbody"></tbody></table>
</div>

<script>
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const MAX_ROWS = 2500;
let lastSeq = 0, selected = null, paused = false, lastStats = null, lastStatus = null;
let prevTotals = null, prevTime = 0;

const $ = id => document.getElementById(id);
const api = (p, o) => fetch(p + (p.includes('?') ? '&' : '?') + 't=' + encodeURIComponent(TOKEN), o);

function hb(n){
  const u=['B','KB','MB','GB','TB']; let i=0; n=Number(n)||0;
  while(Math.abs(n)>=1024 && i<u.length-1){n/=1024;i++;}
  return (i===0? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
}
const esc = s => String(s==null?'':s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

/* ---------------- packet table ---------------- */

/* ================= resizable columns =================
   Fixed table layout means a column that is too narrow clips its text rather
   than widening the table. That is the right default — it keeps Info on
   screen — but only if you can then size the columns yourself. Drag a border
   to resize, double-click one to fit the column to its content, and the
   widths are remembered. Widen past the window and the table scrolls. */

const NCOLS = 10;
// Two of these floors are set by chrome, not by text. Proto holds a badge with
// its own min-width, padding and border, and the cell adds 8px each side —
// under ~74 the squeeze in applyCols() clipped the chip itself, which reads as
// broken in a way ellipsised text does not. Direction holds a single arrow
// whose 16px of side padding left the glyph no room at 22.
const COL_MIN = [34, 56, 60, 60, 26, 70, 70, 74, 44, 90];
// Time's default was 88px for a 12-character hh:mm:ss.mmm stamp that needs
// ~103 — the timestamp shipped ellipsised until you resized the column.
const COL_DEF = [52, 108, 96, 130, 30, 150, 190, 74, 62, 0];  // 0 = take the rest
const IFACE_COL = 2;
const INFO_COL = 9;
let colW = null, colCustom = false;

function loadCols(){
  try {
    const s = JSON.parse(localStorage.getItem('netscope-cols') || 'null');
    if (s && Array.isArray(s.w) && s.w.length === NCOLS){ colW = s.w; colCustom = !!s.custom; }
  } catch(e){}
  if (!colW) colW = COL_DEF.slice();
}
function saveCols(){
  try { localStorage.setItem('netscope-cols',
        JSON.stringify({w: colW, custom: colCustom})); } catch(e){}
}

/* The Interface column only earns its space when more than one adapter is
   being captured — with a single interface every row would say the same
   thing. */
/* Which columns you have chosen to hide. Every width calculation has to
   agree about ignoring them — when only maxWidthFor() forgot, the clamp came
   out a column too tight and the first pixel of a drag snapped backwards. */
const COL_NAMES = ['#','Time','Iface','Process','Direction','Source',
                   'Destination','Proto','Bytes','Info'];
let hiddenCols = new Set();

function colHidden(i){ return hiddenCols.has(i); }

function applyColVis(){
  const rules = [...hiddenCols].map(i => {
    const n = i + 1;
    return '#ptable tr > :nth-child('+n+'){padding-left:0;padding-right:0;' +
           'border-left:0;border-right:0;overflow:hidden;white-space:nowrap}' +
           '#ptable tr > :nth-child('+n+') .rz{display:none}';
  }).join('\n');
  $('colhide').textContent = rules;
  applyCols();
}

function saveColVis(){
  try { localStorage.setItem('netscope-colhide',
        JSON.stringify([...hiddenCols])); } catch(e){}
}
function loadColVis(){
  try {
    const v = JSON.parse(localStorage.getItem('netscope-colhide') || '[]');
    if (Array.isArray(v)) hiddenCols = new Set(v.filter(i => i !== INFO_COL));
  } catch(e){}
}

function buildColMenu(){
  const m = $('colmenu');
  m.innerHTML = COL_NAMES.map((n,i) => i === INFO_COL ? '' :
    '<label><input type="checkbox" data-col="'+i+'"'+
    (hiddenCols.has(i) ? '' : ' checked')+'> '+esc(n)+'</label>').join('') +
    '<div class="hint">Info always stays — it takes the leftover width.</div>';
  m.querySelectorAll('[data-col]').forEach(cb => cb.onchange = () => {
    const i = Number(cb.dataset.col);
    if (cb.checked) hiddenCols.delete(i); else hiddenCols.add(i);
    applyColVis(); saveColVis();
  });
}

function applyCols(){
  const cg = $('cg'), tw = $('tw');
  if (!cg) return;
  const cols = cg.children;
  const avail = tw.clientWidth || 900;
  const w = colW.slice();

  const skip = i => i === INFO_COL || colHidden(i);

  let others = 0, minOthers = 0;
  for (let i=0;i<NCOLS;i++) if (!skip(i)){ others += w[i]; minOthers += COL_MIN[i]; }

  // Whatever the widths are — defaults or yours — squeeze them proportionally
  // if they would not fit. Applied to the local copy only, so shrinking the
  // window never destroys the widths you chose; widen it again and they come
  // straight back.
  const target = avail - COL_MIN[INFO_COL] - 2;
  if (others > target && others > minOthers){
    const scale = Math.max(0, target - minOthers) / (others - minOthers);
    others = 0;
    for (let i=0;i<NCOLS;i++) if (!skip(i)){
      w[i] = Math.max(COL_MIN[i], Math.round(COL_MIN[i] + (w[i]-COL_MIN[i]) * scale));
      others += w[i];
    }
  }

  // Info always absorbs the remainder, so the table fits the window and never
  // scrolls sideways. Horizontal scroll is what hid the Info column in the
  // first place; there is no case that needs it, because widening any column
  // simply takes room from Info and the drag is clamped before Info runs out.
  w[INFO_COL] = Math.max(COL_MIN[INFO_COL], avail - others - 2);

  for (let i=0;i<NCOLS;i++){
    if (colHidden(i)){ cols[i].style.width = '0px'; continue; }
    cols[i].style.width = Math.max(COL_MIN[i], w[i] || COL_MIN[i]) + 'px';
  }
  // Always 100%, never a pixel width. A pixel width is a measurement taken at
  // one moment, and the container's usable width changes on its own — most
  // obviously when the vertical scrollbar appears as rows fill. That is how a
  // horizontal scrollbar came back after a refresh but vanished after a
  // resize. With table-layout:fixed the browser scales the columns down if
  // they ask for more than 100%, so the cells always fit.
  $('ptable').style.width = '100%';
  $('resetCols').style.display = colCustom ? '' : 'none';
}

/* Double-click auto-fit: measure by rendering, not by guessing.
   The old version measured the cell's text with a canvas in one font, then
   added a flat 20px for the padding. That is wrong wherever a cell is not
   plain text in that font — the Proto cell holds a badge with its own 10px
   sans face, letter-spacing, 6px padding and a 1px border, so the estimate
   came out short and the column still truncated after a double-click.
   Instead the sampled cells are cloned into a hidden one-column table with
   table-layout:auto and no clipping, and the browser reports the width that
   shows every one of them, chrome and padding included. */
function autoFit(idx){
  freezeCols();
  const head = $('fithead'), body = $('fitbody');
  head.textContent = ''; body.textContent = '';

  const th = $('hrow').children[idx].cloneNode(true);
  th.querySelectorAll('.rz').forEach(n => n.remove());
  head.appendChild(th);

  const rows = $('rows').children;
  const step = Math.max(1, Math.ceil(rows.length / 300));    // sample big tables
  const frag = document.createDocumentFragment();
  for (let i=0;i<rows.length;i+=step){
    const cell = rows[i].children[idx];
    if (!cell) continue;
    if ((cell.textContent || '').length > 200) continue;     // outlier Info text
    const tr = document.createElement('tr');
    tr.appendChild(cell.cloneNode(true));
    frag.appendChild(tr);
  }
  body.appendChild(frag);

  // +3 covers sub-pixel rounding; the header label may sit under the grab
  // area, which is transparent, so the handle costs no width of its own.
  const px = Math.ceil($('fitmeter').getBoundingClientRect().width) + 3;
  head.textContent = ''; body.textContent = '';

  colW[idx] = Math.min(maxWidthFor(idx), Math.max(COL_MIN[idx], px));
  colCustom = true;
  applyCols(); saveCols();
}

/* Read the widths actually on screen. `colW` may still hold the un-fitted
   defaults (Info is stored as 0, meaning "take the rest"), so switching to
   custom mode without snapshotting first made every column jump the instant
   a drag began. Measured from the <th>s, not the <col>s — a <col> has no box
   in some browsers. */
function freezeCols(){
  const ths = $('hrow').children;
  for (let i=0;i<NCOLS;i++){
    if (colHidden(i)) continue;          // keep its remembered width for later
    const px = Math.round(ths[i].getBoundingClientRect().width);
    if (px > 0) colW[i] = px;
  }
}

let rzDrag = null, rzPending = false;
document.addEventListener('pointerdown', e => {
  const h = e.target.closest ? e.target.closest('.rz') : null;
  if (!h) return;
  const idx = Number(h.dataset.c);
  freezeCols();
  rzDrag = {idx, x: e.clientX, start: colW[idx]};
  h.classList.add('on');
  try { h.setPointerCapture(e.pointerId); } catch (err) {}
  document.body.classList.add('rzing');
  e.preventDefault();
});
/* How wide this column may get before Info would drop below its minimum.
   Clamping here is what keeps the table inside the window: the border stops
   instead of a scrollbar appearing. */
function maxWidthFor(idx){
  const avail = $('tw').clientWidth || 900;
  let otherFixed = 0;
  for (let i=0;i<NCOLS;i++)
    if (i !== idx && i !== INFO_COL && !colHidden(i)) otherFixed += colW[i];
  return Math.max(COL_MIN[idx], avail - otherFixed - COL_MIN[INFO_COL] - 2);
}

document.addEventListener('pointermove', e => {
  if (!rzDrag) return;
  rzDrag.px = Math.min(maxWidthFor(rzDrag.idx),
                       Math.max(COL_MIN[rzDrag.idx],
                                rzDrag.start + (e.clientX - rzDrag.x)));
  if (rzPending) return;
  rzPending = true;
  requestAnimationFrame(() => {          // one relayout per frame, not per event
    rzPending = false;
    if (!rzDrag) return;
    colW[rzDrag.idx] = Math.round(rzDrag.px);
    colCustom = true;
    applyCols();
  });
});
document.addEventListener('pointerup', () => {
  if (!rzDrag) return;
  document.querySelectorAll('.rz.on').forEach(h => h.classList.remove('on'));
  document.body.classList.remove('rzing');
  rzDrag = null;
  saveCols();
});
document.addEventListener('dblclick', e => {
  const h = e.target.closest ? e.target.closest('.rz') : null;
  if (!h) return;
  autoFit(Number(h.dataset.c));
  e.preventDefault();
});
let _fitPending = false;
function refit(){
  if (_fitPending) return;
  _fitPending = true;
  requestAnimationFrame(() => { _fitPending = false; applyCols(); });
}
window.addEventListener('resize', refit);
window.addEventListener('load', refit);
if (document.fonts && document.fonts.ready) document.fonts.ready.then(refit);
// The container's width changes on its own: when the vertical scrollbar
// appears as rows fill, when the side panel resizes, when tabs wrap.
try { new ResizeObserver(refit).observe($('tw')); } catch (e) {}
try { new ResizeObserver(refit).observe($('side')); } catch (e) {}

const records = new Map();       // seq -> packet record, for the display filter

function addRow(p){
  p._hay = ((p.process||'')+' '+(p.rhost||'')+' '+(p.src||'')+' '+(p.dst||'')+' '+
            (p.proto||'')+' '+(p.info||'')+' '+(p.sport||'')+' '+(p.dport||'')+' '+
            (p.iface||'')).toLowerCase();
  records.set(p.seq, p);
  const tr = document.createElement('tr');
  tr.dataset.seq = p.seq;
  const sp = p.sport!=null ? ':'+p.sport : '';
  const dp = p.dport!=null ? ':'+p.dport : '';
  const dstLabel = p.rhost && p.dir==='out' ? p.rhost+dp : p.dst+dp;
  const srcLabel = p.rhost && p.dir==='in'  ? p.rhost+sp : p.src+sp;
  tr.innerHTML =
    '<td class="num">'+p.seq+'</td>'+
    '<td>'+esc(p.time)+'</td>'+
    '<td class="ifcol" title="'+esc(p.iface||'')+'">'+esc(p.iface||'')+'</td>'+
    '<td class="proc'+(/^\(/.test(p.process||'')?' sys':'')+'" title="'+
      esc(p.process)+(p.pid?' ('+p.pid+')':'')+'">'+esc(p.process)+'</td>'+
    '<td class="arrow '+p.dir+'">'+(p.dir==='out'?'▲':'▼')+'</td>'+
    '<td'+(p.rhost&&p.dir==='in'?' class="host"':'')+' title="'+esc(srcLabel)+'">'+esc(srcLabel)+'</td>'+
    '<td'+(p.rhost&&p.dir==='out'?' class="host"':'')+' title="'+esc(dstLabel)+'">'+esc(dstLabel)+'</td>'+
    '<td><span class="pr '+esc(p.proto)+'">'+esc(p.proto)+'</span></td>'+
    '<td class="num">'+p.length+'</td>'+
    '<td class="info" title="'+esc(p.info)+'">'+esc(p.info)+'</td>';
  tr.onclick = () => select(p.seq, tr);
  return tr;
}

/* ================= display filter =================
   A small expression language over captured packets. Parsed once on every
   edit into a predicate, then run against each row's record — so it filters
   what is already on screen and everything that arrives afterwards, without
   touching the capture itself. */

const FIELDS = {
  proto:   r => r.proto,
  process: r => r.process,  proc: r => r.process,
  src:     r => r.src,      dst:  r => r.dst,
  ip:      r => [r.src, r.dst],
  host:    r => r.rhost,    rhost: r => r.rhost,
  port:    r => [r.sport, r.dport],
  sport:   r => r.sport,    dport: r => r.dport,
  bytes:   r => r.length,   len:   r => r.length,
  payload: r => r.payload_len,
  info:    r => r.info,     dir:   r => r.dir,
  pid:     r => r.pid,      stream: r => r.stream,  seq: r => r.seq,
  iface:   r => r.iface,    nic:   r => r.iface,
};

function tokenize(s){
  const out = [];
  const re = /\s*(\(|\)|&&|\|\||\band\b|\bor\b|!~|!=|>=|<=|==|=|~|!|>|<|"[^"]*"|'[^']*'|[^\s()!=<>~|&]+)/giy;
  let m;
  while ((m = re.exec(s)) !== null){
    if (re.lastIndex === m.index) break;
    out.push(m[1]);
    if (re.lastIndex >= s.length) break;
  }
  return out;
}

function parseFilter(text){
  const toks = tokenize(text);
  let i = 0;
  const peek = () => toks[i];
  const eat  = () => toks[i++];
  const isOp = t => ['==','!=','=','~','!~','>','>=','<','<='].includes(t);

  function value(raw){
    if (raw == null) return '';
    if ((raw[0] === '"' && raw.endsWith('"')) || (raw[0] === "'" && raw.endsWith("'")))
      return raw.slice(1,-1);
    return raw;
  }

  function compare(getter, op, want){
    const num = Number(want);
    const isNum = want !== '' && !isNaN(num);
    const w = String(want).toLowerCase();
    return r => {
      let vals = getter(r);
      if (!Array.isArray(vals)) vals = [vals];
      for (let v of vals){
        if (v == null) v = '';
        if (isNum && typeof v === 'number'){
          if (op === '>'  && v >  num) return true;
          if (op === '>=' && v >= num) return true;
          if (op === '<'  && v <  num) return true;
          if (op === '<=' && v <= num) return true;
          if ((op === '==' || op === '=') && v === num) return true;
          if (op === '!=' && v !== num) return false;
          continue;
        }
        const sv = String(v).toLowerCase();
        if (op === '~')  { if (sv.includes(w)) return true; continue; }
        if (op === '!~') { if (sv.includes(w)) return false; continue; }
        if (op === '==' || op === '=') { if (sv === w) return true; continue; }
        if (op === '!=') { if (sv === w) return false; continue; }
      }
      return op === '!=' || op === '!~';
    };
  }

  function primary(){
    const t = peek();
    if (t === undefined) throw new Error('unexpected end of filter');
    if (t === '('){ eat(); const e = orExpr();
      if (peek() !== ')') throw new Error('missing )'); eat(); return e; }
    if (t === '!'){ eat(); const e = primary(); return r => !e(r); }
    const word = eat();
    const key = word.toLowerCase();
    if (FIELDS[key] && isOp(peek())){
      const op = eat();
      const want = value(eat());
      if (want === undefined) throw new Error('missing value after ' + op);
      return compare(FIELDS[key], op, want);
    }
    // A bare word is a substring search across the whole row.
    const w = value(word).toLowerCase();
    return r => (r._hay || '').includes(w);
  }

  function andExpr(){
    let left = primary();
    while (peek() === '&&' || (peek() || '').toLowerCase() === 'and'){
      eat(); const right = primary();
      const l = left; left = r => l(r) && right(r);
    }
    return left;
  }
  function orExpr(){
    let left = andExpr();
    while (peek() === '||' || (peek() || '').toLowerCase() === 'or'){
      eat(); const right = andExpr();
      const l = left; left = r => l(r) || right(r);
    }
    return left;
  }

  const fn = orExpr();
  if (i < toks.length) throw new Error('unexpected "' + toks[i] + '"');
  return fn;
}

let filterFn = null, filterError = null;

function applyFind(){
  const text = $('find').value.trim();
  const box = $('find');
  $('findClear').style.display = text ? '' : 'none';
  if (bufferMode) backToLive();
  if (!text){
    filterFn = null; filterError = null;
    box.classList.remove('bad');
    $('searchAll').style.display = 'none';
  } else {
    try {
      filterFn = parseFilter(text);
      filterError = null;
      box.classList.remove('bad');
    } catch (e){
      // Keep the last good filter applied and say what's wrong, rather than
      // silently showing everything while the user is mid-expression.
      filterError = e.message;
      box.classList.add('bad');
      $('fcount').textContent = e.message;
      return;
    }
  }
  let shown = 0, total = 0;
  for (const tr of $('rows').children){
    total++;
    const rec = records.get(Number(tr.dataset.seq));
    let hit = true;
    if (filterFn && rec){ try { hit = !!filterFn(rec); } catch(e){ hit = false; } }
    tr.style.display = hit ? '' : 'none';
    if (hit) shown++;
  }
  $('fcount').textContent = filterFn ? shown + ' of ' + total : total + ' packets';
  $('emptyMsg').style.display = shown ? 'none' : 'block';
  $('emptyMsg').textContent = filterFn ? 'No packets match this filter.' : 'Waiting for packets…';
  tlDraw();
}

function rowVisible(rec){
  if (!filterFn) return true;
  try { return !!filterFn(rec); } catch(e){ return false; }
}

function updateCount(){
  if (bufferMode) return;
  if (filterError){ $('fcount').textContent = filterError; return; }
  const rows = $('rows').children;
  if (!filterFn){ $('fcount').textContent = rows.length + ' packets'; return; }
  let shown = 0;
  for (const tr of rows) if (tr.style.display !== 'none') shown++;
  $('fcount').textContent = shown + ' of ' + rows.length;
  // Offer the wider search when the buffer holds more than the browser does.
  const buffered = (lastStatus && lastStatus.packets) || 0;
  $('searchAll').style.display = (buffered > rows.length) ? '' : 'none';
}

/* ---------------- search the whole capture buffer ----------------
   The live table holds at most MAX_ROWS; the capture ring holds far more.
   Filtering only what the browser has loaded quietly misses packets that are
   still captured — which is how a QUIC handshake can be in the buffer and
   unfindable. This pulls the ring down and filters all of it. */

let bufferMode = false;

async function searchBuffer(){
  if (!filterFn) return;
  $('fcount').textContent = 'searching…';
  try {
    const d = await (await api('/api/buffer')).json();
    const hits = d.packets.filter(p => {
      p._hay = ((p.process||'')+' '+(p.rhost||'')+' '+(p.src||'')+' '+(p.dst||'')+' '+
                (p.proto||'')+' '+(p.info||'')+' '+(p.sport||'')+' '+(p.dport||'')+' '+
            (p.iface||'')).toLowerCase();
      return rowVisible(p);
    });
    bufferMode = true;
    setPaused(true);           // keep the Pause button honest about the state
    const tb = $('rows');
    tb.innerHTML = ''; records.clear();
    const frag = document.createDocumentFragment();
    for (const p of hits.slice(-MAX_ROWS)) frag.appendChild(addRow(p));
    tb.appendChild(frag);
    $('emptyMsg').style.display = hits.length ? 'none' : 'block';
    $('emptyMsg').textContent = 'No packets in the buffer match this filter.';
    $('fcount').textContent = hits.length.toLocaleString() + ' of ' +
      d.count.toLocaleString() + ' buffered' +
      (hits.length > MAX_ROWS ? ' (showing last ' + MAX_ROWS + ')' : '');
    $('searchAll').style.display = 'none';
    $('backLive').style.display = '';
    $('tw').scrollTop = $('tw').scrollHeight;
  } catch (e){
    $('fcount').textContent = 'buffer search failed';
  }
}

function backToLive(){
  bufferMode = false;
  setPaused(false);
  $('backLive').style.display = 'none';
  $('rows').innerHTML = ''; records.clear();
  lastSeq = 0;
  poll();
}

$('searchAll').onclick = searchBuffer;
$('backLive').onclick = backToLive;

/* ---------------- saved presets ---------------- */

function loadPresets(){
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem('netscope-presets') || '{}'); } catch(e){}
  const sel = $('presets');
  sel.innerHTML = '<option value="">presets…</option>' +
    Object.keys(saved).sort().map(k =>
      '<option value="'+esc(k)+'">'+esc(k)+'</option>').join('');
  return saved;
}
$('presets').onchange = () => {
  const saved = loadPresets();
  const k = $('presets').value;
  if (k && saved[k]){ $('find').value = saved[k]; applyFind(); }
};
$('savePreset').onclick = () => {
  const expr = $('find').value.trim();
  if (!expr) return;
  const name = prompt('Save this filter as:', expr.slice(0, 28));
  if (!name) return;
  const saved = loadPresets(); saved[name] = expr;
  try { localStorage.setItem('netscope-presets', JSON.stringify(saved)); } catch(e){}
  loadPresets(); $('presets').value = name;
};
$('delPreset').onclick = () => {
  const k = $('presets').value;
  if (!k) return;
  const saved = loadPresets(); delete saved[k];
  try { localStorage.setItem('netscope-presets', JSON.stringify(saved)); } catch(e){}
  loadPresets();
};
$('fhelp').onclick = () => {
  const b = $('fhelpbox');
  b.style.display = b.style.display === 'none' ? 'block' : 'none';
};

/* Tab badges have to stay narrow, or a badge can wrap the tab strip (see
   .tab). Counts past 99 read "99+"; frame numbers stay exact to 9999 and then
   abbreviate — the Packet pane's header has the exact frame, and both badges
   carry the exact value as a tooltip. */
function tabCount(el, n){
  el.textContent = !n ? '' : (n > 99 ? '99+' : String(n));
  el.title = n > 99 ? String(n) : '';
  el.classList.toggle('zero', !n);
}
function frameBadge(seq){
  if (seq < 10000) return '#' + seq;
  if (seq < 1e6) return '#' + Math.floor(seq / 1000) + 'k';
  if (seq < 1e8) return '#' + (Math.floor(seq / 1e5) / 10) + 'M';
  return '#' + Math.floor(seq / 1e6) + 'M';
}

function select(seq, tr){
  selected = seq;
  for (const r of $('rows').children) r.classList.toggle('sel', r === tr);
  // Deliberately does NOT switch tabs. Files, Streams and Talkers are
  // session-wide views; yanking the user back to Packet every time they
  // click a row made them feel like they belonged to the selection.
  // The Packet pane still updates underneath, and its tab shows the frame
  // number so it's clear the selection registered.
  const b = $('nPkt');
  b.textContent = frameBadge(seq);
  b.title = 'frame ' + seq;
  b.classList.remove('zero');
  api('/api/packet?seq='+seq).then(r=>r.json()).then(renderDetail).catch(()=>{});
}

/* ---------------- row menu ----------------
   Right-click a packet to hide its program, host or address. Hiding writes
   a clause into the display filter rather than into a hidden list of its
   own, so what is hidden is always on screen in the filter box and undone by
   editing it — a monitor that silently hides things is where the one packet
   that mattered goes unseen. The last items keep a program or host out of
   History, which is a setting of its own (History tab, Not recorded). */
function hideClause(field, value){ addClause(field, '!=', value); }
function addClause(field, op, value){
  const text = $('find').value.trim();
  const clause = field + ' ' + op + ' "' + value + '"';
  // && binds tighter than ||, so an expression with an || is wrapped first.
  const base = /\|\||\bor\b/i.test(text) ? '(' + text + ')' : text;
  $('find').value = text ? base + ' && ' + clause : clause;
  $('find').dispatchEvent(new Event('input'));
}

let rowMenuFrom = null;
function closeRowMenu(){
  const m = $('rowmenu');
  if (!m.classList.contains('on')) return;
  m.classList.remove('on');
  if (rowMenuFrom && document.contains(rowMenuFrom) && rowMenuFrom.focus)
    rowMenuFrom.focus({preventScroll: true});
  rowMenuFrom = null;
}

function openRowMenu(rec, x, y){
  const m = $('rowmenu'), hide = [], keep = [];
  const remote = rec.dir === 'out' ? rec.dst : rec.src;
  const proc = rec.process && rec.process !== '-' ? rec.process : '';
  if (proc)      hide.push(['Hide program ' + proc, () => hideClause('process', proc)]);
  if (rec.rhost) hide.push(['Hide host ' + rec.rhost, () => hideClause('host', rec.rhost)]);
  if (remote)    hide.push(['Hide address ' + remote, () => hideClause('ip', remote)]);
  if (!hide.length) return;
  // Only a real program name: "(System)" and the like are Windows' own
  // stand-ins, not something anyone means to stop recording.
  if (proc && !/^\(/.test(proc))
    keep.push(['Don\'t record ' + proc + ' in History', () => addExclusion('program', proc)]);
  const host = rec.rhost || remote;
  if (host) keep.push(['Don\'t record ' + host + ' in History', () => addExclusion('host', host)]);
  const list = hide.concat(keep.length ? [null] : [], keep);
  m.innerHTML = list.map((it, i) => it
    ? '<button role="menuitem" data-i="' + i + '" title="' + esc(it[0]) + '">' + esc(it[0]) + '</button>'
    : '<div class="sep"></div>').join('') +
    '<div class="hint">Hiding edits the filter box; clear it to show them again.</div>';
  m.querySelectorAll('button').forEach(b => b.onclick = e => {
    e.stopPropagation();
    const fn = list[Number(b.dataset.i)][1];
    closeRowMenu();
    fn();
  });
  rowMenuFrom = document.activeElement;
  m.classList.add('on');
  const w = m.offsetWidth, h = m.offsetHeight;
  m.style.left = Math.max(4, Math.min(window.innerWidth - w - 4, x)) + 'px';
  m.style.top  = Math.max(4, Math.min(window.innerHeight - h - 4, y)) + 'px';
  m.querySelector('button').focus();
}

$('rows').addEventListener('contextmenu', e => {
  const tr = e.target.closest && e.target.closest('tr');
  const rec = tr && records.get(Number(tr.dataset.seq));
  if (!rec) return;                 // the browser's own menu, then
  e.preventDefault();
  openRowMenu(rec, e.clientX, e.clientY);
});
$('rowmenu').addEventListener('keydown', e => {
  const bs = [...$('rowmenu').querySelectorAll('button')];
  const i = bs.indexOf(document.activeElement);
  if (e.key === 'Tab'){ closeRowMenu(); return; }
  if (e.key === 'Escape') closeRowMenu();
  else if (e.key === 'ArrowDown') bs[(i + 1) % bs.length].focus();
  else if (e.key === 'ArrowUp')   bs[(i - 1 + bs.length) % bs.length].focus();
  else if (e.key !== 'Enter' && e.key !== ' ') return;
  // Arrows and Escape are the menu's own; Enter and space still reach the
  // focused button.
  e.stopPropagation();
  if (e.key !== 'Enter' && e.key !== ' ') e.preventDefault();
});
// Not closed on scroll: the live table scrolls itself as packets arrive.
document.addEventListener('mousedown', e => {
  if (!e.target.closest || !e.target.closest('#rowmenu')) closeRowMenu();
});
window.addEventListener('blur', closeRowMenu);
window.addEventListener('resize', closeRowMenu);

/* ---------------- detail pane ---------------- */

/* Pick 8 or 16 bytes per line so a full line always fits the panel width. */
function bytesPerLine(){
  const avail = ($('side').clientWidth || 430) - 50;   // pane + hex padding
  const chW = 6.95;                                    // 11.5px monospace
  return (6 + 16*3 + 16 + 2) * chW <= avail ? 16 : 8;
}

function b64bytes(b64){
  const bin = atob(b64 || '');
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hexdump(bytes, perLine){
  const per = perLine || bytesPerLine(), half = per / 2;
  let out = '';
  for (let i=0;i<bytes.length;i+=per){
    const chunk = bytes.slice(i, i+per);
    let hex = '', asc = '';
    for (let j=0;j<per;j++){
      hex += j<chunk.length ? chunk[j].toString(16).padStart(2,'0')+' ' : '   ';
      if (j === half-1) hex += ' ';
      if (j<chunk.length){ const c=chunk[j]; asc += (c>=32&&c<127)?String.fromCharCode(c):'.'; }
    }
    out += '<span class="off">'+i.toString(16).padStart(4,'0')+'</span>  '+
           hex+' <span class="as">'+esc(asc)+'</span>\n';
  }
  return out;
}

function kv(k,v){ return '<div class="row"><span>'+esc(k)+'</span><span>'+esc(v)+'</span></div>'; }

function renderDetail(d){
  if (d.error){ $('p-detail').innerHTML = '<div class="empty">'+esc(d.error)+'</div>'; return; }
  const p = d.record, dec = p.decoded || {};
  let h = '';

  h += '<div class="sec"><h4>Frame '+p.seq+'</h4>';
  h += kv('Time', p.time);
  h += kv('Direction', p.dir === 'out' ? '▲ outbound' : '▼ inbound');
  h += kv('Length', p.length + ' bytes  (' + p.payload_len + ' payload)');
  h += kv('Process', p.process + (p.pid ? '  [pid ' + p.pid + ']' : ''));
  h += '</div>';

  h += '<div class="sec"><h4>Network</h4>';
  h += kv('Source', p.src + (p.sport!=null ? ':'+p.sport : ''));
  h += kv('Destination', p.dst + (p.dport!=null ? ':'+p.dport : ''));
  if (p.rhost) h += kv('Hostname', p.rhost);
  if (p.ipver) h += kv('IP version', 'IPv'+p.ipver);
  if (p.ttl != null) h += kv('TTL / hop limit', p.ttl);
  h += kv('Protocol', p.proto);
  h += '</div>';

  if (dec.tcp){
    h += '<div class="sec"><h4>TCP</h4>';
    h += kv('Flags', dec.tcp.flags);
    h += kv('Sequence', dec.tcp.seq);
    h += kv('Ack', dec.tcp.ack);
    h += kv('Window', dec.tcp.window);
    h += '</div>';
  }
  if (dec.tls){
    h += '<div class="sec"><h4>TLS</h4>';
    h += kv('Record', dec.tls.record);
    h += kv('Version', dec.tls.version);
    if (dec.tls.handshake) h += kv('Handshake', dec.tls.handshake);
    if (dec.tls.sni) h += kv('Server name (SNI)', dec.tls.sni);
    h += kv('Record length', dec.tls.length);
    if (dec.tls.record === 'ApplicationData')
      h += '<div class="io" style="margin-top:6px">Payload is encrypted — bytes below are ciphertext.</div>';
    h += '</div>';
  }
  if (dec.http){
    h += '<div class="sec"><h4>HTTP</h4>';
    h += kv('Start line', dec.http.start_line);
    for (const k in dec.http.headers) h += kv(k, dec.http.headers[k]);
    h += '</div>';
  }
  if (dec.dns){
    h += '<div class="sec"><h4>'+(p.proto==='MDNS'||p.proto==='LLMNR'?p.proto:'DNS')+
         ' '+(dec.dns.response?'response':'query')+'</h4>';
    h += kv('Transaction ID', '0x'+Number(dec.dns.id).toString(16));
    (dec.dns.queries||[]).forEach(q => h += kv('Query', q.type + '  ' + q.name));
    (dec.dns.answers||[]).forEach(a => h += kv('Answer ' + a.type, a.name + ' → ' + a.data));
    h += '</div>';
  }

  if (dec.icmp){
    h += '<div class="sec"><h4>ICMP'+(dec.icmp.version===6?'v6':'')+'</h4>';
    h += kv('Meaning', dec.icmp.meaning);
    h += kv('Type', dec.icmp.type);
    h += kv('Code', dec.icmp.code);
    h += '</div>';
  }

  if (dec.l2){
    h += '<div class="sec"><h4>Link layer</h4>';
    h += kv('Summary', dec.l2.summary);
    h += kv('Source MAC', dec.l2.src_mac);
    h += kv('Destination MAC', dec.l2.dst_mac);
    h += '</div>';
  }

  if (dec.arp){
    h += '<div class="sec"><h4>ARP</h4>';
    h += kv('Operation', dec.arp.op === 1 ? 'request (who-has)' : 'reply (is-at)');
    h += kv('Sender', dec.arp.sender_ip + '  ' + dec.arp.sender_mac);
    h += kv('Target', dec.arp.target_ip);
    h += '</div>';
  }

  if (dec.quic){
    const q = dec.quic;
    h += '<div class="sec"><h4>QUIC</h4>';
    h += kv('Header form', q.header === 'long' ? 'long' : 'short (1-RTT)');
    if (q.type)    h += kv('Packet type', q.type);
    if (q.version) h += kv('Version', q.version);
    if (q.sni)     h += kv('Server name (SNI)', q.sni);
    if (q.alpn)    h += kv('ALPN', q.alpn.join(', ') + (q.h3 ? '   (HTTP/3)' : ''));
    if (q.dcid)    h += kv('Destination CID', q.dcid);
    if (q.scid)    h += kv('Source CID', q.scid);
    if (q.decrypted)
      h += '<div class="io" style="margin-top:6px">Initial packet decrypted with the '+
           'published salt — that is how the hostname is readable. Everything after '+
           'the handshake is encrypted with keys never sent on the wire.</div>';
    if (q.note) h += kv('Note', q.note);
    h += '</div>';
  }

  if (dec.smb){
    h += '<div class="sec"><h4>SMB</h4>';
    (dec.smb.messages||[]).forEach((m,i) => {
      h += kv('Message '+(i+1), (m.response?'response  ':'request  ') + m.command);
      if (m.filename)    h += kv('  File', m.filename);
      if (m.path)        h += kv('  Share path', m.path);
      if (m.share && !m.path) h += kv('  Share', m.share);
      if (m.access)      h += kv('  Access', m.access);
      if (m.disposition) h += kv('  Disposition', m.disposition);
      if (m.pattern)     h += kv('  Pattern', m.pattern);
      if (m.length!=null)h += kv('  Length', Number(m.length).toLocaleString()+' bytes');
      if (m.offset!=null)h += kv('  Offset', Number(m.offset).toLocaleString());
      if (m.size!=null)  h += kv('  File size', hb(m.size));
      if (m.status)      h += kv('  Status', m.status);
      if (m.note)        h += kv('  Note', m.note);
    });
    h += '</div>';
  }

  if (dec.dhcp){
    const q = dec.dhcp;
    h += '<div class="sec"><h4>DHCP</h4>';
    h += kv('Message', q.msg_type);
    h += kv('Client MAC', q.mac);
    if (q.hostname)      h += kv('Hostname', q.hostname);
    if (q.your_ip)       h += kv('Assigned IP', q.your_ip);
    if (q.requested_ip)  h += kv('Requested IP', q.requested_ip);
    if (q.server_id)     h += kv('Server', q.server_id);
    if (q.lease_secs != null) h += kv('Lease time', (q.lease_secs/3600).toFixed(1)+' h');
    if (q.router)         h += kv('Router', q.router);
    if (q.dns && q.dns.length) h += kv('DNS', q.dns.join(', '));
    if (q.vendor_class)   h += kv('Vendor class', q.vendor_class);
    h += '</div>';
  }

  if (dec.ra){
    const r = dec.ra;
    h += '<div class="sec"><h4>IPv6 Router Advertisement</h4>';
    h += kv('Router', r.router);
    h += kv('Router lifetime', r.router_lifetime + ' s' + (r.router_lifetime === 0 ? '  (not a default router)' : ''));
    h += kv('Flags', (r.managed ? 'M ' : '') + (r.other_config ? 'O' : '') || '—');
    if (r.source_link_layer) h += kv('Source MAC', r.source_link_layer);
    (r.prefixes||[]).forEach(p => h += kv('Prefix', p.prefix +
      (p.on_link ? '  on-link' : '') + (p.autonomous ? '  autonomous' : '')));
    (r.rdnss||[]).forEach(n => h += kv('DNS (RDNSS)', n.server + '  (' + n.lifetime + 's)'));
    h += '</div>';
  }

  if (dec.nbns){
    const nb = dec.nbns;
    h += '<div class="sec"><h4>NBNS</h4>';
    h += kv('Operation', (nb.response ? 'response  ' : '') + nb.opcode);
    h += kv('Name', nb.name + (nb.service ? '  <'+nb.service+'>' : ''));
    if (nb.ips && nb.ips.length) h += kv('Address' + (nb.ips.length>1?'es':''), nb.ips.join(', '));
    h += '</div>';
  }

  if (d.raw_b64){
    h += '<div class="sec"><h4>Raw bytes ('+d.raw_len+')</h4><div class="hex">'+
         hexdump(b64bytes(d.raw_b64))+'</div></div>';
  }

  if (p.stream){
    h += '<div class="rowbtns"><button class="btn-sm" onclick="openStream('+p.stream+
         ')">Follow this connection →</button></div>';
  }
  $('p-detail').innerHTML = h;
}

/* ---------------- files (extracted objects) ---------------- */

let lastObjects = [];       // kept so saveObject() can name the file it saved

function renderFiles(d){
  const list = d.objects || [];
  lastObjects = list;
  if (!list.length){
    $('p-files').innerHTML = '<div class="empty">No files rebuilt yet.<br><br>' +
      'NetScope reconstructs files from <b>unencrypted</b> transfers only — ' +
      'plain HTTP downloads and uploads. Anything over HTTPS stays encrypted ' +
      'and cannot be recovered.</div>';
    return;
  }
  $('p-files').innerHTML =
    '<div class="sec"><h4>' + list.length + ' rebuilt · ' + hb(d.total_bytes) + '</h4>' +
    list.map(o =>
      '<div class="item">' +
        '<div class="l1"><span class="nm">' +
          '<span class="tagx '+(o.direction==='upload'?'up':'dl')+'">' +
          (o.direction==='upload'?'UP':'DL') + '</span>' + esc(o.name) + '</span>' +
          '<span class="sz">'+hb(o.size)+'</span></div>' +
        '<div class="l2">'+esc(o.ctype)+' · '+esc(o.process)+' · '+esc(o.peer)+'</div>' +
        (o.url ? '<div class="l2">'+esc(o.url)+'</div>' : '') +
        '<div class="rowbtns">' +
          '<button class="btn-sm" onclick="saveObject('+o.id+')">Save</button>' +
          '<button class="btn-sm" onclick="previewObject('+o.id+')">Preview</button>' +
          '<button class="btn-sm" onclick="openStream('+o.stream+')">Stream</button>' +
        '</div>' +
      '</div>').join('') + '</div>';
}

/* A rebuilt file is named by the server that sent it, not by this machine, so
   it gets the same scrubbing here that safe_filename() does on the way out —
   the browser sanitises `download` too, but the flash message should not be
   showing a name that differs from what actually landed on disk. */
function safeName(s, fallback){
  s = String(s || '').replace(/[\x00-\x1f\x7f"\\/:*?<>|]/g, '_')
                     .replace(/^\.+/, '').trim();
  return s.slice(0, 120) || fallback;
}

function saveObject(id){
  const o = lastObjects.find(x => x.id === id);
  saveOnce('obj:' + id, safeName(o && o.name, 'netscope-object-' + id),
           '/api/object?id='+id+'&t='+encodeURIComponent(TOKEN));
}

function previewObject(id){
  api('/api/object_preview?id='+id).then(r=>r.json()).then(o => {
    if (o.error) return;
    $('mId').textContent = o.name;
    $('mMeta').textContent = o.ctype + '  ·  ' + hb(o.size);
    let h = '';
    if (o.clipped) h += '<div class="warnbar">Preview shows the first 64 KB. Use Save for the whole file.</div>';
    // The type is whatever the sending server wrote. It used to go into the
    // src attribute as it came, so "image/png" followed by a quote and an
    // onerror handler ran script in the dashboard when Preview was clicked.
    // Only a plain image type, spelled exactly, is used; anything else is
    // shown as bytes.
    if (/^image\/(png|jpe?g|gif|webp|bmp|x-icon|svg\+xml)$/i.test(o.ctype)){
      h += '<img class="previewimg" src="data:'+o.ctype.toLowerCase()+';base64,'+esc(o.b64)+'">';
    } else if (o.textual){
      const txt = new TextDecoder('utf-8', {fatal:false}).decode(b64bytes(o.b64));
      h += '<pre class="convo">'+esc(txt)+'</pre>';
    } else {
      h += '<div class="hex">'+hexdump(b64bytes(o.b64), 16)+'</div>';
    }
    $('mBody').innerHTML = h;
    $('overlay').classList.add('on');
  });
}

/* ================= history =================
   Two series (received / sent) on every chart, so a legend is always present
   and the ▼/▲ glyphs repeat in the legend, tooltip and table — identity never
   depends on colour alone. Values the charts don't label directly are all
   reachable in the table view underneath. */

let histDays = 30, histData = null;

/* Round the axis top in binary units, not decimal ones. A "nice" 3,000,000
   renders as 2.9 MB and its quarters as 732.4 KB — the ticks have to be round
   in the unit the labels are actually printed in.

   Every top on this ladder has quarters hb()'s one decimal prints exactly:
   whole numbers or halves, or (for 1 and 2) 256/512/768 of the unit below.
   That rules out 3 (a 2.25 quarter) and 5 (1.25). From 6 up, consecutive
   steps are at most 4/3 apart, so the tallest bar fills at least three
   quarters of the chart; below that the gaps are wider, worst case half.
   The ladder used to be only 1, 2, 4 and 8: anything from 8 GB to 1 TB got
   a 1 TB axis, gridlines every 256 GB, and a month of ordinary use sat at
   the bottom as a sliver. */
const NICE_TOPS = [1, 2, 4, 6, 8, 10, 12, 16, 20, 24, 32, 40, 48, 64,
                   80, 96, 128, 160, 192, 256, 320, 384, 512, 640, 768, 1024];
function niceMax(v){
  const K = 1024;
  if (v <= 0) return K;
  let unit = 1;
  while (v / unit >= K && unit < Math.pow(K, 4)) unit *= K;
  const scaled = v / unit;
  for (const step of NICE_TOPS) if (scaled <= step) return step * unit;
  return K * unit;
}

/* Rounded at the data end, square at the baseline — never a pill. */
function capPath(x, y, w, h, r){
  r = Math.max(0, Math.min(r, w / 2, h));
  return `M${x},${y+h} L${x},${y+r} Q${x},${y} ${x+r},${y} `
       + `L${x+w-r},${y} Q${x+w},${y} ${x+w},${y+r} L${x+w},${y+h} Z`;
}

function dailyChart(rows){
  const W = 560, H = 168, PADL = 46, PADR = 8, PADT = 12, PADB = 22;
  const plotW = W - PADL - PADR, plotH = H - PADT - PADB;
  const max = niceMax(Math.max(1, ...rows.map(r => r.bytes_in + r.bytes_out)));
  const band = plotW / rows.length;
  const bw = Math.min(24, Math.max(3, band - 4));
  const y = v => PADT + plotH - (v / max) * plotH;

  let g = '';
  for (let i = 0; i <= 4; i++){
    const v = max * i / 4, yy = y(v);
    g += `<line class="gridline" x1="${PADL}" y1="${yy}" x2="${W-PADR}" y2="${yy}"/>`;
    g += `<text class="axlbl" x="${PADL-6}" y="${yy+3.5}" text-anchor="end">${esc(hb(v))}</text>`;
  }

  // Which column gets the one direct label: the biggest.
  let peak = 0;
  rows.forEach((r,i) => { if (r.bytes_in + r.bytes_out >
                              rows[peak].bytes_in + rows[peak].bytes_out) peak = i; });

  let bars = '', hits = '';
  rows.forEach((r, i) => {
    const x = PADL + band * i + (band - bw) / 2;
    const tot = r.bytes_in + r.bytes_out;
    const hIn = (r.bytes_in / max) * plotH;
    const hOut = (r.bytes_out / max) * plotH;
    const yTop = y(tot);
    let seg = '';
    if (tot > 0){
      // Sent sits on top and carries the rounded cap; a 2px surface gap
      // separates it from received underneath.
      if (hOut > 0.5){
        seg += `<path d="${capPath(x, yTop, bw, Math.max(1,hOut), 4)}" fill="var(--series-out)"/>`;
      }
      if (hIn > 0.5){
        const yIn = yTop + hOut + (hOut > 0.5 ? 2 : 0);
        const hh = Math.max(1, PADT + plotH - yIn);
        const d = (hOut > 0.5) ? `<rect x="${x}" y="${yIn}" width="${bw}" height="${hh}" fill="var(--series-in)"/>`
                               : `<path d="${capPath(x, yIn, bw, hh, 4)}" fill="var(--series-in)"/>`;
        seg += d;
      }
    }
    bars += `<g class="colgroup" data-i="${i}">${seg}</g>`;
    hits += `<rect class="hitrect" data-i="${i}" x="${PADL + band*i}" y="${PADT}" `
          + `width="${band}" height="${plotH}"/>`;
    if (i === peak && tot > 0){
      bars += `<text class="axlbl" x="${x + bw/2}" y="${yTop - 5}" `
            + `text-anchor="middle" style="fill:var(--fg);font-weight:600">${esc(hb(tot))}</text>`;
    }
  });

  // Only a handful of x labels, else they collide.
  const every = Math.max(1, Math.ceil(rows.length / 6));
  let xl = '';
  rows.forEach((r, i) => {
    if (i % every === 0 || i === rows.length - 1){
      xl += `<text class="axlbl" x="${PADL + band*i + band/2}" y="${H-7}" `
          + `text-anchor="middle">${esc(r.day.slice(5))}</text>`;
    }
  });

  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Daily traffic">`
       + g + bars + xl + hits + '</svg>';
}

// One program that streams VR can be ten times everything else, and on a
// linear scale the rest are slivers. When the biggest is more than BREAK_RATIO
// times the next, it is drawn at full width with a cut in it and the others
// are scaled against the next-biggest instead. Its label still gives the true
// total, and the cut says plainly that the bar is not to scale.
const BREAK_RATIO = 3;
function hbarScale(rows){
  const tots = rows.map(r => r.bytes_in + r.bytes_out).sort((a, b) => b - a);
  if (tots.length > 1 && tots[1] > 0 && tots[0] > BREAK_RATIO * tots[1])
    return {max: tots[1] * 1.3, cut: tots[0]};
  return {max: Math.max(1, tots[0] || 1), cut: 0};
}

function hbars(rows, keyName){
  const sc = hbarScale(rows);
  return rows.map(r => {
    const tot = r.bytes_in + r.bytes_out;
    const broken = sc.cut && tot === sc.cut && tot > sc.max;
    // A broken bar fills the track, split in the proportion it really has.
    const denom = broken ? tot : sc.max;
    const pin = Math.min(100, (r.bytes_in / denom) * 100);
    const pout = Math.min(100 - pin, (r.bytes_out / denom) * 100);
    return '<div class="hbar">' +
      '<span class="nm" title="'+esc(r[keyName])+'">'+esc(r[keyName])+'</span>' +
      '<span style="color:var(--dim)">'+esc(hb(tot))+'</span>' +
      '<span class="track"'+(broken ? ' title="Shortened to fit: this bar is not to scale. '+
        esc(hb(tot))+' in total."' : '')+'>' +
        (pin  > 0 ? '<i style="width:'+pin.toFixed(2)+'%;background:var(--series-in)"></i>'  : '') +
        (pout > 0 ? '<i style="width:'+pout.toFixed(2)+'%;background:var(--series-out)"></i>' : '') +
        (broken ? '<b class="brk"></b>' : '') +
      '</span></div>';
  }).join('');
}

function hbarNote(rows){
  return hbarScale(rows).cut
    ? '<div class="hint" style="margin:-2px 0 6px">The longest bar is cut short so the others stay '+
      'readable. Its figure is the real total.</div>' : '';
}

function legend(){
  return '<div class="legend">' +
    '<span><i style="background:var(--series-in)"></i>▼ received</span>' +
    '<span><i style="background:var(--series-out)"></i>▲ sent</span></div>';
}

function tableView(rows, cols){
  return '<details class="tvw"><summary>Table view</summary><table class="tv"><tr>' +
    cols.map(c => '<th'+(c.n?' style="text-align:right"':'')+'>'+esc(c.h)+'</th>').join('') +
    '</tr>' + rows.map(r => '<tr>' + cols.map(c =>
      '<td'+(c.n?' class="n"':'')+'>'+esc(c.f(r))+'</td>').join('') + '</tr>').join('') +
    '</table></details>';
}

function renderHistory(d){
  if (!d.enabled){
    $('p-history').innerHTML = '<div class="empty">History is off.' +
      (d.error ? '<br><br>'+esc(d.error) : '<br><br>Start without <code class="k">--no-history</code> to record it.') +
      '</div>';
    return;
  }
  histData = d;
  const s = d.summary, daily = d.daily;
  const tot = s.bytes_in + s.bytes_out;
  const ex = d.exclude || {programs: [], hosts: []};
  const exN = ex.programs.length + ex.hosts.length;

  let h = '<div class="dayrange">' +
    [7,30,90].map(n => '<button class="btn-sm'+(n===histDays?' on':'')+
      '" data-days="'+n+'">'+n+'d</button>').join('') +
    '<span style="color:var(--faint);font:11px var(--mono);margin-left:6px">'+
    (s.since ? 'since '+esc(s.since) : 'no data yet')+'</span>' +
    (exN ? '<a href="#" id="exJump">· '+exN+' not recorded</a>' : '') + '</div>';

  h += '<div class="kpirow">' +
    '<div class="kpi"><div class="k">Total</div><div class="v">'+esc(hb(tot))+
      '</div><div class="s">'+Number(s.packets).toLocaleString()+' packets</div></div>' +
    '<div class="kpi"><div class="k">▼ Received</div><div class="v">'+esc(hb(s.bytes_in))+'</div></div>' +
    '<div class="kpi"><div class="k">▲ Sent</div><div class="v">'+esc(hb(s.bytes_out))+'</div></div>' +
    '<div class="kpi"><div class="k">Programs</div><div class="v">'+s.processes+
      '</div><div class="s">'+s.hosts+' hosts</div></div>' +
    '<div class="kpi"><div class="k">Database</div><div class="v">'+esc(hb(s.size))+
      '</div><div class="s">'+s.retain_days+'d retention</div></div>' +
    '</div>';

  h += '<div class="sec"><h4>Daily traffic · last '+d.days+' days</h4>' + legend() +
       '<div class="chartwrap" id="cw-daily">' + dailyChart(daily) +
       '<div class="tip" id="tip-daily"></div></div>' +
       tableView(daily, [
         {h:'Day', f:r=>r.day},
         {h:'▼ received', n:1, f:r=>hb(r.bytes_in)},
         {h:'▲ sent', n:1, f:r=>hb(r.bytes_out)},
         {h:'Packets', n:1, f:r=>Number(r.packets).toLocaleString()}]) +
       '</div>';

  if (d.week_hours){
    h += '<div class="sec"><h4>Busy hours · last '+d.days+' days</h4>' + weekHoursKey() +
         '<div class="chartwrap" id="cw-week">' + weekHoursChart(d.week_hours) +
         '<div class="tip" id="tip-week"></div></div>' + weekHoursTable(d.week_hours) + '</div>';
  }

  if (d.processes.length){
    h += '<div class="sec"><h4>By program · last '+d.days+' days</h4>' +
         hbarNote(d.processes) + hbars(d.processes, 'name') +
         tableView(d.processes, [
           {h:'Program', f:r=>r.name},
           {h:'▼ received', n:1, f:r=>hb(r.bytes_in)},
           {h:'▲ sent', n:1, f:r=>hb(r.bytes_out)},
           {h:'Packets', n:1, f:r=>Number(r.packets).toLocaleString()}]) + '</div>';
  }

  if (d.hosts.length){
    h += '<div class="sec"><h4>By host · all time</h4>' + hbarNote(d.hosts) + hbars(d.hosts, 'host') +
         tableView(d.hosts, [
           {h:'Host', f:r=>r.host},
           {h:'First seen', f:r=>new Date(r.first_seen*1000).toLocaleDateString()},
           {h:'▼ received', n:1, f:r=>hb(r.bytes_in)},
           {h:'▲ sent', n:1, f:r=>hb(r.bytes_out)}]) + '</div>';
  }

  if (d.new_hosts.length){
    h += '<div class="sec"><h4>First contacted in the last 7 days</h4><div class="tlist">' +
      d.new_hosts.map(r => '<div class="t"><div class="top">'+
        '<span class="nm">'+esc(r.host)+'</span>'+
        '<span class="by">'+esc(hb(r.bytes_in+r.bytes_out))+'</span></div>'+
        '<div class="io">first seen '+esc(new Date(r.first_seen*1000).toLocaleString())+
        '</div></div>').join('') + '</div></div>';
  }

  // The alerts themselves are on the Alerts tab ("Past N days"), where they
  // can be muted and explained. This used to repeat them here in the same
  // cards, which read as a duplicate of that tab rather than as the log.
  const ac = d.alert_counts;
  if (ac && ac.total){
    h += '<div class="sec"><h4>Alerts</h4><div class="hint" style="margin-top:0">' +
      ac.total.toLocaleString() + ' alert' + (ac.total === 1 ? '' : 's') +
      ' logged in this period' +
      (ac.high || ac.warn ? ' (' + [ac.high ? ac.high + ' high' : '', ac.warn ? ac.warn + ' warn' : '']
        .filter(Boolean).join(', ') + ')' : '') +
      '. <a href="#" id="alertsJump">See them on the Alerts tab</a>.</div></div>';
  }

  if (d.sessions.length){
    h += '<div class="sec"><h4>Recent sessions</h4>' + tableView(d.sessions, [
      {h:'Started', f:r=>new Date(r.started*1000).toLocaleString()},
      {h:'Interface', f:r=>r.iface||'—'},
      {h:'Version', f:r=>r.version||'—'},
      {h:'Packets', n:1, f:r=>Number(r.packets).toLocaleString()}]) + '</div>';
  }

  // Said on the tab itself, count and all, so an exclusion added months ago
  // can't quietly go on hiding things from someone who has forgotten it.
  h += '<div class="sec" id="histEx"><h4>Not recorded' + (exN ? ' · ' + exN : '') + '</h4>' +
    '<div class="io">Left out of history. Capture, the live tabs and alerts still see them. ' +
    'A program keeps only its name and when it was first and last seen, so a ' +
    'new one is still noticed; a host is not written at all. A plain host name ' +
    'covers its subdomains, and <code class="k">*</code> matches anything.</div>' +
    ex.programs.map(p => ['program', p]).concat(ex.hosts.map(p => ['host', p])).map(([k, p]) =>
      '<div class="row exrow"><span>' + esc(p) + '<span class="kind">' + k + '</span></span>' +
      '<button class="btn-sm" data-exdel="' + k + '" data-pat="' + esc(p) + '" ' +
      'aria-label="Record ' + esc(p) + ' again">Remove</button></div>').join('') +
    '<div class="exadd"><select id="exKind" aria-label="What to leave out">' +
      '<option value="program">Program</option><option value="host">Host</option></select>' +
      '<input type="text" id="exPat" maxlength="253" placeholder="chrome.exe · example.com" ' +
      'aria-label="Program or host to leave out of history">' +
      '<button class="btn-sm" id="exAdd">Add</button></div>' +
    (histExMsg ? '<div class="io" role="status" id="exMsg">' + esc(histExMsg) + '</div>' : '') +
    '</div>';

  h += '<div class="sec"><h4>Storage</h4><div class="row"><span>File</span>'+
       '<span>'+esc(s.path)+'</span></div>'+
       '<div class="rowbtns"><button class="btn-sm" id="histFlush">Flush now</button>'+
       '<button class="btn-sm danger" id="histWipe">Erase all history</button></div></div>';

  const as = (lastStatus && lastStatus.autostart) || {};
  h += '<div class="sec"><h4>Start with Windows</h4>';
  if (!as.supported){
    h += '<div class="io">Windows only.</div>';
  } else if (as.exists){
    h += '<div class="row"><span>Status</span><span style="color:var(--in)">'+
         'registered as a scheduled task</span></div>';
    if (as.command) h += '<div class="row"><span>Runs</span><span>'+esc(as.command)+'</span></div>';
    if (as.run_as)  h += '<div class="row"><span>As</span><span>'+esc(as.run_as)+'</span></div>';
    if (as.last_run) h += '<div class="row"><span>Last run</span><span>'+esc(as.last_run)+'</span></div>';
    h += '<div class="io" style="margin-top:6px">Remove it with '+
         '<code class="k">NetScope.exe --remove-task</code>.</div>';
  } else {
    h += '<div class="io">Not set up. From an <b>elevated</b> Command Prompt:<br>'+
         '<code class="k">NetScope.exe --install-task</code><br><br>'+
         'This registers a logon task that runs with administrator rights and '+
         'no UAC prompt. The Run key cannot do that for an elevated program.</div>';
  }
  h += '</div>';

  $('p-history').innerHTML = h;

  document.querySelectorAll('#p-history [data-days]').forEach(b =>
    b.onclick = () => { histDays = Number(b.dataset.days); refreshTab('history'); });
  $('p-history').querySelectorAll('[data-exdel]').forEach(b =>
    b.onclick = () => removeExclusion(b.dataset.exdel, b.dataset.pat));
  $('exAdd').onclick = () => addExclusion($('exKind').value, $('exPat').value);
  $('exPat').onkeydown = e => { if (e.key === 'Enter') $('exAdd').click(); };
  const ej = $('exJump');
  if (ej) ej.onclick = e => { e.preventDefault(); $('histEx').scrollIntoView({block: 'start'}); $('exPat').focus({preventScroll: true}); };
  const fl = $('histFlush');
  if (fl) fl.onclick = () => control({action:'history_flush'})
    .then(() => refreshTab('history'));
  const wp = $('histWipe');
  if (wp) wp.onclick = () => {
    if (confirm('Erase all recorded history? This cannot be undone.'))
      control({action:'history_wipe'}).then(() => { alertLog = null; refreshTab('history'); });
  };
  wireDailyHover(daily);
  if (d.week_hours) wireWeekHours(d.week_hours);
}

/* ---------------- busy hours ----------------
   Hour of day against weekday, averaged per day over the selected range, in
   local time. The point is the shape of a normal week, so traffic at an hour
   this machine is usually quiet stands out. One hue in five steps, on a log
   scale like the Timeline's: a linear scale turns every hour outside the
   busiest few into the same pale square, and the quiet hours are the ones
   worth reading. Exact values are in the tooltip and the table view. */
const HM_STEPS = [.18, .36, .56, .78, 1];
function hmDayName(i, style){
  // 2024-01-01 was a Monday.
  return new Date(2024, 0, 1 + i).toLocaleDateString([], {weekday: style || 'short'});
}
// Five steps over three decades below the busiest hour. A log of the raw
// byte count put 20 MB and 2.5 GB one shade apart, which hid exactly the
// quiet hours this is for; anything under a thousandth of the peak still
// gets the palest shade rather than disappearing.
const HM_DECADES = 3;
function hmLevel(v, max){
  if (!(v > 0)) return 0;
  const f = (Math.log10(v) - Math.log10(max) + HM_DECADES) / HM_DECADES;
  return Math.max(1, Math.min(HM_STEPS.length, Math.ceil(f * HM_STEPS.length)));
}
// No marker for the current hour: an outlined square read as a selection.
function weekHoursChart(w){
  const W = 560, L = 40, T = 16, CW = (W - L - 2) / 24, CH = 18, G = 2;
  const H = T + 7 * CH + 2;
  let max = 0;
  for (const row of w.cells) for (const c of row) max = Math.max(max, c[0] + c[1]);
  let g = '';
  for (let h = 0; h < 24; h += 3)
    g += '<text class="axlbl" x="' + (L + h * CW + 1) + '" y="10">' + String(h).padStart(2, '0') + '</text>';
  for (let d = 0; d < 7; d++){
    const y = T + d * CH;
    g += '<text class="axlbl" x="' + (L - 6) + '" y="' + (y + CH / 2 + 3.5) + '" text-anchor="end">' +
         esc(hmDayName(d)) + '</text>';
    for (let h = 0; h < 24; h++){
      const x = L + h * CW, v = w.cells[d][h][0] + w.cells[d][h][1], lv = hmLevel(v, max);
      g += '<rect class="' + (lv ? 'hm-cell' : 'hm-empty') + '" x="' + (x + G / 2) + '" y="' + (y + G / 2) +
           '" width="' + (CW - G) + '" height="' + (CH - G) + '" rx="2"' +
           (lv ? ' fill-opacity="' + HM_STEPS[lv - 1] + '"' : '') + '/>';
    }
  }
  for (let d = 0; d < 7; d++) for (let h = 0; h < 24; h++)
    g += '<rect class="hm-hit" data-d="' + d + '" data-h="' + h + '" x="' + (L + h * CW) + '" y="' +
         (T + d * CH) + '" width="' + CW + '" height="' + CH + '"/>';
  return '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Average traffic by weekday and hour">' +
         g + '</svg>';
}
function weekHoursKey(){
  return '<div class="hmkey">less ' + HM_STEPS.map(o => '<i style="opacity:' + o + '"></i>').join('') +
         ' more <span style="margin-left:8px">per day, local time</span></div>';
}
function weekHoursTable(w){
  const rows = [];
  for (let h = 0; h < 24; h++) rows.push({h, v: w.cells.map(r => r[h][0] + r[h][1])});
  return tableView(rows, [{h: 'Hour', f: r => String(r.h).padStart(2, '0') + ':00'}]
    .concat([0, 1, 2, 3, 4, 5, 6].map(d => ({h: hmDayName(d), n: 1, f: r => r.v[d] ? hb(r.v[d]) : '–'}))));
}
function wireWeekHours(w){
  const wrap = $('cw-week'), tip = $('tip-week');
  if (!wrap || !tip) return;
  wrap.querySelectorAll('.hm-hit').forEach(hit => {
    const d = Number(hit.dataset.d), h = Number(hit.dataset.h), c = w.cells[d][h], n = w.counts[d];
    const show = ev => {
      const hh = x => String(x % 24).padStart(2, '0') + ':00';
      tip.innerHTML = '<div class="th">' + esc(hmDayName(d, 'long')) + ' ' + hh(h) + '–' + hh(h + 1) + '</div>' +
        '<div class="tr"><span><span class="sw" style="background:var(--series-in)"></span>▼ received</span><b>' +
          esc(hb(c[0])) + '</b></div>' +
        '<div class="tr"><span><span class="sw" style="background:var(--series-out)"></span>▲ sent</span><b>' +
          esc(hb(c[1])) + '</b></div>' +
        '<div class="tr"><span>average of</span><b>' + n + ' ' + esc(hmDayName(d, 'long')) + (n === 1 ? '' : 's') + '</b></div>';
      tip.classList.add('on');
      const box = wrap.getBoundingClientRect(), r = hit.getBoundingClientRect();
      const tw = tip.offsetWidth, x = r.left - box.left + r.width / 2;
      tip.style.left = Math.max(4, Math.min(box.width - tw - 4, x > box.width / 2 ? x - tw - 10 : x + 10)) + 'px';
      tip.style.top = Math.max(0, r.bottom - box.top + 4) + 'px';
    };
    const hide = () => tip.classList.remove('on');
    hit.addEventListener('pointerenter', show);
    hit.addEventListener('pointerleave', hide);
    hit.addEventListener('focus', show);
    hit.addEventListener('blur', hide);
    hit.setAttribute('tabindex', '0');
  });
}

function wireDailyHover(rows){
  const wrap = $('cw-daily'), tip = $('tip-daily');
  if (!wrap || !tip) return;
  const svg = wrap.querySelector('svg');
  wrap.querySelectorAll('.hitrect').forEach(hit => {
    const i = Number(hit.dataset.i), r = rows[i];
    const grp = wrap.querySelector('.colgroup[data-i="'+i+'"]');
    const show = ev => {
      grp && grp.classList.add('hot');
      // textContent-style assembly: every value is escaped, no raw interpolation.
      tip.innerHTML = '<div class="th">'+esc(r.day)+'</div>'+
        '<div class="tr"><span><span class="sw" style="background:var(--series-in)"></span>▼ received</span><b>'+esc(hb(r.bytes_in))+'</b></div>'+
        '<div class="tr"><span><span class="sw" style="background:var(--series-out)"></span>▲ sent</span><b>'+esc(hb(r.bytes_out))+'</b></div>'+
        '<div class="tr"><span>packets</span><b>'+Number(r.packets).toLocaleString()+'</b></div>';
      tip.classList.add('on');
      const box = wrap.getBoundingClientRect();
      const x = (ev.clientX !== undefined ? ev.clientX - box.left : box.width / 2);
      // Flip to the other side of the pointer near the right edge, so the
      // tooltip never sits on top of the column it is describing.
      const w = tip.offsetWidth;
      const left = (x > box.width / 2) ? x - w - 12 : x + 12;
      tip.style.left = Math.max(4, Math.min(box.width - w - 4, left)) + 'px';
      tip.style.top = '4px';
    };
    const hide = () => { grp && grp.classList.remove('hot'); tip.classList.remove('on'); };
    hit.addEventListener('pointermove', show);
    hit.addEventListener('pointerleave', hide);
    hit.addEventListener('focus', show);
    hit.addEventListener('blur', hide);
    hit.setAttribute('tabindex', '0');
  });
}

/* ---------------- alerts ---------------- */

const RULE_LABELS = {
  new_process:     'A program uses the network for the first time',
  new_host:        'First contact with a host (chatty — off by default)',
  threshold:       'A program crosses a bandwidth threshold',
  cleartext_creds: 'Credentials sent in the clear',
  cleartext_proto: 'Unencrypted protocols (FTP, Telnet, POP3, IMAP)',
  cert_problems:   'Expired, self-signed or weakly signed certificates',
  dns_resolver:    'DNS going to an unexpected resolver',
  port_scan:       'Many distinct ports/hosts touched in a short burst',
  dhcp_rogue_server: 'An unexpected DHCP server hands out a lease',
  arp_spoof:       'The MAC address answering for an IP changes',
  rogue_ra:        'An unexpected IPv6 router advertises itself',
  checkin:         'A program starts checking in with a host on a schedule',
};

function ago(ts){
  const s = Math.max(0, Math.round(Date.now()/1000 - ts));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.round(s/60) + 'm ago';
  return Math.round(s/3600) + 'h ago';
}

// Remembered across renders (and across the 2.5s auto-refresh) rather than
// re-derived from the DOM each time, so collapsing the rules or leaving a
// "why did this fire?" open survives the next poll instead of snapping shut
// under you.
let rulesCollapsed = false;
/* Two views of alerts. "This session" is the alert engine's own list, in
   memory: repeats folded together, dismissable, gone after Clear alerts or a
   restart. "Past N days" is the log in the history database, which outlives
   both — the security record, so it has no Dismiss. They used to be split
   across two tabs in identical cards, which read as one list shown twice. */
let alertView = 'session', alertLog = null, lastAlerts = null;
try { if (localStorage.getItem('netscope-alertview') === 'log') alertView = 'log'; } catch (e){}

async function loadAlertLog(more){
  const have = alertLog && alertLog.enabled && alertLog.rows.length;
  const q = more && have ? '?before=' + alertLog.rows[alertLog.rows.length - 1].id
          : have ? '?after=' + alertLog.rows[0].id + '&limit=500' : '';
  const d = await (await api('/api/alert_log' + q)).json();
  if (!d.enabled){ alertLog = {enabled: false, error: d.error, rows: []}; return; }
  if (q && !more && (d.more || d.counts.newest < alertLog.rows[0].id)){
    // Too many new ones to join up, or the log was erased: start over.
    alertLog = null;
    return loadAlertLog(false);
  }
  if (!q) alertLog = {enabled: true, rows: d.alerts, more: d.more};
  else if (more){ alertLog.rows.push(...d.alerts); alertLog.more = d.more; }
  else alertLog.rows = d.alerts.concat(alertLog.rows);
  alertLog.counts = d.counts; alertLog.days = d.retain_days;
}

function alertLogHTML(d){
  const days = d.log_days;
  const L = alertLog;
  if (!L) return '<div class="empty">Loading the alert log…</div>';
  if (!L.enabled) return '<div class="empty">History is off, so alerts are only kept for ' +
    'this session.<br><br>Start without <code class="k">--no-history</code> to keep a log.</div>';
  const c = L.counts || {total: 0, high: 0, warn: 0};
  let h = '<h4 style="margin-bottom:4px">' + (c.total ? c.total.toLocaleString() + ' alerts · ' +
    c.high + ' high · ' + c.warn + ' warn' : 'Alerts') + '</h4>' +
    '<div class="hint" style="margin:0 0 8px">Logged on disk for ' + (L.days || days) +
    ' days, including earlier sessions. Clear alerts and restarts don\'t remove them.</div>';
  if (!L.rows.length)
    return h + '<div class="empty">No alerts logged in the past ' + (L.days || days) + ' days.</div>';
  const muted = new Set((d.mutes || []).map(m => m.rule + '\u0000' + m.subject));
  h += L.rows.map(a => {
    const isMuted = a.subject && muted.has(a.rule + '\u0000' + a.subject);
    return '<div class="alert logrow ' + esc(a.severity) + '">' +
      '<div class="t"><span class="ti">' + esc(a.title) + '</span>' +
      '<span class="when">' + esc(new Date(a.ts * 1000).toLocaleString()) + '</span></div>' +
      '<div class="d">' + esc(a.detail) + '</div>' +
      '<div class="rl" title="' + esc((d.why || {})[a.rule] || '') + '">' + esc(a.rule) +
        (a.process ? ' · ' + esc(a.process) : '') + '</div>' +
      ((d.why || {})[a.rule] ? '<details class="why" data-lid="' + a.id + '"><summary>Why did this fire?</summary>' +
        esc(d.why[a.rule]) + '</details>' : '') +
      (a.subject ? '<div class="rowbtns">' + (isMuted
        ? '<button class="btn-sm" data-unmute="' + esc(a.rule) + '" data-subject="' + esc(a.subject) +
          '" title="' + esc(a.subject) + ' is muted for this rule">Unmute ' + esc(a.subject) + '</button>'
        : '<button class="btn-sm" data-mute="' + esc(a.rule) + '" data-subject="' + esc(a.subject) +
          '" title="Stop this rule reporting ' + esc(a.subject) + ', and leave it watching ' +
          'everything else">Mute ' + esc(a.subject) + '</button>') + '</div>' : '') +
      '</div>';
  }).join('');
  if (L.more) h += '<div class="rowbtns"><button class="btn-sm" id="alertMore">Show older</button></div>';
  return h;
}

function setAlertView(v){
  alertView = v === 'log' ? 'log' : 'session';
  try { localStorage.setItem('netscope-alertview', alertView); } catch (e){}
  if (lastAlerts) renderAlerts(lastAlerts);
  if (alertView === 'log') loadAlertLog(false).then(() => {
    if (alertView === 'log' && lastAlerts) renderAlerts(lastAlerts);
  }).catch(() => {});
}
// History's "See them on the Alerts tab" opens the log view there.
$('p-history').addEventListener('click', e => {
  if (e.target.id !== 'alertsJump') return;
  e.preventDefault();
  alertView = 'log';
  try { localStorage.setItem('netscope-alertview', 'log'); } catch (e2){}
  showTab('alerts');
});
try { rulesCollapsed = localStorage.getItem('rulesCollapsed') === '1'; } catch(e) {}
let openWhy = new Set();

function renderAlerts(d){
  lastAlerts = d;
  let h = '';
  if (!rulesCollapsed){
    h += '<div class="sec"><h4>Rules</h4><div class="rulegrid">';
    for (const k in RULE_LABELS){
      h += '<label><input type="checkbox" data-rule="'+k+'"'+
           (d.rules[k] ? ' checked' : '')+'> '+esc(RULE_LABELS[k])+'</label>';
    }
    h += '<label>Threshold <input type="number" id="thrMb" min="1" value="'+
         d.threshold_mb+'"> MB per program</label>';
    h += '<label><input type="checkbox" id="toasts"'+(d.toasts ? ' checked' : '')+
         (d.toasts_supported ? '' : ' disabled')+'> Windows desktop notifications'+
         (d.toasts_supported ? '' : ' (Windows only)')+'</label>';
    h += '<label title="Looks up a name for IPs nothing on the wire has '+
         'already named. Off by default: unlike everything else here, this '+
         'sends DNS queries out."><input type="checkbox" id="reverseDns"'+
         (d.reverse_dns ? ' checked' : '')+'> Reverse DNS for unlabeled IPs'+
         '</label>';
    const rs = d.reverse_dns_stats;
    if (d.reverse_dns && rs){
      h += '<div class="hint" style="margin-left:23px">'+rs.attempted+
           ' looked up · '+rs.resolved+' resolved'+
           (rs.pending ? ' · '+rs.pending+' pending' : '')+
           (rs.cap_reached ? ' · limit reached, restart NetScope to resume'
                           : '')+
           '. Most unresolved IPs simply have no reverse DNS record — '+
           'that is normal, not a fault.</div>';
    }
    const ev = d.tracking_evicted;
    if (ev && (ev.processes || ev.hosts || ev.names)){
      h += '<div class="hint">Long-running limits reached: dropped the '+
           'quietest '+ev.processes+' programs, '+ev.hosts+' addresses and '+
           ev.names+' names from the running totals. Clear packets resets this.'+
           '</div>';
    }
    h += '</div><div class="rowbtns">'+
         '<button class="btn-sm" id="applyRules">Apply</button>'+
         '<button class="btn-sm danger" id="clearAlerts">Clear alerts</button></div>'+
         '<div class="hint">Settings are remembered between runs.</div></div>';
  }

  // Muted subjects, listed where you can undo them. A mute you cannot see is
  // indistinguishable from a rule that stopped working.
  const mutes = d.mutes || [];
  if (mutes.length){
    h += '<div class="sec"><h4>Muted · ' + mutes.length + '</h4>' +
      mutes.map(m =>
        '<div class="mute"><span class="s">' + esc(m.subject) + '</span>' +
        '<span class="r">' + esc(m.rule) +
        (m.until ? ' · until ' + new Date(m.until*1000).toLocaleTimeString() : '') +
        '</span><button class="btn-sm" data-unmute="' + esc(m.rule) +
        '" data-subject="' + esc(m.subject) + '">Unmute</button></div>').join('') +
      '</div>';
  }

  // The switch only appears when there is a log to switch to.
  const logView = alertView === 'log' && d.log_days;
  if (d.log_days){
    h += '<div class="rowbtns" style="margin:0 0 10px"><span class="viewsw" id="alertSw" ' +
      'role="group" aria-label="Which alerts">' +
      '<button class="btn-sm' + (logView ? '' : ' on') + '" data-av="session" aria-pressed="' +
        !logView + '">This session</button>' +
      '<button class="btn-sm' + (logView ? ' on' : '') + '" data-av="log" aria-pressed="' +
        !!logView + '" title="Every alert logged in the history database, from this and ' +
        'earlier sessions">Past ' + d.log_days + ' days</button></span>' +
      '<button class="btn-sm" id="toggleRules" style="margin-left:auto">' +
      (rulesCollapsed ? 'Show rules' : 'Hide rules') + '</button></div>';
  }
  const list = d.alerts || [];
  if (logView){
    h += '<div class="sec">' + alertLogHTML(d) + '</div>';
  } else {
  h += '<div class="sec"><div class="sechead"><h4>'+
       (list.length ? list.length+' alerts · '+d.counts.high+' high · '+d.counts.warn+' warn'
                    : 'Alerts')+
       '</h4>'+(d.log_days ? '' : '<button class="btn-sm" id="toggleRules">'+
       (rulesCollapsed ? 'Show rules' : 'Hide rules')+'</button>')+'</div>';
  if (!list.length){
    h += '<div class="empty">Nothing flagged yet. Rules run on every packet; '+
         'alerts appear here and repeat counts are folded together.</div>';
  } else {
    h += list.map(a =>
      '<div class="alert '+a.severity+'">'+
        '<div class="t"><span class="ti">'+esc(a.title)+'</span>'+
        '<span class="when">'+(a.count>1 ? '×'+a.count+' · ' : '')+ago(a.ts)+'</span></div>'+
        '<div class="d">'+esc(a.detail)+'</div>'+
        '<div class="rl" title="'+esc((d.why||{})[a.rule]||'')+'">'+esc(a.rule)+
          (a.process ? ' · '+esc(a.process) : '')+'</div>'+
        ((d.why||{})[a.rule] ? '<details class="why" data-aid="'+a.id+'"'+
          (openWhy.has(a.id) ? ' open' : '')+'><summary>Why did this '+
          'fire?</summary>'+esc(d.why[a.rule])+'</details>' : '')+
        '<div class="rowbtns">'+
          (a.subject ? '<button class="btn-sm" data-mute="'+esc(a.rule)+
            '" data-subject="'+esc(a.subject)+'" title="Stop this rule '+
            'reporting '+esc(a.subject)+', and leave it watching everything '+
            'else">Mute '+esc(a.subject)+'</button>' : '')+
          (a.subject ? '<button class="btn-sm" data-mute1h="'+esc(a.rule)+
            '" data-subject="'+esc(a.subject)+'">Mute 1h</button>' : '')+
          '<button class="btn-sm" data-dismiss="'+a.id+'">Dismiss</button>'+
        '</div>'+
      '</div>').join('');
  }
  h += '</div>';
  }
  const pane0 = $('p-alerts'), openLog = new Set();
  // Keep open "why" boxes in the log open across the 2.5 s redraw; the
  // session list does this with alert ids, which log rows don't share.
  pane0.querySelectorAll('.logrow details.why[open]').forEach(x => openLog.add(x.dataset.lid));
  pane0.innerHTML = h;

  // Alerts that no longer exist (dismissed, muted, cleared) don't need to be
  // remembered as "open" forever.
  pane0.querySelectorAll('.logrow details.why').forEach(x => {
    if (openLog.has(x.dataset.lid)) x.open = true; });
  if (!logView){
    const liveIds = new Set(list.map(a => a.id));
    openWhy.forEach(id => { if (!liveIds.has(id)) openWhy.delete(id); });
  }
  pane0.querySelectorAll('#alertSw [data-av]').forEach(b => b.onclick = () => setAlertView(b.dataset.av));
  const more = $('alertMore');
  if (more) more.onclick = () => { more.disabled = true;
    loadAlertLog(true).then(() => renderAlerts(lastAlerts)).catch(() => { more.disabled = false; }); };

  const toggleRules = $('toggleRules');
  if (toggleRules) toggleRules.onclick = () => {
    rulesCollapsed = !rulesCollapsed;
    try { localStorage.setItem('rulesCollapsed', rulesCollapsed ? '1' : '0'); } catch(e) {}
    renderAlerts(d);
  };
  document.querySelectorAll('#p-alerts details.why[data-aid]').forEach(det => {
    det.addEventListener('toggle', () => {
      const id = Number(det.dataset.aid);
      if (det.open) openWhy.add(id); else openWhy.delete(id);
    });
  });

  const apply = $('applyRules');
  if (apply) apply.onclick = () => {
    const rules = {};
    document.querySelectorAll('#p-alerts [data-rule]').forEach(
      cb => rules[cb.dataset.rule] = cb.checked);
    control({action:'alerts', rules,
             threshold_mb: Number($('thrMb').value) || 500,
             toasts: $('toasts').checked,
             reverse_dns: $('reverseDns').checked}).then(() => refreshTab('alerts'));
  };
  const clr = $('clearAlerts');
  if (clr) clr.onclick = () => control({action:'clear_alerts'})
    .then(() => refreshTab('alerts'));

  const pane = $('p-alerts');
  const after = p => p.then(() => refreshTab('alerts'));
  pane.querySelectorAll('[data-mute]').forEach(b => b.onclick = () =>
    after(control({action:'mute', rule:b.dataset.mute, subject:b.dataset.subject})));
  pane.querySelectorAll('[data-mute1h]').forEach(b => b.onclick = () =>
    after(control({action:'mute', rule:b.dataset.mute1h,
                   subject:b.dataset.subject, minutes:60})));
  pane.querySelectorAll('[data-unmute]').forEach(b => b.onclick = () =>
    after(control({action:'unmute', rule:b.dataset.unmute, subject:b.dataset.subject})));
  pane.querySelectorAll('[data-dismiss]').forEach(b => b.onclick = () =>
    after(control({action:'dismiss_alert', id:Number(b.dataset.dismiss)})));
}

/* ---------------- streams ---------------- */

function renderStreams(d){
  const list = d.streams || [];
  if (!list.length){ $('p-streams').innerHTML = '<div class="empty">No TCP connections yet.</div>'; return; }
  $('p-streams').innerHTML = '<div class="sec"><h4>'+list.length+' connections</h4>' +
    list.map(s =>
      '<div class="item" onclick="openStream('+s.id+')">' +
        '<div class="l1"><span class="nm">'+esc(s.process)+' → '+
          esc(s.host || s.server)+'</span>' +
          '<span class="sz">'+hb(s.bytes_c2s+s.bytes_s2c)+'</span></div>' +
        '<div class="l2">#'+s.id+' · '+esc(s.hint||'TCP')+' · '+esc(s.client)+
          ' → '+esc(s.server)+' · '+s.packets+' pkts'+
          (s.closed?' · closed':'')+(s.truncated?' · truncated':'')+'</div>' +
      '</div>').join('') + '</div>';
}

function renderDhcp(d){
  const list = d.leases || [];
  if (!list.length){
    $('p-dhcp').innerHTML = '<div class="empty">No DHCP leases seen yet.</div>';
    return;
  }
  const age = s => { const h = s / 3600;
    return h >= 1 ? h.toFixed(1) + 'h lease' : Math.round(s/60) + 'm lease'; };
  $('p-dhcp').innerHTML = '<div class="sec"><h4>'+list.length+' lease'+
    (list.length===1?'':'s')+'</h4>' +
    list.map(l =>
      '<div class="item">' +
        '<div class="l1"><span class="nm">'+esc(l.hostname || '(no hostname)')+
          '</span><span class="sz">'+esc(l.ip)+'</span></div>' +
        '<div class="l2">'+esc(l.mac)+' · server '+esc(l.server)+
          (l.lease_secs ? ' · '+age(l.lease_secs) : '')+'</div>' +
      '</div>').join('') + '</div>';
}

let streamData = null, streamMode = 'text';

/* Printable runs, ASCII and UTF-16LE — the readable part of a binary protocol.
   SMB filenames are UTF-16, which is why the plain text view shows them as
   letters separated by dots. */
function stringsOf(bytes, min){
  min = min || 4;
  const seen = new Set(), out = [];
  const push = (s, tag) => {
    const k = s + tag;
    if (s.length >= min && !seen.has(k)){ seen.add(k); out.push(s + tag); }
  };
  let cur = '';
  for (let i=0;i<bytes.length;i++){
    const c = bytes[i];
    if (c>=32 && c<127) cur += String.fromCharCode(c);
    else { push(cur, ''); cur = ''; }
  }
  push(cur, '');
  for (const align of [0,1]){
    cur = '';
    for (let i=align;i+1<bytes.length;i+=2){
      if (bytes[i+1]===0 && bytes[i]>=32 && bytes[i]<127) cur += String.fromCharCode(bytes[i]);
      else { push(cur, '   ·utf-16'); cur = ''; }
    }
    push(cur, '   ·utf-16');
  }
  return out;
}

function openStream(id){
  api('/api/stream?id='+id).then(r=>r.json()).then(d => {
    if (d.error){ alert(d.error); return; }
    streamData = d;
    const s = d.summary;
    $('mId').textContent = '#'+s.id;
    $('mMeta').textContent = s.process + '   ' + s.client + '  ↔  ' +
      (s.host ? s.host+' ('+s.server+')' : s.server) +
      '   ▲' + hb(s.bytes_c2s) + '  ▼' + hb(s.bytes_s2c);
    renderConvo();
    $('overlay').classList.add('on');
  });
}

function renderConvo(){
  const d = streamData;
  if (!d) return;
  let h = '';
  const gaps = (d.sides.c2s.gaps||0) + (d.sides.s2c.gaps||0);
  if (gaps) h += '<div class="warnbar">'+gaps+' gap'+(gaps>1?'s':'')+
    ' in the captured sequence — some packets were missed, so the reconstruction is incomplete.</div>';
  if (d.clipped) h += '<div class="warnbar">Showing the first 1 MB of this connection.</div>';
  if (d.summary.hint === 'TLS') h += '<div class="warnbar">' +
    'This connection is TLS-encrypted. The bytes below are ciphertext — reassembling them does not make them readable.</div>';

  (d.blocks||[]).forEach(b => {
    const bytes = b64bytes(b.b64);
    const cls = b.dir === 0 ? 'c' : 's';
    const who = b.dir === 0 ? '▲ CLIENT → SERVER  ('+bytes.length+' bytes)'
                            : '▼ SERVER → CLIENT  ('+bytes.length+' bytes)';
    let content;
    if (streamMode === 'hex'){
      content = '<div class="hex">'+hexdump(bytes, 16)+'</div>';
    } else if (streamMode === 'strings'){
      const ss = stringsOf(bytes);
      content = ss.length ? esc(ss.join('\n'))
                          : '<span class="np">no readable strings in this block</span>';
    } else {
      let s = '';
      for (let i=0;i<bytes.length;i++){
        const c = bytes[i];
        s += (c===10||c===13||c===9||(c>=32&&c<127)) ? String.fromCharCode(c) : '·';
      }
      content = esc(s);
    }
    h += '<div class="blk '+cls+'"><div class="who">'+who+'</div>'+content+'</div>';
  });
  if (!(d.blocks||[]).length) h += '<div class="empty">No payload bytes captured on this connection.</div>';
  $('mBody').innerHTML = h;
}

$('mClose').onclick = () => $('overlay').classList.remove('on');
$('overlay').onclick = e => { if (e.target.id === 'overlay') $('overlay').classList.remove('on'); };
function setMode(m){
  streamMode = m;
  $('mText').classList.toggle('on', m === 'text');
  $('mStr').classList.toggle('on', m === 'strings');
  $('mHex').classList.toggle('on', m === 'hex');
  renderConvo();
}
$('mText').onclick = () => setMode('text');
$('mStr').onclick  = () => setMode('strings');
$('mHex').onclick  = () => setMode('hex');

/* ---------------- talkers pane ---------------- */

/* ---------------- connections ----------------
   The packet list says what happened; this says what is open. The rows come
   from the OS socket table joined to flow accounting off the capture — the
   socket table knows state and owner but no byte counts, the capture knows
   byte counts but cannot see an idle or listening socket. */

let connMode = 'active';
let lastConns = null;

function connAge(sec){
  if (sec === null || sec === undefined) return '';
  if (sec < 60) return Math.round(sec) + 's';
  if (sec < 3600) return Math.round(sec/60) + 'm';
  return (sec/3600).toFixed(1) + 'h';
}

/* TCP state names are long enough to blow out a column in a narrow panel.
   The abbreviations are unambiguous and the full name stays in the tooltip. */
const STATE_SHORT = {
  ESTABLISHED:'ESTAB', TIME_WAIT:'TIME_W', CLOSE_WAIT:'CLOSE_W',
  SYN_SENT:'SYN_S', SYN_RECV:'SYN_R', FIN_WAIT1:'FIN_W1', FIN_WAIT2:'FIN_W2',
  LAST_ACK:'LAST_ACK', CLOSING:'CLOSING', LISTEN:'LISTEN', NONE:'—',
};
function shortState(s){ return STATE_SHORT[s] || s || '—'; }

/* Windows adapter names are written for a properties dialog, not a table
   column — "PIA OpenVPN WinTUN Adapter" is 26 characters to say "PIA". Drop
   the words that appear on every adapter and keep what distinguishes it; the
   full name stays in the tooltip. */
/* Only words that are redundant on every adapter. "Ethernet", "Network" and
   "Connection" are left alone because they can be the entire name. */
const IFACE_NOISE = /\b(adapter|miniport|driver|nic|interface|virtual|wintun|tap|tun|windows)\b/gi;
function shortIface(s){
  if (!s) return '';
  let t = String(s).replace(IFACE_NOISE, ' ').replace(/\s+/g, ' ').trim() || String(s);
  // Still too long for the column: the first word is the distinguishing one.
  // "PIA OpenVPN WinTUN Adapter" -> "PIA OpenVPN" -> "PIA".
  if (t.length > 9) t = t.split(' ')[0];
  return t.length > 10 ? t.slice(0, 9) + '…' : t;
}

/* Inline activity sparkline — 60 seconds of bytes/sec for one connection.
   Deliberate choices:
   - One series, not the green/orange in-out split the footer chart uses. That
     pair fails deuteranope separation on this dark surface (measured when the
     History charts were built, which is why those are blue/orange), and the
     In and Out columns two cells away already carry direction numerically.
     What the table cannot show is *shape over time*, and that is all this is for.
   - A filled area, not a line: at 60x16 a hairline across sixty points is
     noise, while a silhouette reads as steady / bursty / stalled at a glance.
   - Scaled per row. A shared scale would flatten every ordinary connection
     into a straight line next to one busy download; magnitude is already in
     the In/Out columns, so the sparkline spends its pixels on shape.
   - No axis, no gridline, no labels: this is a mark, not a chart. */
const SPARK_W = 40, SPARK_H = 14;
function sparkSVG(series){
  if (!series || !series.length) return '';
  const n = series.length, max = Math.max(...series);
  const x = i => (i / (n - 1)) * SPARK_W;
  if (!max){
    // Genuinely idle, which is worth seeing: a flat baseline, not an empty
    // cell. An empty cell means "no data", and those are different states.
    return '<svg class="spk" viewBox="0 0 '+SPARK_W+' '+SPARK_H+'" '+
           'preserveAspectRatio="none" aria-hidden="true">'+
           '<rect x="0" y="'+(SPARK_H-1)+'" width="'+SPARK_W+'" height="1" '+
           'class="spk-base"/></svg>';
  }
  let d = 'M0,' + SPARK_H;
  for (let i = 0; i < n; i++)
    d += 'L' + x(i).toFixed(2) + ',' +
         (SPARK_H - (series[i] / max) * (SPARK_H - 1)).toFixed(2);
  d += 'L' + SPARK_W + ',' + SPARK_H + 'Z';
  return '<svg class="spk" viewBox="0 0 '+SPARK_W+' '+SPARK_H+'" '+
         'preserveAspectRatio="none" aria-hidden="true">'+
         '<path d="'+d+'" class="spk-fill"/></svg>';
}

function sparkTitle(series){
  if (!series || !series.length) return '';
  const max = Math.max(...series);
  const live = series.filter(v => v > 0).length;
  return max ? 'Peak ' + hb(max) + '/s, active ' + live + 's of the last ' +
               series.length + 's (scaled to this row)'
             : 'Idle for the last ' + series.length + 's';
}

function connRows(d){
  if (connMode === 'listening') return d.listening || [];
  if (connMode === 'recent')    return d.closed || [];
  if (connMode === 'quality'){
    // Everything that carries a measurement, worst first: loss outranks a slow
    // handshake, because a slow handshake is often just distance and loss
    // rarely is.
    return (d.connections || []).concat(d.closed || [])
      .filter(r => r.rtt != null || r.tls_ms != null || r.resent || r.dup_ack)
      .sort((a,b) => (b.resent + b.dup_ack) - (a.resent + a.dup_ack) ||
                     (b.rtt || 0) - (a.rtt || 0));
  }
  return d.connections || [];
}

function ms(v){
  if (v == null) return '';
  return v >= 1000 ? (v/1000).toFixed(2) + 's' : Math.round(v) + 'ms';
}

function renderConns(d){
  lastConns = d;
  const pane = $('p-conns');
  const counts = {active: (d.connections||[]).length,
                  listening: (d.listening||[]).length,
                  recent: (d.closed||[]).length};
  counts.quality = ((d.connections||[]).concat(d.closed||[])
    .filter(r => r.rtt != null || r.tls_ms != null || r.resent || r.dup_ack)).length;
  const btn = (k, label) =>
    '<button class="btn-sm' + (connMode===k?' on':'') + '" data-cmode="'+k+'">' +
    label + ' ' + counts[k] + '</button>';

  let head = '<div class="cfilter">' + btn('active','Open') +
             btn('listening','Listening') + btn('recent','Just closed') +
             btn('quality','Quality') + '</div>';

  if (d.offline)
    head += '<div class="chint">Reading a saved capture — these are the ' +
            'conversations in the file, not sockets on this machine.</div>';
  else if (d.demo)
    head += '<div class="chint">Demo traffic — invented conversations, so ' +
            'this machine\'s real sockets are deliberately left out.</div>';
  else if (!d.supported)
    head += '<div class="chint">psutil is not available, so the socket table ' +
            'cannot be read. Only conversations seen on the wire are listed.</div>';
  else if (d.error)
    head += '<div class="chint">' + esc(d.error) + '</div>';

  const rows = connRows(d);
  if (!rows.length){
    const what = connMode === 'listening' ? 'No listening sockets.'
               : connMode === 'recent' ? 'Nothing has closed recently.'
               : connMode === 'quality' ? 'Nothing measurable yet — a connection '
                 + 'needs a handshake or a TLS setup before it can be timed.'
               : 'No open connections.';
    pane.innerHTML = head + '<div class="empty">' + what + '</div>';
    wireConnFilter();
    return;
  }

  /* Two lines per connection instead of a seven-column table.
     A readable text column needs about 90px and this panel is 429 wide, so
     seven of them never fit — every previous revision of this view was me
     shaving percentages, dropping Proto, then State, and abbreviating headers
     to buy pixels that were not there. Files and Streams solved the same
     problem in the same panel long ago: put the identity on its own full-width
     line and the numbers underneath in dim text. Nothing truncates, the
     columns that had been squeezed out come back, and there are no widths left
     to argue about. */
  const listening = connMode === 'listening';
  const sep = ' <span class="sx">·</span> ';
  // Only worth saying when there is more than one adapter to distinguish.
  const showIface = new Set(rows.map(r => r.iface).filter(Boolean)).size > 1;

  const body = rows.map(r => {
    const peer = listening ? (r.laddr + ':' + r.lport)
                           : ((r.rhost || r.raddr) + ':' + r.rport);
    const title = esc(r.process + (r.pid ? ' (pid ' + r.pid + ')' : '') + '  ' +
                      r.laddr + ':' + r.lport + ' → ' +
                      (r.raddr ? r.raddr + ':' + r.rport : '—') +
                      (r.iface ? '   via ' + r.iface : ''));

    let l1 = '<span class="who">' + esc(r.process) + '</span>' +
             (listening ? '' : '<span class="ar">→</span>') +
             '<span class="peer">' + esc(peer) + '</span>';
    if (connMode === 'active')
      l1 += '<span class="spw" title="' + esc(sparkTitle(r.spark)) + '">' +
            sparkSVG(r.spark) + '</span>';

    const bits = [];
    if (connMode === 'quality'){
      if (r.rtt != null) bits.push('handshake <b>' + ms(r.rtt) + '</b>');
      if (r.tls_ms != null) bits.push('TLS <b>' + ms(r.tls_ms) + '</b>');
      if (r.resent) bits.push('<b class="warn">' + r.resent + '</b> resent');
      if (r.dup_ack) bits.push('<b class="warn">' + r.dup_ack + '</b> dup ACK');
    } else {
      if (r.in || r.out)
        bits.push('<span class="dn">▼</span> <b>' + hb(r.in) + '</b>' +
                  ' <span class="up">▲</span> <b>' + hb(r.out) + '</b>');
      const when = connAge(r.closed ? r.idle : r.age);
      if (when) bits.push((r.closed ? 'idle ' : '') + '<b>' + when + '</b>');
      bits.push(esc(r.proto) + (r.state ? ' ' + esc(shortState(r.state)) : ''));
      if (showIface && r.iface)
        bits.push('via <b>' + esc(shortIface(r.iface)) + '</b>');
    }

    return '<div class="citem' + (r.closed ? ' dim' : '') + '"' +
           ' data-ip="' + esc(r.raddr) + '" data-port="' + r.lport + '"' +
           ' title="' + title + '">' +
             '<div class="l1">' + l1 + '</div>' +
             '<div class="l2">' + bits.join(sep) + '</div>' +
           '</div>';
  }).join('');

  pane.innerHTML = head +
    '<div class="chint">' + (connMode === 'quality'
      ? 'Handshake and TLS setup times, measured off the wire — so they work '
        + 'on encrypted traffic too. Resent segments and duplicate ACKs are '
        + 'the shape of packet loss.'
      : 'Click a row to filter the packet list to that conversation.') +
    '</div>' + body;

  wireConnFilter();
  pane.querySelectorAll('.citem[data-ip]').forEach(el => {
    el.onclick = () => {
      const ip = el.dataset.ip, port = el.dataset.port;
      $('find').value = ip ? 'ip == ' + ip + ' && port == ' + port
                           : 'port == ' + port;
      $('find').dispatchEvent(new Event('input'));
    };
  });
}

function wireConnFilter(){
  $('p-conns').querySelectorAll('[data-cmode]').forEach(b => {
    b.onclick = () => { connMode = b.dataset.cmode; if (lastConns) renderConns(lastConns); };
  });
}

function renderTalkers(s){
  if (!s || !s.processes.length){ $('p-talkers').innerHTML = '<div class="empty">No traffic yet.</div>'; return; }
  const max = a => Math.max(1, ...a.map(x => x.in + x.out));
  const list = (items, key) => {
    const m = max(items);
    return '<div class="tlist">' + items.map(x => {
      const tot = x.in + x.out, pct = (tot/m*100).toFixed(1);
      const label = key === 'name' ? x.name : (x.name ? x.name : x.host);
      const sub = key === 'name' ? x.packets+' pkts'
                                 : (x.name ? x.host+' · ' : '') + x.packets+' pkts';
      return '<div class="t"><div class="top"><span class="nm" title="'+esc(label)+'">'+esc(label)+'</span>'+
             '<span class="by">'+hb(tot)+'</span></div>'+
             '<div class="bar"><i style="width:'+pct+'%"></i></div>'+
             '<div class="io"><span class="d">▼'+hb(x.in)+'</span> · <span class="u">▲'+hb(x.out)+
             '</span> · '+esc(sub)+'</div></div>';
    }).join('') + '</div>';
  };
  $('p-talkers').innerHTML =
    '<div class="sec"><h4>By process</h4>'  + list(s.processes, 'name') + '</div>' +
    '<div class="sec"><h4>By remote host</h4>' + list(s.hosts, 'host') + '</div>';
}

/* ================= timeline =================
   An hour of per-second totals from /api/timeline, one lane per program or
   per host. The server keeps them (the packet ring is far too short), keyed
   by what a conversation's packets have in common; the page draws lanes from
   those keys. So the display filter applies here as it does to the table,
   except for per-packet fields, which the timeline says it can't apply
   rather than quietly showing everything.

   The marks use a log scale shared by every lane. A linear one would make a
   200-byte check-in invisible next to a download, and the check-in is the
   thing worth seeing: a lane whose bursts come at a steady interval is
   marked "every ~Ns". Updaters and sync clients look like that; so does
   malware calling home. */
const TL_LANE = 26;
const TL_NO_FIELDS = {bytes: 'size', len: 'size', payload: 'payload size', info: 'Info',
                      pid: 'PID', stream: 'stream', seq: 'packet number'};
// var, not const: applyFind() redraws the timeline and can run while the
// page is still starting, before this line has been reached.
var TL = {gen: null, keys: [], secs: new Map(), newest: 0, now: 0, offline: false,
            win: 300, group: 'process', lanes: [], order: [], orderSig: '', orderAt: 0,
            sig: '', busy: false, bins: 0, start: 0};
var viewMode = 'table', tableTop = 0;
try {
  const saved = JSON.parse(localStorage.getItem('netscope-tl') || '{}');
  if ([60, 300, 900, 3600].includes(saved.win)) TL.win = saved.win;
  if (saved.group === 'host') TL.group = 'host';
} catch (e){}

function tlRecord(k){
  const [process, rhost, remote, local, dir, proto, rport, iface] = k;
  const out = dir === 'out';
  const r = {process, rhost, remote, dir, proto, iface,
             src: out ? local : remote, dst: out ? remote : local,
             sport: out ? null : rport, dport: out ? rport : null};
  r._hay = (process + ' ' + rhost + ' ' + remote + ' ' + local + ' ' + proto + ' ' +
            (rport == null ? '' : rport) + ' ' + iface).toLowerCase();
  return r;
}

async function tlFetch(){
  if (TL.busy) return;
  TL.busy = true;
  try {
    // The last second may still have been filling, so it is fetched again.
    const q = TL.gen == null ? '' : '?gen=' + TL.gen + '&kfrom=' + TL.keys.length +
              (TL.newest ? '&since=' + (TL.newest - 1) : '');
    const d = await (await api('/api/timeline' + q)).json();
    if (d.full || d.gen !== TL.gen){ TL.keys = []; TL.secs.clear(); TL.newest = 0; }
    if (d.kfrom !== TL.keys.length){ TL.gen = null; return; }   // start over next time
    TL.gen = d.gen;
    for (const k of d.keys) TL.keys.push(tlRecord(k));
    for (const [sec, list] of d.buckets) TL.secs.set(sec, list);
    TL.newest = d.newest; TL.now = d.now; TL.offline = d.offline;
    const cut = d.newest - d.retain;
    for (const sec of TL.secs.keys()) if (sec < cut) TL.secs.delete(sec);
  } catch (e){
  } finally { TL.busy = false; }
}

function tlUnsupported(text){
  const toks = tokenize(text), bad = [];
  for (let i = 0; i + 1 < toks.length; i++){
    const k = toks[i].toLowerCase();
    if (TL_NO_FIELDS[k] && /^(==|!=|=|~|!~|>=?|<=?)$/.test(toks[i + 1]) &&
        !bad.includes(TL_NO_FIELDS[k])) bad.push(TL_NO_FIELDS[k]);
  }
  return bad;
}

// Seconds between check-ins if a lane's bursts come at a steady interval,
// else 0. Bursts are runs of active seconds; the gaps between their starts
// must mostly agree, and the bursts must be short against the gap, so a
// steady stream with a few pauses doesn't qualify.
function tlRegular(secs){
  if (secs.length < 5) return 0;
  const starts = [], ends = [];
  for (const t of secs){
    if (!starts.length || t - ends[ends.length - 1] > 2){ starts.push(t); ends.push(t); }
    else ends[ends.length - 1] = t;
  }
  if (starts.length < 5) return 0;
  const gaps = [];
  for (let i = 1; i < starts.length; i++) gaps.push(starts[i] - starts[i - 1]);
  const med = gaps.slice().sort((a, b) => a - b)[gaps.length >> 1];
  if (med < 5) return 0;
  const tol = Math.max(2, med * 0.1);
  const fit = gaps.filter(g => Math.abs(g - med) <= tol).length;
  if (fit < 4 || fit / gaps.length < 0.8) return 0;
  const busy = starts.reduce((a, t, i) => a + ends[i] - t + 1, 0) / starts.length;
  return busy <= med / 3 ? med : 0;
}

function tlPeriod(sec){
  return sec < 120 ? '~' + sec + 's' : '~' + Math.round(sec / 60) + ' min';
}

function tlIsIP(s){ return /^[\d.]+$/.test(s) || s.includes(':'); }

// "Programs: Claude.exe 81%, svchost.exe 12%, ..." for a lane, by bytes in
// the window: who is behind a host, or where a program's traffic goes.
function tlShares(l, n){
  const all = [...l.pairs.values()].filter(p => p.bytes > 0).sort((a, b) => b.bytes - a.bytes);
  if (!all.length) return '';
  const tot = all.reduce((a, p) => a + p.bytes, 0);
  const pct = p => { const v = p.bytes / tot * 100; return v >= 1 ? Math.round(v) + '%' : '<1%'; };
  return (TL.group === 'host' ? 'Programs: ' : 'Hosts: ') +
    all.slice(0, n).map(p => p.name + ' ' + pct(p)).join(', ') +
    (all.length > n ? ', and ' + (all.length - n) + ' more' : '');
}

function tlCheckText(l){
  if (!l.checks.length) return 'Active every ' + tlPeriod(l.own) + ', like clockwork.';
  if (TL.group === 'host')
    return 'Contacted on a schedule by ' +
      l.checks.map(c => c.name + ' (every ' + tlPeriod(c.sec) + ')').join(', ') + '.';
  return 'Checks in with ' + l.checks.map(c => c.name + ' every ' + tlPeriod(c.sec)).join(', ') + '.';
}

function tlBuild(W){
  const bad = tlUnsupported($('find').value);
  const pass = TL.keys.map(r => !bad.length && rowVisible(r));
  const end = TL.offline ? TL.newest + 1 : Math.floor(TL.now) + 1;
  const start = end - TL.win;
  const B = Math.max(1, Math.min(W, TL.win));
  const byName = new Map();
  for (const [sec, list] of TL.secs){
    const inWin = sec >= start && sec < end;
    const j = Math.floor((sec - start) / TL.win * B);
    for (const [k, bytes, pkts] of list){
      if (!pass[k]) continue;
      const r = TL.keys[k];
      const host = r.rhost || r.remote || '(none)', proc = r.process || '-';
      const name = TL.group === 'host' ? host : proc;
      const other = TL.group === 'host' ? proc : host;
      let ln = byName.get(name);
      if (!ln){
        ln = {name, bytes: 0, pkts: 0, active: new Set(), bins: null, regular: 0,
              pairs: new Map(), checks: [], own: 0};
        byName.set(name, ln);
      }
      ln.active.add(sec);
      // The same lane split by what's on the other side: hosts for a program,
      // programs for a host. A check-in is often one pair inside a busy lane.
      let pr = ln.pairs.get(other);
      if (!pr){ pr = {name: other, bytes: 0, all: 0, active: new Set()}; ln.pairs.set(other, pr); }
      pr.active.add(sec);
      pr.all += bytes;
      if (!inWin) continue;
      pr.bytes += bytes;
      if (!ln.bins) ln.bins = new Float64Array(B * 3);
      ln.bins[j * 3 + (r.dir === 'out' ? 1 : 0)] += bytes;
      ln.bins[j * 3 + 2] += pkts;
      ln.bytes += bytes; ln.pkts += pkts;
    }
  }
  let lanes = [...byName.values()].filter(l => l.bins);
  const bySec = (a, b) => a - b;
  for (const l of lanes){
    l.own = tlRegular([...l.active].sort(bySec));
    // A program checking in with one host every 45 s, while it also does
    // other things, never looks regular as a whole: the other traffic fills
    // the gaps. So each program-and-host pair is checked on its own too.
    l.checks = [...l.pairs.values()]
      .filter(pr => pr.active.size >= 5 && pr.name !== '(none)')
      .map(pr => ({name: pr.name, sec: tlRegular([...pr.active].sort(bySec)), all: pr.all}))
      .filter(c => c.sec)
      .sort((a, b) => b.all - a.all);
    l.regular = l.own || (l.checks.length ? l.checks[0].sec : 0);
  }
  // Busiest first, but not re-ranked every second: lanes swapping places
  // under the pointer is noise. The order holds for ten seconds, or until
  // the window, grouping or filter changes; new lanes join at the end.
  const sig = TL.win + '|' + TL.group + '|' + $('find').value;
  lanes.sort((a, b) => b.bytes - a.bytes);
  if (sig === TL.orderSig && Date.now() - TL.orderAt < 10000){
    const rank = new Map(TL.order.map((n, i) => [n, i]));
    const busiest = new Map(lanes.map((l, i) => [l.name, i]));
    const at = l => rank.has(l.name) ? rank.get(l.name) : 1e9 + busiest.get(l.name);
    lanes.sort((a, b) => at(a) - at(b));
  } else { TL.orderSig = sig; TL.orderAt = Date.now(); }
  TL.order = lanes.map(l => l.name);
  TL.lanes = lanes; TL.bins = B; TL.start = start;
  return bad;
}

function tlDraw(){
  if (viewMode !== 'timeline') return;
  const cv = $('tlCanvas'), ax = $('tlAxis');
  const W = Math.max(60, Math.floor(ax.clientWidth || cv.clientWidth));
  const bad = tlBuild(W);
  const lanes = TL.lanes, B = TL.bins, binW = W / B;
  const cs = getComputedStyle($('tlview'));
  const col = n => cs.getPropertyValue(n).trim();
  const cIn = col('--series-in'), cOut = col('--series-out'), cGrid = col('--grid');
  const dpr = window.devicePixelRatio || 1;

  // Note, empty state.
  const what = TL.group === 'host' ? 'host' : 'program';
  const span = {60: 'minute', 300: '5 minutes', 900: '15 minutes', 3600: 'hour'}[TL.win];
  const regular = lanes.filter(l => l.regular).length;
  const note = $('tlNote');
  if (bad.length){
    note.className = 'tlnote warn';
    note.textContent = 'The filter uses ' + bad.join(', ') + ', which the timeline doesn\'t ' +
      'keep: it holds totals per program, host and port, not each packet.';
  } else {
    note.className = 'tlnote';
    note.textContent = lanes.length ? lanes.length + ' ' + what + (lanes.length === 1 ? '' : 's') +
      (regular ? ' · ' + regular + ' check' + (regular === 1 ? 's' : '') + ' in on a schedule' : '') : '';
  }
  const empty = $('tlEmpty');
  empty.style.display = lanes.length ? 'none' : 'block';
  empty.textContent = bad.length ? 'Nothing to draw with this filter.'
    : !TL.keys.length ? 'Waiting for packets…'
    : filterFn ? 'Nothing matching this filter in the last ' + span + '.'
    : 'No traffic in the last ' + span + '.';

  // Lane labels: rebuilt only when the lanes change, so hover and focus hold.
  const sigL = TL.group + '|' + lanes.map(l => l.name + '/' + l.regular + '/' +
    l.checks.map(c => c.name).join(',')).join('\n');
  const box = $('tlLabels');
  if (sigL !== TL.sig){
    TL.sig = sigL;
    const had = document.activeElement && box.contains(document.activeElement)
      ? document.activeElement.dataset.name : null;
    box.innerHTML = lanes.map((l, i) =>
      '<button class="ln' + (/^[-(]/.test(l.name) ? ' sys' : '') + '" data-i="' + i + '" data-name="' +
      esc(l.name) + '"><span class="nm">' + esc(l.name) + '</span>' +
      (l.regular ? '<span class="rg" title="' + esc(tlCheckText(l) +
        '\nUpdaters and sync clients check in like this; so does malware calling home.' +
        (l.checks.length ? '\nClick to filter to ' + (l.checks.length > 1 ? 'the first.' : 'it.') : '')) +
        '">every ' + tlPeriod(l.regular) +
        (l.checks.length ? ' · ' + esc(l.checks[0].name) : '') + '</span>' : '') +
      '<span class="tot"></span></button>').join('');
    if (had){
      const b = [...box.children].find(x => x.dataset.name === had);
      if (b) b.focus({preventScroll: true});
    }
  }
  [...box.children].forEach((b, i) => {
    const l = lanes[i];
    b.querySelector('.tot').textContent = hb(l.bytes);
    b.title = l.name + ' — ' + hb(l.bytes) + ', ' + l.pkts.toLocaleString() +
      ' packets in the last ' + span + '.\n' + tlShares(l, 5) +
      (l.regular ? '\n' + tlCheckText(l) : '') +
      '\nClick to filter to it; right-click to hide it.';
  });

  // Lanes.
  const H = Math.max(1, lanes.length * TL_LANE);
  cv.style.height = H + 'px';
  cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
  const g = cv.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, W, H);
  let max = 1;
  for (const l of lanes) for (let j = 0; j < B; j++)
    max = Math.max(max, l.bins[j * 3], l.bins[j * 3 + 1]);
  const lmax = Math.log1p(max), half = TL_LANE / 2 - 3;
  const ticks = tlTicks(W);
  g.fillStyle = cGrid;
  for (const t of ticks) g.fillRect(Math.round(t.x), 0, 1, H);
  const bw = binW > 3 ? binW - 1 : Math.max(1, binW);
  lanes.forEach((l, i) => {
    const y0 = i * TL_LANE, mid = y0 + TL_LANE / 2;
    g.fillStyle = cGrid;
    g.fillRect(0, y0 + TL_LANE - 1, W, 1);
    g.fillRect(0, Math.round(mid), W, 1);
    for (let j = 0; j < B; j++){
      const x = j * binW, vin = l.bins[j * 3], vout = l.bins[j * 3 + 1];
      // At least a pixel for any traffic at all: one small packet is still
      // a check-in, and that is what this view is for.
      if (vout > 0){
        const h = Math.max(1, Math.round(Math.log1p(vout) / lmax * half));
        g.fillStyle = cOut; g.fillRect(x, Math.round(mid) - h, bw, h);
      }
      if (vin > 0){
        const h = Math.max(1, Math.round(Math.log1p(vin) / lmax * half));
        g.fillStyle = cIn; g.fillRect(x, Math.round(mid) + 1, bw, h);
      }
    }
  });

  // Axis.
  ax.width = Math.round(W * dpr); ax.height = Math.round(22 * dpr);
  const a = ax.getContext('2d');
  a.setTransform(dpr, 0, 0, dpr, 0, 0);
  a.clearRect(0, 0, W, 22);
  a.font = '10px ' + col('--mono');
  a.textBaseline = 'middle';
  for (const t of ticks){
    a.fillStyle = cGrid; a.fillRect(Math.round(t.x), 15, 1, 7);
    a.fillStyle = col('--faint');
    const w = a.measureText(t.label).width;
    a.fillText(t.label, Math.max(0, Math.min(W - w, t.x - w / 2)), 9);
  }
}

// Tick marks on round local times, at least ~90px apart.
function tlTicks(W){
  const pxPerSec = W / TL.win;
  const step = [5, 10, 15, 30, 60, 120, 300, 600, 900, 1800].find(s => s * pxPerSec >= 90) || 3600;
  const tz = new Date().getTimezoneOffset() * 60;
  const out = [];
  for (let t = Math.ceil((TL.start - tz) / step) * step + tz; t <= TL.start + TL.win; t += step){
    const d = new Date(t * 1000), p = n => String(n).padStart(2, '0');
    out.push({x: (t - TL.start) * pxPerSec,
              label: p(d.getHours()) + ':' + p(d.getMinutes()) + (step < 60 ? ':' + p(d.getSeconds()) : '')});
  }
  return out;
}

function tlLaneRec(name){
  if (TL.group === 'process') return {process: name};
  return tlIsIP(name) ? {dir: 'out', dst: name} : {rhost: name};
}

function setView(v){
  const tl = v === 'timeline';
  if (tl === (viewMode === 'timeline')) return;
  if (tl) tableTop = $('tw').scrollTop;
  viewMode = tl ? 'timeline' : 'table';
  document.body.classList.toggle('tlmode', tl);
  $('tlview').style.display = tl ? '' : 'none';
  $('vTable').classList.toggle('on', !tl); $('vTable').setAttribute('aria-pressed', !tl);
  $('vTime').classList.toggle('on', tl);   $('vTime').setAttribute('aria-pressed', tl);
  try { localStorage.setItem('netscope-view', viewMode); } catch (e){}
  if (tl){ tlDraw(); tlFetch().then(tlDraw); }
  else {
    $('tlTip').classList.remove('on');
    const w = $('tw');
    w.scrollTop = $('follow').checked ? w.scrollHeight : tableTop;
    refit();
  }
}

function tlSetting(){
  document.querySelectorAll('#tlWin button').forEach(b =>
    b.classList.toggle('on', Number(b.dataset.w) === TL.win));
  document.querySelectorAll('#tlGroup button').forEach(b =>
    b.classList.toggle('on', b.dataset.g === TL.group));
  try { localStorage.setItem('netscope-tl', JSON.stringify({win: TL.win, group: TL.group})); } catch (e){}
}

$('vTable').onclick = () => setView('table');
$('vTime').onclick = () => setView('timeline');
document.querySelectorAll('#tlWin button').forEach(b => b.onclick = () => {
  TL.win = Number(b.dataset.w); tlSetting(); tlDraw();
});
document.querySelectorAll('#tlGroup button').forEach(b => b.onclick = () => {
  TL.group = b.dataset.g; tlSetting(); $('tlScroll').scrollTop = 0; tlDraw();
});
tlSetting();

$('tlLabels').addEventListener('click', e => {
  const b = e.target.closest && e.target.closest('.ln');
  if (!b) return;
  const name = b.dataset.name;
  if (name === '(none)') return;
  const fieldOf = (n, g) => g === 'process' ? 'process' : tlIsIP(n) ? 'ip' : 'host';
  // The "every ~Ns" box narrows to the pair that checks in, not just the lane.
  const l = TL.lanes.find(x => x.name === name);
  const pair = e.target.closest('.rg') && l && l.checks.length ? l.checks[0].name : null;
  addClause(fieldOf(name, TL.group), '==', name);
  if (pair) addClause(fieldOf(pair, TL.group === 'process' ? 'host' : 'process'), '==', pair);
});
$('tlLabels').addEventListener('contextmenu', e => {
  const b = e.target.closest && e.target.closest('.ln');
  if (!b || b.dataset.name === '(none)') return;
  e.preventDefault();
  let x = e.clientX, y = e.clientY;
  if (!x && !y){ const r = b.getBoundingClientRect(); x = r.left + 20; y = r.bottom; }
  openRowMenu(tlLaneRec(b.dataset.name), x, y);
});

$('tlCanvas').addEventListener('mousemove', e => {
  const cv = $('tlCanvas'), r = cv.getBoundingClientRect(), tip = $('tlTip');
  const i = Math.floor((e.clientY - r.top) / TL_LANE), l = TL.lanes[i];
  const j = Math.floor((e.clientX - r.left) / (r.width / TL.bins));
  if (!l || j < 0 || j >= TL.bins){ tip.classList.remove('on'); return; }
  const per = TL.win / TL.bins, t0 = TL.start + j * per;
  const f = t => new Date(t * 1000).toLocaleTimeString([], {hour12: false});
  const vin = l.bins[j * 3], vout = l.bins[j * 3 + 1], n = l.bins[j * 3 + 2];
  tip.innerHTML = '<b>' + esc(l.name) + '</b><br>' + esc(f(t0)) +
    (per >= 2 ? '–' + esc(f(t0 + per)) : '') + '<br>' +
    (n ? '▲ ' + esc(hb(vout)) + ' &nbsp;▼ ' + esc(hb(vin)) + ' &nbsp;' + n + ' pkt' + (n === 1 ? '' : 's')
       : 'nothing') +
    '<br><span style="color:var(--dim)">' + esc(tlShares(l, 3)) + '</span>' +
    (l.regular ? '<br>' + esc(tlCheckText(l)) : '');
  const v = $('tlview').getBoundingClientRect();
  tip.classList.add('on');
  const x = e.clientX - v.left + 14, y = e.clientY - v.top + 14;
  tip.style.left = Math.min(x, v.width - tip.offsetWidth - 6) + 'px';
  tip.style.top = (y + tip.offsetHeight > v.height ? y - tip.offsetHeight - 20 : y) + 'px';
});
$('tlCanvas').addEventListener('mouseleave', () => $('tlTip').classList.remove('on'));
try { new ResizeObserver(() => tlDraw()).observe($('tlScroll')); } catch (e){}

/* ---------------- sparkline ---------------- */

function drawSpark(tl){
  const c = $('spark'), g = c.getContext('2d');
  const W = c.width, H = c.height;
  g.clearRect(0,0,W,H);
  if (!tl || !tl.length) return;
  const data = tl.slice(-60);
  const max = Math.max(1, ...data.map(d => Math.max(d.in, d.out)));
  const bw = W / 60;
  const cs = getComputedStyle(document.documentElement);
  const cIn = cs.getPropertyValue('--in').trim(), cOut = cs.getPropertyValue('--out').trim();
  data.forEach((d, i) => {
    const x = W - (data.length - i) * bw;
    const hi = (d.in  / max) * (H/2 - 1);
    const ho = (d.out / max) * (H/2 - 1);
    g.fillStyle = cIn;  g.fillRect(x, H/2, Math.max(1,bw-1), hi);
    g.fillStyle = cOut; g.fillRect(x, H/2 - ho, Math.max(1,bw-1), ho);
  });
  g.strokeStyle = cs.getPropertyValue('--line').trim();
  g.beginPath(); g.moveTo(0,H/2); g.lineTo(W,H/2); g.stroke();
}

/* ---------------- status + polling ---------------- */

function renderStatus(st){
  lastStatus = st;
  $('ver').textContent = 'v' + st.version;
  $('demoBadge').style.display = st.demo ? '' : 'none';
  const dot = $('dot');
  dot.className = 'dot' + (st.error ? ' err' : st.running ? ' live' : '');
  let txt;
  if (st.source) txt = 'offline · <b>' + esc(st.source) + '</b> · ' +
                       (st.packets||0).toLocaleString() + ' packets';
  else if (st.running) txt = st.demo ? 'generating demo traffic'
        : (st.multi
            ? 'capturing on <b>' + st.ifaces.length + ' interfaces</b> · ' +
              esc(st.ifaces.join(', ')).slice(0, 60)
            : 'capturing on <b>' + esc(st.iface || '?') + '</b>');
  else txt = 'stopped';
  if (st.filter) txt += ' · filter <b>' + esc(st.filter) + '</b>';
  if (!st.demo && !st.admin) txt += ' · <b style="color:#f0883e">not elevated</b>';
  // Losing packets invalidates every count on the page, so it is said here
  // rather than left to a number in the footer nobody is looking at.
  const cap = st.capture;
  if (cap && cap.dropped > 0)
    txt += ' · <b style="color:#f0883e">dropping ' + cap.loss_pct + '% of packets</b>';
  $('statusText').innerHTML = txt;
  syncIface(st);
  announceNewIfaces(st);
  $('toggle').textContent = st.running ? 'Stop' : 'Start';
  $('toggle').classList.toggle('on', !st.running);
  if (st.error){ $('errBox').style.display = ''; $('errBox').textContent = 'Capture error: ' + st.error; }
  else $('errBox').style.display = 'none';
  tabCount($('nFiles'), st.objects);
  tabCount($('nDhcp'), st.dhcp_leases);

  const a = st.alerts || {};
  const na = $('nAlerts');
  tabCount(na, a.total);
  na.classList.toggle('high', (a.high || 0) > 0);
}

function renderStats(s){
  lastStats = s;
  $('sPk').textContent = s.total_packets.toLocaleString();
  $('sIn').textContent = hb(s.total_in);
  $('sOut').textContent = hb(s.total_out);
  const now = Date.now()/1000, tot = s.total_in + s.total_out;
  if (prevTotals !== null && now > prevTime)
    $('sRate').textContent = hb((tot - prevTotals) / (now - prevTime)) + '/s';
  prevTotals = tot; prevTime = now;
  if (s.attribution_pct !== undefined){
    $('sAttr').textContent = s.attribution_pct.toFixed(0) + '%';
    $('sAttr').title = s.attributed.toLocaleString() + ' of ' +
      s.total_packets.toLocaleString() + ' packets tied to a program';
  }
  $('sProto').innerHTML = Object.entries(s.protocols).slice(0,7)
    .map(([k,v]) => '<span class="pr '+esc(k)+'" style="margin-left:5px">'+esc(k)+' '+v+'</span>').join('');
  // The tooltip always says what the driver reports, so a clean capture is
  // distinguishable from one whose statistics could not be read at all —
  // otherwise both look identical, which makes the warning untestable.
  const cap = lastStatus && lastStatus.capture;
  $('kvPk').title = cap
    ? 'Driver received ' + cap.received.toLocaleString() + ', discarded ' +
      cap.dropped.toLocaleString() + ' (' + cap.loss_pct + '%). NetScope has ' +
      'decoded ' + s.total_packets.toLocaleString() + '.'
    : 'Packets NetScope has decoded. The capture driver is not reporting ' +
      'statistics on this machine, so dropped packets cannot be detected.';
  if (cap && cap.dropped > 0){
    $('kvDrop').style.display = '';
    $('sDrop').textContent = cap.dropped.toLocaleString() +
      ' (' + cap.loss_pct + '%)';
  } else {
    $('kvDrop').style.display = 'none';
    $('sDrop').textContent = '';      // don't leave a stale count in the DOM
  }
  drawSpark(s.timeline);
  if (activeTab() === 'talkers') renderTalkers(s);
}

async function poll(){
  try{
    const r = await api('/api/state?since=' + lastSeq);
    const d = await r.json();
    renderStatus(d.status);
    renderStats(d.stats);
    if (viewMode === 'timeline' && !paused) tlFetch().then(tlDraw);
    if (!paused && d.packets.length){
      const tb = $('rows'), w = $('tw'), frag = document.createDocumentFragment();
      const following = $('follow').checked;
      let shown = 0;
      for (const p of d.packets){
        lastSeq = Math.max(lastSeq, p.seq);
        const tr = addRow(p);
        if (!rowVisible(p)) tr.style.display = 'none'; else shown++;
        frag.appendChild(tr);
      }
      tb.appendChild(frag);

      // Trimming the oldest rows shortens the content *above* the viewport, so
      // everything below slides up while scrollTop stays where it was — the
      // rows you were reading walk off the top of the screen on their own.
      // Nothing here scrolls, which is why turning off follow looked broken.
      // Measure what was removed and take the same amount off scrollTop.
      let trimmed = 0;
      if (tb.children.length > MAX_ROWS){
        const hBefore = tb.offsetHeight;
        while (tb.children.length > MAX_ROWS){
          records.delete(Number(tb.firstChild.dataset.seq));
          tb.removeChild(tb.firstChild);
        }
        trimmed = hBefore - tb.offsetHeight;
      }

      if (shown) $('emptyMsg').style.display = 'none';
      updateCount();
      if (following) w.scrollTop = w.scrollHeight;
      else if (trimmed > 0) w.scrollTop = Math.max(0, w.scrollTop - trimmed);
    } else if (d.packets.length){
      for (const p of d.packets) lastSeq = Math.max(lastSeq, p.seq);
    }
  }catch(e){
    $('dot').className = 'dot err';
    $('statusText').textContent = 'lost connection to NetScope';
  }
}

/* ---------------- controls ---------------- */

function control(body){
  return api('/api/control', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)
  }).then(r=>r.json()).then(d => renderStatus(d.status));
}

function activeTab(){ return document.querySelector('.tab.on').dataset.p; }

function refreshTab(name){
  if (name === 'conns') return api('/api/connections')
    .then(r=>r.json()).then(renderConns).catch(()=>{});
  if (name === 'talkers') renderTalkers(lastStats);
  else if (name === 'files')   api('/api/objects').then(r=>r.json()).then(renderFiles).catch(()=>{});
  else if (name === 'streams') api('/api/streams').then(r=>r.json()).then(renderStreams).catch(()=>{});
  else if (name === 'dhcp')    api('/api/dhcp').then(r=>r.json()).then(renderDhcp).catch(()=>{});
  else if (name === 'alerts')  return api('/api/alerts').then(r=>r.json()).then(d =>
    alertView === 'log' && d.log_days ? loadAlertLog(false).then(() => d) : d)
    .then(renderAlerts).catch(()=>{});
  else if (name === 'history') return loadHistory(false);
}

/* History is the tab the page opens on and the one people leave up, so it
   refreshes itself on the database's own flush beat rather than only when its
   tab is clicked — it used to show the page-load numbers for hours, and a
   failed first fetch left "Loading history…" up for good. A redraw rebuilds
   the whole pane, so the automatic one happens only when the data changed,
   waits while a column's tooltip is showing, and keeps any Table view you
   opened, where you had scrolled to, and which control had keyboard focus.
   It also waits while text in the pane is selected — while capturing, the
   data changes on every beat, so otherwise nothing could be copied from it.
   A newer request supersedes an older
   one still in flight, so a slow refresh can't paint over a 7d/30d/90d click. */
const HISTORY_REFRESH_MS = 10000;
let histSeen = null, histSeq = 0, histInflight = 0;
function loadHistory(auto){
  if (auto && histInflight) return Promise.resolve();
  const seq = ++histSeq;
  histInflight++;
  return api('/api/history?days='+histDays).then(r=>r.text()).then(t => {
    if (seq !== histSeq) return;
    const key = t + JSON.stringify((lastStatus && lastStatus.autostart) || null);
    if (auto && (key === histSeen || document.querySelector('#p-history .tip.on') || histSelecting())) return;
    const d = JSON.parse(t);
    histSeen = key;
    redrawHistory(d);
  }).catch(()=>{}).finally(() => { histInflight--; });
}

// Table views are remembered by their section's heading, not their position:
// a section appearing (the first program recorded) would shift every index.
function histSecName(x){
  const h = x.closest('.sec') && x.closest('.sec').querySelector('h4');
  return h ? h.textContent : '';
}
function histSelecting(){
  const s = window.getSelection();
  return !!(s && !s.isCollapsed && s.rangeCount &&
            $('p-history').contains(s.getRangeAt(0).commonAncestorContainer));
}
// Focus is found again the same way: by section, tag and label, since the
// element itself is gone once the pane is rebuilt.
function histFocusKey(x){
  return [histSecName(x), x.tagName, x.dataset.days || '', x.dataset.i || '', x.id,
          x.textContent.trim()].join('|');
}
function redrawHistory(d){
  const pane = $('p-history'), top = pane.scrollTop;
  const open = new Set([...pane.querySelectorAll('details')].filter(x => x.open).map(histSecName));
  const act = document.activeElement;
  const focus = act && act !== pane && pane.contains(act) ? histFocusKey(act) : null;
  // Half-typed text in the pane's own fields, and where the caret was.
  const typed = [...pane.querySelectorAll('input[id],select[id]')].map(x =>
    [x.id, x.value, x.selectionStart, x.selectionEnd]);
  renderHistory(d);
  pane.querySelectorAll('details').forEach(x => { if (open.has(histSecName(x))) x.open = true; });
  for (const [id, v, a, b] of typed){
    const x = $(id);
    if (x && pane.contains(x)){
      x.value = v;
      if (a != null) try { x.setSelectionRange(a, b); } catch (e){}
    }
  }
  if (focus){
    const el = [...pane.querySelectorAll(act.tagName)].find(x => histFocusKey(x) === focus);
    if (el) el.focus({preventScroll: true});
  }
  pane.scrollTop = top;
}

/* ---------------- not recorded ----------------
   Programs and hosts kept out of the history database. Adding one stops
   future writes; erasing what is already there is a second, confirmed step,
   since "stop recording this" and "delete what you have" are different
   decisions. Removing one only resumes recording. */
let histExMsg = '';

function excludeCall(body){
  return api('/api/control', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)}).then(r => r.json()).then(d => { renderStatus(d.status); return d; });
}

function addExclusion(kind, pattern){
  const pat = String(pattern || '').trim().toLowerCase();
  if (!pat) return Promise.resolve();
  return excludeCall({action: 'history_exclude', kind, pattern: pat}).then(d => {
    if (!d.listed){
      histExMsg = 'The list is full. Remove an entry first.';
      return refreshTab('history');
    }
    histExMsg = pat + ' is no longer recorded.';
    if ($('exPat') && $('exPat').value.trim().toLowerCase() === pat) $('exPat').value = '';
    const ask = kind === 'host'
      ? 'Also erase what is already recorded for ' + pat + ' (and its subdomains)?'
      : 'Also erase what is already recorded for ' + pat + '?\n\nIts usage is erased. ' +
        'The hosts it talked to stay: history does not record which program ' +
        'contacted a host, so they cannot be told apart from anyone else\'s.';
    if (!confirm(ask)) return refreshTab('history');
    return excludeCall({action: 'history_purge', kind, pattern: pat}).then(r => {
      const g = r.purged || {}, bits = [];
      const n = (k, one) => g[k] ? bits.push(g[k] + ' ' + one + (g[k] === 1 ? '' : 's')) : 0;
      n('usage', 'hourly usage row'); n('hosts', 'host'); n('alerts', 'alert');
      histExMsg = pat + ' is no longer recorded. Erased ' +
                  (bits.length ? bits.join(', ') : 'nothing, none was recorded') + '.';
      return refreshTab('history');
    });
  }).catch(() => { histExMsg = 'Could not reach NetScope.'; return refreshTab('history'); });
}

function removeExclusion(kind, pattern){
  return excludeCall({action: 'history_exclude', kind, pattern, remove: true}).then(() => {
    histExMsg = pattern + ' is recorded again from now on.';
    return refreshTab('history');
  }).catch(() => {});
}

function showTab(name){
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t.dataset.p === name));
  document.querySelectorAll('.pane').forEach(p => p.classList.toggle('on', p.id === 'p-'+name));
  refreshTab(name);
}
document.querySelectorAll('.tab').forEach(t => t.onclick = () => showTab(t.dataset.p));

$('apply').onclick = () => control({action:'restart', iface:$('iface').value, filter:$('bpf').value});
$('toggle').onclick = () => {
  const starting = $('toggle').textContent === 'Start';
  control(starting ? {action:'start', iface:$('iface').value, filter:$('bpf').value}
                   : {action:'stop'});
};
$('clear').onclick = () => {
  control({action:'clear'});
  $('rows').innerHTML = ''; records.clear(); lastSeq = 0; prevTotals = null;
  TL.gen = null; TL.keys = []; TL.secs.clear(); TL.newest = 0; tlDraw();
  $('p-detail').innerHTML = '<div class="empty">Click a packet to inspect it.</div>';
  $('emptyMsg').style.display = 'block';
  selected = null;
  $('nPkt').textContent = ''; $('nPkt').classList.add('zero');
};
$('find').oninput = applyFind;
$('findClear').onclick = () => { $('find').value = ''; applyFind(); $('find').focus(); };
$('bpf').onkeydown = e => { if (e.key === 'Enter') $('apply').click(); };
$('theme').onclick = () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try{ localStorage.setItem('netscope-theme', next); }catch(e){}
  drawSpark(lastStats && lastStats.timeline);
  tlDraw();
};
/* Pause was a spacebar shortcut with no control and no label — the only sign
   it had happened was the status text dimming. "Follow" was then the only
   visible thing that sounded like it might stop the table moving, which is
   not what it does. Both now have a button and a tooltip saying which is
   which: pause stops rows arriving, follow stops the view chasing them. */
function setPaused(v){
  paused = v;
  const b = $('pause');
  b.textContent = paused ? 'Resume' : 'Pause';
  b.classList.toggle('on', paused);
  $('statusText').style.opacity = paused ? .5 : 1;
  $('fcount').textContent = paused
    ? 'paused — the capture is still running, the ' +
      (viewMode === 'timeline' ? 'timeline' : 'table') + ' is not updating'
    : '';
  if (!paused) updateCount();
}
$('pause').onclick = () => setPaused(!paused);

// Space pauses the feed unless a control was reached from the keyboard. It
// used to take space from focused buttons too, so no button on the page could
// be pressed with space. But a button clicked with the mouse keeps focus as
// well, and handing it space would make "click Clear, press space to pause"
// clear again. :focus-visible can't tell the two apart — Chrome turns it on
// for a mouse-focused button as soon as any key is pressed — so how focus
// arrived is noted here: within a moment of a pointer press means the mouse,
// and any pointer press ends keyboard focus even on an already-focused button.
const SPACE_OWNERS = 'button, summary, a[href], [role=button], [role=menuitem], [role=checkbox]';
let lastPointer = -Infinity, keyFocus = null;   // not 0: now() counts from page load
document.addEventListener('pointerdown', () => { lastPointer = performance.now(); keyFocus = null; }, true);
document.addEventListener('focusin', e => {
  keyFocus = performance.now() - lastPointer < 500 ? null : e.target;
}, true);
document.addEventListener('keydown', e => {
  const t = e.target;
  if (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA' ||
      t.isContentEditable) return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === ' ' && t === keyFocus && t.closest && t.closest(SPACE_OWNERS)) return;
  if (e.key === ' '){ e.preventDefault(); setPaused(!paused); }
  if (e.key === '/'){ e.preventDefault(); $('find').focus(); }
});

try{
  const t = localStorage.getItem('netscope-theme');
  if (t) document.documentElement.dataset.theme = t;
}catch(e){}

function loadInterfaces(){
  return api('/api/interfaces').then(r=>r.json()).then(d => {
    const sel = $('iface');
    sel.innerHTML = '<option value="all">All active interfaces</option>' +
      d.interfaces.map(i =>
        '<option value="'+esc(i.name)+'">'+esc((i.description||i.name).slice(0,44)) +
        (i.ip ? '  ('+esc(i.ip)+')' : '') + '</option>').join('');
    sel.value = (d.spec === 'all') ? 'all'
              : ((d.active && d.active.length === 1) ? d.active[0] : (d.current || 'all'));
  }).catch(()=>{});
}

/* Keep the selector honest. It used to be set once at page load, so switching
   the capture interface from anywhere else left the dropdown showing the old
   adapter — and pressing Apply would then move capture to that stale choice.
   Never touched while the user has the control focused. */
/* Adapters attached to a running capture are worth saying out loud: the
   capture silently covering more than it did a minute ago is good news, but
   only if you know it happened. Each is announced once. */
const announcedIfaces = new Set();
function announceNewIfaces(st){
  for (const n of (st.new_ifaces || [])){
    if (announcedIfaces.has(n)) continue;
    announcedIfaces.add(n);
    flash('now also capturing ' + n);
    loadInterfaces();
  }
}

function syncIface(st){
  const sel = $('iface');
  if (document.activeElement === sel) return;
  const want = st.multi ? 'all'
             : ((st.ifaces && st.ifaces.length === 1) ? st.ifaces[0] : st.iface);
  if (!want || sel.value === want) return;
  if (Array.from(sel.options).some(o => o.value === want)) sel.value = want;
  else loadInterfaces();
}

loadInterfaces();

/* Adapters come and go while the app is running — Wi-Fi associates after a
   reboot, a VPN connects, a phone tethers. The list used to be fetched once
   at page load, so any of those stayed missing from the dropdown until you
   reloaded the page. Re-fetched on a slow beat, and never while you have the
   control open, which would yank the menu shut under your cursor. */
setInterval(() => {
  if (document.activeElement !== $('iface')) loadInterfaces();
}, 15000);

try { if (localStorage.getItem('netscope-view') === 'timeline') setView('timeline'); } catch (e){}
poll();
setInterval(poll, 700);
// History is the tab the page opens on, so fetch it now rather than waiting
// for a click that will never come.
refreshTab(activeTab());
// The Files and Streams lists are heavier, so refresh them on a slower beat.
setInterval(() => {
  const t = activeTab();
  if (t === 'files' || t === 'streams' || t === 'alerts' || t === 'conns')
    refreshTab(t);
}, 2500);
setInterval(() => { if (activeTab() === 'history') loadHistory(true); }, HISTORY_REFRESH_MS);

/* ---------------- pcap save / open ---------------- */

/* Saving anything used to be silent, and silence reads as failure: click Save,
   nothing happens, click again, get two identical files a second apart. Both
   halves are fixed here — say what was saved, and refuse an immediate repeat
   of the *same* save while still allowing two different files in quick
   succession. */
let _flashTimer = null;
function flash(msg){
  const f = $('flash');
  f.textContent = msg;
  f.classList.add('on');
  clearTimeout(_flashTimer);
  _flashTimer = setTimeout(() => f.classList.remove('on'), 3400);
}

const SAVE_GUARD_MS = 1800;
const _lastSave = {};                 // key -> {t, name}
function saveOnce(key, name, href){
  const prev = _lastSave[key];
  if (prev && Date.now() - prev.t < SAVE_GUARD_MS){
    flash('already saved ' + prev.name + ' — check your Downloads folder');
    return;
  }
  _lastSave[key] = {t: Date.now(), name};
  const a = document.createElement('a');
  a.href = href;
  // Naming the file here rather than leaving it to Content-Disposition means
  // the message below can state the real filename instead of guessing at one.
  a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  flash('saved ' + name + ' to your Downloads folder');
}

function pcapStamp(){
  const d = new Date(), p = n => String(n).padStart(2, '0');
  return '' + d.getFullYear() + p(d.getMonth()+1) + p(d.getDate()) + '-' +
         p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}

$('savePcap').onclick = () => {
  saveOnce('pcap', 'netscope-' + pcapStamp() + '.pcap',
           '/api/export.pcap?t=' + encodeURIComponent(TOKEN));
};
$('openPcap').onclick = () => $('pcapFile').click();
$('pcapFile').onchange = async () => {
  const f = $('pcapFile').files[0];
  if (!f) return;
  $('statusText').textContent = 'loading ' + f.name + '…';
  try {
    const r = await api('/api/import?name=' + encodeURIComponent(f.name),
                        {method:'POST', body: f});
    const d = await r.json();
    if (d.error){ $('errBox').style.display = ''; $('errBox').textContent = d.error; return; }
    $('rows').innerHTML = ''; records.clear(); lastSeq = 0; prevTotals = null;
    $('p-detail').innerHTML = '<div class="empty">Click a packet to inspect it.</div>';
    $('nPkt').textContent = ''; $('nPkt').classList.add('zero');
    poll();
  } catch (e){
    $('errBox').style.display = ''; $('errBox').textContent = 'Import failed: ' + e;
  } finally {
    $('pcapFile').value = '';
  }
};

$('resetCols').onclick = () => {
  colW = COL_DEF.slice(); colCustom = false;
  applyCols(); saveCols();
};

loadCols();
loadColVis();
buildColMenu();
applyColVis();
$('colsBtn').onclick = e => {
  const m = $('colmenu'), b = e.currentTarget.getBoundingClientRect();
  buildColMenu();
  m.style.left = Math.max(8, b.right - 190) + 'px';
  m.style.top  = (b.bottom + 4) + 'px';
  m.classList.toggle('on');
  e.stopPropagation();
};
document.addEventListener('click', e => {
  if (!e.target.closest || !e.target.closest('.colmenu')) $('colmenu').classList.remove('on');
});
loadPresets();
applyFind();
</script>
</body>
</html>
"""
