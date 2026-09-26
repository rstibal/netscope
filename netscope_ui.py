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
/* Eight tabs with 10px sides needed 563px against the 583px the 600px panel
   gives them, so the first packet badge wrapped Talkers onto a second line
   and every pane jumped down a row. At 6px, and with badges capped in width
   (tabCount(), frameBadge()), the strip takes the same number of lines with
   or without badges at every panel width: one at 600, two at 430 and 360. */
.tab{padding:6px 6px;border-radius:6px 6px 0 0;color:var(--dim);cursor:pointer;
  font:600 12px var(--sans);border:1px solid transparent;border-bottom:none;
  white-space:nowrap;display:flex;align-items:center;gap:4px}
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
  overflow:hidden;display:flex;gap:2px}
.hbar .track i{display:block;height:100%}
.hbar .track i:first-child{border-radius:2px 0 0 2px}
.hbar .track i:last-child{border-radius:0 2px 2px 0}
.dayrange{display:flex;gap:6px;align-items:center;margin-bottom:10px}
.dayrange button{padding:3px 10px;font:600 11px var(--sans)}
.dayrange button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
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
    $('mId').textContent = esc(o.name);
    $('mMeta').textContent = o.ctype + '  ·  ' + hb(o.size);
    let h = '';
    if (o.clipped) h += '<div class="warnbar">Preview shows the first 64 KB. Use Save for the whole file.</div>';
    if (/^image\//.test(o.ctype)){
      h += '<img class="previewimg" src="data:'+o.ctype+';base64,'+o.b64+'">';
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

function hbars(rows, keyName){
  const max = Math.max(1, ...rows.map(r => r.bytes_in + r.bytes_out));
  return rows.map(r => {
    const tot = r.bytes_in + r.bytes_out;
    const pin = (r.bytes_in / max) * 100, pout = (r.bytes_out / max) * 100;
    return '<div class="hbar">' +
      '<span class="nm" title="'+esc(r[keyName])+'">'+esc(r[keyName])+'</span>' +
      '<span style="color:var(--dim)">'+esc(hb(tot))+'</span>' +
      '<span class="track">' +
        (pin  > 0 ? '<i style="width:'+pin.toFixed(2)+'%;background:var(--series-in)"></i>'  : '') +
        (pout > 0 ? '<i style="width:'+pout.toFixed(2)+'%;background:var(--series-out)"></i>' : '') +
      '</span></div>';
  }).join('');
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

  let h = '<div class="dayrange">' +
    [7,30,90].map(n => '<button class="btn-sm'+(n===histDays?' on':'')+
      '" data-days="'+n+'">'+n+'d</button>').join('') +
    '<span style="color:var(--faint);font:11px var(--mono);margin-left:6px">'+
    (s.since ? 'since '+esc(s.since) : 'no data yet')+'</span></div>';

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

  if (d.processes.length){
    h += '<div class="sec"><h4>By program · last '+d.days+' days</h4>' +
         hbars(d.processes, 'name') +
         tableView(d.processes, [
           {h:'Program', f:r=>r.name},
           {h:'▼ received', n:1, f:r=>hb(r.bytes_in)},
           {h:'▲ sent', n:1, f:r=>hb(r.bytes_out)},
           {h:'Packets', n:1, f:r=>Number(r.packets).toLocaleString()}]) + '</div>';
  }

  if (d.hosts.length){
    h += '<div class="sec"><h4>By host · all time</h4>' + hbars(d.hosts, 'host') +
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

  if (d.alerts.length){
    h += '<div class="sec"><h4>Alert history</h4>' + d.alerts.slice(0,40).map(a =>
      '<div class="alert '+esc(a.severity)+'"><div class="t">'+
      '<span class="ti">'+esc(a.title)+'</span><span class="when">'+
      esc(new Date(a.ts*1000).toLocaleString())+'</span></div>'+
      '<div class="d">'+esc(a.detail)+'</div></div>').join('') + '</div>';
  }

  if (d.sessions.length){
    h += '<div class="sec"><h4>Recent sessions</h4>' + tableView(d.sessions, [
      {h:'Started', f:r=>new Date(r.started*1000).toLocaleString()},
      {h:'Interface', f:r=>r.iface||'—'},
      {h:'Version', f:r=>r.version||'—'},
      {h:'Packets', n:1, f:r=>Number(r.packets).toLocaleString()}]) + '</div>';
  }

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
  const fl = $('histFlush');
  if (fl) fl.onclick = () => control({action:'history_flush'})
    .then(() => refreshTab('history'));
  const wp = $('histWipe');
  if (wp) wp.onclick = () => {
    if (confirm('Erase all recorded history? This cannot be undone.'))
      control({action:'history_wipe'}).then(() => refreshTab('history'));
  };
  wireDailyHover(daily);
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
try { rulesCollapsed = localStorage.getItem('rulesCollapsed') === '1'; } catch(e) {}
let openWhy = new Set();

function renderAlerts(d){
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

  const list = d.alerts || [];
  h += '<div class="sec"><div class="sechead"><h4>'+
       (list.length ? list.length+' alerts · '+d.counts.high+' high · '+d.counts.warn+' warn'
                    : 'Alerts')+
       '</h4><button class="btn-sm" id="toggleRules">'+
       (rulesCollapsed ? 'Show rules' : 'Hide rules')+'</button></div>';
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
  $('p-alerts').innerHTML = h;

  // Alerts that no longer exist (dismissed, muted, cleared) don't need to be
  // remembered as "open" forever.
  const liveIds = new Set(list.map(a => a.id));
  openWhy.forEach(id => { if (!liveIds.has(id)) openWhy.delete(id); });

  const toggleRules = $('toggleRules');
  if (toggleRules) toggleRules.onclick = () => {
    rulesCollapsed = !rulesCollapsed;
    try { localStorage.setItem('rulesCollapsed', rulesCollapsed ? '1' : '0'); } catch(e) {}
    renderAlerts(d);
  };
  document.querySelectorAll('#p-alerts details.why').forEach(det => {
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
  else if (name === 'alerts')  return api('/api/alerts').then(r=>r.json()).then(renderAlerts).catch(()=>{});
  else if (name === 'history') return loadHistory(false);
}

/* History is the tab the page opens on and the one people leave up, so it
   refreshes itself on the database's own flush beat rather than only when its
   tab is clicked — it used to show the page-load numbers for hours, and a
   failed first fetch left "Loading history…" up for good. A redraw rebuilds
   the whole pane, so the automatic one happens only when the data changed,
   waits while a column's tooltip is showing, and keeps any Table view you
   opened and where you had scrolled to. A newer request supersedes an older
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
    if (auto && (key === histSeen || document.querySelector('#tip-daily.on'))) return;
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
function redrawHistory(d){
  const pane = $('p-history'), top = pane.scrollTop;
  const open = new Set([...pane.querySelectorAll('details')].filter(x => x.open).map(histSecName));
  renderHistory(d);
  pane.querySelectorAll('details').forEach(x => { if (open.has(histSecName(x))) x.open = true; });
  pane.scrollTop = top;
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
    ? 'paused — the capture is still running, the table is not updating'
    : '';
  if (!paused) updateCount();
}
$('pause').onclick = () => setPaused(!paused);

document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
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
