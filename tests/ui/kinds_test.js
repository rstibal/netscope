const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Kinds view (1.48): one row per kind of traffic (the decoded protocol,
// or the port for what isn't decoded), a bar of its bytes and a line of its
// shape over the window. Drawn from /api/timeline, answered here with a
// fixed minute so sizes and order are deterministic.
const NOW = Math.floor(Date.now()/1000);
const KEYS = [
  // program, host, remote, local, dir, proto, remote port, adapter, VPN copy
  ['chrome.exe',  'github.com', '140.82.112.3',  '10.0.0.2', 'out', 'TLS',  443,  'eth0', 0], // 0
  ['chrome.exe',  'github.com', '140.82.112.3',  '10.0.0.2', 'in',  'TLS',  443,  'eth0', 0], // 1
  ['chrome.exe',  'github.com', '140.82.112.3',  '10.0.0.2', 'in',  'TCP',  443,  'eth0', 0], // 2: the same connections' bare ACKs
  ['chrome.exe',  'google.com', '142.250.80.14', '10.0.0.2', 'in',  'QUIC', 443,  'eth0', 0], // 3
  ['chrome.exe',  'google.com', '142.250.80.14', '10.0.0.2', 'out', 'UDP',  443,  'eth0', 0], // 4: QUIC not decoded
  ['svchost.exe', 'router.lan', '10.0.0.1',      '10.0.0.2', 'out', 'DNS',  53,   'eth0', 0], // 5
  ['app.exe',     '',           '203.0.113.9',   '10.0.0.2', 'in',  'TCP',  8080, 'eth0', 0], // 6: nothing decoded on 8080
  ['vpnclient.exe','',          '198.51.100.50', '10.0.0.2', 'out', 'UDP',  51820,'eth0', 1], // 7: VPN copy
  ['svchost.exe', '',           '224.0.0.251',   '10.0.0.2', 'out', 'MDNS', 5353, 'eth0', 0], // 8: multicast
];
const SMALL = 60;       // more small kinds than the pane has rows for
for (let i = 0; i < SMALL; i++)
  KEYS.push(['small.exe', '', '198.51.100.' + (i + 100), '10.0.0.2', 'out', 'TCP', 9000 + i, 'eth0', 0]);
function payload(){
  const secs = new Map();
  const add = (t, k, b, p) => { if (!secs.has(t)) secs.set(t, []); secs.get(t).push([k, b, p, 1]); };
  for (let t = NOW - 59; t <= NOW; t++){
    add(t, 0, 1000, 2); add(t, 1, 6000, 6); add(t, 2, 1000, 4);   // TLS: 60 KB sent, 420 KB received
    add(t, 3, 3000, 4); add(t, 4, 500, 1);                        // QUIC: 30 KB sent, 180 KB received
    add(t, 5, 100, 1);                                            // DNS: 6 KB
    if (t > NOW - 30) add(t, 6, 4000, 4);                         // TCP 8080: 120 KB, all in the last half
    add(t, 7, 50000, 30);                                         // the VPN's copy: biggest of all
    add(t, 8, 50, 1);                                             // mDNS: 3 KB
  }
  for (let i = 0; i < SMALL; i++) add(NOW - 5, 9 + i, 1000 - i, 1);
  return {gen: 3, full: true, kfrom: 0, keys: KEYS, now: NOW + 0.5, newest: NOW,
          offline: false, retain: 3600, buckets: [...secs.entries()].sort((a,b)=>a[0]-b[0])};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const ctx = await b.newContext({ viewport:{width:1500,height:900} });
  const p = await ctx.newPage();
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.route('**/api/timeline*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(payload())}));

  await p.click('#vKind', {timeout: 5000});
  await p.click('#kdWin button[data-w="60"]');
  await p.waitForFunction(()=>document.querySelectorAll('#kdSvg .bln').length > 4);
  const sw = await p.evaluate(()=>({
    on: getComputedStyle($('kdview')).display !== 'none',
    others: ['tlview', 'flview', 'blview'].map(v => getComputedStyle($(v)).display).join(),
    twH: $('tw').offsetHeight,
    pressed: [...document.querySelectorAll('#vTable,#vTime,#vFlow,#vBal,#vKind')].map(x => x.getAttribute('aria-pressed')).join(),
    hscroll: document.documentElement.scrollWidth > innerWidth}));
  check('Kinds replaces the table and the other drawings, and says which view is on',
        sw.on && sw.others === 'none,none,none' && sw.twH === 0 && sw.pressed === 'false,false,false,false,true', JSON.stringify(sw));
  check('...with no sideways scroll', !sw.hscroll);

  const read = () => p.evaluate(() => {
    const num = (e, a) => e ? Number(e.getAttribute(a)) : 0;
    return {
      rows: [...document.querySelectorAll('#kdSvg .bln')].map(g => {
        const n = KD.rows[Number(g.dataset.i)];
        const o = g.querySelector('.blb.out'), i = g.querySelector('.blb.in');
        return {name: n.name, lump: g.classList.contains('lump'), out: n.out, in: n.in,
                ow: num(o, 'width'), ox: num(o, 'x'), iw: num(i, 'width'), ix: num(i, 'x'),
                line: !!g.querySelector('path.kdt.l'), trend: n.trend || []};
      }),
      note: $('kdNote').textContent,
      svgH: $('kdSvg').getBoundingClientRect().height, wrapH: $('kdWrap').clientHeight};
  });
  let r = await read();
  const row = n => r.rows.find(x => x.name === n) || {};
  const names = () => r.rows.map(x => x.name);
  check('kinds are busiest first', names().slice(0, 5).join() === 'TLS,QUIC,TCP 8080,DNS,MDNS', names().slice(0, 6).join());
  check('plain TCP and UDP on a port with a decoded protocol count under that protocol',
        row('TLS').out === 60000 && row('TLS').in === 420000 && row('QUIC').out === 30000 && row('QUIC').in === 180000 &&
        !row('TCP 443').name && !row('UDP 443').name, JSON.stringify([row('TLS'), row('QUIC')]));
  check('what isn\'t decoded is named by its port', row('TCP 8080').in === 120000, JSON.stringify(row('TCP 8080')));
  check('the VPN\'s encrypted copy is left out, and the note says how much',
        !row('UDP 51820').name && /VPN copy left out: 2\.9 MB/.test(r.note), r.note);
  check('multicast is a kind of traffic, and is kept', row('MDNS').out === 3000, JSON.stringify(row('MDNS')));
  const lump = r.rows[r.rows.length - 1];
  check('kinds that don\'t fit are one "other" row, at the end', lump.lump && /^\d+ other kinds$/.test(lump.name), JSON.stringify(lump));
  check('...and the drawing fits the height', r.svgH <= r.wrapH + 1, JSON.stringify([r.svgH, r.wrapH]));
  const tls = row('TLS'), quic = row('QUIC');
  check('a bar is the sent part, then the received', tls.ow > 0 && Math.abs(tls.ox + tls.ow - tls.ix) < 0.2 && tls.ox === quic.ox,
        JSON.stringify([tls, quic]));
  check('bar length follows bytes, on one scale',
        Math.abs((tls.ow + tls.iw) / (quic.ow + quic.iw) - 480 / 210) < 0.03 && Math.abs(tls.iw / tls.ow - 7) < 0.1,
        JSON.stringify([tls.ow, tls.iw, quic.ow, quic.iw]));
  const least = Math.min(...r.rows.map(x => x.ow + x.iw));
  check('...and the smallest is still drawn', least >= 1.4, String(least));
  const t8 = row('TCP 8080').trend;
  check('each row has a line of its shape over the window',
        r.rows.every(x => x.line) && t8.length === 60 && t8.slice(0, 29).every(v => v === 0) && t8.slice(31).every(v => v === 4000),
        JSON.stringify(t8));

  // Hover: a tip, and no redraw underneath the pointer.
  await p.locator('#kdSvg .bln').first().hover();
  const hv = await p.evaluate(() => ({hot: document.querySelectorAll('#kdSvg .bln.hot').length,
    tip: $('kdTip').classList.contains('on') ? $('kdTip').textContent : ''}));
  check('hovering a kind gives its bytes each way, its programs and what was counted with it',
        hv.hot === 1 && /TLS/.test(hv.tip) && /58\.6 KB sent/.test(hv.tip) && /410\.2 KB received/.test(hv.tip) &&
        /Programs: chrome\.exe 100%/.test(hv.tip) && /TCP on port 443/.test(hv.tip), JSON.stringify(hv));
  const before = await p.evaluate(() => $('kdSvg').innerHTML);
  await p.evaluate(() => kdDraw(true));
  check('...and the automatic redraw waits while the pointer is on it',
        await p.evaluate(b => $('kdSvg').innerHTML === b && KD.stale, before));
  await p.mouse.move(5, 5);
  check('...and catches up on leaving', await p.evaluate(() => !KD.stale && !$('kdTip').classList.contains('on')));

  // Click a row: a filter that means the same packets, and the drawing follows it.
  await p.locator('#kdSvg .bln').first().click();
  check('clicking a kind filters to it, the plain packets counted with it included',
        await p.inputValue('#find') === '(proto == "TLS" || (proto == "TCP" && port == 443))', await p.inputValue('#find'));
  await p.mouse.move(5, 5);
  r = await read();
  check('...and only it remains, the same size', names().join() === 'TLS' && r.rows[0].out + r.rows[0].in === 480000,
        JSON.stringify(r.rows.map(x => [x.name, x.out + x.in])));
  await p.click('#findClear');
  await p.mouse.move(5, 5);
  await p.waitForFunction(() => KD.rows.length > 3);
  await p.locator('#kdSvg .bln').nth(2).click();
  check('clicking an undecoded kind filters by its port',
        await p.inputValue('#find') === 'proto == "TCP" && port == 8080', await p.inputValue('#find'));
  await p.mouse.move(5, 5);
  r = await read();
  check('...and only it remains', names().join() === 'TCP 8080', names().join());
  await p.click('#findClear');
  await p.mouse.move(5, 5);
  await p.waitForFunction(() => KD.rows.length > 3);
  await p.evaluate(() => document.querySelector('#kdSvg .bln.lump').dispatchEvent(new MouseEvent('click', {bubbles: true})));
  check('the "other" row is not clickable', await p.inputValue('#find') === '');

  // Right-click: hidden through the filter box, where it can be seen.
  await p.locator('#kdSvg .bln').nth(3).click({button: 'right'});
  check('right-clicking a kind hides it with a filter clause', await p.inputValue('#find') === 'proto != "DNS"', await p.inputValue('#find'));
  await p.mouse.move(5, 5);
  r = await read();
  check('...and it is gone from the drawing', !row('DNS').name && row('TLS').name === 'TLS', names().slice(0, 5).join());
  await p.click('#findClear');

  // A field the totals don't keep.
  await p.fill('#find', 'len > 100');
  await p.waitForFunction(() => /doesn't/.test($('kdNote').textContent));
  check('a filter it can\'t apply draws nothing and says so',
        await p.evaluate(() => $('kdNote').classList.contains('warn') && !document.querySelector('#kdSvg .bln') &&
                               $('kdEmpty').style.display === 'block'));
  await p.click('#findClear');

  // One window for all the drawings; the view is remembered.
  await p.click('#kdWin button[data-w="900"]');
  check('the window is shared with the Timeline', await p.evaluate(() =>
    TL.win === 900 && document.querySelector('#tlWin button[data-w="900"]').classList.contains('on')));
  await p.reload();
  await p.waitForFunction(() => document.querySelectorAll('#kdSvg .bln').length > 2, null, {timeout: 30000});
  check('a reload comes back to Kinds', await p.evaluate(() => viewMode === 'kinds' && $('vKind').classList.contains('on')));
  await p.click('#vTable');
  check('...and Table brings the table back', await p.evaluate(() => $('tw').offsetHeight > 100 &&
    getComputedStyle($('kdview')).display === 'none'));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})().catch(e => { console.log('FAIL  the test ran to the end  -- ' + String(e).split('\n')[0]); process.exit(1); });
