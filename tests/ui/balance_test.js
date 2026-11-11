const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Balance view (1.47): one row per program (or host), bytes sent to the
// left of a centre line and received to the right, the biggest sender first.
// Drawn from /api/timeline, answered here with a fixed minute so sizes and
// order are deterministic.
const NOW = Math.floor(Date.now()/1000);
const KEYS = [
  // program, host, remote, local, dir, proto, remote port, adapter, VPN copy
  ['backup.exe',  'nas.example.net', '203.0.113.200', '10.0.0.2', 'out', 'TLS', 443, 'eth0', 0], // 0
  ['backup.exe',  'nas.example.net', '203.0.113.200', '10.0.0.2', 'in',  'TLS', 443, 'eth0', 0], // 1
  ['chrome.exe',  'github.com',      '140.82.112.3',  '10.0.0.2', 'out', 'TLS', 443, 'eth0', 0], // 2
  ['chrome.exe',  'github.com',      '140.82.112.3',  '10.0.0.2', 'in',  'TLS', 443, 'eth0', 0], // 3
  ['chrome.exe',  'example.com',     '93.184.216.34', '10.0.0.2', 'in',  'TLS', 443, 'eth0', 0], // 4
  ['vpnclient.exe','',               '198.51.100.50', '10.0.0.2', 'out', 'UDP', 51820, 'eth0', 1], // 5: VPN copy
  ['svchost.exe', '',                '239.255.255.250','10.0.0.2','out', 'UDP', 1900, 'eth0', 0], // 6: multicast
];
const SMALL = 60;       // more small programs than the pane has rows for
for (let i = 0; i < SMALL; i++)
  KEYS.push(['small' + String(i).padStart(2, '0') + '.exe', 'h' + i + '.example.net', '198.51.100.' + (i + 100),
             '10.0.0.2', 'out', 'TLS', 443, 'eth0', 0]);
function payload(){
  const secs = new Map();
  const add = (t, k, b, p) => { if (!secs.has(t)) secs.set(t, []); secs.get(t).push([k, b, p, 1]); };
  for (let t = NOW - 59; t <= NOW; t++){
    add(t, 0, 8000, 6); add(t, 1, 500, 2);        // backup: 480 KB sent, 30 KB received
    add(t, 2, 1000, 2); add(t, 3, 9000, 6);       // chrome <-> github
    add(t, 4, 2000, 2);                           // chrome <- example.com: 60 KB sent, 660 KB received in all
    add(t, 5, 50000, 30);                         // the VPN's copy: biggest of all
    add(t, 6, 400, 1);                            // SSDP
  }
  for (let i = 0; i < SMALL; i++) add(NOW - 5, 7 + i, 1000 - i, 1);   // sent only
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

  await p.click('#vBal', {timeout: 5000});
  await p.click('#blWin button[data-w="60"]');
  await p.click('#blGroup button[data-g="process"]');
  await p.waitForFunction(()=>document.querySelectorAll('#blSvg .bln').length > 4);
  const sw = await p.evaluate(()=>({
    on: getComputedStyle($('blview')).display !== 'none',
    tl: getComputedStyle($('tlview')).display, fl: getComputedStyle($('flview')).display,
    twH: $('tw').offsetHeight,
    pressed: [...document.querySelectorAll('#vTable,#vTime,#vFlow,#vBal')].map(x => x.getAttribute('aria-pressed')).join(),
    hscroll: document.documentElement.scrollWidth > innerWidth}));
  check('Balance replaces the table and the other drawings, and says which view is on',
        sw.on && sw.tl === 'none' && sw.fl === 'none' && sw.twH === 0 && sw.pressed === 'false,false,false,true', JSON.stringify(sw));
  check('...with no sideways scroll', !sw.hscroll);

  const read = () => p.evaluate(() => {
    const num = (e, a) => e ? Number(e.getAttribute(a)) : 0;
    return {
      rows: [...document.querySelectorAll('#blSvg .bln')].map(g => {
        const o = g.querySelector('.blb.out'), i = g.querySelector('.blb.in');
        return {name: BL.rows[Number(g.dataset.i)].name, lump: g.classList.contains('lump'),
                ow: num(o, 'width'), ox: num(o, 'x'), iw: num(i, 'width'), ix: num(i, 'x'),
                ratio: (g.querySelector('.blr') || {textContent: ''}).textContent};
      }),
      note: $('blNote').textContent,
      svgH: $('blSvg').getBoundingClientRect().height, wrapH: $('blWrap').clientHeight};
  });
  let r = await read();
  const row = n => r.rows.find(x => x.name === n) || {};
  check('the biggest sender is first, not the busiest program',
        r.rows[0].name === 'backup.exe' && r.rows[1].name === 'chrome.exe', JSON.stringify(r.rows.slice(0, 3)));
  check('the VPN\'s encrypted copy is left out, and the note says how much',
        !row('vpnclient.exe').name && /VPN copy left out: 2\.9 MB/.test(r.note), r.note);
  check('multicast is not counted', !row('svchost.exe').name, JSON.stringify(r.rows.map(x => x.name).slice(0, 6)));
  const lump = r.rows[r.rows.length - 1];
  check('programs that don\'t fit are one "other" row, at the end', lump.lump && /^\d+ other programs$/.test(lump.name), JSON.stringify(lump));
  check('...and the drawing fits the height', r.svgH <= r.wrapH + 1, JSON.stringify([r.svgH, r.wrapH]));
  const bk = row('backup.exe'), ch = row('chrome.exe');
  check('sent is drawn left of the centre line and received right of it',
        Math.abs(bk.ox + bk.ow - bk.ix) < 0.2 && Math.abs(ch.ox + ch.ow - bk.ix) < 0.2 && ch.ix === bk.ix, JSON.stringify([bk, ch]));
  // One linear scale for every bar: backup's 480 KB sent against chrome's 660 KB received.
  check('bar length follows bytes, on one scale for both sides',
        Math.abs(bk.ow / ch.iw - 480 / 660) < 0.02 && Math.abs(ch.ow / bk.ow - 60 / 480) < 0.02, JSON.stringify([bk, ch]));
  const sm = row('small00.exe');
  check('the smallest amount is still drawn, and nothing is drawn for none', sm.ow >= 1.4 && sm.iw === 0, JSON.stringify(sm));
  check('a program that sends more than it receives says by how much',
        bk.ratio === 'sends 16×' && ch.ratio === '' && sm.ratio === 'sends only', JSON.stringify([bk.ratio, ch.ratio, sm.ratio]));

  // Hover: a tip, and no redraw underneath the pointer.
  await p.locator('#blSvg .bln').first().hover();
  const hv = await p.evaluate(() => ({hot: document.querySelectorAll('#blSvg .bln.hot').length,
    tip: $('blTip').classList.contains('on') ? $('blTip').textContent : ''}));
  check('hovering a program gives its bytes each way and names its hosts',
        hv.hot === 1 && /backup\.exe/.test(hv.tip) && /468\.8 KB sent/.test(hv.tip) && /29\.3 KB received/.test(hv.tip) &&
        /Hosts: nas\.example\.net 100%/.test(hv.tip), JSON.stringify(hv));
  const before = await p.evaluate(() => $('blSvg').innerHTML);
  await p.evaluate(() => blDraw(true));
  check('...and the automatic redraw waits while the pointer is on it',
        await p.evaluate(b => $('blSvg').innerHTML.replace(/ hot/g, '') === b.replace(/ hot/g, '') && BL.stale, before));
  await p.mouse.move(5, 5);
  check('...and catches up on leaving', await p.evaluate(() => !BL.stale && !$('blTip').classList.contains('on')));

  // Click a row: a filter clause, and the drawing follows it.
  await p.locator('#blSvg .bln').first().click();
  check('clicking a program filters to it', await p.inputValue('#find') === 'process == "backup.exe"', await p.inputValue('#find'));
  await p.mouse.move(5, 5);
  r = await read();
  check('...and only it remains', r.rows.map(x => x.name).join() === 'backup.exe', JSON.stringify(r.rows.map(x => x.name)));
  await p.click('#findClear');
  await p.mouse.move(5, 5);
  await p.waitForFunction(() => BL.rows.length > 3);
  await p.evaluate(() => document.querySelector('#blSvg .bln.lump').dispatchEvent(new MouseEvent('click', {bubbles: true})));
  check('the "other" row is not clickable', await p.inputValue('#find') === '');

  // By host: who this machine sends to.
  await p.click('#blGroup button[data-g="host"]');
  await p.mouse.move(5, 5);
  r = await read();
  check('Hosts lists hosts, the one sent the most first',
        r.rows[0].name === 'nas.example.net' && r.rows[1].name === 'github.com' &&
        /^\d+ other hosts$/.test(r.rows[r.rows.length - 1].name), JSON.stringify(r.rows.slice(0, 3)));
  check('...and the choice is the Timeline\'s too', await p.evaluate(() =>
    TL.group === 'host' && document.querySelector('#tlGroup button[data-g="host"]').classList.contains('on')));
  await p.locator('#blSvg .bln').first().hover();
  check('...hovering a host names its programs', await p.evaluate(() => /Programs: backup\.exe 100%/.test($('blTip').textContent)),
        await p.evaluate(() => $('blTip').textContent));
  await p.locator('#blSvg .bln').first().click();
  check('...and clicking one filters by host', await p.inputValue('#find') === 'host == "nas.example.net"', await p.inputValue('#find'));
  await p.click('#findClear');
  await p.click('#blGroup button[data-g="process"]');
  await p.mouse.move(5, 5);

  // A field the totals don't keep.
  await p.fill('#find', 'len > 100');
  await p.waitForFunction(() => /doesn't/.test($('blNote').textContent));
  check('a filter it can\'t apply draws nothing and says so',
        await p.evaluate(() => $('blNote').classList.contains('warn') && !document.querySelector('#blSvg .bln') &&
                               $('blEmpty').style.display === 'block'));
  await p.click('#findClear');

  // One window for all three drawings; the view is remembered.
  await p.click('#blWin button[data-w="900"]');
  check('the window is shared with the Timeline', await p.evaluate(() =>
    TL.win === 900 && document.querySelector('#tlWin button[data-w="900"]').classList.contains('on')));
  await p.reload();
  await p.waitForFunction(() => document.querySelectorAll('#blSvg .bln').length > 2, null, {timeout: 30000});
  check('a reload comes back to Balance', await p.evaluate(() => viewMode === 'balance' && $('vBal').classList.contains('on')));
  await p.click('#vTable');
  check('...and Table brings the table back', await p.evaluate(() => $('tw').offsetHeight > 100 &&
    getComputedStyle($('blview')).display === 'none'));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})().catch(e => { console.log('FAIL  the test ran to the end  -- ' + String(e).split('\n')[0]); process.exit(1); });
