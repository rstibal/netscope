const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Flows view (1.46; strings since 1.54): programs left, hosts right, one
// thin string per pair, 1-5 px by the square root of its bytes, every host on
// a row of its own. Drawn from /api/timeline, answered here with a fixed
// minute so sizes and order are deterministic.
const NOW = Math.floor(Date.now()/1000);
const KEYS = [
  // program, host, remote, local, dir, proto, remote port, adapter, VPN copy
  ['chrome.exe',  'github.com',   '140.82.112.3',    '10.0.0.2', 'out', 'TLS', 443, 'eth0', 0], // 0
  ['chrome.exe',  'github.com',   '140.82.112.3',    '10.0.0.2', 'in',  'TLS', 443, 'eth0', 0], // 1
  ['chrome.exe',  'example.com',  '93.184.216.34',   '10.0.0.2', 'in',  'TLS', 443, 'eth0', 0], // 2
  ['Code.exe',    'github.com',   '140.82.112.3',    '10.0.0.2', 'in',  'TLS', 443, 'eth0', 0], // 3
  ['vpnclient.exe','',            '198.51.100.50',   '10.0.0.2', 'out', 'UDP', 51820, 'eth0', 1], // 4: VPN copy
  ['svchost.exe', '',             '239.255.255.250', '10.0.0.2', 'out', 'UDP', 1900, 'eth0', 0], // 5: multicast
];
// Twenty small programs, to make the left column run out of room.
for (let i = 0; i < 20; i++)
  KEYS.push(['small' + String(i).padStart(2, '0') + '.exe', 'h' + i + '.example.net', '203.0.113.' + (i + 1),
             '10.0.0.2', 'out', 'TLS', 443, 'eth0', 0]);
// More hosts than FL_MAX (150), all from one program.
function crowd(){
  const keys = [], buckets = [];
  for (let i = 0; i < 160; i++){
    keys.push(['crowd.exe', 'c' + i + '.example.org', '198.51.100.' + (i % 250), '10.0.0.2', 'out', 'TLS', 443, 'eth0', 0]);
    buckets.push([NOW - 160 + i, [[i, 1000 + i, 1, 1]]]);
  }
  return {gen: 4, full: true, kfrom: 0, keys, now: NOW + 0.5, newest: NOW, offline: false, retain: 3600, buckets};
}
function payload(){
  const secs = new Map();
  const add = (t, k, b, p) => { if (!secs.has(t)) secs.set(t, []); secs.get(t).push([k, b, p, 1]); };
  for (let t = NOW - 59; t <= NOW; t++){
    add(t, 0, 1000, 2); add(t, 1, 9000, 6);       // chrome <-> github: 600 KB a minute
    add(t, 2, 2000, 2);                           // chrome <- example.com
    add(t, 3, 5000, 4);                           // Code <- github
    add(t, 4, 50000, 30);                         // the VPN's copy: biggest of all
    add(t, 5, 400, 1);                            // SSDP
  }
  for (let i = 0; i < 20; i++) add(NOW - 5, 6 + i, 100 + i, 1);
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
  let feed = payload;
  await p.route('**/api/timeline*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(feed())}));

  await p.click('#vFlow');
  await p.click('#flWin button[data-w="60"]');
  await p.waitForFunction(()=>document.querySelectorAll('#flSvg .fln').length > 4);
  const sw = await p.evaluate(()=>({
    on: getComputedStyle($('flview')).display !== 'none',
    tl: getComputedStyle($('tlview')).display,
    twH: $('tw').offsetHeight,
    pressed: [...document.querySelectorAll('#vTable,#vTime,#vFlow')].map(x => x.getAttribute('aria-pressed')).join(),
    hscroll: document.documentElement.scrollWidth > innerWidth}));
  check('Flows replaces the table and the timeline, and says which view is on',
        sw.on && sw.tl === 'none' && sw.twH === 0 && sw.pressed === 'false,false,true', JSON.stringify(sw));
  check('...with no sideways scroll', !sw.hscroll);

  const read = () => p.evaluate(() => {
    const side = s => [...document.querySelectorAll('#flSvg .fln[data-s="' + s + '"]')].map(g => ({
      name: FL.nodes[s][Number(g.dataset.i)].name, lump: g.classList.contains('lump'),
      y: g.getBBox().y + g.getBBox().height / 2}));
    const strings = [...document.querySelectorAll('#flSvg .flb:not(.hit)')];
    return {p: side('p'), h: side('h'), note: $('flNote').textContent,
            svgH: $('flSvg').getBoundingClientRect().height, wrapH: $('flWrap').clientHeight,
            scrollH: $('flWrap').scrollHeight,
            strings: strings.length, hits: document.querySelectorAll('#flSvg .flb.hit').length,
            widths: Object.fromEntries(strings.map(e => { const m = FL.pairs[Number(e.dataset.m)];
              return [FL.nodes.p[m.a].name + '>' + FL.nodes.h[m.b].name, parseFloat(e.style.strokeWidth)]; })),
            pairs: FL.pairs.map(m => FL.nodes.p[m.a].name + '>' + FL.nodes.h[m.b].name + ':' + (m.out + m.in))};
  });
  let r = await read();
  check('programs busiest first', r.p[0].name === 'chrome.exe' && r.p[1].name === 'Code.exe', JSON.stringify(r.p.slice(0, 3)));
  check('hosts are grouped under the program that sends them most, busiest first',
        r.h[0].name === 'github.com' && r.h[1].name === 'example.com' &&
        r.h.slice(2).every((n, i) => n.name === 'h' + (19 - i) + '.example.net'), JSON.stringify(r.h.map(n => n.name)));
  check('the VPN\'s encrypted copy is left out, and the note says how much',
        !r.p.some(n => n.name === 'vpnclient.exe') && /VPN copy left out: 2\.9 MB/.test(r.note), r.note);
  check('multicast is not a host being talked to', !r.h.some(n => /239\./.test(n.name)) &&
        !r.p.some(n => n.name === 'svchost.exe'), JSON.stringify(r.h.map(n => n.name)));
  check('every program and every host has a row of its own, no "other" node',
        r.p.length === 22 && r.h.length === 22 && !r.p.some(n => n.lump) && !r.h.some(n => n.lump),
        JSON.stringify([r.p.length, r.h.length]));
  check('one string per pair, each with a wider copy to point at',
        r.strings === r.pairs.length && r.hits === r.pairs.length && r.strings === 23, JSON.stringify([r.strings, r.hits]));
  // Square root of the bytes, 1 to 5 px: chrome>github (600 KB) is the
  // busiest; Code>github (300 KB) is 1 + 4*sqrt(1/2).
  const w = r.widths;
  check('the busiest string is 5 px', Math.abs(w['chrome.exe>github.com'] - 5) < 0.01, JSON.stringify(w));
  check('...others by the square root of their bytes',
        Math.abs(w['Code.exe>github.com'] - (1 + 4 * Math.sqrt(0.5))) < 0.02, String(w['Code.exe>github.com']));
  check('...and the smallest is still at least 1 px', Math.min(...Object.values(w)) >= 1, JSON.stringify(w));
  const progY = Object.fromEntries(r.p.map(n => [n.name, n.y])), hostY = Object.fromEntries(r.h.map(n => [n.name, n.y]));
  check('a program sits level with the middle of its hosts',
        Math.abs(progY['chrome.exe'] - (hostY['github.com'] + hostY['example.com']) / 2) < 2 &&
        Math.abs(progY['small05.exe'] - hostY['h5.example.net']) <= 10, JSON.stringify([progY, hostY]));

  // Hover: highlight, a tip, and no redraw underneath the pointer.
  const node = p.locator('#flSvg .fln[data-s="p"]').first();
  await node.hover();
  const hv = await p.evaluate(() => ({focus: $('flSvg').classList.contains('focus'),
    hot: document.querySelectorAll('#flSvg .flb.hot:not(.hit)').length,
    tip: $('flTip').classList.contains('on') ? $('flTip').textContent : ''}));
  check('hovering a program lights its strings and names its hosts',
        hv.focus && hv.hot === 2 && /chrome\.exe/.test(hv.tip) && /Hosts: github\.com 83%, example\.com 17%/.test(hv.tip), JSON.stringify(hv));
  const before = await p.evaluate(() => $('flSvg').innerHTML);
  await p.evaluate(() => flDraw(true));
  check('...and the automatic redraw waits while the pointer is on it',
        await p.evaluate(b => $('flSvg').innerHTML === b && FL.stale, before));
  await p.mouse.move(5, 5);
  check('...and catches up on leaving', await p.evaluate(() => !FL.stale && !$('flTip').classList.contains('on')));

  // Click a node: a filter clause, and the drawing follows it.
  await p.locator('#flSvg .fln[data-s="h"]').first().click();
  check('clicking a host filters to it', await p.inputValue('#find') === 'host == "github.com"', await p.inputValue('#find'));
  await p.mouse.move(5, 5);
  r = await read();
  check('...and only its programs remain', r.p.map(n => n.name).join() === 'chrome.exe,Code.exe' && r.h.length === 1,
        JSON.stringify([r.p, r.h]));
  await p.click('#findClear');
  // Click a band: both ends.
  await p.waitForFunction(() => FL.pairs.length > 3);
  await p.evaluate(() => {
    const e = [...document.querySelectorAll('#flSvg .flb')].find(e => { const m = FL.pairs[Number(e.dataset.m)];
      return FL.nodes.p[m.a].name === 'Code.exe'; });
    e.dispatchEvent(new MouseEvent('click', {bubbles: true}));
  });
  check('clicking a band filters to the pair', await p.inputValue('#find') === 'process == "Code.exe" && host == "github.com"',
        await p.inputValue('#find'));
  await p.click('#findClear');
  await p.mouse.move(5, 5);
  // A 1 px string can be pointed at through its wider copy.
  const thin = await p.evaluate(() => {
    const e = [...document.querySelectorAll('#flSvg .flb.hit')].find(e => { const m = FL.pairs[Number(e.dataset.m)];
      return FL.nodes.p[m.a].name === 'small00.exe'; });
    e.scrollIntoView({block: 'center'});
    const l = e.getTotalLength(), pt = e.getPointAtLength(l / 2), m = e.getScreenCTM();
    return {x: pt.x * m.a + m.e, y: pt.y * m.d + m.f + 3};
  });
  await p.mouse.move(thin.x, thin.y);
  check('pointing 3 px off a thin string still finds it', /small00\.exe ⇄ h0\.example\.net/.test(
    await p.evaluate(() => $('flTip').classList.contains('on') ? $('flTip').textContent : '')));
  await p.mouse.move(5, 5);

  // A field the totals don't keep.
  await p.fill('#find', 'len > 100');
  await p.waitForFunction(() => /doesn't/.test($('flNote').textContent));
  check('a filter it can\'t apply draws nothing and says so',
        await p.evaluate(() => $('flNote').classList.contains('warn') && !document.querySelector('#flSvg .flb') &&
                               $('flEmpty').style.display === 'block'));
  await p.click('#findClear');

  // Past FL_MAX hosts, the rest are one "other" row, and the pane scrolls.
  feed = crowd;
  await p.evaluate(() => { TL.gen = -1; });
  await p.click('#flWin button[data-w="300"]');
  await p.waitForFunction(() => FL.nodes.h.length === 150, null, {timeout: 15000}).catch(() => {});
  r = await read();
  const last = r.h[r.h.length - 1];
  check('past 150 hosts the rest are one "other" row, at the end',
        r.h.length === 150 && last.lump && last.name === '11 other hosts', JSON.stringify([r.h.length, last]));
  check('...and the pane scrolls rather than squeezing rows', r.scrollH > r.wrapH + 100 &&
        Math.abs((r.h[1].y - r.h[0].y) - 18) < 0.5, JSON.stringify([r.scrollH, r.wrapH]));
  await p.evaluate(() => document.querySelector('#flSvg .fln.lump').dispatchEvent(new MouseEvent('click', {bubbles: true})));
  check('the "other" row is not clickable', await p.inputValue('#find') === '');
  feed = payload;
  await p.evaluate(() => { TL.gen = -1; });

  // One window for both views; the view is remembered.
  await p.click('#flWin button[data-w="900"]');
  check('the window is shared with the Timeline', await p.evaluate(() =>
    TL.win === 900 && document.querySelector('#tlWin button[data-w="900"]').classList.contains('on')));
  await p.reload();
  await p.waitForFunction(() => document.querySelectorAll('#flSvg .fln').length > 2, null, {timeout: 30000});
  check('a reload comes back to Flows', await p.evaluate(() => viewMode === 'flows' && $('vFlow').classList.contains('on')));
  await p.click('#vTable');
  check('...and Table brings the table back', await p.evaluate(() => $('tw').offsetHeight > 100 &&
    getComputedStyle($('flview')).display === 'none'));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
