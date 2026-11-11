const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Lookups view (1.50): DNS lookups across the window as bars, answered
// with failed stacked on top, and under them the names that failed. First the
// real endpoint against the demo, then /api/lookups answered with fixed
// lookups so counts and order are deterministic.
const NOW = Math.floor(Date.now()/1000);
const EV = [];
const add = (ago, name, outcome, proc, ms) =>
  EV.push([NOW - ago, name, 'A', outcome, outcome === 'timeout' ? null : (ms == null ? 12 : ms), proc || 'svchost.exe', '10.0.0.1', 'eth0']);
// Forty answered, one a second, two names by turns, 10 to 14 ms.
for (let i = 0; i < 40; i++) add(58 - i, i % 2 ? 'example.com' : 'github.com', 'ok', 'svchost.exe', 10 + i % 5);
for (let i = 0; i < 6; i++) add(15 - i, 'dead.example.net', 'nxdomain', 'updater.exe');
[30, 20, 10].forEach(t => add(t, 'wpad.localdomain', 'nxdomain'));
add(40, 'slow.example', 'timeout', 'chrome.exe'); add(39, 'slow.example', 'timeout', 'chrome.exe');
add(25, 'broken.example', 'error');
add(200, 'old.example', 'nxdomain');                                  // outside the last minute
const GEN = 30;         // more failing names than the pane has rows for, all in one second
for (let i = 0; i < GEN; i++) add(5, 'gen' + String(i).padStart(2, '0') + '.dga.example', 'nxdomain', 'mal.exe');
EV.sort((a, b) => a[0] - b[0]);
let polls = 0;
function answer(url){
  polls++;
  const q = new URL(url).searchParams;
  const after = q.get('gen') === '5' && q.get('after') != null ? Number(q.get('after')) : 0;
  return {gen: 5, start: after, next: EV.length, newest: NOW, retain: 3600, now: NOW + 0.5, offline: false,
          samples: EV.slice(after)};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const ctx = await b.newContext({ viewport:{width:1500,height:900} });
  const p = await ctx.newPage();
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});

  // The real thing: the demo looks names up, and each lookup is kept with how it ended.
  let real = null;
  for (let i = 0; i < 80 && !(real && real.samples.length >= 3 && real.samples.some(s => s[3] === 'ok')); i++){
    real = await p.evaluate(() => api('/api/lookups').then(r => r.json()));
    await p.waitForTimeout(500);
  }
  const ok0 = real.samples.find(s => s[3] === 'ok') || [];
  check('the server keeps lookups: when, the name, the type, how it ended, how long, who asked whom',
        real.samples.length >= 3 && ok0.length === 8 && /\./.test(ok0[1]) && ok0[2] === 'A' && ok0[4] > 0 && ok0[4] < 1000 &&
        typeof ok0[5] === 'string' && !!ok0[6] && !!ok0[7] &&
        real.samples.every(s => ['ok', 'nxdomain', 'error', 'timeout'].includes(s[3])), JSON.stringify([real.samples.length, ok0]));
  const again = await p.evaluate(a => api('/api/lookups?after=' + a[0] + '&gen=' + a[1]).then(r => r.json()), [real.next, real.gen]);
  check('...and a second read gets only what is new', again.start === real.next && again.samples.length < real.samples.length + 8,
        JSON.stringify([again.start, again.samples.length]));

  await p.route('**/api/lookups*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(answer(r.request().url()))}));
  await p.click('#vLook', {timeout: 5000});
  await p.click('#lkWin button[data-w="60"]');
  await p.waitForFunction(()=>document.querySelectorAll('#lkSvg .bln').length > 4 && LK.total === 82);
  const sw = await p.evaluate(()=>({
    on: getComputedStyle($('lkview')).display !== 'none',
    others: ['tlview', 'flview', 'blview', 'kdview', 'laview'].map(v => getComputedStyle($(v)).display).join(),
    twH: $('tw').offsetHeight,
    pressed: [...document.querySelectorAll('#vTable,#vTime,#vFlow,#vBal,#vKind,#vLat,#vLook')].map(x => x.getAttribute('aria-pressed')).join(),
    hscroll: document.documentElement.scrollWidth > innerWidth}));
  check('Lookups replaces the table and the other drawings, and says which view is on',
        sw.on && sw.others === 'none,none,none,none,none' && sw.twH === 0 &&
        sw.pressed === 'false,false,false,false,false,false,true', JSON.stringify(sw));
  check('...with no sideways scroll', !sw.hscroll);

  const read = () => p.evaluate(() => {
    const num = (e, a) => e ? Number(e.getAttribute(a)) : 0;
    return {
      total: LK.total, failed: LK.failed, bins: LK.bins.map(x => [x.ok, x.bad]),
      bars: LK.bins.map((x, i) => {
        const o = document.querySelector('#lkSvg .lkb.ok[data-s="' + i + '"]'), d = document.querySelector('#lkSvg .lkb.bad[data-s="' + i + '"]');
        return {oy: num(o, 'y'), oh: num(o, 'height'), by: num(d, 'y'), bh: num(d, 'height')};
      }),
      rows: [...document.querySelectorAll('#lkSvg .bln')].map(g => {
        const n = LK.rows[Number(g.dataset.i)];
        return {name: n.name, lump: g.classList.contains('lump'), n: n.n, fig: (g.querySelector('.tot') || {textContent: ''}).textContent};
      }),
      text: $('lkSvg').textContent, note: $('lkNote').textContent,
      svgH: $('lkSvg').getBoundingClientRect().height, wrapH: $('lkWrap').clientHeight};
  });
  let r = await read();
  const row = n => r.rows.find(x => x.name === n) || {};
  const names = () => r.rows.map(x => x.name);
  check('the note counts the lookups, the share that failed and the usual answer time',
        r.total === 82 && r.failed === 42 && /82 lookups in the last minute/.test(r.note) && /51% failed/.test(r.note) &&
        /usually answered in 12ms/.test(r.note), r.note);
  check('the window is sixty slices, each lookup in the one it was asked in',
        r.bins.length === 60 && r.bins.reduce((a, x) => a + x[0], 0) === 40 && r.bins[54].join() === '0,30' &&
        r.bins[29].join() === '1,1' && r.bins[0].join() === '0,0', JSON.stringify(r.bins));
  const both = r.bars[29], burst = r.bars[54], calm = r.bars[10];
  check('failed lookups are stacked on the answered ones', both.oh > 0 && both.bh > 0 && Math.abs(both.by + both.bh - both.oy) < 0.2 &&
        Math.abs(both.oh - both.bh) < 0.2, JSON.stringify(both));
  check('...and a burst of failures is the tallest thing in the chart, thirty times one lookup',
        Math.abs(burst.bh / calm.oh - 30) < 0.5 && burst.oh === 0 && calm.bh === 0, JSON.stringify([burst, calm]));
  check('the names that failed are listed, most failures first',
        names().slice(0, 4).join() === 'dead.example.net,wpad.localdomain,slow.example,broken.example', names().slice(0, 5).join());
  check('...each with how often, why, and who asked',
        /^6 · doesn't exist · updater\.exe$/.test(row('dead.example.net').fig) && /^2 · no answer · chrome\.exe$/.test(row('slow.example').fig) &&
        /^1 · server error · svchost\.exe$/.test(row('broken.example').fig), JSON.stringify(r.rows.slice(0, 4)));
  check('a name that only ever answered is not in the list, nor one that failed before the window',
        !row('github.com').name && !row('old.example').name);
  const lump = r.rows[r.rows.length - 1];
  check('names that don\'t fit are one "other" row, at the end', lump.lump && /^\d+ other names$/.test(lump.name), JSON.stringify(lump));
  check('...and the drawing fits the height', r.svgH <= r.wrapH + 1, JSON.stringify([r.svgH, r.wrapH]));

  // Hover: a name, then a slice of the chart; no redraw underneath the pointer.
  await p.locator('#lkSvg .bln').first().hover();
  const hv = await p.evaluate(() => ({hot: document.querySelectorAll('#lkSvg .bln.hot').length,
    tip: $('lkTip').classList.contains('on') ? $('lkTip').textContent : ''}));
  check('hovering a name says how its lookups ended and who made them',
        hv.hot === 1 && /dead\.example\.net/.test(hv.tip) && /6 lookups failed/.test(hv.tip) && /doesn't exist/.test(hv.tip) &&
        /updater\.exe/.test(hv.tip) && /10\.0\.0\.1/.test(hv.tip), JSON.stringify(hv));
  const before = await p.evaluate(() => $('lkSvg').innerHTML);
  await p.evaluate(() => lkDraw(true));
  check('...and the automatic redraw waits while the pointer is on it',
        await p.evaluate(b => $('lkSvg').innerHTML === b && LK.stale, before));
  await p.locator('#lkSvg .lks[data-s="54"]').hover();
  const hs = await p.evaluate(() => $('lkTip').classList.contains('on') ? $('lkTip').textContent : '');
  check('hovering a slice gives its counts', /30 lookups/.test(hs) && /30 failed/.test(hs), hs);
  await p.mouse.move(5, 5);
  check('...and it catches up on leaving', await p.evaluate(() => !LK.stale && !$('lkTip').classList.contains('on')));

  // Polling again must not count anything twice.
  const seen = polls;
  await p.waitForTimeout(2200);
  r = await read();
  check('later polls add only what is new', polls > seen && r.total === 82, JSON.stringify([polls - seen, r.total]));

  // The display filter applies: by who asked, and by the name.
  await p.fill('#find', 'process == "chrome.exe"');
  await p.waitForFunction(() => LK.total === 2);
  r = await read();
  check('a filter on the program keeps its lookups', names().join() === 'slow.example' && /100% failed/.test(r.note), JSON.stringify([names(), r.note]));
  await p.fill('#find', 'host == "github.com"');
  await p.waitForFunction(() => LK.total === 20);
  r = await read();
  check('a filter on the name keeps that name, and says so when none failed',
        r.failed === 0 && r.rows.length === 0 && /No lookup failed in the last minute/.test(r.text), r.text.slice(-80));
  await p.fill('#find', 'len > 100');
  await p.waitForFunction(() => $('lkNote').classList.contains('warn'));
  check('a filter it can\'t apply draws nothing and says so',
        await p.evaluate(() => /size/.test($('lkNote').textContent) && !document.querySelector('#lkSvg .lkb') && $('lkEmpty').style.display === 'block'));
  await p.click('#findClear');
  await p.mouse.move(5, 5);
  await p.waitForFunction(() => LK.total === 82);

  // Click a name: its packets, in the table.
  await p.evaluate(() => document.querySelector('#lkSvg .bln.lump').dispatchEvent(new MouseEvent('click', {bubbles: true})));
  check('the "other" row is not clickable', await p.inputValue('#find') === '' && await p.evaluate(() => viewMode) === 'lookups');
  await p.locator('#lkSvg .bln').first().click();
  check('clicking a name opens the table filtered to its DNS packets',
        await p.evaluate(() => viewMode) === 'table' && await p.inputValue('#find') === 'proto == "DNS" && info ~ "dead.example.net"',
        await p.inputValue('#find'));
  await p.click('#findClear');
  await p.click('#vLook');

  // One window for all the drawings; a longer one reaches further back.
  await p.click('#lkWin button[data-w="300"]');
  await p.mouse.move(5, 5);
  await p.waitForFunction(() => LK.total === 83);
  r = await read();
  check('the window is shared with the Timeline, and a longer one counts older lookups', await p.evaluate(() =>
    TL.win === 300 && document.querySelector('#tlWin button[data-w="300"]').classList.contains('on')) &&
    r.total === 83 && r.failed === 43 && /83 lookups in the last 5 minutes/.test(r.note), r.note);
  await p.reload();
  await p.waitForFunction(() => document.querySelectorAll('#lkSvg .bln').length > 2, null, {timeout: 30000});
  check('a reload comes back to Lookups', await p.evaluate(() => viewMode === 'lookups' && $('vLook').classList.contains('on')));
  await p.click('#vTable');
  check('...and Table brings the table back', await p.evaluate(() => $('tw').offsetHeight > 100 &&
    getComputedStyle($('lkview')).display === 'none'));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})().catch(e => { console.log('FAIL  the test ran to the end  -- ' + String(e).split('\n')[0]); process.exit(1); });
