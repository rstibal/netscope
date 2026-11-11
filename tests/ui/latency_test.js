const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Latency view (1.49): one row per host, a dot per timed handshake placed
// by when and how long, with "All hosts" on top. First the real endpoint
// against the demo, then /api/latency answered with fixed samples so counts
// and order are deterministic.
const NOW = Math.floor(Date.now()/1000);
const SAMPLES = [];
const add = (ago, ms, proc, host, ip, iface) => SAMPLES.push([NOW - ago, ms, proc, host, ip, 443, iface || 'eth0']);
// github.com: ten connections, one of them far slower than the rest.
[20, 22, 24, 21, 23, 25, 22, 24, 23].forEach((v, i) => add(55 - i * 5, v, 'chrome.exe', 'github.com', '140.82.112.3'));
add(10, 200, 'chrome.exe', 'github.com', '140.82.112.3');
// The router: 6 ms is three times its usual 2, and still nothing to remark on.
[1, 2, 2, 6].forEach((v, i) => add(40 - i * 10, v, 'svchost.exe', 'router.lan', '10.0.0.1'));
add(30, 50, 'app.exe', '', '203.0.113.9'); add(20, 60, 'app.exe', '', '203.0.113.9');   // never named
add(200, 70, 'old.exe', 'old.example', '198.51.100.9');                                 // outside the last minute
const SMALL = 60;       // more hosts than the pane has rows for
for (let i = 0; i < SMALL; i++) add(5, 30 + i, 'small.exe', 'h' + String(i).padStart(2, '0') + '.example.net', '198.51.100.' + (100 + i));
SAMPLES.sort((a, b) => a[0] - b[0]);
let polls = 0;
function answer(url){
  polls++;
  const q = new URL(url).searchParams;
  const after = q.get('gen') === '5' && q.get('after') != null ? Number(q.get('after')) : 0;
  return {gen: 5, start: after, next: SAMPLES.length, newest: NOW, retain: 3600, now: NOW + 0.5, offline: false,
          samples: SAMPLES.slice(after)};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const ctx = await b.newContext({ viewport:{width:1500,height:900} });
  const p = await ctx.newPage();
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});

  // The real thing: the demo opens connections, and their handshakes are kept.
  let real = null;
  for (let i = 0; i < 60 && !(real && real.samples.length >= 2); i++){
    real = await p.evaluate(() => api('/api/latency').then(r => r.json()));
    if (real.samples.length < 2) await p.waitForTimeout(500);
  }
  const s0 = real.samples[0] || [];
  check('the server keeps handshake times: when, how long, whose, where to, on what',
        real.samples.length >= 2 && s0.length === 7 && s0[1] > 0 && s0[1] < 1000 && typeof s0[2] === 'string' &&
        !!s0[4] && s0[5] === 443 && !!s0[6] && real.next - real.start === real.samples.length, JSON.stringify([real.samples.length, s0]));
  check('...with the host\'s name', real.samples.some(s => /[a-z]\.[a-z]/.test(s[3])), JSON.stringify(real.samples.slice(0, 3)));
  const again = await p.evaluate(a => api('/api/latency?after=' + a[0] + '&gen=' + a[1]).then(r => r.json()), [real.next, real.gen]);
  check('...and a second read gets only what is new', again.start === real.next && again.samples.length < real.samples.length + 5 &&
        again.samples.every(s => s[0] >= real.samples[real.samples.length - 1][0]), JSON.stringify([again.start, again.samples.length]));

  await p.route('**/api/latency*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(answer(r.request().url()))}));
  await p.click('#vLat', {timeout: 5000});
  await p.click('#laWin button[data-w="60"]');
  await p.waitForFunction(()=>document.querySelectorAll('#laSvg .bln').length > 4 && LA.rows[0].n === 76);
  const sw = await p.evaluate(()=>({
    on: getComputedStyle($('laview')).display !== 'none',
    others: ['tlview', 'flview', 'blview', 'kdview'].map(v => getComputedStyle($(v)).display).join(),
    twH: $('tw').offsetHeight,
    pressed: [...document.querySelectorAll('#vTable,#vTime,#vFlow,#vBal,#vKind,#vLat')].map(x => x.getAttribute('aria-pressed')).join(),
    hscroll: document.documentElement.scrollWidth > innerWidth}));
  check('Latency replaces the table and the other drawings, and says which view is on',
        sw.on && sw.others === 'none,none,none,none' && sw.twH === 0 && sw.pressed === 'false,false,false,false,false,true', JSON.stringify(sw));
  check('...with no sideways scroll', !sw.hscroll);

  const read = () => p.evaluate(() => ({
    rows: [...document.querySelectorAll('#laSvg .bln')].map(g => {
      const n = LA.rows[Number(g.dataset.i)];
      const dots = [...g.querySelectorAll('circle.lad')].map(c => ({x: Number(c.getAttribute('cx')), y: Number(c.getAttribute('cy')),
                                                                     slow: c.classList.contains('slow')}));
      return {name: n.name, lump: g.classList.contains('lump'), all: !!n.all, n: n.n, med: n.med, worst: n.worst, dots,
              fig: (g.querySelector('.tot') || {textContent: ''}).textContent};
    }),
    note: $('laNote').textContent,
    svgH: $('laSvg').getBoundingClientRect().height, wrapH: $('laWrap').clientHeight}));
  let r = await read();
  const row = n => r.rows.find(x => x.name === n) || {};
  const names = () => r.rows.map(x => x.name);
  check('"All hosts" is the first row, with every connection in the window',
        r.rows[0].all && r.rows[0].name === 'All hosts' && r.rows[0].n === 76 && r.rows[0].dots.length === 76, JSON.stringify([r.rows[0].name, r.rows[0].n]));
  check('then the hosts connected to most, an unnamed one by its address',
        names().slice(1, 4).join() === 'github.com,router.lan,203.0.113.9', names().slice(0, 5).join());
  check('a connection outside the window is not counted', !row('old.example').name && /76 connections timed in the last minute/.test(r.note), r.note);
  const lump = r.rows[r.rows.length - 1];
  check('hosts that don\'t fit are one "other" row, at the end', lump.lump && /^\d+ other hosts$/.test(lump.name), JSON.stringify([lump.name, lump.n]));
  check('...and the drawing fits the height', r.svgH <= r.wrapH + 1, JSON.stringify([r.svgH, r.wrapH]));
  const gh = row('github.com');
  check('a row gives the usual time, the worst and how many', gh.med === 23 && gh.worst === 200 && gh.n === 10 &&
        /23ms/.test(gh.fig) && /200ms/.test(gh.fig) && /10/.test(gh.fig), JSON.stringify([gh.med, gh.worst, gh.n, gh.fig]));
  const slow = gh.dots.filter(d => d.slow);
  check('one dot per connection, later ones further right', gh.dots.length === 10 &&
        gh.dots.every((d, i) => i === 0 || d.x > gh.dots[i - 1].x), JSON.stringify(gh.dots.map(d => d.x)));
  check('a connection far slower than the host\'s usual is marked, and is the highest dot',
        slow.length === 1 && slow[0].y === Math.min(...gh.dots.map(d => d.y)) && slow[0].x === Math.max(...gh.dots.map(d => d.x)),
        JSON.stringify(gh.dots));
  check('...but a few milliseconds over a tiny usual is not', row('router.lan').dots.length === 4 && !row('router.lan').dots.some(d => d.slow),
        JSON.stringify(row('router.lan').dots));

  // Hover: a tip, and no redraw underneath the pointer.
  await p.locator('#laSvg .bln').nth(1).hover();
  const hv = await p.evaluate(() => ({hot: document.querySelectorAll('#laSvg .bln.hot').length,
    tip: $('laTip').classList.contains('on') ? $('laTip').textContent : ''}));
  check('hovering a host gives its times and the programs that connected',
        hv.hot === 1 && /github\.com/.test(hv.tip) && /usually 23ms/.test(hv.tip) && /worst 200ms/.test(hv.tip) &&
        /fastest 20ms/.test(hv.tip) && /10 connections/.test(hv.tip) && /Programs: chrome\.exe 100%/.test(hv.tip), JSON.stringify(hv));
  const before = await p.evaluate(() => $('laSvg').innerHTML);
  await p.evaluate(() => laDraw(true));
  check('...and the automatic redraw waits while the pointer is on it',
        await p.evaluate(b => $('laSvg').innerHTML === b && LA.stale, before));
  await p.mouse.move(5, 5);
  check('...and catches up on leaving', await p.evaluate(() => !LA.stale && !$('laTip').classList.contains('on')));

  // Polling again must not count anything twice.
  const seen = polls;
  await p.waitForTimeout(2200);
  r = await read();
  check('later polls add only what is new', polls > seen && r.rows[0].n === 76, JSON.stringify([polls - seen, r.rows[0].n]));

  // Click a row: a filter clause, and the drawing follows it.
  await p.locator('#laSvg .bln').nth(1).click();
  check('clicking a host filters to it', await p.inputValue('#find') === 'host == "github.com"', await p.inputValue('#find'));
  await p.mouse.move(5, 5);
  r = await read();
  check('...and only it remains, under an "All hosts" that is now just it',
        names().join() === 'All hosts,github.com' && r.rows[0].n === 10, JSON.stringify(r.rows.map(x => [x.name, x.n])));
  await p.click('#findClear');
  await p.mouse.move(5, 5);
  await p.waitForFunction(() => LA.rows.length > 4);
  await p.locator('#laSvg .bln').nth(3).click();
  check('clicking an unnamed host filters by address', await p.inputValue('#find') === 'ip == "203.0.113.9"', await p.inputValue('#find'));
  await p.mouse.move(5, 5);
  r = await read();
  check('...and only it remains', names().join() === 'All hosts,203.0.113.9' && r.rows[1].n === 2, JSON.stringify(r.rows.map(x => [x.name, x.n])));
  await p.click('#findClear');
  await p.mouse.move(5, 5);
  await p.waitForFunction(() => LA.rows.length > 4);
  await p.evaluate(() => { for (const s of ['.bln.all', '.bln.lump'])
    document.querySelector('#laSvg ' + s).dispatchEvent(new MouseEvent('click', {bubbles: true})); });
  check('"All hosts" and the "other" row are not clickable', await p.inputValue('#find') === '');

  // Fields a handshake time doesn't have.
  for (const [f, word] of [['len > 100', 'size'], ['proto == "TLS"', 'protocol']]){
    await p.fill('#find', f);
    await p.waitForFunction(w => $('laNote').classList.contains('warn') && $('laNote').textContent.includes(w), word);
    check('a filter on ' + word + ' draws nothing and says so',
          await p.evaluate(() => !document.querySelector('#laSvg .bln') && $('laEmpty').style.display === 'block'));
    await p.click('#findClear');
  }

  // One window for all the drawings; a longer one reaches further back.
  await p.click('#laWin button[data-w="300"]');
  await p.mouse.move(5, 5);
  r = await read();
  check('the window is shared with the Timeline, and a longer one counts older connections', await p.evaluate(() =>
    TL.win === 300 && document.querySelector('#tlWin button[data-w="300"]').classList.contains('on')) && r.rows[0].n === 77,
    String(r.rows[0].n));
  await p.reload();
  await p.waitForFunction(() => document.querySelectorAll('#laSvg .bln').length > 2, null, {timeout: 30000});
  check('a reload comes back to Latency', await p.evaluate(() => viewMode === 'latency' && $('vLat').classList.contains('on')));
  await p.click('#vTable');
  check('...and Table brings the table back', await p.evaluate(() => $('tw').offsetHeight > 100 &&
    getComputedStyle($('laview')).display === 'none'));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})().catch(e => { console.log('FAIL  the test ran to the end  -- ' + String(e).split('\n')[0]); process.exit(1); });
