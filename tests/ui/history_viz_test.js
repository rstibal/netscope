const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// 1.43: a trend per day beside each History bar, a day of the daily chart
// opened into its hours, programs and hosts, and live throughput per adapter
// on the Talkers tab. History's data is answered here, so the shapes are
// known; the adapters come from the demo server itself.
const K = 1024;
let dayAsked = [];
function history(){
  const daily = [];
  for (let i = 0; i < 7; i++)
    daily.push({day:'2026-10-' + String(25 + i).padStart(2,'0'), bytes_in:(i+1)*K, bytes_out:K, packets:10});
  return {enabled:true, days:7, iface:'', ifaces:['Wi-Fi'], daily,
          hosts:[{host:'a.example', bytes_in:K, bytes_out:1, packets:1, first_seen:1.8e9,
                  trend_in:[0,0,0,0,0,0,K], trend_out:[0,0,1,0,0,0,0]}],
          new_hosts:[], sessions:[],
          processes:[{name:'steady.exe', bytes_in:7*K, bytes_out:0, packets:7,
                      trend_in:[K,K,K,K,K,K,K], trend_out:[0,0,0,0,0,0,0]},
                     {name:'burst.exe', bytes_in:9*K, bytes_out:K, packets:1,
                      trend_in:[0,0,0,9*K,0,0,0], trend_out:[0,0,0,K,0,0,0]}],
          range:{bytes_in:16*K, bytes_out:K, packets:8, programs:2, hosts:1},
          alert_counts:{total:0}, exclude:{programs:[],hosts:[]},
          summary:{since:'2026-10-25', path:'C:\\history.db', size:1, retain_days:90, alert_retain_days:30}};
}
function dayData(day){
  return {day, iface:'', hours:Array.from({length:24}, (_, h) => ({hour:h, bytes_in: h === 0 ? 5*K : 0, bytes_out: h === 0 ? K : 0})),
          programs:[{name:'burst.exe', bytes_in:5*K, bytes_out:K, packets:3}],
          hosts:[{host:'b.example', bytes_in:5*K, bytes_out:K, packets:3}]};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:1000} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));

  // The real server answers the new endpoints.
  const base = process.argv[2].replace(/\/\?/, '/api/');
  const ad = await (await fetch(base.replace('/api/', '/api/adapters?'))).json().catch(()=>null);
  check('the server reports throughput per adapter',
        ad && Array.isArray(ad.adapters) && ad.window === 300, JSON.stringify(ad && Object.keys(ad)));
  const bad = await fetch(base.replace('/api/', '/api/history/day?day=x&'));
  check('...and refuses a malformed day', bad.status === 400, String(bad.status));

  await p.route('**/api/history?*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history())}));
  await p.route('**/api/history/day?*', r => {
    const day = new URL(r.request().url()).searchParams.get('day');
    dayAsked.push(day);
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(dayData(day))});
  });
  await p.goto(process.argv[2]);
  await p.evaluate(() => showTab('history'));
  await p.waitForSelector('#cw-daily svg', {timeout: 30000});

  // -- trends ------------------------------------------------------------------------
  // 1.51: each program and host is a lane of per-day bars on the daily chart's
  // own day columns, sent above received, on one log scale.
  const lanes = () => p.evaluate(() => {
    const box = e => { const b = e.getBoundingClientRect(); return {l: b.left, r: b.right, t: b.top, b: b.bottom, h: b.height, cx: b.left + b.width / 2}; };
    const chart = box(document.querySelector('#cw-daily svg'));
    const cols = [...document.querySelectorAll('#cw-daily .hitrect')].map(h => box(h).cx);
    const rows = [...document.querySelectorAll('#p-history .hbar[data-k]')].map(r => {
      const s = r.querySelector('svg.lanes'), hot = s && s.querySelector('.lhot');
      return {n: r.querySelector('.nm').textContent, tot: (r.querySelector('.tot') || {}).textContent || '',
              svg: s ? box(s) : null, title: s ? s.querySelector('title').textContent : '',
              ins: s ? [...s.querySelectorAll('.lb.in')].map(b => Object.assign(box(b), {i: +b.dataset.i})) : [],
              outs: s ? [...s.querySelectorAll('.lb.out')].map(b => Object.assign(box(b), {i: +b.dataset.i})) : [],
              hot: hot && getComputedStyle(hot).display !== 'none' ? box(hot).cx : null};
    });
    return {chart, cols, rows, hotCol: [...document.querySelectorAll('#cw-daily .colgroup.hot')].map(g => g.dataset.i).join()};
  });
  let ln = await lanes();
  const near = (a, b) => Math.abs(a - b) <= 1;
  check('each program and host has a lane as wide as the daily chart',
        ln.rows.length === 3 && ln.rows.every(r => r.svg && near(r.svg.l, ln.chart.l) && near(r.svg.r, ln.chart.r)),
        JSON.stringify(ln.rows.map(r => r.svg)) + ' vs ' + JSON.stringify(ln.chart));
  const row = (g, re) => g.rows.find(r => re.test(r.n));
  let steady = row(ln, /steady/), burst = row(ln, /burst/), host = row(ln, /a\.example/);
  check('...a steady program has a bar every day, a burst one a single day',
        steady.ins.length === 7 && steady.outs.length === 0 && burst.ins.length === 1 && burst.outs.length === 1,
        JSON.stringify([steady.ins.length, steady.outs.length, burst.ins.length, burst.outs.length]));
  check('...each bar under its day of the chart above',
        burst.ins[0].i === 3 && near(burst.ins[0].cx, ln.cols[3]) && steady.ins.every(b => near(b.cx, ln.cols[b.i])),
        JSON.stringify([burst.ins[0], ln.cols]));
  check('...sent drawn above received', burst.outs[0].b <= burst.ins[0].t + 0.5, JSON.stringify([burst.outs[0], burst.ins[0]]));
  const ratio = burst.ins[0].h / steady.ins[0].h;
  check('...on a log scale: nine times the bytes is taller, not nine times as tall',
        ratio > 1.1 && ratio < 3, String(ratio));
  check('...and a single byte still shows', host.outs.length === 1 && host.outs[0].h >= 0.9, JSON.stringify(host.outs));
  check('...the row gives its total and the split', /^10\.0 KB/.test(burst.tot) && /▼ 9\.0 KB/.test(burst.tot) && /▲ 1\.0 KB/.test(burst.tot), burst.tot);
  check('...and says when its busiest day was', /busiest 10\.0 KB on 2026-10-28, active 1 of 7 days/.test(burst.title), burst.title);
  check('no bar and no trend line is left beside the name',
        await p.evaluate(() => !document.querySelector('#p-history .hbar[data-k] .track, #p-history svg.trend')));

  // Pointing at a day marks it through every lane, and the rows give that day.
  const hit0 = await p.$eval('#cw-daily .hitrect[data-i="3"]', r => { const b = r.getBoundingClientRect(); return [b.x + b.width/2, b.y + b.height/2]; });
  await p.mouse.move(hit0[0], hit0[1]);
  ln = await lanes(); steady = row(ln, /steady/); burst = row(ln, /burst/);
  check('pointing at a day of the chart marks that day in every lane',
        ln.rows.every(r => r.hot !== null && near(r.hot, ln.cols[3])), JSON.stringify(ln.rows.map(r => r.hot)));
  check('...and each row shows that day', /10-28/.test(burst.tot) && /▼ 9\.0 KB/.test(burst.tot) && /10-28/.test(steady.tot) && /▼ 1\.0 KB/.test(steady.tot),
        burst.tot + ' | ' + steady.tot);
  // ...and the other way: a day pointed at in a lane lights the chart's column.
  await p.mouse.move(ln.cols[5], (burst.svg.t + burst.svg.b) / 2);
  ln = await lanes(); burst = row(ln, /burst/);
  check('pointing at a day in a lane marks the chart column too',
        ln.hotCol === '5' && ln.rows.every(r => r.hot !== null && near(r.hot, ln.cols[5])), ln.hotCol);
  check('...and a day with nothing says so', /10-30/.test(burst.tot) && /nothing/.test(burst.tot), burst.tot);
  await p.mouse.move(5, 5);
  ln = await lanes(); burst = row(ln, /burst/);
  check('moving away puts the period totals back',
        ln.hotCol === '' && ln.rows.every(r => r.hot === null) && /^10\.0 KB/.test(burst.tot), burst.tot + ' ' + ln.hotCol);

  // -- a day opened ---------------------------------------------------------------------
  const hit = i => p.$eval('#cw-daily .hitrect[data-i="'+i+'"]', r => { const b = r.getBoundingClientRect(); return [b.x + b.width/2, b.y + b.height/2]; });
  let at = await hit(3);
  await p.mouse.click(at[0], at[1]);
  await p.waitForSelector('#histDay h5');
  const day = await p.evaluate(() => ({
    head: document.querySelector('#histDay .dayhead').textContent,
    cols: document.querySelectorAll('#cw-hours .colgroup').length,
    progs: [...document.querySelectorAll('#histDay .hbar .nm')].map(x => x.textContent),
    sel: [...document.querySelectorAll('#cw-daily .colgroup.sel')].map(g => g.dataset.i),
    picked: $('cw-daily').classList.contains('picked'),
    under: $('cw-daily').nextElementSibling === $('histDay')}));
  check('clicking a day asks for that day', dayAsked[dayAsked.length - 1] === '2026-10-28', dayAsked.join());
  check('...and opens it under the chart, its column marked',
        day.under && day.picked && day.sel.join() === '3', JSON.stringify(day));
  check('...with its 24 hours, total and day named', day.cols === 24 && /Oct 28/.test(day.head) && /6\.0 KB/.test(day.head), day.head);
  // The peak is at 00:00, the first column: its label must not run into the
  // axis labels beside it (it did, on a real midnight-heavy day).
  const clash = await p.evaluate(() => {
    const ts = [...document.querySelectorAll('#cw-hours text')].map(t => t.getBoundingClientRect());
    const out = [];
    ts.forEach((a, i) => ts.forEach((b, j) => {
      if (i < j && a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5)
        out.push([i, j]);
    }));
    return out;
  });
  check('...whose labels do not overlap', clash.length === 0, JSON.stringify(clash));
  check('...and the programs and hosts that made it', day.progs.join() === 'burst.exe,b.example', day.progs.join());
  check('...which are plain bars, not more drill-downs',
        await p.evaluate(() => !document.querySelector('#histDay .hbar[data-k]')));

  // It survives the tab's own refresh.
  await p.mouse.move(5, 5);
  await p.evaluate(() => { histSeen = ''; return loadHistory(true); });
  await p.waitForTimeout(400);
  check('the open day stays open across a refresh',
        await p.evaluate(() => !!$('histDay') && document.querySelectorAll('#cw-hours .colgroup').length === 24));

  // Another day replaces it; the same day, or Close, shuts it.
  at = await hit(5);
  await p.mouse.click(at[0], at[1]);
  await p.waitForFunction(() => /Oct 30/.test(($('histDay') || {}).textContent || '') && document.querySelector('#histDay h5'));
  check('clicking another day switches to it', await p.evaluate(() => document.querySelectorAll('.dayx').length === 1));
  await p.mouse.click(at[0], at[1]);
  check('clicking the open day again closes it',
        await p.evaluate(() => !$('histDay') && !$('cw-daily').classList.contains('picked')));
  await p.focus('#cw-daily .hitrect[data-i="1"]');
  await p.keyboard.press('Enter');
  await p.waitForSelector('#histDay h5');
  check('Enter on a focused day opens it too', dayAsked[dayAsked.length - 1] === '2026-10-26');
  await p.click('#dayClose');
  check('...and Close shuts it', await p.evaluate(() => !$('histDay')));

  // -- per adapter, live -----------------------------------------------------------------
  await p.click('.tab[data-p="talkers"]');
  await p.waitForSelector('#talkAd svg', {timeout: 15000});
  const t = await p.evaluate(() => {
    const row = document.querySelector('#talkAd .t'), s = row.querySelector('svg');
    return {first: $('p-talkers').firstElementChild.id, name: row.querySelector('.nm').textContent,
            rate: row.querySelector('.rate').textContent, paths: s.querySelectorAll('path').length,
            w: s.getBoundingClientRect().width, pane: $('p-talkers').getBoundingClientRect().width,
            h4: $('talkAd').querySelector('h4').textContent};
  });
  check('Talkers opens with throughput per adapter', t.first === 'talkAd' && t.h4 === 'By adapter · last 5 min', JSON.stringify(t));
  check('...one row per adapter, its current rate both ways', t.name === 'demo0' && /▼.*\/s · ▲.*\/s/.test(t.rate), t.rate);
  check('...received and sent drawn the width of the panel', t.paths === 2 && t.w > t.pane * 0.8, JSON.stringify(t));
  check('no sideways scroll', await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
