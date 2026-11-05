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
          hosts:[{host:'a.example', bytes_in:K, bytes_out:1, packets:1, first_seen:1.8e9, trend:[0,0,1,0,0,0,K]}],
          new_hosts:[], sessions:[],
          processes:[{name:'steady.exe', bytes_in:7*K, bytes_out:0, packets:7, trend:[K,K,K,K,K,K,K]},
                     {name:'burst.exe', bytes_in:9*K, bytes_out:0, packets:1, trend:[0,0,0,9*K,0,0,0]}],
          range:{bytes_in:16*K, bytes_out:K, packets:8, programs:2, hosts:1},
          alert_counts:{total:0}, exclude:{programs:[],hosts:[]},
          summary:{since:'2026-10-25', path:'C:\\history.db', size:1, retain_days:90, alert_retain_days:30}};
}
function dayData(day){
  return {day, iface:'', hours:Array.from({length:24}, (_, h) => ({hour:h, bytes_in: h === 9 ? 5*K : 0, bytes_out: h === 9 ? K : 0})),
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
  const tr = await p.evaluate(() => [...document.querySelectorAll('#p-history .hbar[data-k]')].map(r => {
    const s = r.querySelector('svg.trend'), b = s && s.getBoundingClientRect();
    return {n: r.querySelector('.nm').textContent, w: b ? Math.round(b.width) : 0,
            title: s ? s.querySelector('title').textContent : '', line: s ? s.querySelector('path.l').getAttribute('d') : ''};
  }));
  check('each program and host bar has a trend beside it', tr.length === 3 && tr.every(t => t.w === 64), JSON.stringify(tr));
  const steady = tr.find(t => /steady/.test(t.n)), burst = tr.find(t => /burst/.test(t.n));
  check('...a steady program draws flat, a burst one a spike',
        /M0\.0,1\.0 L/.test(steady.line) && !/,13\.0 L/.test(steady.line) && /,13\.0 L/.test(burst.line),
        steady.line + ' | ' + burst.line);
  check('...and says when its busiest day was', /busiest 9\.0 KB on 2026-10-28, active 1 of 7 days/.test(burst.title), burst.title);

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
