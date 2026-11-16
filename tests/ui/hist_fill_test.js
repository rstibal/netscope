const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// 1.51.1: a history shorter than the chosen range. The server sends only the
// days from the first recorded one, so three days on the 30-day view are
// three columns across the chart, not three pushed to the right of 27 empty
// ones, and the headings say how many days there are.
const K = 1024;
function history(n){
  const daily = [];
  for (let i = 0; i < n; i++)
    daily.push({day:'2026-10-' + String(25 + i).padStart(2,'0'), bytes_in:(i+1)*K, bytes_out:K, packets:10});
  const t = v => Array.from({length:n}, (_, i) => i === n - 1 ? v : 0);
  return {enabled:true, days:30, iface:'', ifaces:['Wi-Fi'], daily,
          hosts:[{host:'a.example', bytes_in:K, bytes_out:0, packets:1, first_seen:1.8e9, trend_in:t(K), trend_out:t(0)}],
          new_hosts:[], sessions:[],
          processes:[{name:'new.exe', bytes_in:n*K, bytes_out:0, packets:7,
                      trend_in:Array.from({length:n}, () => K), trend_out:t(0)}],
          range:{bytes_in:16*K, bytes_out:K, packets:8, programs:1, hosts:1},
          alert_counts:{total:0}, exclude:{programs:[],hosts:[]},
          summary:{since:'2026-10-25', path:'C:\\history.db', size:1, retain_days:90, alert_retain_days:30}};
}
let current = history(3);

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:1000} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.route('**/api/history?*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(current)}));
  await p.route('**/api/history/detail*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(
    {kind:'program', name:'new.exe', days:30, pairs_since:'2026-10-25', total:3*K, unlisted:0, hours:[],
     busiest:[{day:'2026-10-27', hour:12, bytes_in:K, bytes_out:0, host:'a.example'}],
     rows:[{name:'a.example', bytes_in:K, bytes_out:0, packets:1, trend_in:[0,0,K], trend_out:[0,0,0]}]})}));
  await p.goto(process.argv[2]);
  await p.evaluate(() => showTab('history'));
  await p.waitForSelector('#cw-daily svg', {timeout: 30000});

  await p.evaluate(async () => { document.querySelectorAll('#p-history details[data-fold]:not([open]) > summary').forEach(s => s.click()); await new Promise(r => setTimeout(r, 60)); });

  const read = () => p.evaluate(() => {
    const box = e => { const q = e.getBoundingClientRect(); return {l: q.left, r: q.right, cx: q.left + q.width / 2}; };
    const svg = box(document.querySelector('#cw-daily svg'));
    const hits = [...document.querySelectorAll('#cw-daily .hitrect')].map(box);
    return {svg, hits,
            lane: [...document.querySelectorAll('.hbar[data-k="program"] .lb.in')].map(box),
            heads: [...document.querySelectorAll('#p-history h4, #p-history h5')].map(h => h.textContent)};
  });
  let g = await read();
  check('three recorded days are three columns', g.hits.length === 3, String(g.hits.length));
  check('...spread across the chart, not pushed to the right',
        g.hits[0].l < g.svg.l + 60 && g.hits[2].r > g.svg.r - 20 &&
        g.hits[2].r - g.hits[0].l > (g.svg.r - g.svg.l) * 0.8, JSON.stringify([g.svg, g.hits]));
  check('...with each lane bar under its day', g.lane.length === 3 && g.lane.every((q, i) => Math.abs(q.cx - g.hits[i].cx) <= 1),
        JSON.stringify(g.lane));
  const titled = re => g.heads.filter(t => re.test(t));
  check('the headings say how many days there are, not the range asked for',
        titled(/^(Daily traffic|By program|By host) · 3 days so far$/).length === 3 && !titled(/last 30 days/).length,
        JSON.stringify(g.heads));
  await p.click('.hbar[data-k="program"]');
  await p.waitForSelector('.hdet .hbar.lane');
  g = await read();
  check('...in an opened row too',
        titled(/^Talked to · 3 days so far$/).length === 1 && titled(/^Busiest hours · 3 days so far$/).length === 1 && !titled(/last 30 days/).length,
        JSON.stringify(g.heads));

  // One day: a lone column, and the singular.
  current = history(1);
  await p.reload();
  await p.evaluate(() => showTab('history'));
  await p.waitForSelector('#cw-daily svg', {timeout: 30000});

  await p.evaluate(async () => { document.querySelectorAll('#p-history details[data-fold]:not([open]) > summary').forEach(s => s.click()); await new Promise(r => setTimeout(r, 60)); });
  g = await read();
  check('a single day draws, and is called 1 day', g.hits.length === 1 && g.lane.length === 1 &&
        g.heads.includes('Daily traffic · 1 day so far'), JSON.stringify(g.heads));

  // A full range still reads as before.
  current = history(7); current.days = 7;
  await p.reload();
  await p.evaluate(() => showTab('history'));
  await p.waitForSelector('#cw-daily svg', {timeout: 30000});

  await p.evaluate(async () => { document.querySelectorAll('#p-history details[data-fold]:not([open]) > summary').forEach(s => s.click()); await new Promise(r => setTimeout(r, 60)); });
  g = await read();
  check('a range the history fills says last N days', g.heads.includes('Daily traffic · last 7 days'), JSON.stringify(g.heads));

  check('no sideways scroll', await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
