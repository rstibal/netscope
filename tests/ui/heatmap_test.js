const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// History's busy-hours heatmap. The demo runs with --no-history, so the
// data is answered here: busy working hours, quiet nights, an empty hour,
// and one odd night that should stand out.
const G = Math.pow(1024,3), M = Math.pow(1024,2);
let total = 5*G;
function weekHours(){
  const cells = [];
  for (let d = 0; d < 7; d++){
    const row = [];
    for (let h = 0; h < 24; h++){
      let v = (d < 5 && h >= 8 && h <= 18) ? 2*G : h < 7 ? 20*M : 0.3*G;
      if (h === 5) v = 0;
      if (d === 2 && h === 3) v = 1.5*G;
      row.push([Math.round(v*0.75), Math.round(v*0.25)]);
    }
    cells.push(row);
  }
  return {cells, counts: [4,4,4,4,5,5,4]};
}
function history(){
  const daily = [];
  for (let i=0;i<30;i++) daily.push({day:'2026-09-'+String(i+1).padStart(2,'0'), bytes_in:G, bytes_out:G/4, packets:10});
  return {enabled:true, days:30, daily, hourly:[], hosts:[], new_hosts:[], sessions:[], processes:[],
          exclude:{programs:[],hosts:[]}, week_hours: weekHours(),
          summary:{bytes_in: total*0.8, bytes_out: total*0.2, packets:1, processes:1, hosts:0, size:1024,
                   retain_days:90, since:'2026-09-01', path:'C:\\history.db'}};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.route('**/api/history*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history())}));
  await p.goto(process.argv[2]);
  await p.waitForSelector('#cw-week svg', {timeout: 30000});

  const g = await p.evaluate(()=>{
    const cells = [...document.querySelectorAll('#cw-week rect.hm-cell, #cw-week rect.hm-empty')];
    const op = (d, h) => { const r = cells[d*24+h]; return r.classList.contains('hm-empty') ? 0 : Number(r.getAttribute('fill-opacity')); };
    return {n: cells.length, hits: document.querySelectorAll('#cw-week .hm-hit').length,
            work: op(1, 10), night: op(1, 2), empty: op(1, 5), odd: op(2, 3), evening: op(5, 21),
            days: [...document.querySelectorAll('#cw-week text')].filter(t=>t.getAttribute('text-anchor')==='end').map(t=>t.textContent),
            marked: document.querySelectorAll('#cw-week .hm-now').length,
            title: document.querySelector('#cw-week').closest('.sec').querySelector('h4').textContent};
  });
  check('a 7 × 24 grid, under its own heading', g.n===168 && g.hits===168 && g.title==='Busy hours · last 30 days', JSON.stringify(g));
  check('Monday first, in the browser\'s own day names', g.days.length===7 &&
        g.days[0]===new Date(2024,0,1).toLocaleDateString([], {weekday:'short'}), JSON.stringify(g.days));
  check('busy hours are darkest, quiet nights pale, but still shown', g.work===1 && g.night>0 && g.night<=0.36, JSON.stringify(g));
  check('an hour with nothing is drawn as empty', g.empty===0);
  check('one odd busy night stands out from the nights around it', g.odd>=0.78 && g.odd>g.night, JSON.stringify(g));
  check('no square is outlined as if selected', g.marked===0);

  await p.hover('#cw-week .hm-hit[data-d="2"][data-h="3"]');
  const tip = await p.evaluate(()=>{ const t = document.getElementById('tip-week');
    const r = t.getBoundingClientRect(), w = document.getElementById('cw-week').getBoundingClientRect();
    return {on: t.classList.contains('on'), text: t.textContent, inside: r.left>=w.left-1 && r.right<=w.right+1}; });
  const wed = await p.evaluate(()=>new Date(2024,0,3).toLocaleDateString([], {weekday:'long'}));
  check('hovering an hour says which, how much each way, and over how many days',
        tip.on && tip.text.startsWith(wed+' 03:00–04:00') && /▼ received1\.1 GB/.test(tip.text) &&
        /▲ sent384\.0 MB/.test(tip.text) && tip.text.endsWith('average of4 '+wed+'s'), tip.text);
  check('...inside the chart', tip.inside);
  // A click focuses the square; it must not stay outlined once the pointer leaves.
  await p.click('#cw-week .hm-hit[data-d="2"][data-h="3"]');
  await p.mouse.move(5, 5);
  const stuck = await p.evaluate(()=>getComputedStyle(document.querySelector('#cw-week .hm-hit[data-d="2"][data-h="3"]')).stroke);
  check('a clicked square is not left outlined', stuck==='none', stuck);
  await p.hover('#cw-week .hm-hit[data-d="2"][data-h="3"]');

  // The 10-second refresh waits while the tooltip is up.
  total = 9*G;
  await p.evaluate(()=>loadHistory(true));
  await p.waitForTimeout(400);
  check('an automatic refresh waits while the tooltip is showing',
        await p.evaluate(()=>document.querySelector('#p-history .kpi .v').textContent)==='5.0 GB');
  await p.mouse.move(5, 5);
  await p.evaluate(()=>loadHistory(true));
  await p.waitForFunction(()=>document.querySelector('#p-history .kpi .v').textContent==='9.0 GB');

  // Table view: every value reachable without hovering.
  await p.click('#cw-week ~ details.tvw summary');
  const t = await p.evaluate(()=>{ const tb = document.querySelector('#cw-week').parentNode.querySelector('table.tv');
    const pane = document.getElementById('p-history');
    return {rows: tb.querySelectorAll('tr').length, cols: tb.querySelector('tr').children.length,
            r3: [...tb.querySelectorAll('tr')[4].children].map(x=>x.textContent),
            fits: pane.scrollWidth <= pane.clientWidth}; });
  check('the table view has an hour per row and a column per day', t.rows===25 && t.cols===8, JSON.stringify(t));
  check('...with the values', t.r3[0]==='03:00' && t.r3[3]==='1.5 GB' && t.r3[2]==='20.0 MB', JSON.stringify(t.r3));
  check('...and fits the side panel without scrolling sideways', t.fits);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
