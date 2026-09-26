const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The demo server runs with --no-history, so /api/history is answered here
// instead: a payload whose totals we can change between refreshes.
const G = Math.pow(1024,3);
let total = 10*G, served = 0, failFirst = true;
function payload(){
  const daily = [];
  for (let i=0;i<30;i++) daily.push({day:'2026-09-'+String(i+1).padStart(2,'0'),
    bytes_in: (i===29?total:G)*0.8, bytes_out: (i===29?total:G)*0.2, packets: 1000});
  const sessions = [];
  for (let i=0;i<10;i++) sessions.push({started: 1790000000+i*3600, iface:'Ethernet', version:'1.22.1', packets: 5000});
  const processes = [];
  for (let i=0;i<15;i++) processes.push({name:'prog'+i+'.exe', bytes_in: G, bytes_out: G/4, packets: 10});
  return {enabled:true, days:30, daily, hourly:[], processes, hosts:[], new_hosts:[], alerts:[], sessions,
          summary:{bytes_in: total*0.8, bytes_out: total*0.2, packets: 123, processes: 15, hosts: 0,
                   size: 1024*1024, retain_days: 90, since:'2026-09-01', path:'C:\\history.db'}};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:700} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.route('**/api/history*', route => {
    served++;
    if (failFirst){ failFirst = false; return route.abort(); }
    route.fulfill({status:200, contentType:'application/json', body: JSON.stringify(payload())});
  });
  await p.clock.install();
  await p.goto(process.argv[2]);
  await p.waitForTimeout(800);
  const tick = async () => { await p.clock.runFor(10000); await p.waitForTimeout(600); };
  const kpi = () => p.evaluate(()=>{
    const v = document.querySelector('#p-history .kpi .v'); return v ? v.textContent : null; });

  // --- A failed first fetch used to leave "Loading history…" up for good.
  check('the first fetch failed, as arranged', served===1, 'served '+served);
  check('...leaving the placeholder', /Loading history/.test(await p.textContent('#p-history')));
  await tick();
  check('the pane recovers on the next beat without a click', (await kpi())==='10.0 GB', await kpi());

  // --- New data shows up by itself, keeping the reader's place.
  await p.evaluate(()=>{
    const pane = document.getElementById('p-history');
    const s = [...pane.querySelectorAll('.sec')].find(x=>/Recent sessions/.test(x.textContent));
    s.querySelector('details').open = true;
    pane.scrollTop = 300;
  });
  const before = await p.evaluate(()=>document.getElementById('p-history').scrollTop);
  total = 20*G;
  await tick();
  check('changed totals appear without a click', (await kpi())==='20.0 GB', await kpi());
  const kept = await p.evaluate(()=>{
    const pane = document.getElementById('p-history');
    const open = [...pane.querySelectorAll('details')].filter(d=>d.open)
                 .map(d=>d.closest('.sec').querySelector('h4').textContent);
    return {open, top: pane.scrollTop};
  });
  check('an opened Table view stays open across the refresh',
        kept.open.length===1 && kept.open[0]==='Recent sessions', JSON.stringify(kept.open));
  check('...and the scroll position is kept', before>0 && kept.top===before, before+' -> '+kept.top);

  // --- Nothing changed: the pane is not rebuilt at all.
  await p.evaluate(()=>{ document.querySelector('#p-history .kpirow').dataset.mark = '1'; });
  await tick();
  check('an unchanged refresh leaves the DOM alone',
        await p.evaluate(()=>document.querySelector('#p-history .kpirow').dataset.mark==='1'));

  // --- A showing tooltip defers the redraw instead of vanishing under the pointer.
  await p.evaluate(()=>{
    const pane = document.getElementById('p-history'); pane.scrollTop = 0;
    const hit = pane.querySelector('.hitrect'), r = hit.getBoundingClientRect();
    hit.dispatchEvent(new PointerEvent('pointermove',{clientX:r.left+2, clientY:r.top+2, bubbles:true}));
  });
  total = 30*G;
  await tick();
  check('no redraw while the chart tooltip is showing',
        (await kpi())==='20.0 GB' && await p.evaluate(()=>!!document.querySelector('#tip-daily.on')), await kpi());
  await p.evaluate(()=>document.querySelector('#p-history .hitrect')
                        .dispatchEvent(new PointerEvent('pointerleave')));
  await tick();
  check('...and it catches up once the tooltip is gone', (await kpi())==='30.0 GB', await kpi());

  // --- Other tabs aren't charged for History's refresh.
  await p.click('.tab[data-p="alerts"]');
  const n = served;
  await tick(); await tick();
  check('History is not fetched while another tab is open', served===n, (served-n)+' fetches');

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
