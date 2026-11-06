const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// 1.44.1: History's charts were drawn 560 units wide and stretched to the
// pane. Under 1100px the side panel moves below the table and goes full
// width, so every label and bar came out nearly twice the size, and the axis
// labels ran off the left edge. They are now drawn one unit to a pixel, and
// redrawn when the pane changes width.
const K = 1024;
function history(){
  const daily = [];
  for (let i = 0; i < 7; i++)
    daily.push({day:'2026-10-' + String(25 + i).padStart(2,'0'), bytes_in:(i+1)*300*K*K, bytes_out:20*K*K, packets:10});
  return {enabled:true, days:7, iface:'', ifaces:[], daily, hosts:[], new_hosts:[],
          processes:[{name:'a.exe', bytes_in:K, bytes_out:0, packets:1, trend:[0,0,0,0,0,0,K]}],
          range:{bytes_in:K, bytes_out:K, packets:8, programs:1, hosts:0},
          alert_counts:{total:0}, exclude:{programs:[],hosts:[]},
          summary:{since:'2026-10-25', path:'C:\\history.db', size:1, retain_days:90, alert_retain_days:30}};
}
const day = d => ({day:d, iface:'', programs:[], hosts:[],
  hours:Array.from({length:24}, (_, h) => ({hour:h, bytes_in: h === 2 ? 5*K : 0, bytes_out: 0}))});

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1072,height:1260} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.route('**/api/history?*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history())}));
  await p.route('**/api/history/day?*', r => r.fulfill({status:200, contentType:'application/json',
    body: JSON.stringify(day(new URL(r.request().url()).searchParams.get('day')))}));
  await p.goto(process.argv[2]);
  await p.evaluate(() => showTab('history'));
  await p.waitForSelector('#cw-daily svg', {timeout: 30000});
  await p.evaluate(() => openDay('2026-10-31'));
  await p.waitForSelector('#cw-hours svg');

  const measure = () => p.evaluate(() => [...document.querySelectorAll('#cw-daily svg, #cw-hours svg')].map(s => {
    const r = s.getBoundingClientRect(), vb = s.viewBox.baseVal, pane = $('p-history').getBoundingClientRect();
    const lbl = [...s.querySelectorAll('.axlbl')].map(t => t.getBoundingClientRect());
    return {scale: r.width / vb.width, font: Math.max(...lbl.map(x => x.height)),
            left: Math.min(...lbl.map(x => x.left)) - pane.left};
  }));

  let m = await measure();
  check('full width under the table: drawn one unit to a pixel', m.length === 2 && m.every(x => Math.abs(x.scale - 1) < 0.02), JSON.stringify(m));
  check('...so the labels stay small', m.every(x => x.font <= 13), JSON.stringify(m));
  check('...and none runs off the left edge', m.every(x => x.left >= 0), JSON.stringify(m));

  // Wide enough for the side panel to come back beside the table.
  await p.setViewportSize({width:1500, height:1000});
  await p.waitForTimeout(400);
  m = await measure();
  check('a resize redraws both charts to the new width', m.length === 2 && m.every(x => Math.abs(x.scale - 1) < 0.02), JSON.stringify(m));
  check('...still answering hover', await p.evaluate(() => {
    const h = document.querySelector('#cw-daily .hitrect[data-i="2"]'), r = h.getBoundingClientRect();
    h.dispatchEvent(new PointerEvent('pointermove', {clientX: r.left + 2, clientY: r.top + 2, bubbles: true}));
    return $('tip-daily').classList.contains('on') && /2026-10-27/.test($('tip-daily').textContent);
  }));
  check('...and the open day keeps its column marked',
        await p.evaluate(() => [...document.querySelectorAll('#cw-daily .colgroup.sel')].map(g => g.dataset.i).join() === '6'));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
