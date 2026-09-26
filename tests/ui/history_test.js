const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:980} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);

  // --- History is the tab the page opens on, and it loads without a click.
  const first = await p.evaluate(()=>({
    tab: document.querySelector('.tab.on').dataset.p,
    panes: [...document.querySelectorAll('.pane')].filter(x=>getComputedStyle(x).display!=='none').map(x=>x.id),
  }));
  check('History is the active tab on load', first.tab==='history', first.tab);
  check('...and its pane is the only one showing',
        first.panes.length===1 && first.panes[0]==='p-history', JSON.stringify(first.panes));
  await p.waitForFunction(()=>!/Loading history/.test(document.getElementById('p-history').textContent),
                          null,{timeout:10000}).catch(()=>{});
  check('History is fetched without clicking its tab',
        !/Loading history/.test(await p.textContent('#p-history')),
        (await p.textContent('#p-history')).slice(0,80));

  // --- Clicking a packet still doesn't pull you off the tab you're on
  //     (a deliberate choice, see select()); the Packet badge shows it took.
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>20,null,{timeout:90000});
  await p.click('#rows tr:nth-child(5)');
  await p.waitForTimeout(400);
  const after = await p.evaluate(()=>({tab: document.querySelector('.tab.on').dataset.p,
                                      badge: document.getElementById('nPkt').textContent}));
  check('clicking a packet leaves History showing', after.tab==='history', after.tab);
  check('...and the Packet tab badge shows the selection', /^#\d+$/.test(after.badge), after.badge);

  // --- The daily chart's axis fits the data. It used to jump straight from
  //     8 to 1024 of a unit, so a month of 10-40 GB days drew against a 1 TB
  //     axis with 256 GB gridlines and every bar was a sliver.
  const chart = await p.evaluate(()=>{
    const G = Math.pow(1024,3), out = [];
    for (const peakGB of [5, 9, 20, 37, 65, 130, 300, 700]){
      const rows = [];
      for (let i=0;i<30;i++){
        const tot = peakGB*G*(0.3 + 0.7*((i*7)%30)/29);      // peak on one day
        rows.push({day:'2026-09-'+String(i+1).padStart(2,'0'),
                   bytes_in: tot*0.8, bytes_out: tot*0.2, packets: 1});
      }
      const svg = new DOMParser().parseFromString(dailyChart(rows),'image/svg+xml');
      const peak = svg.querySelector('text[style*="font-weight"]');
      const labels = [...svg.querySelectorAll('text.axlbl')].filter(t=>t.getAttribute('text-anchor')==='end')
                     .map(t=>t.textContent);
      // plot runs from y=12 (top) to y=146 (baseline); the peak label sits 5px above its bar
      const barTop = Number(peak.getAttribute('y')) + 5;
      out.push({peakGB, fill: (146 - barTop) / 134, labels});
    }
    return out;
  });
  const thin = chart.filter(c => c.fill < 0.75);
  check('the tallest day fills at least three quarters of the chart',
        thin.length===0, JSON.stringify(thin.map(c=>[c.peakGB+' GB', c.fill.toFixed(2), c.labels.at(-1)])));
  const top20 = chart.find(c=>c.peakGB===20);
  check('a 20 GB month is not drawn against a 1 TB axis',
        top20 && !/TB/.test(top20.labels.join(' ')), JSON.stringify(top20 && top20.labels));
  const ugly = chart.flatMap(c=>c.labels).filter(l=>!/^\d+\.[05] [KMGT]?B$|^0 B$/.test(l));
  check('every gridline label is a clean number', ugly.length===0, JSON.stringify(ugly));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
