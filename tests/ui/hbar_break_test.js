const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// History's By program chart. One program that streams VR can dwarf the rest;
// its bar is cut short with a visible break so the others stay readable.
const G = Math.pow(1024,3);
function history(processes, hosts){
  const daily = [];
  for (let i=0;i<30;i++) daily.push({day:'2026-09-'+String(i+1).padStart(2,'0'), bytes_in:G, bytes_out:G/4, packets:10});
  return {enabled:true, days:30, daily, hourly:[], hosts: hosts||[], new_hosts:[], sessions:[], processes,
          exclude:{programs:[],hosts:[]},
          week_hours:{cells:Array.from({length:7},()=>Array.from({length:24},()=>[0,0])), counts:[4,4,4,4,4,4,4]},
          summary:{bytes_in: 1, bytes_out: 1, packets:1, processes:1, hosts:0, size:1024,
                   retain_days:90, since:'2026-09-01', path:'C:\history.db'}};
}
const proc = (name, gb) => ({name, bytes_in: Math.round(gb*G*0.9), bytes_out: Math.round(gb*G*0.1), packets: 100});
let current = history([proc('vrstreamer.exe',231), proc('chrome.exe',25), proc('steam.exe',8), proc('code.exe',1)]);

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.route('**/api/history*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(current)}));
  await p.goto(process.argv[2]);
  await p.waitForSelector('.hbar', {timeout: 30000});

  const read = () => p.evaluate(()=>{
    const sec = [...document.querySelectorAll('.sec')].find(s=>/By program/.test(s.querySelector('h4').textContent));
    const rows = [...sec.querySelectorAll('.hbar')].map(r=>{
      const t = r.querySelector('.track'), w = t.getBoundingClientRect().width;
      const fill = [...t.querySelectorAll('i')].reduce((a,i)=>a+i.getBoundingClientRect().width,0);
      return {name: r.querySelector('.nm').textContent, label: r.children[1].textContent,
              pct: fill/w*100, brk: !!t.querySelector('b.brk'), title: t.getAttribute('title')||''};
    });
    return {rows, note: /cut short/.test(sec.textContent)};
  });

  let g = await read();
  const [big, second, third, small] = g.rows;
  check('the outlier is cut and fills the track', big.brk && big.pct > 95, JSON.stringify(big));
  check('...and still reports its real total', big.label === '231.0 GB', big.label);
  check('...and says it is not to scale', /not to scale/.test(big.title), big.title);
  check('the next program is no longer a sliver', second.pct > 60 && second.pct < 100 && !second.brk, JSON.stringify(second));
  check('the rest keep their proportions to each other',
        Math.abs(third.pct/second.pct - 8/25) < 0.03 && Math.abs(small.pct/second.pct - 1/25) < 0.02,
        JSON.stringify([second.pct, third.pct, small.pct]));
  check('a one-line note explains the cut', g.note);

  // Without an outlier nothing changes.
  current = history([proc('a.exe',20), proc('b.exe',12), proc('c.exe',6)]);
  await p.reload();
  await p.waitForSelector('.hbar', {timeout: 30000});
  g = await read();
  check('a balanced list has no cut and no note', g.rows.every(r=>!r.brk) && !g.note, JSON.stringify(g));
  check('...and the biggest fills the track', Math.abs(g.rows[0].pct - 100) < 1, g.rows[0].pct);

  // Exactly at the limit is not an outlier; a single program never is.
  current = history([proc('a.exe',30), proc('b.exe',10)]);
  await p.reload(); await p.waitForSelector('.hbar', {timeout: 30000});
  g = await read();
  check('3x the next is not yet cut', g.rows.every(r=>!r.brk), JSON.stringify(g.rows));
  current = history([proc('solo.exe',200)]);
  await p.reload(); await p.waitForSelector('.hbar', {timeout: 30000});
  g = await read();
  check('a lone program is not cut', g.rows.length===1 && !g.rows[0].brk && g.rows[0].pct > 95, JSON.stringify(g.rows));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
