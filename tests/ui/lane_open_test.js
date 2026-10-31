const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// Clicking a Timeline lane opens its packets: the table, filtered to the lane,
// with the newest one selected and shown in the Packet tab.
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:980} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>20,null,{timeout:90000});
  await p.click('#vTime');
  await p.click('#tlGroup [data-g="process"]');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length>1, null, {timeout:20000});
  // A lane that has packets in the buffer right now.
  const lane = await p.evaluate(()=>{ const names=[...document.querySelectorAll('#tlLabels .ln')].map(b=>b.dataset.name);
    const recent=[...records.values()].reverse().map(r=>r.process);
    return names.find(n=>!/^\(/.test(n) && recent.includes(n)); });
  check('found a lane with packets in the buffer', !!lane);
  await p.click('#tlLabels .ln[data-name="'+lane+'"] .nm');
  await p.waitForTimeout(400);
  const r = await p.evaluate(()=>{
    const tr = document.querySelector('#rows tr.sel'), rec = selected != null ? records.get(selected) : null;
    const box = tr && tr.getBoundingClientRect(), tw = document.getElementById('tw').getBoundingClientRect();
    const visible = [...records.values()].filter(rowVisible);
    return {view: viewMode, find: document.getElementById('find').value, proc: rec && rec.process,
            newest: visible.length ? visible[visible.length-1].seq === selected : false,
            onScreen: !!box && box.top >= tw.top - 1 && box.bottom <= tw.bottom + 1,
            tab: document.querySelector('.tab.on').dataset.p,
            detail: document.getElementById('p-detail').textContent.length};
  });
  check('the table is shown', r.view==='table', JSON.stringify(r));
  check('...filtered to the lane, in the filter box', r.find==='process == "'+lane+'"', r.find);
  check("...with the lane's newest packet selected", r.proc===lane && r.newest, JSON.stringify(r));
  check('...on screen', r.onScreen, JSON.stringify(r));
  check('...and open in the Packet tab', r.tab==='detail' && r.detail>20, JSON.stringify(r));
  check('no page errors', errs.length===0, errs.join(' | '));
  await b.close();
  console.log(); console.log('FAILED:', fails.length ? fails : 'none');
  process.exit(fails.length?1:0);
})();
