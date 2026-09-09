const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport: { width: 1680, height: 900 } });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>60,null,{timeout:60000});

  const geom = () => p.evaluate(() => {
    const out = {};
    for (const id of ['spark','sPk','sIn','sOut','sRate','sAttr']){
      const r = document.getElementById(id).getBoundingClientRect();
      out[id] = {x: Math.round(r.x*100)/100, w: Math.round(r.width*100)/100};
    }
    out.text = ['sPk','sIn','sOut','sRate','sAttr']
      .map(i => document.getElementById(i).textContent).join('|');
    return out;
  });

  // Sample across many poll cycles while the values are actively changing.
  const samples = [];
  for (let i=0;i<14;i++){ samples.push(await geom()); await p.waitForTimeout(1000); }

  const xs = v => [...new Set(samples.map(s => s[v].x))];
  const changed = [...new Set(samples.map(s => s.text))].length;
  check('values really did change during the run', changed > 3, `${changed} distinct readings`);

  check('spark never moves', xs('spark').length === 1, JSON.stringify(xs('spark')));
  for (const id of ['sPk','sIn','sOut','sRate','sAttr'])
    check(id + ' never moves', xs(id).length === 1, JSON.stringify(xs(id)));

  check('spark is the first footer child',
        await p.evaluate(()=>document.querySelector('footer').firstElementChild.id === 'spark'));

  // Narrow window: the footer wraps, but nothing should jitter or overflow.
  await p.setViewportSize({width: 900, height: 800});
  await p.waitForTimeout(1200);
  const narrow = [];
  for (let i=0;i<5;i++){ narrow.push(await geom()); await p.waitForTimeout(1000); }
  check('spark stable at 900px too',
        [...new Set(narrow.map(s=>s.spark.x))].length === 1,
        JSON.stringify([...new Set(narrow.map(s=>s.spark.x))]));
  check('no document h-scroll at 900px',
        await p.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
