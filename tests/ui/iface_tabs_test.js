const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Table view gets a tab per adapter, and the Alerts pane stops redrawing
// under the pointer (a new alert used to slide Mute under a click aimed at
// "Why did this fire?").
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>40,null,{timeout:60000});

  // Feed rows from two adapters through the real row builder.
  await p.evaluate(() => {
    for (const [i, n] of [[900001,'Alpha NIC'],[900002,'Beta NIC'],[900003,'Beta NIC']]){
      const tr = addRow({seq:i,time:'00:00:00',iface:n,process:'t.exe',dir:'out',src:'1.1.1.1',dst:'2.2.2.2',
                         proto:'TCP',length:60,info:'x',sport:1,dport:2});
      $('rows').appendChild(tr);
    }
  });
  const bar = () => p.evaluate(() => ({shown: $('ifbar').style.display !== 'none',
                                       labels: [...$('ifbar').children].map(x => x.textContent)}));
  const bb = await bar();
  check('the strip appears with two adapters', bb.shown && bb.labels[0] === 'All' && bb.labels.length >= 3, JSON.stringify(bb));

  const vis = () => p.evaluate(() => [...$('rows').children].filter(t => t.style.display !== 'none').length);
  const seqVis = s => p.evaluate(s => { const t = $('rows').querySelector('tr[data-seq="'+s+'"]'); return t.style.display !== 'none'; }, s);
  await p.click('#ifbar [data-if="Beta NIC"]');
  check('a tab shows only its adapter', await seqVis(900002) && await seqVis(900003) && !await seqVis(900001));
  check('...and the count says so', /of/.test(await p.textContent('#fcount')));

  // It combines with the filter box.
  await p.fill('#find', 'seq == 900003');
  check('...and combines with the filter box', await vis() === 1, String(await vis()));
  await p.fill('#find', '');

  await p.click('#ifbar [data-if=""]');
  check('All shows everything again', await seqVis(900001) && await seqVis(900002));

  // The Alerts pane waits while the pointer is over it.
  await p.click('.tab[data-p="alerts"]');
  await p.waitForSelector('#p-alerts [data-rule]', {timeout: 40000});
  await p.hover('#p-alerts');
  await p.evaluate(() => { const m = document.createElement('i'); m.id = 'marker'; $('p-alerts').appendChild(m); });
  await p.waitForTimeout(6000);
  check('no redraw while the pointer is over the pane', await p.locator('#marker').count() === 1);
  await p.mouse.move(5, 5);
  await p.waitForTimeout(3500);
  check('...and it resumes when the pointer leaves', await p.locator('#marker').count() === 0);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
