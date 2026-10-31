const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The header dropdown filters the view by adapter, and the Alerts pane stops redrawing
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
  // The header dropdown is the adapter filter (1.41): it lists them, and
  // choosing one never touches the capture.
  const opts = await p.$$eval('#iface option', o => o.map(x => [x.value, x.textContent]));
  check('the dropdown offers All adapters and each adapter seen',
        opts[0][0] === '' && /All adapters/.test(opts[0][1]) &&
        opts.some(o => o[0] === 'Alpha NIC') && opts.some(o => o[0] === 'Beta NIC'), JSON.stringify(opts));
  check('the old adapter tabs are gone', !(await p.$('#ifbar')));
  const capturing = await p.evaluate(() => lastStatus.iface);
  let posted = [];
  p.on('request', r => { if (r.url().includes('/api/control')) posted.push(r.postData()); });

  // The clear button sits inside the box's right end, and the box is marked while a filter is on.
  await p.fill('#find', 'proto == TCP');
  const cl = await p.evaluate(() => {
    const f = $('find').getBoundingClientRect(), x = $('findClear').getBoundingClientRect();
    return {inside: x.left > f.left && x.right <= f.right && x.top >= f.top && x.bottom <= f.bottom,
            active: $('findwrap').classList.contains('active'), boxW: f.width};
  });
  check('the clear button is inside the filter box', cl.inside, JSON.stringify(cl));
  check('...the box is capped so the button stays near the text', cl.boxW <= 640, String(cl.boxW));
  check('...and the box shows a filter is in force', cl.active);
  await p.focus('#find'); await p.keyboard.press('Escape');
  check('Esc clears the filter', await p.inputValue('#find') === '' &&
        await p.evaluate(() => !$('findwrap').classList.contains('active')));

  const vis = () => p.evaluate(() => [...$('rows').children].filter(t => t.style.display !== 'none').length);
  const seqVis = s => p.evaluate(s => { const t = $('rows').querySelector('tr[data-seq="'+s+'"]'); return t.style.display !== 'none'; }, s);
  await p.selectOption('#iface', 'Beta NIC');
  check('choosing an adapter shows only its packets', await seqVis(900002) && await seqVis(900003) && !await seqVis(900001));
  check('...and the count says so', /of/.test(await p.textContent('#fcount')));
  check('...the dropdown is outlined while it narrows', await p.$eval('#iface', s => s.classList.contains('on')));
  await p.waitForTimeout(1500);
  check('...and the capture is not touched', posted.length === 0 &&
        await p.evaluate(() => lastStatus.iface) === capturing, JSON.stringify(posted));

  // It combines with the filter box.
  await p.fill('#find', 'seq == 900003');
  check('...and combines with the filter box', await vis() === 1, String(await vis()));
  await p.fill('#find', '');

  await p.selectOption('#iface', '');
  check('All adapters shows everything again', await seqVis(900001) && await seqVis(900002));
  check('...and the outline goes', await p.$eval('#iface', s => !s.classList.contains('on')));
  await p.click('#apply');
  await p.waitForTimeout(500);
  check('Apply sends no adapter', posted.length === 1 && !/iface/.test(posted[0]), JSON.stringify(posted));

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
