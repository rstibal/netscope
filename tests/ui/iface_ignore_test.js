const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1280,height:860} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>$('iface').options.length > 2 && lastStatus, null, {timeout:60000});

  const before = await p.$eval('#iface', s => s.value);
  await p.selectOption('#iface', '__ignore');
  await p.waitForSelector('#rowmenu.on');
  check('choosing "Ignore adapters…" opens the list', true);
  check('...and puts the dropdown back where it was',
        await p.$eval('#iface', s => s.value) === before, await p.$eval('#iface', s => s.value));
  const items = await p.$$eval('#rowmenu button', bs => bs.map(x => x.textContent));
  check('each adapter with an address is offered',
        items.some(t => /^Ignore demo0/.test(t)) && items.some(t => /^Ignore demo1/.test(t)), items.join(' | '));

  await p.click('#rowmenu button:has-text("Ignore demo1")');
  await p.waitForFunction(() => /1 ignored/.test($('statusText').textContent));
  check('the header says one adapter is ignored', true);
  check('...and names it on hover',
        /demo1/.test(await p.$eval('#ignNote', n => n.title)), await p.$eval('#ignNote', n => n.title));
  await p.waitForFunction(() => [...$('iface').options].some(o => o.value === 'demo1' && /ignored/.test(o.textContent)));
  check('the dropdown marks it ignored', true);
  check('...and All says how many are left out',
        /but 1 ignored/.test(await p.$eval('#iface option[value="all"]', o => o.textContent)));

  // Ignoring the last adapter would capture nothing: refused, and said so.
  await p.click('#ignNote');
  await p.waitForSelector('#rowmenu.on');
  const again = await p.$$eval('#rowmenu button', bs => bs.map(x => x.textContent));
  check('from the header, an ignored adapter can be captured again',
        again.some(t => /^Capture again: demo1/.test(t)), again.join(' | '));
  await p.click('#rowmenu button:has-text("Ignore demo0")');
  await p.waitForFunction(() => /no adapter/.test($('flash').textContent));
  check('ignoring the last adapter is refused, with the reason', true);
  check('...and nothing changed',
        (await p.evaluate(() => lastStatus.ignored_ifaces)).join() === 'demo1');

  await p.click('#ignNote');
  await p.click('#rowmenu button:has-text("Capture again: demo1")');
  await p.waitForFunction(() => !$('ignNote'));
  check('capturing it again clears the note', true);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
