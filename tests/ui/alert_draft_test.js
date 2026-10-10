const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Alerts pane redraws every 2.5 s from the server. A rule box changed but
// not yet applied used to snap back at the next redraw.
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.click('.tab[data-p="alerts"]');
  await p.waitForSelector('#p-alerts [data-rule]', {timeout: 40000});

  const rules = () => p.evaluate(async () => (await (await fetch('/api/alerts?t='+TOKEN)).json()).rules);
  const box = rule => p.locator('#p-alerts [data-rule="'+rule+'"]');
  const rule = await p.evaluate(() => document.querySelector('#p-alerts [data-rule]').dataset.rule);
  const before = await box(rule).isChecked();

  await box(rule).setChecked(!before);
  await p.locator('#thrMb').fill('777');
  await p.waitForTimeout(6000);                       // two or more redraws
  check('a changed rule box survives the redraw', await box(rule).isChecked() === !before);
  check('...and so does an edited threshold', await p.locator('#thrMb').inputValue() === '777');
  check('...and the server is untouched until Apply', (await rules())[rule] === before);
  check('the button says changes are waiting', /changes/.test(await p.locator('#applyRules').textContent()));

  // Focus and caret are not stolen by the redraw.
  await p.locator('#thrMb').focus();
  await p.waitForTimeout(3000);
  check('a focused field keeps focus across the redraw',
        await p.evaluate(() => document.activeElement && document.activeElement.id) === 'thrMb');

  await p.click('#applyRules');
  await p.waitForTimeout(500);
  check('Apply sends the change', (await rules())[rule] === !before);
  await p.waitForTimeout(3000);
  check('...and the box keeps it after Apply', await box(rule).isChecked() === !before);
  check('...and the button goes back to Apply', (await p.locator('#applyRules').textContent()).trim() === 'Apply');

  // Put things back.
  await box(rule).setChecked(before);
  await p.locator('#thrMb').fill('500');
  await p.click('#applyRules');
  await p.waitForTimeout(500);
  check('restored', (await rules())[rule] === before);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
