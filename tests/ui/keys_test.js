const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// Space pauses the feed, except that a control reached from the keyboard
// keeps it: space used to be taken from every focused button, so none could
// be pressed with it. A mouse-clicked button keeps focus too, and must not
// get it — "click Clear, press space" would clear a second time.
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  const paused = () => p.evaluate(()=>paused);
  const menuOn = () => p.evaluate(()=>document.getElementById('colmenu').classList.contains('on'));

  // Nothing focused: space pauses and resumes.
  await p.evaluate(()=>document.activeElement.blur());
  await p.keyboard.press(' ');
  check('space with nothing focused pauses the feed', await paused()===true);
  await p.keyboard.press(' ');
  check('...and again resumes it', await paused()===false);

  // Keyboard focus on a button: space presses the button. This runs within a
  // second of page load, which is what caught focus tracking that assumed
  // performance.now() started far from 0.
  await p.focus('#fhelp');
  await p.keyboard.press('Shift+Tab');       // Tab order: ... Columns, [Reset], ?
  if (await p.evaluate(()=>document.activeElement.id)!=='colsBtn')
    await p.keyboard.press('Shift+Tab');     // past Reset columns, if shown
  const onCols = await p.evaluate(()=>document.activeElement.id);
  await p.keyboard.press(' ');
  await p.waitForTimeout(150);
  check('space on a keyboard-focused button presses it', await menuOn()===true,
        'focus on '+onCols);
  check('...and does not pause the feed', await paused()===false);
  await p.keyboard.press('Escape');
  await p.mouse.click(5, 895);                // close the menu

  // Mouse-clicked button: space pauses, and does not press it again.
  let clicks = 0;
  await p.exposeFunction('countClick', ()=>{ clicks++; });
  await p.evaluate(()=>document.getElementById('colsBtn').addEventListener('click', ()=>countClick()));
  await p.click('#colsBtn');
  await p.mouse.click(5, 895);                // close the menu again; focus leaves too
  await p.click('#colsBtn');                  // focus is on it now, from the mouse
  await p.mouse.move(5, 5);
  const before = clicks;
  const fv = await p.evaluate(()=>document.activeElement.id+' '+document.activeElement.matches(':focus-visible'));
  await p.keyboard.press(' ');
  await p.waitForTimeout(100);
  check('space after clicking a button pauses instead', await paused()===true, fv);
  check('...and does not click the button a second time', clicks===before, (clicks-before)+' extra clicks');
  await p.keyboard.press(' ');
  check('...and space again resumes', await paused()===false);

  // Reached by keyboard, then clicked: the click ends keyboard focus even
  // though focus never moved, so space goes back to pausing.
  await p.focus('#fhelp');
  await p.keyboard.press('Shift+Tab');
  if (await p.evaluate(()=>document.activeElement.id)!=='colsBtn') await p.keyboard.press('Shift+Tab');
  await p.click('#colsBtn');                  // opens the menu; focus stays put
  await p.click('#colsBtn');                  // and closes it
  const n = clicks;
  await p.keyboard.press(' ');
  await p.waitForTimeout(100);
  check('a keyboard-focused button that is then clicked gives space back to pause',
        await paused()===true && clicks===n, 'paused '+(await paused())+', '+(clicks-n)+' extra clicks');
  await p.keyboard.press(' ');

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
