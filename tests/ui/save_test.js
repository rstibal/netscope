const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const ctx = await b.newContext({ viewport:{width:1680,height:900}, acceptDownloads:true });
  const p = await ctx.newPage();
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  const downloads = [];
  p.on('download', d => downloads.push(d.suggestedFilename()));

  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>80,null,{timeout:60000});

  // --- double-click Save must produce ONE file, and say so
  await p.dblclick('#savePcap');
  await p.waitForTimeout(1200);
  check('double-click yields exactly one download', downloads.length === 1,
        JSON.stringify(downloads));
  check('filename matches netscope-YYYYMMDD-HHMMSS.pcap',
        /^netscope-\d{8}-\d{6}\.pcap$/.test(downloads[0]||''), downloads[0]);

  const msg1 = await p.textContent('#flash');
  const vis1 = await p.evaluate(()=>document.getElementById('flash').classList.contains('on'));
  check('flash is visible after saving', vis1);
  check('flash names the file that was saved',
        msg1.includes(downloads[0]) && /saved/.test(msg1), msg1);

  // the blocked second click should have told the user the first one worked
  check('second click explains rather than silently doing nothing',
        /already saved/.test(msg1) || /saved/.test(msg1), msg1);

  // --- flash goes away on its own
  await p.waitForTimeout(3800);
  check('flash auto-dismisses',
        !(await p.evaluate(()=>document.getElementById('flash').classList.contains('on'))));

  // --- after the guard expires a deliberate second save works
  await p.click('#savePcap');
  await p.waitForTimeout(1200);
  check('a later save is allowed', downloads.length === 2, JSON.stringify(downloads));
  check('the two saves have different names', downloads[0] !== downloads[1],
        JSON.stringify(downloads));

  // --- rapid repeat is still blocked (wait out the 1800ms guard first, so the
  //     first of these two clicks is a legitimate save and only the second is
  //     the accidental repeat we care about)
  await p.waitForTimeout(2000);
  const before = downloads.length;
  await p.click('#savePcap'); await p.waitForTimeout(120);
  await p.click('#savePcap'); await p.waitForTimeout(900);
  check('rapid repeat blocked', downloads.length === before + 1,
        `${before} -> ${downloads.length}`);
  check('blocked click says already saved',
        /already saved/.test(await p.textContent('#flash')), await p.textContent('#flash'));

  // --- client-side name scrubbing matches the server's
  const scrub = await p.evaluate(() => [
    safeName('report.pdf','fb'),
    safeName('evil"\r\nSet-Cookie: a=b','fb'),
    safeName('../../../etc/passwd','fb'),
    safeName('','fb'),
    safeName('...','fb'),
  ]);
  check('safeName matches server output', JSON.stringify(scrub) === JSON.stringify(
    ['report.pdf','evil___Set-Cookie_ a=b','_.._.._etc_passwd','fb','fb']), JSON.stringify(scrub));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
