const { chromium } = require('playwright');
const fails = [];
const check = (n, c, extra='') => { console.log((c?'PASS  ':'FAIL  ')+n+((!c&&extra)?'  -- '+extra:'')); if(!c) fails.push(n); };

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport: { width: 1680, height: 900 } });
  const errs=[]; p.on('pageerror', e=>errs.push(String(e)));

  // Shrink the ring buffer so the trim path runs constantly. Only the constant
  // changes; the code under test is the shipped poll().
  await p.route('**/?t=*', async route => {
    const r = await route.fetch();
    let body = await r.text();
    body = body.replace('const MAX_ROWS = 2500;', 'const MAX_ROWS = 240;');
    await route.fulfill({ response: r, body });
  });

  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>=240,null,{timeout:60000});
  await p.waitForTimeout(1500);
  check('buffer is full so trimming is active',
        await p.evaluate(()=>document.querySelectorAll('#rows tr').length) === 240);

  const topSeq = () => p.evaluate(() => {
    const w = document.getElementById('tw');
    const y = w.getBoundingClientRect().top + 40;
    for (const tr of document.getElementById('rows').children){
      const r = tr.getBoundingClientRect();
      if (r.bottom > y) return tr.dataset.seq;
    }
    return null;
  });

  // ---- follow OFF: the row you are looking at must stay where it is
  await p.uncheck('#follow');
  await p.evaluate(()=>{ const w=document.getElementById('tw'); w.scrollTop = Math.round(w.scrollHeight/2); });
  await p.waitForTimeout(150);
  const before = await topSeq();
  await p.waitForTimeout(3000);          // shorter than the buffer's turnover
  const after = await topSeq();
  check('follow OFF: view stays on the same row across trims',
        before === after, `was ${before}, now ${after}`);

  // and it must not have silently pinned to the bottom
  const atBottom = await p.evaluate(()=>{
    const w=document.getElementById('tw');
    return w.scrollHeight - w.scrollTop - w.clientHeight < 4;
  });
  check('follow OFF: not stuck at the bottom', !atBottom);

  // ---- follow ON: must track the newest row
  await p.check('#follow');
  await p.waitForTimeout(2500);
  check('follow ON: pinned to the bottom', await p.evaluate(()=>{
    const w=document.getElementById('tw');
    return w.scrollHeight - w.scrollTop - w.clientHeight < 4;
  }));

  // ---- Pause button stops rows arriving
  await p.click('#pause');
  const label = await p.textContent('#pause');
  check('pause button relabels to Resume', label.trim() === 'Resume', label);
  const seqAtPause = await p.evaluate(()=>document.getElementById('rows').lastChild.dataset.seq);
  await p.waitForTimeout(3000);
  const seqAfterPause = await p.evaluate(()=>document.getElementById('rows').lastChild.dataset.seq);
  check('paused: no new rows appended', seqAtPause === seqAfterPause, `${seqAtPause} -> ${seqAfterPause}`);
  check('paused: says so in the filter bar',
        (await p.textContent('#fcount')).includes('paused'));

  await p.click('#pause');
  check('resume relabels to Pause', (await p.textContent('#pause')).trim() === 'Pause');
  await p.waitForTimeout(2500);
  const seqAfterResume = await p.evaluate(()=>document.getElementById('rows').lastChild.dataset.seq);
  check('resumed: rows arriving again', Number(seqAfterResume) > Number(seqAfterPause),
        `${seqAfterPause} -> ${seqAfterResume}`);

  // ---- spacebar keeps the button in sync
  await p.keyboard.press(' ');
  check('spacebar syncs the button', (await p.textContent('#pause')).trim() === 'Resume');
  await p.keyboard.press(' ');
  check('spacebar toggles back', (await p.textContent('#pause')).trim() === 'Pause');

  check('no page errors', errs.length === 0, errs.join(' | '));
  console.log('\nFAILED:', fails.length ? fails : 'none');
  await b.close();
  process.exit(fails.length ? 1 : 0);
})();
