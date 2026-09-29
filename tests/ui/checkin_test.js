const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The check-in alert, end to end: the demo's AgentSvc.exe contacts
// checkin.example.net every 20 seconds, the server's half-minute pass over the
// Timeline notices once it has five bursts, and the alert appears on the
// Alerts tab. Slow by nature — five check-ins take 80 seconds.
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.click('.tab[data-p="alerts"]');
  await p.waitForSelector('#p-alerts [data-rule]');

  const rule = await p.evaluate(()=>{ const cb = document.querySelector('#p-alerts [data-rule="checkin"]');
    return cb ? {on: cb.checked, label: cb.parentNode.textContent.trim()} : null; });
  check('the rule is listed, and on by default', rule && rule.on &&
        /checking in with a host on a schedule/.test(rule.label), JSON.stringify(rule));

  const t0 = Date.now();
  await p.waitForFunction(()=>[...document.querySelectorAll('#p-alerts .alert .rl')]
    .some(x=>/^checkin/.test(x.textContent)), null, {timeout: 170000, polling: 1000});
  const secs = Math.round((Date.now()-t0)/1000);
  const a = await p.evaluate(()=>{
    const card = [...document.querySelectorAll('#p-alerts .alert')].find(x=>/^checkin/.test(x.querySelector('.rl').textContent));
    return {cls: card.className, title: card.querySelector('.ti').textContent,
            detail: card.querySelector('.d').textContent, rl: card.querySelector('.rl').textContent,
            why: (card.querySelector('details.why')||{}).textContent || '',
            mute: (card.querySelector('[data-mute]')||{}).textContent || ''};
  });
  console.log('      (after ' + secs + 's)');
  check('the demo\'s 20-second check-in raises it', a.title==='New scheduled check-in' &&
        /^AgentSvc\.exe contacts checkin\.example\.net every ~20s \(\d+ times in the last hour\)$/.test(a.detail),
        JSON.stringify(a));
  check('...as a note, since the demo keeps no history', /\binfo\b/.test(a.cls), a.cls);
  check('...naming the program, with a reason and a mute for the host',
        a.rl==='checkin · AgentSvc.exe' && /on a fixed schedule/.test(a.why) &&
        a.mute==='Mute checkin.example.net', JSON.stringify(a));

  const all = await p.evaluate(()=>api('/api/alerts').then(r=>r.json()).then(d=>d.alerts.filter(x=>x.rule==='checkin')));
  check('nothing without a program behind it is reported',
        all.every(x=>!/^\(/.test(x.process)), JSON.stringify(all.map(x=>x.process)));
  check('...and the check-in is reported once', all.filter(x=>x.process==='AgentSvc.exe').length===1 &&
        all.find(x=>x.process==='AgentSvc.exe').count===1, JSON.stringify(all));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
