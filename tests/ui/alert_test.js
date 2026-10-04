const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>60,null,{timeout:60000});
  // Mutes persist across runs by design, and previous runs of this very test
  // have silenced the alerts it needs. Start from a clean slate.
  await p.evaluate(async ()=>{
    const r = await fetch('/api/alerts?t='+TOKEN); const j = await r.json();
    for (const m of (j.mutes||[]))
      await fetch('/api/control?t='+TOKEN, {method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({action:'unmute', rule:m.rule, subject:m.subject})});
  });
  await p.click('.tab[data-p="alerts"]');
  await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .alert').length>0,
                          null,{timeout:40000});

  const first = await p.evaluate(()=>{
    const a=document.querySelector('#p-alerts .alert');
    return {title:a.querySelector('.ti').textContent,
            mute:a.querySelector('[data-mute]')?.dataset.subject,
            rule:a.querySelector('[data-mute]')?.dataset.mute,
            hasWhy:!!a.querySelector('details.why'),
            hasDismiss:!!a.querySelector('[data-dismiss]')};
  });
  check('alerts offer a mute for their subject', !!first.mute, JSON.stringify(first));
  check('alerts offer a dismiss', first.hasDismiss);
  check('alerts explain why they fired', first.hasWhy);

  // the explanation is real text, not a placeholder
  await p.click('#p-alerts details.why summary');
  await p.waitForTimeout(150);
  const why = await p.evaluate(()=>document.querySelector('#p-alerts details.why').textContent);
  check('the explanation says something', why.replace(/Why did this fire\?/,'').trim().length>40,
        why.slice(0,70));

  // mute the first alert's subject
  // The demo keeps raising new alerts while this runs, so row counts before
  // and after can match when one went and another arrived. Check the alert
  // that was muted instead: nothing for its subject should be left.
  await p.click('#p-alerts [data-mute]');
  await p.waitForTimeout(1200);
  // (rule, subject): another rule may still have its own alert for the subject.
  const after = await p.evaluate(([rule, subj])=>({
    left: [...document.querySelectorAll('#p-alerts .alert [data-mute]')]
            .filter(b=>b.dataset.mute===rule && b.dataset.subject===subj).length,
    mutes: [...document.querySelectorAll('#p-alerts .mute')].map(m=>m.querySelector('.s').textContent),
  }), [first.rule, first.mute]);
  check('the muted subject is listed where you can see it',
        after.mutes.includes(first.mute), JSON.stringify(after.mutes));
  check('its alert is gone from the list', after.left === 0, `${after.left} left for ${first.rule}/${first.mute}`);

  // the API agrees, and the rule is still enabled
  const api = await p.evaluate(async ()=> (await (await api2('/api/alerts')).json()),
    ).catch(async ()=> await p.evaluate(async ()=>{
      const r = await fetch('/api/alerts?t='+TOKEN); return r.json(); }));
  check('the mute is recorded server-side',
        (api.mutes||[]).some(m=>m.subject===first.mute), JSON.stringify(api.mutes));
  check('the rule itself stays on', api.rules[first.rule] === true,
        first.rule + '=' + api.rules[first.rule]);

  // unmute puts it back
  await p.click('#p-alerts [data-unmute="'+first.rule+'"][data-subject="'+first.mute+'"]');
  await p.waitForTimeout(1200);
  const api2r = await p.evaluate(async ()=>{ const r=await fetch('/api/alerts?t='+TOKEN); return r.json(); });
  check('unmute removes it', !(api2r.mutes||[]).some(m=>m.subject===first.mute),
        JSON.stringify(api2r.mutes));

  // dismiss removes exactly one
  // By id, for the same reason as above: a new alert may arrive meanwhile.
  const dismissId = await p.evaluate(()=>{
    const b = document.querySelector('#p-alerts [data-dismiss]'); return b ? b.dataset.dismiss : null; });
  const n0 = await p.evaluate(()=>document.querySelectorAll('#p-alerts .alert').length);
  if (n0 > 1 && dismissId){
    await p.click('#p-alerts [data-dismiss="'+dismissId+'"]');
    await p.waitForTimeout(1000);
    const still = await p.evaluate((id)=>document.querySelectorAll('#p-alerts [data-dismiss="'+id+'"]').length, dismissId);
    const others = await p.evaluate(()=>document.querySelectorAll('#p-alerts .alert').length);
    check('dismiss removes that alert', still === 0, `alert ${dismissId} still listed`);
    check('...and not all of them', others > 0, String(others));
  } else { check('dismiss removes one alert (skipped, only one alert)', true); }


  // --- the muted row must actually show its subject, not a crushed stub
  await p.click('#p-alerts [data-mute]');
  await p.waitForTimeout(1200);
  const shown = await p.evaluate(()=>{
    const m=document.querySelector('#p-alerts .mute');
    if(!m) return null;
    const s=m.querySelector('.s');
    return {text:s.textContent, width:Math.round(s.getBoundingClientRect().width),
            clipped: s.scrollWidth > s.clientWidth + 1};
  });
  check('the muted subject is readable, not crushed',
        shown && shown.width >= 80 && !shown.clipped, JSON.stringify(shown));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
