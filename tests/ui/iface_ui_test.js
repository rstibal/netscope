const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>40,null,{timeout:60000});

  check('the dropdown is populated', await p.evaluate(()=>$('iface').options.length>0));

  // an adapter attached mid-capture is announced once, not on every poll
  const first = await p.evaluate(async ()=>{
    renderStatus(Object.assign({}, lastStatus, {new_ifaces:['Wi-Fi']}));
    await new Promise(r=>setTimeout(r,80));
    return {text: document.getElementById('flash').textContent,
            on: document.getElementById('flash').classList.contains('on')};
  });
  check('a newly attached adapter is announced', first.on && /now also capturing Wi-Fi/.test(first.text),
        JSON.stringify(first));

  const second = await p.evaluate(async ()=>{
    document.getElementById('flash').textContent = '';
    renderStatus(Object.assign({}, lastStatus, {new_ifaces:['Wi-Fi']}));
    await new Promise(r=>setTimeout(r,80));
    return document.getElementById('flash').textContent;
  });
  check('and not announced again on the next poll', second === '', second);

  const third = await p.evaluate(async ()=>{
    renderStatus(Object.assign({}, lastStatus, {new_ifaces:['Wi-Fi','Ethernet 2']}));
    await new Promise(r=>setTimeout(r,80));
    return document.getElementById('flash').textContent;
  });
  check('a different adapter is announced', /Ethernet 2/.test(third), third);

  // the dropdown must not be yanked shut while it is in use
  const guarded = await p.evaluate(()=>{
    $('iface').focus();
    const before = $('iface').options.length;
    // the periodic refresh skips a focused control
    return {focused: document.activeElement === $('iface'), before};
  });
  check('the refresh respects a focused dropdown', guarded.focused);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
