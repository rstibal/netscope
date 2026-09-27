const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The demo server runs with --no-history, so the History tab's data is
// answered here. The exclusion list itself is the server's: it is taken from
// the real response, so what the page shows is what the server holds.
const G = Math.pow(1024,3);
let total = 10*G;
function payload(exclude){
  const daily = [];
  for (let i=0;i<30;i++) daily.push({day:'2026-09-'+String(i+1).padStart(2,'0'),
    bytes_in: G*0.8, bytes_out: G*0.2, packets: 1000});
  return {enabled:true, days:30, daily, hourly:[], hosts:[], new_hosts:[], alerts:[], sessions:[],
          processes:[{name:'chrome.exe', bytes_in:G, bytes_out:G/4, packets:10}], exclude,
          summary:{bytes_in: total*0.8, bytes_out: total*0.2, packets: 123, processes: 1, hosts: 0,
                   size: 1024*1024, retain_days: 90, since:'2026-09-01', path:'C:\\history.db'}};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  let dialogs = [], answer = false;
  p.on('dialog', d => { dialogs.push(d.message()); answer ? d.accept() : d.dismiss(); });
  await p.route('**/api/history*', async route => {
    const real = await (await route.fetch()).json();
    route.fulfill({status:200, contentType:'application/json', body: JSON.stringify(payload(real.exclude))});
  });
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>20,null,{timeout:90000});
  const serverList = () => p.evaluate(()=>api('/api/history').then(r=>r.json()).then(d=>d.exclude));

  // ---------------- the row menu ----------------
  // A row with a named host and a real program, so every item is offered.
  const seq = await p.evaluate(()=>{
    for (const tr of document.querySelectorAll('#rows tr')){
      const r = records.get(Number(tr.dataset.seq));
      if (r && r.rhost && r.process && !/^[-(]/.test(r.process)) return r.seq;
    }
    return null;
  });
  check('the demo has a row with a program and a named host', seq!==null);
  const rec = await p.evaluate(s=>records.get(s), seq);
  const row = () => p.locator('#rows tr[data-seq="'+seq+'"]');
  await p.evaluate(()=>setPaused(true));      // keep the row where it is
  await row().click({button:'right'});
  const menu = await p.evaluate(()=>{
    const m = document.getElementById('rowmenu'), r = m.getBoundingClientRect();
    return {on: m.classList.contains('on'), items: [...m.querySelectorAll('button')].map(x=>x.textContent),
            inView: r.left>=0 && r.top>=0 && r.right<=innerWidth && r.bottom<=innerHeight,
            focused: document.activeElement.parentNode===m};
  });
  check('right-clicking a packet opens the menu', menu.on);
  check('...offering its program, host and address, then the History items',
        menu.items.length===5 && menu.items[0]==='Hide program '+rec.process &&
        menu.items[1]==='Hide host '+rec.rhost && /^Hide address /.test(menu.items[2]) &&
        menu.items[3]==="Don't record "+rec.process+' in History' &&
        menu.items[4]==="Don't record "+rec.rhost+' in History', JSON.stringify(menu.items));
  check('...inside the window, with focus on the first item', menu.inView && menu.focused);

  await p.keyboard.press('ArrowDown');
  await p.keyboard.press(' ');                   // must not reach the page's pause toggle
  // Space on the focused item activates it: Hide host.
  await p.waitForTimeout(200);
  const afterHost = await p.evaluate(()=>({v: document.getElementById('find').value, paused,
    bad: document.getElementById('find').classList.contains('bad'),
    open: document.getElementById('rowmenu').classList.contains('on')}));
  check('keyboard: arrow then space picks the second item', afterHost.v==='host != "'+rec.rhost+'"', afterHost.v);
  check('...without toggling the feed, and the menu closes', afterHost.paused===true && !afterHost.open);

  const shown = await p.evaluate(h=>[...document.querySelectorAll('#rows tr')]
    .filter(tr=>tr.style.display!=='none').map(tr=>records.get(Number(tr.dataset.seq)))
    .filter(r=>r && r.rhost===h).length, rec.rhost);
  check('the hidden host is gone from the table', shown===0, shown+' rows still shown');

  // An || in the filter is wrapped before a clause is added.
  await p.fill('#find', 'proto == TCP || proto == UDP');
  const other = await p.evaluate(()=>{
    for (const tr of document.querySelectorAll('#rows tr')){
      if (tr.style.display==='none') continue;
      const r = records.get(Number(tr.dataset.seq));
      if (r && r.process && !/^[-(]/.test(r.process)) return r.seq;
    }
  });
  const oproc = await p.evaluate(s=>records.get(s).process, other);
  await p.locator('#rows tr[data-seq="'+other+'"]').click({button:'right'});
  await p.locator('#rowmenu button', {hasText: 'Hide program '}).click();
  check('hiding with an || filter wraps it first',
        await p.inputValue('#find')==='(proto == TCP || proto == UDP) && process != "'+oproc+'"',
        await p.inputValue('#find'));
  check('...and the expression is valid', !(await p.evaluate(()=>document.getElementById('find').classList.contains('bad'))));

  await row().click({button:'right'}).catch(()=>{});
  await p.evaluate(()=>{ if (!document.getElementById('rowmenu').classList.contains('on'))
    openRowMenu(records.get(Number(document.querySelector('#rows tr').dataset.seq)), 50, 50); });
  await p.keyboard.press('Escape');
  check('Escape closes the menu', !(await p.evaluate(()=>document.getElementById('rowmenu').classList.contains('on'))));

  // "Don't record" goes to the server, and asks before erasing anything.
  await p.fill('#find', '');
  await p.evaluate(s=>openRowMenu(records.get(s), 60, 60), seq);
  dialogs = []; answer = false;
  await p.locator('#rowmenu button', {hasText: "Don't record "+rec.rhost}).click();
  await p.waitForTimeout(500);
  const l1 = await serverList();
  check("Don't record adds the host to the server's list",
        JSON.stringify(l1.hosts)===JSON.stringify([rec.rhost.toLowerCase()]), JSON.stringify(l1));
  check('...and asks, separately, whether to erase what is already recorded',
        dialogs.length===1 && /Also erase/.test(dialogs[0]), JSON.stringify(dialogs));

  // ---------------- the History section ----------------
  await p.evaluate(()=>setPaused(false));
  await p.click('.tab[data-p="history"]');
  await p.waitForSelector('#histEx');
  const sec = await p.evaluate(()=>({h: document.querySelector('#histEx h4').textContent,
    rows: [...document.querySelectorAll('#histEx .exrow')].map(r=>r.textContent),
    jump: (document.getElementById('exJump')||{}).textContent}));
  check('History lists what is not recorded, with a count',
        sec.h==='Not recorded · 1' && sec.rows.length===1 && sec.rows[0].startsWith(rec.rhost.toLowerCase()),
        JSON.stringify(sec));
  check('...and says so at the top of the tab', sec.jump==='· 1 not recorded', sec.jump);

  // Add from the form, accepting the erase.
  await p.selectOption('#exKind', 'program');
  await p.fill('#exPat', '  Secret.EXE ');
  dialogs = []; answer = true;
  await p.click('#exAdd');
  await p.waitForFunction(()=>document.querySelectorAll('#histEx .exrow').length===2);
  const l2 = await serverList();
  check('the form adds a program, trimmed and lower-cased', JSON.stringify(l2.programs)==='["secret.exe"]', JSON.stringify(l2));
  check('...the program erase warning says hosts stay', dialogs.length===1 && /hosts it talked to stay/.test(dialogs[0]), JSON.stringify(dialogs));
  check('...and the result is reported', /secret\.exe is no longer recorded\. Erased nothing/.test(
        await p.textContent('#exMsg')), await p.textContent('#exMsg'));
  check('...and the field is cleared', await p.inputValue('#exPat')==='');

  // Half-typed text survives the tab's automatic refresh.
  await p.fill('#exPat', 'half-typ');
  await p.focus('#exPat');
  total = 20*G;
  await p.evaluate(()=>loadHistory(true));
  await p.waitForFunction(()=>document.querySelector('#p-history .kpi .v').textContent==='20.0 GB');
  const kept = await p.evaluate(()=>({v: document.getElementById('exPat').value,
    f: document.activeElement.id}));
  check('text typed into the field survives a refresh, focus too', kept.v==='half-typ' && kept.f==='exPat', JSON.stringify(kept));

  // Remove.
  await p.click('#histEx [data-exdel="host"]');
  await p.waitForFunction(()=>document.querySelectorAll('#histEx .exrow').length===1);
  const l3 = await serverList();
  check('Remove takes it off the server list', l3.hosts.length===0 && l3.programs.length===1, JSON.stringify(l3));
  check('...and says recording resumes', /recorded again/.test(await p.textContent('#exMsg')));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
