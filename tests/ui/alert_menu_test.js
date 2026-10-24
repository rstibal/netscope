// An alert card offers the packet row menu's "Don't record" and "Block":
// rows scroll by in seconds, and the alert is where you notice something.
const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  const dialogs=[]; p.on('dialog', d => { dialogs.push(d.message()); d.dismiss(); });
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>60,null,{timeout:60000});
  await p.click('.tab[data-p="alerts"]');
  // A card for a named program talking to a real address.
  await p.waitForFunction(()=>(lastAlerts && lastAlerts.alerts || []).some(a =>
      a.process && !/^[(-]/.test(a.process) && /^\d+\.\d+\.\d+\.\d+$/.test(a.peer || '')),
    null, {timeout:60000});
  const a = await p.evaluate(()=>lastAlerts.alerts.find(a =>
      a.process && !/^[(-]/.test(a.process) && /^\d+\.\d+\.\d+\.\d+$/.test(a.peer || '')));
  check('alerts carry the host and pid the menu needs', 'host' in a && 'pid' in a, JSON.stringify(a));

  await p.mouse.move(5, 5);                    // the pane holds still while hovered
  await p.waitForSelector('#p-alerts [data-amenu="' + a.id + '"]', {timeout: 10000});
  await p.click('#p-alerts [data-amenu="' + a.id + '"]');
  await p.waitForSelector('#rowmenu.on');
  const items = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
  check('the menu offers not recording the program', items.includes("Don't record " + a.process + ' in History'),
        JSON.stringify(items));
  check('...and the host', items.includes("Don't record " + (a.host || a.peer) + ' in History'), JSON.stringify(items));
  check('...and blocking the host and the program',
        items.includes('Block host ' + a.peer) && items.includes('Block program ' + a.process),
        JSON.stringify(items));
  const box = await p.evaluate(()=>{
    const m = document.getElementById('rowmenu').getBoundingClientRect();
    return m.left >= 0 && m.right <= innerWidth && m.top >= 0 && m.bottom <= innerHeight;
  });
  check('the menu opens on screen', box);

  // Don't record goes to the real exclusion list.
  await p.click('#rowmenu button:has-text("Don\'t record ' + a.process + '")');
  await p.waitForFunction(pr => api('/api/history').then(r=>r.json())
      .then(d => (d.exclude.programs || []).includes(pr.toLowerCase())), a.process, {timeout: 10000})
    .catch(()=>{});
  const ex = await p.evaluate(()=>api('/api/history').then(r=>r.json()).then(d=>d.exclude));
  check("Don't record adds the program to History's exclusions",
        (ex.programs || []).includes(a.process.toLowerCase()), JSON.stringify(ex));
  // The demo server is shared with the other tests: put the list back.
  await p.evaluate(pr => control({action: 'history_exclude', kind: 'program',
                                  pattern: pr.toLowerCase(), remove: true}), a.process);

  // Block asks first, and says what it would do.
  await p.click('.tab[data-p="alerts"]');
  await p.mouse.move(5, 5);
  await p.waitForSelector('#p-alerts [data-amenu="' + a.id + '"]', {timeout: 10000});
  await p.click('#p-alerts [data-amenu="' + a.id + '"]');
  await p.click('#rowmenu button:has-text("Block host ' + a.peer + '")');
  await p.waitForTimeout(300);
  check('Block asks before doing anything', dialogs.some(m => m.includes('Block all traffic to and from ' + a.peer)),
        JSON.stringify(dialogs));

  // Placeholders and multicast get nothing to block or exclude.
  const none = await p.evaluate(()=>[
    alertMenuItems({process:'(broadcast)', peer:'224.0.0.251'}).length,
    alertMenuItems({process:'pid 1234', peer:'ff02::fb'}).length,
    alertMenuItems({process:'chrome.exe', peer:'224.0.0.251'}).map(i => i && i[0])]);
  check('nothing to offer for placeholders and multicast', none[0] === 0 && none[1] === 0, JSON.stringify(none));
  check('...and a multicast peer is never offered for blocking or excluding',
        !none[2].some(t => t && /224\.0\.0\.251/.test(t)), JSON.stringify(none[2]));

  // The log view has the menu too. A log row has only process and peer (no
  // host or pid columns). This server runs without history, so the view is
  // drawn directly from a stand-in row.
  const lg = await p.evaluate(()=>{
    const row = {id: 7, ts: Date.now() / 1000, severity: 'warn', rule: 'new_process',
                 title: 'New program on the network', detail: 'd', process: 'Agent.exe',
                 peer: '203.0.113.9', subject: 'Agent.exe'};
    alertLog = {enabled: true, rows: [row], more: false, days: 30,
                counts: {total: 1, high: 0, warn: 1}};
    const div = document.createElement('div');
    div.innerHTML = alertLogHTML({log_days: 30, why: {}, mutes: []});
    alertLog = null;
    return {btn: !!div.querySelector('[data-lmenu="7"]'),
            items: alertMenuItems(row).filter(Boolean).map(i => i[0])};
  });
  check('rows in Past 30 days have the menu too', lg.btn, JSON.stringify(lg));
  check('...offering the same items from process and peer',
        ["Don't record Agent.exe in History", "Don't record 203.0.113.9 in History",
         'Block host 203.0.113.9', 'Block program Agent.exe'].every(t => lg.items.includes(t)),
        JSON.stringify(lg.items));

  // A block leaves a "Blocked ..." note, which can undo it while it stands.
  // (Demo mode's firewall is in memory.)
  await p.evaluate(async ()=>{
    await control({action: 'blocking', enabled: true});
    await control({action: 'block', kind: 'host', address: '203.0.113.77'});
  });
  await p.mouse.move(5, 5);
  await p.evaluate(()=>refreshTab('alerts'));
  await p.waitForSelector('#p-alerts [data-aunblock]', {timeout: 10000}).catch(()=>{});
  const note = await p.evaluate(()=>{
    const card = [...document.querySelectorAll('#p-alerts .alert')]
      .find(c => /Blocked host 203\.0\.113\.77/.test(c.textContent));
    return card ? {unblock: !!card.querySelector('[data-aunblock]'),
                   menu: !!card.querySelector('[data-amenu]')} : null;
  });
  check('the Blocked note offers Unblock', note && note.unblock, JSON.stringify(note));
  check('...and no Don\'t record / Block menu of its own', note && !note.menu, JSON.stringify(note));
  if (note && note.unblock){
    p.removeAllListeners('dialog');
    p.on('dialog', d => { dialogs.push(d.message()); d.accept(); });
    await p.click('#p-alerts [data-aunblock]');
    await p.waitForFunction(()=>api('/api/blocks').then(r=>r.json())
        .then(d => !d.blocks.some(b => b.target === '203.0.113.77')), null, {timeout: 10000}).catch(()=>{});
    const left = await p.evaluate(()=>api('/api/blocks').then(r=>r.json()).then(d=>d.blocks.map(b=>b.target)));
    check('Unblock on the note removes the block', !left.includes('203.0.113.77'), JSON.stringify(left));
    await p.mouse.move(5, 5);
    await p.evaluate(()=>refreshTab('alerts'));
    await p.waitForFunction(()=>[...document.querySelectorAll('#p-alerts .alert')]
        .some(c => /Blocked host 203\.0\.113\.77/.test(c.textContent) && /no longer blocked/.test(c.textContent)),
      null, {timeout: 10000}).catch(()=>{});
    const after = await p.evaluate(()=>{
      const card = [...document.querySelectorAll('#p-alerts .alert')]
        .find(c => /Blocked host 203\.0\.113\.77/.test(c.textContent));
      return card ? {unblock: !!card.querySelector('[data-aunblock]'), text: card.textContent} : null;
    });
    check('...after which the note says it is no longer blocked',
          after && !after.unblock && /no longer blocked/.test(after.text), JSON.stringify(after));
    p.removeAllListeners('dialog');
    p.on('dialog', d => { dialogs.push(d.message()); d.dismiss(); });
  }
  // The demo server is shared with the other tests: switch blocking back
  // off and dismiss the Blocked/Unblocked notes this test made.
  await p.evaluate(async ()=>{
    await control({action: 'blocking', enabled: false});
    const d = await api('/api/alerts').then(r=>r.json());
    for (const a of d.alerts)
      if (/block$/.test(a.rule) && a.subject === '203.0.113.77')
        await control({action: 'dismiss_alert', id: a.id});
  });

  // The menu's hint says where blocks are listed.
  const hint = await p.evaluate(()=>{
    const b = document.createElement('button'); document.body.appendChild(b);
    openAlertMenu({id: 1, process: 'Agent.exe', peer: '203.0.113.9'}, b);
    const t = document.querySelector('#rowmenu .hint').textContent;
    closeRowMenu(); b.remove(); return t;
  });
  check('the menu hint points to Connections > Blocked',
        /listed, and undone, under Connections > Blocked/.test(hint), hint);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
