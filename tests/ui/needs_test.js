const { chromium } = require('playwright');
const { spawn } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path'), net = require('net');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Alerts tab is two piles: "Needs you" cards at the top, one per program
// or device that wants a decision, and "Recorded" lines under them for what
// needs nothing. The demo seeds three cards: SilentUpdater.exe (unsigned, in a
// temp folder, started by chrome.exe), Vanished.exe (its file is gone, so it
// can't be trusted) and an ARP card for 192.168.1.1.
const DAY = 86400;
function logReply(){
  const now = Date.now()/1000, y = now - DAY, y2 = now - 2*DAY;
  const rows = [
    {id: 4, ts: y, severity:'info', rule:'new_process', pile:'recorded', title:'New program',
     detail:'Foo.exe · signed by Foo Ltd', process:'Foo.exe', peer:'', subject:'Foo.exe'},
    {id: 3, ts: y - 60, severity:'high', rule:'new_process', pile:'needs',
     title:'Unsigned program in a folder anyone can write to', detail:'Bad.exe · C:\\Temp\\Bad.exe',
     process:'Bad.exe', peer:'', subject:'Bad.exe'},
    {id: 2, ts: y - 120, severity:'warn', rule:'threshold', pile:'recorded', title:'Heavy traffic',
     detail:'Steam.exe moved 2 GB', process:'Steam.exe', peer:'', subject:'Steam.exe'},
    {id: 1, ts: y2, severity:'info', rule:'checkin', pile:null, title:'New scheduled check-in',
     detail:'a contacts b', process:'a.exe', peer:'', subject:'b'},
  ];
  return {enabled: true, alerts: rows, more: false, retain_days: 30,
          counts: {total: rows.length, high: 1, warn: 1, info: 2, newest: 4}};
}

/* The runner's shared demo runs with --no-history, and without history a new
   program is only a "first this session" note, never judged, so it would
   show the ARP card alone. This test starts a demo of its own, with the
   demo's in-memory history, in a scratch settings folder. */
function startDemo(){
  return new Promise((resolve, reject) => {
    const srv = net.createServer().listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => {
        const home = fs.mkdtempSync(path.join(os.tmpdir(), 'netscope-needs-'));
        const py = process.env.NETSCOPE_PYTHON || 'python';
        const proc = spawn(py, ['-u', path.join(__dirname, '..', '..', 'netscope.py'), '--demo',
                                '--port', String(port), '--no-browser'],
          {cwd: path.join(__dirname, '..', '..'),
           env: {...process.env, PYTHONUNBUFFERED: '1', LOCALAPPDATA: home, HOME: home}});
        let buf = '';
        const timer = setTimeout(() => reject(new Error('the demo did not start: ' + buf.slice(-400))), 60000);
        proc.stdout.on('data', c => {
          buf += c;
          const m = buf.match(new RegExp('(http://127\\.0\\.0\\.1:' + port + '/\\?t=\\S+)'));
          if (m){ clearTimeout(timer); resolve({proc, url: m[1], home}); }
        });
        proc.stderr.on('data', c => { buf += c; });
        proc.on('exit', () => { clearTimeout(timer); reject(new Error('the demo exited: ' + buf.slice(-400))); });
      });
    });
  });
}

(async () => {
  const demo = await startDemo();
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(demo.url);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.click('.tab[data-p="alerts"]');
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .ncard').length===3, null, {timeout:60000})
    .catch(()=>{});
  const n0 = await p.evaluate(()=>document.querySelectorAll('#p-alerts .ncard').length);
  check('the demo\'s three cards are shown', n0===3, String(n0));

  const top = await p.evaluate(()=>{
    const n = document.getElementById('needsSec'), r = document.getElementById('recSec');
    return {needs: !!n, rec: !!r, order: n && r ? n.getBoundingClientRect().top < r.getBoundingClientRect().top : false,
            h4: n ? n.querySelector('h4').textContent : '', rh4: r ? r.querySelector('h4').textContent : ''};
  });
  check('Needs you is above Recorded', top.needs && top.rec && top.order, JSON.stringify(top));
  check('...headed with its count', top.h4==='Needs you · 3', top.h4);
  check('...and Recorded says it is today\'s', top.rh4==='Recorded, nothing to do · today', top.rh4);
  // The badge follows the status poll, a beat behind the pane.
  await p.waitForFunction(()=>$('nAlerts').textContent==='3', null, {timeout:3000}).catch(()=>{});
  check('the badge counts the cards', await p.textContent('#nAlerts')==='3', await p.textContent('#nAlerts'));
  check('...in the high colour', await p.evaluate(()=>$('nAlerts').classList.contains('high')));

  const card = name => p.evaluate(nm => {
    const c = [...document.querySelectorAll('#p-alerts .ncard')].find(x => x.textContent.includes(nm));
    if (!c) return null;
    return {id: c.dataset.nid, text: c.textContent,
            talk: c.querySelectorAll('.talk').length,
            acts: [...c.querySelectorAll('[data-nact]')].map(x => x.dataset.nact),
            bad: [...c.querySelectorAll('.bad')].map(x => x.textContent)};
  }, name);
  const su = await card('SilentUpdater.exe');
  check('SilentUpdater shows its path', su && su.text.includes('C:\\Users\\Demo\\AppData\\Local\\Temp\\su7\\SilentUpdater.exe'),
        su && su.text);
  check('...that it is not signed, in the high colour', su && su.bad.includes('not signed'), su && JSON.stringify(su.bad));
  check('...who started it', su && su.text.includes('chrome.exe'));
  check('...and who it talked to', su && su.talk >= 1, su && String(su.talk));
  check('...with trust, packets and dismiss', su && ['trust', 'packets', 'dismiss'].every(a => su.acts.includes(a)),
        su && JSON.stringify(su.acts));
  check('...and no Block while blocking is off', su && !su.acts.includes('block'), su && JSON.stringify(su.acts));
  const va = await card('Vanished.exe');
  check('...and its Signed row says the file is gone, not "not signed"',
        va && !va.bad.includes('not signed') && /Signedfile not found/.test(va.text), va && JSON.stringify([va.bad, va.text]));
  check('Vanished has no trust button', va && !va.acts.includes('trust') && va.acts.includes('dismiss'),
        va && JSON.stringify(va.acts));
  const arp = await card('192.168.1.1');
  check('the ARP card offers packets, expected and dismiss',
        arp && JSON.stringify(arp.acts)===JSON.stringify(['packets', 'expected', 'dismiss']), arp && JSON.stringify(arp.acts));

  // Block appears once blocking is on (demo mode's firewall is in memory).
  await p.evaluate(()=>control({action: 'blocking', enabled: true}));
  await p.mouse.move(5, 5);
  await p.evaluate(()=>refreshTab('alerts'));
  await p.waitForTimeout(300);
  const su2 = await card('SilentUpdater.exe');
  check('Block is offered once blocking is on', su2 && su2.acts[0]==='block', su2 && JSON.stringify(su2.acts));
  await p.evaluate(()=>control({action: 'blocking', enabled: false}));

  // Show packets filters the table on the program.
  await p.click('#p-alerts .ncard[data-nid="'+su.id+'"] [data-nact="packets"]');
  await p.waitForTimeout(200);
  check('Show packets filters the table on the program',
        await p.inputValue('#find')==='process == "SilentUpdater.exe"' &&
        await p.evaluate(()=>viewMode==='table'), await p.inputValue('#find'));
  await p.fill('#find', ''); await p.evaluate(()=>applyFind());

  // Trust: the card goes, the program is listed as trusted, the badge drops.
  await p.mouse.move(5, 5);
  await p.click('#p-alerts .ncard[data-nid="'+su.id+'"] [data-nact="trust"]');
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .ncard').length===2, null, {timeout:5000}).catch(()=>{});
  const tr = await p.evaluate(()=>({n: document.querySelectorAll('#p-alerts .ncard').length,
    trusted: (document.querySelector('#trustedSec > summary')||{}).textContent || '',
    folded: !(document.getElementById('trustedSec')||{}).open,
    untrust: document.querySelectorAll('#trustedSec [data-untrust]').length}));
  check('trusting a card removes it', tr.n===2, JSON.stringify(tr));
  check('...and lists it under Trusted programs, folded', /^Trusted programs · 1/.test(tr.trusted) && tr.folded && tr.untrust===1,
        JSON.stringify(tr));
  await p.waitForFunction(()=>$('nAlerts').textContent==='2', null, {timeout:3000}).catch(()=>{});
  check('...and the badge reads 2', await p.textContent('#nAlerts')==='2');

  // A Recorded line opens and stays open across the 2.5 s redraw.
  // Waited for, not read once: the demo's alerts arrive on their own time.
  // (Before Clear alerts below, which empties them until the demo fires more.)
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>document.querySelectorAll('#recSec details.recline').length>0,
                          null, {timeout: 60000}).catch(()=>{});
  const kind = await p.evaluate(()=>{ const r = document.querySelector('#recSec details.recline');
    return r ? r.dataset.kind : null; });
  check('Recorded has a line per kind', !!kind);
  if (kind){
    const sum = await p.textContent('#recSec details.recline[data-kind="'+kind+'"] > summary');
    check('...whose summary reads Label · count', /^[A-Z][a-z -]+ · \d+/.test(sum.trim()), sum);
    await p.click('#recSec details.recline[data-kind="'+kind+'"] > summary');
    await p.mouse.move(5, 5);
    await p.waitForTimeout(3200);
    check('...that stays open across a refresh', await p.evaluate(k =>
      document.querySelector('#recSec details.recline[data-kind="'+k+'"]').open, kind));
    check('...and lists its alerts with their controls', await p.evaluate(k => {
      const a = document.querySelector('#recSec details.recline[data-kind="'+k+'"] .alert');
      return !!a && !!a.querySelector('[data-dismiss]'); }, kind));
  }
  const order = await p.evaluate(()=>[...document.querySelectorAll('#recSec details.recline')].map(x=>x.dataset.kind));
  const want = ['programs','devices','checkins','bandwidth','network','insecure','hosts','blocks','other'];
  check('...in the set order', order.every((k, i) => i === 0 || want.indexOf(order[i-1]) < want.indexOf(k)), JSON.stringify(order));

  // Clear alerts is under Rules and settings, and leaves the cards alone.
  check('the rules are folded away', await p.evaluate(()=>!$('rulesSec').open && !!$('rulesSec').querySelector('[data-rule]')));
  check('the old This session / Past days switch is gone', await p.$('#alertSw')===null);
  await p.click('#rulesSec > summary');
  await p.click('#clearAlerts');
  await p.mouse.move(5, 5);
  await p.waitForTimeout(800);
  check('Clear alerts leaves the 2 cards',
        await p.evaluate(()=>document.querySelectorAll('#p-alerts .ncard').length)===2);
  check('...and Rules and settings stays open', await p.evaluate(()=>$('rulesSec').open));

  await p.reload();
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.click('.tab[data-p="alerts"]');
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .ncard').length>0, null, {timeout:10000}).catch(()=>{});
  check('a reload still shows 2 cards', await p.evaluate(()=>document.querySelectorAll('#p-alerts .ncard').length)===2);

  // A card settled today is still findable: under Earlier days › Today, first,
  // marked "needed you" (this demo has the in-memory history, so a real log).
  const van = await card('Vanished.exe');
  if (van){
    await p.click('#p-alerts .ncard[data-nid="'+van.id+'"] [data-nact="dismiss"]');
    await p.mouse.move(5, 5);
    await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .ncard').length===1, null, {timeout:5000}).catch(()=>{});
  }
  check('dismissing Vanished leaves one card', await p.evaluate(()=>document.querySelectorAll('#p-alerts .ncard').length)===1);
  await p.click('#earlierSec > summary');
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>[...document.querySelectorAll('#earlierSec .logrow.needed')]
    .some(x=>x.textContent.includes('Vanished.exe')), null, {timeout:8000}).catch(()=>{});
  const td = await p.evaluate(()=>{
    const day = document.querySelector('#earlierSec .eday');
    const first = day && day.querySelector('.logrow');
    return day ? {h5: day.querySelector('h5').textContent,
                  van: [...day.querySelectorAll('.logrow.needed')].some(x=>x.textContent.includes('Vanished.exe') &&
                         x.textContent.includes('needed you')),
                  firstNeeded: !!first && first.classList.contains('needed')} : null;
  });
  check('a card dismissed today is under Earlier days › Today, marked needed you',
        td && /^Today · \d+$/.test(td.h5) && td.van && td.firstNeeded, JSON.stringify(td));
  await p.click('#earlierSec > summary');                  // fold it again
  await p.mouse.move(5, 5);                               // so the pane redraws

  // Earlier days: folded, and loads the log when opened.
  await p.route('**/api/alert_log*', r =>
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(logReply())}));
  await p.route('**/api/alerts*', async r => {
    const d = await (await r.fetch()).json(); d.log_days = 30;
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(d)}); });
  await p.evaluate(()=>refreshTab('alerts'));
  await p.waitForTimeout(300);
  check('Earlier days is folded', await p.evaluate(()=>!!$('earlierSec') && !$('earlierSec').open));
  await p.click('#earlierSec > summary');
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>document.querySelectorAll('#earlierSec .logrow').length===4, null, {timeout:5000}).catch(()=>{});
  const ed = await p.evaluate(()=>({
    rows: document.querySelectorAll('#earlierSec .logrow').length,
    days: document.querySelectorAll('#earlierSec .eday').length,
    first: (document.querySelector('#earlierSec .eday .logrow .ti')||{}).textContent,
    needed: [...document.querySelectorAll('#earlierSec .logrow.needed')].map(x=>x.textContent.includes('needed you')),
    kinds: [...document.querySelectorAll('#earlierSec .eday')].map(d =>
      [...d.querySelectorAll('details.recline')].map(x=>x.dataset.kind).join('+'))}));
  check('Earlier days lists the log by day', ed.rows===4 && ed.days===2, JSON.stringify(ed));
  check('...what needed you first, marked so', ed.first==='Unsigned program in a folder anyone can write to' &&
        ed.needed.length===1 && ed.needed[0], JSON.stringify(ed));
  check('...then by the same kinds', ed.kinds[0]==='programs+bandwidth' && ed.kinds[1]==='checkins', JSON.stringify(ed.kinds));
  await p.waitForTimeout(3000);
  check('...and stays open across a refresh', await p.evaluate(()=>$('earlierSec').open));
  await p.unroute('**/api/alert_log*'); await p.unroute('**/api/alerts*');

  // Width: no sideways scroll at full width and at the side panel's narrowest,
  // with every fold open (today's log rows carry a program's whole path).
  await p.evaluate(()=>{ refreshTab('alerts');
    document.querySelectorAll('#p-alerts details').forEach(d => { d.open = true; }); });
  await p.mouse.move(5, 5);
  await p.waitForTimeout(3000);
  await p.evaluate(()=>document.querySelectorAll('#p-alerts details').forEach(d => { d.open = true; }));
  await p.waitForTimeout(300);
  const wide = () => p.evaluate(()=>({doc: document.documentElement.scrollWidth > innerWidth,
    pane: $('p-alerts').scrollWidth > $('p-alerts').clientWidth + 1,
    over: [...$('p-alerts').querySelectorAll('*')].filter(e =>
      e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflowX !== 'hidden')
      .slice(0, 4).map(e => e.tagName + '.' + e.className + ' ' + (e.textContent || '').slice(0, 50))}));
  let w = await wide();
  check('no sideways scroll at 1680', !w.doc && !w.pane, JSON.stringify(w));
  await p.setViewportSize({width:1120, height:900});
  await p.waitForTimeout(400);
  w = await wide();
  check('...nor at the side panel\'s narrowest', !w.doc && !w.pane, JSON.stringify(w));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close();
  demo.proc.kill();
  try { fs.rmSync(demo.home, {recursive: true, force: true}); } catch (e){}
  process.exit(fails.length?1:0);
})().catch(e => { console.log('FAIL  ' + e); console.log('\nFAILED: crashed'); process.exit(1); });
