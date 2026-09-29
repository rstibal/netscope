const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The alert log moved from the History tab into the Alerts tab, as a second
// view beside this session's alerts. The demo server runs with --no-history,
// so the log is answered here; mutes go to the real server.
const NOW = Date.now()/1000;
const LOG = [];
for (let i = 1; i <= 150; i++)
  LOG.push({id: i, ts: NOW - (151 - i) * 3600, severity: i % 25 ? 'warn' : 'high',
            rule: 'new_host', title: 'First contact ' + i, detail: 'chrome.exe connected to h' + i + '.example',
            process: 'chrome.exe', peer: '1.2.3.4', subject: i === 150 ? null : 'h' + i + '.example'});
function logReply(url){
  const q = new URL(url).searchParams;
  const before = q.get('before'), after = q.get('after'), limit = Number(q.get('limit') || 100);
  let rows = LOG.slice().reverse();
  if (before) rows = rows.filter(r => r.id < Number(before));
  if (after) rows = rows.filter(r => r.id > Number(after));
  const high = LOG.filter(r => r.severity === 'high').length;
  return {enabled: true, alerts: rows.slice(0, limit), more: rows.length > limit, retain_days: 30,
          counts: {total: LOG.length, high, warn: LOG.length - high, info: 0, newest: LOG[LOG.length-1].id}};
}
const G = Math.pow(1024,3);
function history(){
  const daily = [];
  for (let i=0;i<30;i++) daily.push({day:'2026-09-'+String(i+1).padStart(2,'0'), bytes_in:G, bytes_out:G/4, packets:10});
  return {enabled:true, days:30, daily, hourly:[], hosts:[], new_hosts:[], sessions:[], processes:[],
          exclude:{programs:[],hosts:[]}, alert_counts:{total:150, high:6, warn:144, info:0, newest:150},
          summary:{bytes_in:G, bytes_out:G, packets:1, processes:1, hosts:0, size:1024,
                   retain_days:90, since:'2026-09-01', path:'C:\\history.db'}};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});

  // ---------------- without history ----------------
  const real = await p.evaluate(()=>Promise.all([api('/api/alert_log').then(r=>r.json()),
                                                 api('/api/alerts').then(r=>r.json())]));
  check('with history off, the log endpoint says so', real[0].enabled===false && real[0].alerts.length===0,
        JSON.stringify(real[0]));
  check('...and the Alerts tab is told there is no log', real[1].log_days===null, real[1].log_days);
  await p.click('.tab[data-p="alerts"]');
  await p.waitForFunction(()=>document.querySelector('#p-alerts .sec'));
  check('...so it shows no switch, just this session', await p.$('#alertSw')===null);

  // ---------------- with a log ----------------
  let logCalls = [];
  await p.route('**/api/alert_log*', r => { logCalls.push(r.request().url());
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(logReply(r.request().url()))}); });
  await p.route('**/api/alerts*', async r => {
    const d = await (await r.fetch()).json(); d.log_days = 30;
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(d)}); });
  await p.route('**/api/history*', r =>
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history())}));

  await p.waitForSelector('#alertSw', {timeout: 5000});
  const sw = await p.evaluate(()=>[...document.querySelectorAll('#alertSw button')].map(x=>x.textContent+'|'+x.classList.contains('on')));
  check('the Alerts tab offers This session and Past 30 days, on this session',
        sw.join()==='This session|true,Past 30 days|false', JSON.stringify(sw));
  check('...and the session view still has Dismiss',
        (await p.$$('#p-alerts [data-dismiss]')).length>0 || await p.$('#p-alerts .empty')!==null);

  await p.click('#alertSw [data-av="log"]');
  await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .logrow').length===100);
  const v = await p.evaluate(()=>({
    h4: [...document.querySelectorAll('#p-alerts .sec h4')].pop().textContent,
    first: document.querySelector('#p-alerts .logrow .ti').textContent,
    when: document.querySelector('#p-alerts .logrow .when').textContent,
    dismiss: document.querySelectorAll('#p-alerts .logrow [data-dismiss]').length,
    mute: document.querySelector('#p-alerts .logrow [data-mute]') ? document.querySelector('#p-alerts .logrow [data-mute]').textContent : '',
    older: !!document.getElementById('alertMore')}));
  check('the log shows the newest 100, with the totals',
        v.h4==='150 alerts · 6 high · 144 warn' && v.first==='First contact 150' && v.older, JSON.stringify(v));
  check('...dated, not "x ago"', /\d{4}|\d+\/\d+/.test(v.when), v.when);
  check('...with no Dismiss: the log is the record', v.dismiss===0);
  check('...and a Mute for rows that know their subject; none for one that doesn\'t',
        v.mute==='Mute h149.example' &&
        await p.evaluate(()=>!document.querySelector('#p-alerts .logrow').querySelector('[data-mute],[data-unmute]')),
        v.mute);

  await p.click('#alertMore');
  await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .logrow').length===150);
  check('Show older loads the rest, and goes away at the end', !(await p.$('#alertMore')));

  // Keep a why box open across the tab's 2.5 s refresh.
  await p.click('#p-alerts .logrow:nth-child(4) details.why summary');
  // A new alert is logged; the refresh fetches only what's new.
  LOG.push({id: 151, ts: Date.now()/1000, severity:'high', rule:'cleartext_creds', title:'Password in the clear',
            detail:'ftp.exe sent a password', process:'ftp.exe', peer:'5.6.7.8', subject:'5.6.7.8'});
  logCalls = [];
  await p.waitForFunction(()=>document.querySelector('#p-alerts .logrow .ti').textContent==='Password in the clear',
                          null, {timeout: 6000});
  check('a newly logged alert appears at the top by itself',
        await p.evaluate(()=>document.querySelectorAll('#p-alerts .logrow').length)===151);
  check('...fetched incrementally', logCalls.some(u=>/after=150/.test(u)), JSON.stringify(logCalls));
  check('...and an open "why" box stays open',
        await p.evaluate(()=>document.querySelectorAll('#p-alerts .logrow details.why[open]').length)===1);

  // Muting from the log goes to the real server, and the row then offers Unmute.
  await p.click('#p-alerts .logrow [data-mute][data-subject="h149.example"]');
  await p.waitForSelector('#p-alerts .logrow [data-unmute][data-subject="h149.example"]', {timeout: 5000});
  const mutes = await p.evaluate(()=>api('/api/alerts').then(r=>r.json()).then(d=>d.mutes));
  check('Mute in the log mutes that subject for that rule',
        mutes.some(m=>m.rule==='new_host' && m.subject==='h149.example'), JSON.stringify(mutes));
  await p.click('#p-alerts .logrow [data-unmute][data-subject="h149.example"]');
  await p.waitForSelector('#p-alerts .logrow [data-mute][data-subject="h149.example"]', {timeout: 5000});

  // ---------------- remembered, and reached from History ----------------
  await p.reload();
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.waitForSelector('.tab[data-p="history"].on');
  await p.waitForSelector('#alertsJump', {timeout: 15000});
  const hist = await p.evaluate(()=>({
    old: [...document.querySelectorAll('#p-history h4')].some(x=>/Alert history/.test(x.textContent)),
    cards: document.querySelectorAll('#p-history .alert').length,
    text: document.getElementById('alertsJump').parentNode.textContent}));
  check('History no longer repeats the alerts', !hist.old && hist.cards===0, JSON.stringify(hist));
  check('...it counts them and links to them', /^151 alerts|^150 alerts logged in this period \(6 high, 144 warn\)/.test(hist.text), hist.text);
  await p.evaluate(()=>localStorage.setItem('netscope-alertview','session'));
  await p.click('#alertsJump');
  await p.waitForFunction(()=>document.querySelector('.tab[data-p="alerts"]').classList.contains('on') &&
                              document.querySelectorAll('#p-alerts .logrow').length>0, null, {timeout: 5000});
  check('the link opens the Alerts tab on the log', await p.evaluate(()=>
        document.querySelector('#alertSw [data-av="log"]').classList.contains('on')));
  await p.reload();
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.click('.tab[data-p="alerts"]');
  await p.waitForFunction(()=>document.querySelectorAll('#p-alerts .logrow').length>0, null, {timeout: 5000});
  check('the chosen view is remembered after a reload', true);

  const hs = await p.evaluate(()=>document.documentElement.scrollWidth > innerWidth);
  check('no sideways scroll', !hs);
  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
