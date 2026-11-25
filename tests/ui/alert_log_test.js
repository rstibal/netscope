const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The alert log is the Alerts tab's Earlier days: folded, loaded when opened,
// by day and then by kind. The demo server runs with --no-history, so the
// log is answered here; mutes go to the real server. Every row is from
// before today (Earlier days leaves today to the Recorded lines above it).
const BASE = new Date().setHours(0, 0, 0, 0) / 1000 - 1;   // last second of yesterday
const YD = new Date(BASE * 1000), YDAY = YD.getFullYear() + '-' + String(YD.getMonth() + 1).padStart(2, '0') +
  '-' + String(YD.getDate()).padStart(2, '0');
const LOG = [];
for (let i = 1; i <= 150; i++)
  LOG.push({id: i, ts: BASE - (150 - i) * 3600, severity: i % 25 ? 'warn' : 'high', pile: 'recorded',
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
  await p.waitForSelector('#earlierSec');
  check('...so there is no This session / Past days switch', await p.$('#alertSw')===null);
  await p.click('#earlierSec > summary');
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>/History is off/.test($('earlierSec').textContent), null, {timeout: 3000}).catch(()=>{});
  check('...and Earlier days says history is off', await p.evaluate(()=>/History is off/.test($('earlierSec').textContent)));
  await p.click('#earlierSec > summary');                     // fold it again

  // ---------------- with a log ----------------
  let logCalls = [];
  await p.route('**/api/alert_log*', r => { logCalls.push(r.request().url());
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(logReply(r.request().url()))}); });
  await p.route('**/api/alerts*', async r => {
    const d = await (await r.fetch()).json(); d.log_days = 30;
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(d)}); });
  await p.route('**/api/history*', r =>
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history())}));

  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>/logged for 30 days/.test($('earlierSec').textContent), null, {timeout: 5000}).catch(()=>{});
  check('Earlier days is folded, saying how long the log is kept',
        await p.evaluate(()=>!$('earlierSec').open && /logged for 30 days/.test($('earlierSec').textContent)));
  check('...and nothing is fetched until it is opened', logCalls.length===0, JSON.stringify(logCalls));
  check('...the session\'s Dismiss is still on today\'s alerts',
        (await p.$$('#recSec [data-dismiss]')).length>0 || await p.$('#recSec .nquiet')!==null);

  await p.click('#earlierSec > summary');
  await p.mouse.move(5, 5);
  await p.waitForFunction(()=>document.querySelectorAll('#earlierSec .logrow').length===100, null, {timeout: 5000}).catch(()=>{});
  const v = await p.evaluate(()=>({
    n: document.querySelectorAll('#earlierSec .logrow').length,
    hint: [...document.querySelectorAll('#earlierSec > .hint')].map(x=>x.textContent).join(),
    first: document.querySelector('#earlierSec .logrow .ti').textContent,
    day: document.querySelector('#earlierSec .eday h5').textContent,
    lines: [...document.querySelectorAll('#earlierSec .eday')].map(d=>[...d.querySelectorAll('details.recline')].map(x=>x.dataset.kind).join('+')),
    when: document.querySelector('#earlierSec .logrow .when').textContent,
    dismiss: document.querySelectorAll('#earlierSec .logrow [data-dismiss]').length,
    mute: document.querySelector('#earlierSec .logrow [data-mute]') ? document.querySelector('#earlierSec .logrow [data-mute]').textContent : '',
    older: !!document.getElementById('alertMore')}));
  check('the log shows the newest 100, with the totals',
        v.n===100 && /^150 logged · 6 high · 144 warn\./.test(v.hint) && v.first==='First contact 150' && v.older, JSON.stringify(v));
  check('...by day, newest first, under a line per kind',
        /^Yesterday · 24$/.test(v.day) && v.lines.length>=5 && v.lines.every(k=>k==='hosts'), JSON.stringify([v.day, v.lines]));
  check('...dated, not "x ago"', /\d{4}|\d+\/\d+/.test(v.when), v.when);
  check('...with no Dismiss: the log is the record', v.dismiss===0);
  check('...and a Mute for rows that know their subject; none for one that doesn\'t',
        v.mute==='Mute h149.example' &&
        await p.evaluate(()=>!document.querySelector('#earlierSec .logrow').querySelector('[data-mute],[data-unmute]')),
        v.mute);

  await p.click('#alertMore');
  await p.waitForFunction(()=>document.querySelectorAll('#earlierSec .logrow').length===150, null, {timeout: 5000}).catch(()=>{});
  check('Show older loads the rest, and goes away at the end',
        await p.evaluate(()=>document.querySelectorAll('#earlierSec .logrow').length)===150 && !(await p.$('#alertMore')));

  // Keep a day's line, and a why box in it, open across the tab's 2.5 s refresh.
  const line = '#earlierSec .eday[data-day="' + YDAY + '"] details.recline[data-kind="hosts"]';
  await p.click(line + ' > summary');
  await p.click(line + ' .logrow:nth-child(4) details.why summary');
  // The pane doesn't redraw under the pointer, so take it away.
  await p.mouse.move(5, 5);
  // A new alert is logged; the refresh fetches only what's new.
  LOG.push({id: 151, ts: BASE - 10, severity:'high', rule:'cleartext_creds', pile:'recorded', title:'Password in the clear',
            detail:'ftp.exe sent a password', process:'ftp.exe', peer:'5.6.7.8', subject:'5.6.7.8'});
  logCalls = [];
  await p.waitForFunction(()=>[...document.querySelectorAll('#earlierSec .logrow .ti')].some(x=>x.textContent==='Password in the clear'),
                          null, {timeout: 6000}).catch(()=>{});
  const nl = await p.evaluate(day=>({n: document.querySelectorAll('#earlierSec .logrow').length,
    lines: [...document.querySelectorAll('#earlierSec .eday[data-day="' + day + '"] details.recline')].map(x=>x.dataset.kind).join('+')}), YDAY);
  check('a newly logged alert appears by itself, on its own line', nl.n===151 && nl.lines==='insecure+hosts', JSON.stringify(nl));
  check('...fetched incrementally', logCalls.some(u=>/after=150/.test(u)), JSON.stringify(logCalls));
  check('...and the open line and "why" box stay open',
        await p.evaluate(l=>document.querySelector(l).open &&
          document.querySelectorAll('#earlierSec .logrow details.why[open]').length===1, line));

  // Muting from the log goes to the real server, and the row then offers Unmute.
  await p.click('#earlierSec .logrow [data-mute][data-subject="h149.example"]');
  await p.waitForSelector('#earlierSec .logrow [data-unmute][data-subject="h149.example"]', {timeout: 5000});
  const mutes = await p.evaluate(()=>api('/api/alerts').then(r=>r.json()).then(d=>d.mutes));
  check('Mute in the log mutes that subject for that rule',
        mutes.some(m=>m.rule==='new_host' && m.subject==='h149.example'), JSON.stringify(mutes));
  await p.click('#earlierSec .logrow [data-unmute][data-subject="h149.example"]');
  await p.waitForSelector('#earlierSec .logrow [data-mute][data-subject="h149.example"]', {timeout: 5000});

  // ---------------- reached from History ----------------
  await p.reload();
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.waitForSelector('.tab[data-p="history"].on');
  await p.waitForSelector('#histMore', {timeout: 15000});
  await p.click('#histMore > summary');       // the alert count is under More (1.40)
  await p.waitForSelector('#alertsJump', {timeout: 15000});
  const hist = await p.evaluate(()=>({
    old: [...document.querySelectorAll('#p-history h4')].some(x=>/Alert history/.test(x.textContent)),
    cards: document.querySelectorAll('#p-history .alert').length,
    text: document.getElementById('alertsJump').parentNode.textContent}));
  check('History no longer repeats the alerts', !hist.old && hist.cards===0, JSON.stringify(hist));
  check('...it counts them and links to them', /^151 alerts|^150 alerts logged \(6 high, 144 warn\)/.test(hist.text), hist.text);
  await p.click('#alertsJump');
  await p.waitForFunction(()=>document.querySelector('.tab[data-p="alerts"]').classList.contains('on') &&
                              document.querySelectorAll('#earlierSec .logrow').length>0, null, {timeout: 5000}).catch(()=>{});
  check('the link opens the Alerts tab with Earlier days open', await p.evaluate(()=>
        $('earlierSec').open && document.querySelectorAll('#earlierSec .logrow').length>0));

  await p.reload();
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.click('.tab[data-p="alerts"]');
  await p.waitForSelector('#earlierSec');
  check('Earlier days starts folded on a fresh page', await p.evaluate(()=>!$('earlierSec').open));

  // The log says how to erase it, and the link goes to the button that does.
  await p.click('#earlierSec > summary');
  await p.waitForSelector('#wipeJump', {timeout: 5000});
  const hintText = await p.evaluate(()=>document.getElementById('wipeJump').parentNode.textContent);
  check('the log says Erase all history removes it',
        /Erase all history on the History tab does\./.test(hintText), hintText);
  await p.mouse.move(5, 5);
  await p.click('#wipeJump');
  await p.waitForFunction(()=>document.querySelector('.tab[data-p="history"]').classList.contains('on') &&
                              document.activeElement && document.activeElement.id==='histWipe',
                          null, {timeout: 5000}).catch(()=>{});
  const wipeOnScreen = await p.evaluate(()=>{ const r = document.getElementById('histWipe').getBoundingClientRect();
    return document.activeElement.id==='histWipe' && r.top >= 0 && r.bottom <= innerHeight; });
  check('...and opens History with that button focused and on screen', wipeOnScreen);

  const hs = await p.evaluate(()=>document.documentElement.scrollWidth > innerWidth);
  check('no sideways scroll', !hs);
  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
