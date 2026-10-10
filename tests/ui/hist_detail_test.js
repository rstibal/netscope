const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// History's By program / By host bars open to show why a program or host has
// the bytes it has: who it talked to, and when.
const MB = 1024*1024;
const history = {
  enabled:true, days:30, hourly:[], new_hosts:[], sessions:[],
  daily: Array.from({length:30},(_, i)=>({day:'2026-09-'+String(i+1).padStart(2,'0'), bytes_in:MB, bytes_out:MB/4, packets:10})),
  processes:[{name:'mystery.exe', bytes_in:90*MB, bytes_out:10*MB, packets:900},
             {name:'chrome.exe', bytes_in:50*MB, bytes_out:5*MB, packets:500}],
  hosts:[{host:'cdn.example', first_seen:1, last_seen:2, bytes_in:80*MB, bytes_out:1*MB, packets:5}],
  exclude:{programs:[],hosts:[]},
  week_hours:{cells:Array.from({length:7},()=>Array.from({length:24},()=>[0,0])), counts:[4,4,4,4,4,4,4]},
  summary:{bytes_in:1, bytes_out:1, packets:1, processes:2, hosts:1, size:1024,
           retain_days:90, since:'2026-09-01', path:'C:\\history.db'}
};
const hours = Array.from({length:72},(_, i)=>({day:'2026-10-10', hour:i%24,
  bytes_in: i===60 ? 40*MB : 0, bytes_out: 0}));
const detail = {
  program: {kind:'program', name:'mystery.exe', days:30, pairs_since:'2026-10-10',
    total:100*MB, unlisted:60*MB, hours,
    rows:[{name:'cdn.example', bytes_in:35*MB, bytes_out:1*MB, packets:50},
          {name:'api.example', bytes_in:3*MB, bytes_out:1*MB, packets:9}],
    busiest:[{day:'2026-10-10', hour:12, bytes_in:40*MB, bytes_out:0, host:'cdn.example'}]},
  host: {kind:'host', name:'cdn.example', days:30, pairs_since:'2026-10-10', total:36*MB,
    unlisted:0, hours:[], busiest:[],
    rows:[{name:'mystery.exe', bytes_in:35*MB, bytes_out:1*MB, packets:50}]},
};

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  const asked=[];
  await p.route('**/api/history?*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history)}));
  await p.route('**/api/history/detail*', r => {
    const u = new URL(r.request().url()); asked.push(u.searchParams.get('kind')+'|'+u.searchParams.get('name'));
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(detail[u.searchParams.get('kind')])});
  });
  await p.goto(process.argv[2]);
  await p.waitForSelector('.hbar', {timeout: 30000});

  const bar = name => p.locator('.hbar[data-k="program"][data-n="'+name+'"]');
  check('program bars are buttons, closed at first',
        await bar('mystery.exe').getAttribute('aria-expanded') === 'false' &&
        await bar('mystery.exe').getAttribute('role') === 'button');
  check('nothing is fetched until asked', asked.length === 0, asked.join());

  await bar('mystery.exe').click();
  const det = p.locator('.hdet[data-for="program|mystery.exe"]');
  await det.locator('.hstrip').waitFor({timeout: 5000});
  const text = await det.innerText();
  check('opens, and asks for exactly that program', asked.join() === 'program|mystery.exe', asked.join());
  check('lists the hosts it talked to', /cdn\.example/.test(text) && /api\.example/.test(text), text);
  check('says how much has no host detail, and why', /not broken down/.test(text) && /60\.0 MB/.test(text) && /recorded from 2026-10-10/.test(text), text);
  check('draws 72 hourly cells, the busy one lit', await det.locator('.hstrip i').count() === 72 &&
        await det.locator('.hstrip i.on').count() === 1);
  check('names the busiest hour and its host', /busiest hours/i.test(text) && /cdn\.example/.test(text.split(/busiest hours/i)[1] || ''), text);

  // A redraw (the page re-polls) keeps it open.
  await p.evaluate(() => { histSeen = null; return loadHistory(false); });
  await p.waitForTimeout(400);
  check('stays open across a redraw',
        await bar('mystery.exe').getAttribute('aria-expanded') === 'true' &&
        await det.locator('.hstrip i').count() === 72);

  // Keyboard.
  await bar('chrome.exe').focus();
  await p.keyboard.press('Enter');
  check('Enter opens a focused bar', await bar('chrome.exe').getAttribute('aria-expanded') === 'true');
  await p.keyboard.press('Enter');
  check('...and closes it again', await bar('chrome.exe').getAttribute('aria-expanded') === 'false');

  // Closing hides it.
  await bar('mystery.exe').click();
  check('a click closes it', await det.isHidden());

  // Hosts.
  await p.locator('.hbar[data-k="host"][data-n="cdn.example"]').click();
  const hd = p.locator('.hdet[data-for="host|cdn.example"]');
  await hd.locator('.hbar').first().waitFor({timeout: 5000});
  check('a host lists the programs that contacted it', /mystery\.exe/.test(await hd.innerText()));
  check('...and has no hourly strip', await hd.locator('.hstrip').count() === 0);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
