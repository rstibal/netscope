const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// "Erase VPN overhead" on the History tab: previews what it would erase, asks,
// and only then deletes. The demo server runs without history, so the History
// data and the history_vpn action are answered here; the real server supplies
// the status object the page needs on every control reply.
const G = Math.pow(1024,3);
const payload = () => ({enabled:true, days:30, daily:[], hourly:[], hosts:[], new_hosts:[], alerts:[], sessions:[],
  processes:[{name:'chrome.exe', bytes_in:G, bytes_out:G/4, packets:10}], exclude:{programs:[],hosts:[]},
  summary:{bytes_in:G, bytes_out:G/4, packets:1, processes:1, hosts:0, size:1024, retain_days:90,
           since:'2026-09-01', path:'C:\history.db'}});

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  const dialogs=[]; let answer=false;
  p.on('dialog', d => { dialogs.push(d.message()); answer ? d.accept() : d.dismiss(); });
  const calls=[]; let programs={'openvpn.exe': 5*G};
  await p.route('**/api/history*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(payload())}));
  await p.route('**/api/control*', async route => {
    const body = JSON.parse(route.request().postData() || '{}');
    if (body.action !== 'history_vpn') return route.continue();
    calls.push(body);
    const real = await (await route.fetch({postData: JSON.stringify({action:'history_flush'})})).json();
    const shown = programs;
    if (!body.dry) programs = {};
    route.fulfill({status:200, contentType:'application/json', body: JSON.stringify({status: real.status, vpn:{programs: shown, usage: 3}})});
  });
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.click('.tab[data-p="history"]');
  await p.waitForSelector('#histVpn');

  await p.click('#histVpn');
  await p.waitForTimeout(400);
  check('it previews first, naming the program and its size',
        dialogs.length===1 && /openvpn\.exe/.test(dialogs[0]) && /5(\.0)? ?GB/.test(dialogs[0]), dialogs[0]);
  check('declining deletes nothing', calls.length===1 && calls[0].dry===true, JSON.stringify(calls));

  answer = true; dialogs.length = 0; calls.length = 0;
  await p.click('#histVpn');
  await p.waitForSelector('#vpnMsg');
  check('accepting sends the delete after the preview',
        calls.length===2 && calls[0].dry===true && !calls[1].dry, JSON.stringify(calls));
  const msg = await p.textContent('#vpnMsg');
  check('and says what it erased', /Erased the usage of 1 VPN program/.test(msg), msg);

  dialogs.length = 0; calls.length = 0;
  await p.click('#histVpn');
  await p.waitForFunction(()=>/nothing to erase/.test(($('vpnMsg')||{}).textContent||''));
  check('with nothing recorded it says so and does not ask', dialogs.length===0 && calls.length===1);

  check('no page errors', errs.length===0, errs.join('; '));
  await b.close();
  console.log(); console.log('FAILED:', fails.length ? fails : 'none');
  process.exit(fails.length?1:0);
})();
