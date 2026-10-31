const { chromium } = require('playwright');
const fs = require('fs');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// Export: packets (what the filter shows, built in the page), connections,
// History totals and alerts (built on the server), as CSV or JSON.
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const ctx = await b.newContext({ viewport:{width:1680,height:900}, acceptDownloads:true });
  const p = await ctx.newPage();
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>40,null,{timeout:90000});

  const grab = async (label) => {
    await p.click('#exportTxt');
    const items = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
    const [dl] = await Promise.all([p.waitForEvent('download', {timeout:15000}),
      p.locator('#rowmenu button', {hasText: label}).first().click()]);
    await p.waitForTimeout(1900);   // past the double-click guard
    return {items, name: dl.suggestedFilename(), text: fs.readFileSync(await dl.path(), 'utf8')};
  };

  await p.fill('#find', 'proto == "DNS"');
  await p.waitForTimeout(300);
  const csv = await grab('Packets the filter shows — CSV');
  check('the menu offers four exports in two formats', csv.items.length===8 &&
        csv.items.every(t=>/ — (CSV|JSON)$/.test(t)), JSON.stringify(csv.items));
  check('packets CSV is named for what it holds', /^netscope-packets-\d{8}-\d{6}\.csv$/.test(csv.name), csv.name);
  const lines = csv.text.replace(/^﻿/, '').trim().split('\r\n');
  check('...starts with a header row', lines[0]==='seq,time,ts,iface,dir,src,sport,dst,dport,proto,length,process,pid,rhost,info', lines[0]);
  const procCol = lines[0].split(',').indexOf('proto');
  check('...and holds only what the filter shows', lines.length>1 &&
        lines.slice(1).every(l=>l.split(',')[procCol]==='DNS'), lines.slice(0,3).join(' | '));

  await p.fill('#find', '');
  await p.waitForTimeout(300);
  const js = await grab('All buffered packets — JSON');
  const arr = JSON.parse(js.text);
  check('with no filter, JSON holds the whole buffer', Array.isArray(arr) && arr.length>=40 &&
        'process' in arr[0] && 'info' in arr[0], js.text.slice(0,120));

  const conns = await grab('Connections — CSV');
  check('connections CSV has its header and rows',
        /^﻿?list,state,proto,process,pid,laddr,lport,raddr,rport,rhost/.test(conns.text) &&
        conns.text.trim().split('\r\n').length>1, conns.text.slice(0,120));
  const al = await grab('alerts — JSON');
  let alerts = null; try { alerts = JSON.parse(al.text); } catch(e) {}
  check("alerts JSON parses (this session's: the test demo has no history)",
        Array.isArray(alerts) && (!alerts.length || ('title' in alerts[0] && 'time' in alerts[0])), al.text.slice(0,120));
  const hist = await grab('History totals per program and host — CSV');
  check('History with history off is a header and nothing else',
        hist.text.replace(/^﻿/,'').trim()==='kind,name,first_seen,last_seen,bytes_in,bytes_out,packets', hist.text);

  // A cell a spreadsheet would run as a formula is defused, as the server does.
  const cells = await p.evaluate(()=>[csvCell('=HYPERLINK("x")'), csvCell('-cmd'), csvCell(-5), csvCell('a,b'), csvCell('ok')]);
  check('formula-looking text is defused, numbers and plain text kept',
        JSON.stringify(cells)===JSON.stringify(["\"'=HYPERLINK(\"\"x\"\")\"", "'-cmd", "-5", '"a,b"', 'ok']), JSON.stringify(cells));
  check('no page errors', errs.length===0, errs.join(' | '));
  await b.close();
  console.log(); console.log('FAILED:', fails.length ? fails : 'none');
  process.exit(fails.length?1:0);
})();
