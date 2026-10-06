const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// Blocking from the Connections tab. The demo server gives blocking a firewall
// of its own in memory, so nothing here touches the real one.
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:980} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  const dialogs=[]; let accept=false;
  p.on('dialog', d => { dialogs.push(d.message()); accept ? d.accept() : d.dismiss(); });
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});
  await p.click('.tab[data-p="conns"]');
  await p.waitForSelector('#p-conns .citem .blk', {timeout:20000});

  const state = () => p.evaluate(async () => (await (await api('/api/blocks')).json()));
  check('nothing is blocked to start', (await state()).blocks.length===0);

  await p.click('#p-conns .citem .blk');
  const items = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
  check('the menu offers host, host:port and program', items.length===3 &&
        /^Block host /.test(items[0]) && /only \(tcp, outbound\)/.test(items[1]) && /^Block program /.test(items[2]), JSON.stringify(items));
  check('opening it does not also select the row', !(await p.inputValue('#find')));

  // declined: nothing happens
  await p.click('#rowmenu button:first-child');
  await p.waitForTimeout(300);
  check('it asks first', dialogs.length===1 && /Block all traffic to and from/.test(dialogs[0]), dialogs[0]);
  check('declining blocks nothing', (await state()).blocks.length===0);

  // accepted: blocking is off, so it offers to turn it on, then blocks
  accept = true; dialogs.length = 0;
  await p.waitForSelector('#p-conns .citem .blk');
  await p.click('#p-conns .citem .blk');
  await p.click('#rowmenu button:first-child');
  for (let i=0; i<50 && (await state()).blocks.length!==1; i++) await p.waitForTimeout(200);
  check('blocking being off is explained before it is switched on',
        dialogs.length===2 && /switched off/.test(dialogs[1]), JSON.stringify(dialogs));
  const s1 = await state();
  check('the block exists and is active', s1.enabled && s1.blocks[0].kind==='host' && s1.blocks[0].state==='active', JSON.stringify(s1));
  check('the alert log records it', await p.evaluate(async () =>
        (await (await api('/api/alerts')).json()).alerts.some(a => a.rule==='block' && /^Blocked host /.test(a.title))));

  // the Blocked view
  await p.click('#p-conns [data-cmode="blocked"]');
  await p.waitForSelector('#p-conns [data-unblock]');
  const txt = await p.textContent('#p-conns');
  check('it is listed, with its state', txt.includes(s1.blocks[0].target) && /blocking/.test(txt) && /both directions/.test(txt), txt.slice(0,300));
  check('the tab button counts it', /Blocked 1/.test(await p.textContent('#p-conns [data-cmode="blocked"]')));

  // the same host again is refused, and says why
  await p.evaluate(async t => { window.__r = await (await api('/api/control',{method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({action:'block',kind:'host',address:t})})).status; }, s1.blocks[0].target);
  check('a duplicate is refused with a 400', await p.evaluate(()=>window.__r)===400);
  check('...as is loopback', await p.evaluate(async () => (await api('/api/control',{method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({action:'block',kind:'host',address:'127.0.0.1'})})).status)===400);
  check('...and a program the page names by path rather than pid', await p.evaluate(async () => (await api('/api/control',{method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({action:'block',kind:'program',path:'C:/Windows/System32/x.exe'})})).status)===400);

  // unblock
  dialogs.length = 0; accept = false;
  await p.click('#p-conns [data-unblock]');
  await p.waitForTimeout(300);
  check('unblock asks, and declining keeps the block', dialogs.length===1 && (await state()).blocks.length===1);
  accept = true;
  await p.click('#p-conns [data-unblock]');
  await p.waitForFunction(()=>/Nothing is blocked/.test(document.getElementById('p-conns').textContent), null, {timeout:10000});
  check('accepting removes it', (await state()).blocks.length===0);

  const l1w = await p.evaluate(()=>{ document.querySelector('#p-conns [data-cmode="active"]').click(); return 0; });
  await p.waitForSelector('#p-conns .citem .blk');
  const ov = await p.evaluate(()=>{ const pane=document.getElementById('p-conns');
    const bad=[...pane.querySelectorAll('.citem')].filter(it=>{ const w=it.querySelector('.who'), pe=it.querySelector('.peer');
      return (w&&w.scrollWidth>w.clientWidth+1)||(pe&&pe.scrollWidth>pe.clientWidth+1); }).length;
    return {bad, side: pane.scrollWidth-pane.clientWidth}; });
  check('the Block button does not clip a program or host name', ov.bad===0, JSON.stringify(ov));
  check('or make the panel scroll sideways', ov.side<=1, ov.side);

  check('no page errors', errs.length===0, errs.join('; '));
  await b.close();
  console.log(); console.log('FAILED:', fails.length ? fails : 'none');
  process.exit(fails.length?1:0);
})();
