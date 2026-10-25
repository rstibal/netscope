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
  check('the menu offers host, host inbound, host:port, program and program inbound',
        /^Block host [^,]+$/.test(items[0]) && items.some(t=>/^Block host .*, inbound only$/.test(t)) &&
        items.some(t=>/only \(TCP, outbound\)/.test(t)) && items.some(t=>/^Block program [^,]+$/.test(t)) &&
        items.some(t=>/^Block program .*, inbound only$/.test(t)), JSON.stringify(items));
  check('an outbound connection offers no local-port block', !items.some(t=>/local port/.test(t)), JSON.stringify(items));
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

  // right-click, in the table and in the timeline
  accept = false; dialogs.length = 0;
  await p.click('#vTable');
  const seq = await p.evaluate(()=>{ for (const [k,r] of records) if (r.dir==='out' && r.transport==='tcp' && r.process!=='-' && r.dport) return k; });
  await p.locator('#rows tr[data-seq="'+seq+'"]').click({button:'right'});
  const tmenu = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
  check('the packet menu offers host, host:port and program', tmenu.some(t=>/^Block host /.test(t)) &&
        tmenu.some(t=>/only \(TCP, outbound\)/.test(t)) && tmenu.some(t=>/^Block program /.test(t)), JSON.stringify(tmenu));
  check('the existing items are still there', tmenu.some(t=>/^Hide program /.test(t)));
  await p.locator('#rowmenu button', {hasText: 'Block host '}).first().click();
  await p.waitForTimeout(300);
  check('choosing it asks first', dialogs.length===1 && /Block all traffic/.test(dialogs[0]), JSON.stringify(dialogs));
  check('and declining blocks nothing', (await state()).blocks.length===0);

  await p.click('#vTime');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length>0, null, {timeout:20000});
  await p.click('#tlGroup [data-g="process"]');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length>0);
  const lane = await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>b.dataset.name).find(n=>n!=='(none)' && !/^\(/.test(n)));
  await p.locator('#tlLabels .ln[data-name="'+lane+'"]').click({button:'right'});
  const pmenu = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
  check('a program lane offers to block the program only', pmenu.some(t=>t==='Block program '+lane) &&
        !pmenu.some(t=>/^Block host /.test(t)), JSON.stringify(pmenu));
  await p.keyboard.press('Escape');
  await p.click('#tlGroup [data-g="host"]');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length>0);
  const ipLane = await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>b.dataset.name).find(n=>/^[\d.]+$/.test(n)));
  const nameLane = await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>b.dataset.name).find(n=>n!=='(none)' && !/^[\d.]+$/.test(n) && !n.includes(':')));
  if (nameLane){
    await p.locator('#tlLabels .ln[data-name="'+nameLane+'"]').click({button:'right'});
    const nmenu = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
    check('a host-name lane offers to block the name, and only that',
          nmenu.filter(t=>/^Block /.test(t)).join('|')==='Block name '+nameLane, JSON.stringify(nmenu));
    accept = true; dialogs.length = 0;
    await p.locator('#rowmenu button', {hasText: 'Block name '}).click();
    for (let i=0; i<50 && !dialogs.length && !(await state()).blocks.some(x=>x.kind==='name'); i++) await p.waitForTimeout(200);
    await p.waitForTimeout(300);
    const nb = (await state()).blocks.find(x=>x.kind==='name');
    check('blocking it asks, mentioning shared addresses', /CDN/.test(dialogs[0]||''), dialogs[0]);
    check('...and either blocks its addresses or says none are known yet',
          (nb && nb.target===nameLane.toLowerCase() && nb.ips.length>0 && nb.dir==='both') ||
          dialogs.some(d=>/hasn't seen an address/.test(d)), JSON.stringify({nb, dialogs}));
    if (nb) await p.evaluate(id => blockCall({action:'unblock', id}), nb.id);
    accept = false;
  }
  if (ipLane){
    await p.locator('#tlLabels .ln[data-name="'+ipLane+'"]').click({button:'right'});
    check('an address lane offers to block the address', await p.evaluate(a=>[...document.querySelectorAll('#rowmenu button')].some(x=>x.textContent==='Block host '+a), ipLane));
    await p.keyboard.press('Escape');
  }
  await p.click('#vTable');

  // Inbound-only and local-port blocks, from the Listening view
  accept = true; dialogs.length = 0;
  await p.click('.tab[data-p="conns"]');
  await p.click('#p-conns [data-cmode="listening"]');
  const hasListen = await p.waitForSelector('#p-conns .citem .blk', {timeout:10000}).then(()=>true, ()=>false);
  check('a listening program has a Block button', hasListen);
  if (hasListen){
    await p.click('#p-conns .citem .blk');
    const lmenu = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
    check('it offers the program inbound, and on its local port', lmenu.some(t=>/, inbound only$/.test(t)) &&
          lmenu.some(t=>/on local port \d+ only \((TCP|UDP), inbound\)/.test(t)) && !lmenu.some(t=>/^Block host /.test(t)), JSON.stringify(lmenu));
    // The demo's one listener is System, which the server refuses (part of
    // Windows): that refusal is the right answer, so check it, then make the
    // same kind of block for a demo program through the API.
    await p.locator('#rowmenu button', {hasText: 'on local port'}).click();
    await p.waitForTimeout(500);
    check('blocking System is refused, saying why', dialogs.some(d=>/part of Windows/.test(d)), JSON.stringify(dialogs));
    await p.evaluate(async () => { await blockCall({action:'block', kind:'program', name:'chrome.exe', lport:8080, proto:'tcp'}); });
    for (let i=0; i<50 && !(await state()).blocks.some(x=>x.lport); i++) await p.waitForTimeout(200);
    const lb = (await state()).blocks.find(x=>x.lport);
    check('the block is inbound to that one port', lb && lb.kind==='program' && lb.dir==='in', JSON.stringify(lb));
    await p.click('#p-conns [data-cmode="blocked"]');
    await p.waitForSelector('#p-conns [data-unblock]');
    check('the Blocked view says so', new RegExp('inbound to local port ' + (lb&&lb.lport)).test(await p.textContent('#p-conns')));
  }
  await p.evaluate(async () => { await blockCall({action:'block', kind:'host', address:'198.51.100.77', dir:'in'}); });
  const ib = (await state()).blocks.find(x=>x.target==='198.51.100.77');
  check('a host can be blocked inbound only', ib && ib.dir==='in', JSON.stringify(ib));
  await p.click('#p-conns [data-cmode="blocked"]');
  await p.waitForFunction(()=>/inbound only/.test(document.getElementById('p-conns').textContent), null, {timeout:10000}).catch(()=>{});
  check('...and the Blocked view says inbound only', /inbound only/.test(await p.textContent('#p-conns')));
  check('the alert note names the direction', await p.evaluate(async () =>
        (await (await api('/api/alerts')).json()).alerts.some(a => a.rule==='block' && /198\.51\.100\.77 inbound$/.test(a.title))));

  check('no page errors', errs.length===0, errs.join('; '));
  await b.close();
  console.log(); console.log('FAILED:', fails.length ? fails : 'none');
  process.exit(fails.length?1:0);
})();
