const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:980} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>200,null,{timeout:90000});
  await p.click('.tab[data-p="conns"]'); await p.waitForTimeout(1800);

  const modes = await p.evaluate(()=>[...document.querySelectorAll('#p-conns [data-cmode]')].map(x=>x.dataset.cmode));
  check('four views', modes.length===4, JSON.stringify(modes));
  check('demo says why real sockets are absent', /Demo traffic/.test(await p.textContent('#p-conns')));

  // --- the whole point: nothing that identifies a row gets truncated
  const ident = await p.evaluate(()=>{
    const bad=[], pane=document.getElementById('p-conns');
    for (const it of document.querySelectorAll('#p-conns .citem')){
      for (const sel of ['.who','.peer']){
        const el=it.querySelector(sel); if(!el) continue;
        if (el.scrollWidth > el.clientWidth + 1)
          bad.push({sel, text:el.textContent, need:el.scrollWidth, got:el.clientWidth});
      }
    }
    return {bad, overflow: pane.scrollWidth - pane.clientWidth,
            n: document.querySelectorAll('#p-conns .citem').length};
  });
  check('process names are never clipped', !ident.bad.some(x=>x.sel==='.who'),
        JSON.stringify(ident.bad.filter(x=>x.sel==='.who').slice(0,2)));
  check('remote hosts are never clipped', !ident.bad.some(x=>x.sel==='.peer'),
        JSON.stringify(ident.bad.filter(x=>x.sel==='.peer').slice(0,2)));
  check('the panel does not scroll sideways', ident.overflow<=1, ident.overflow);
  check('rows rendered', ident.n>0, ident.n);

  // --- the columns the old table had to drop are back
  const l2 = await p.evaluate(()=>document.querySelector('#p-conns .citem .l2').textContent);
  check('protocol is back on the row', /tcp|udp/.test(l2), l2);
  check('state is back on the row', /ESTAB|TIME_W|LISTEN|CLOSE|SYN/.test(l2), l2);
  check('both byte directions are shown', /▼/.test(l2) && /▲/.test(l2), l2);

  // --- a single adapter should not be announced on every row
  check('no "via" when there is only one adapter', !/via/.test(l2), l2);

  // --- the activity mark, Open view only
  const marks = await p.evaluate(()=>({
    open: document.querySelectorAll('#p-conns .citem svg.spk').length,
    rows: document.querySelectorAll('#p-conns .citem').length}));
  check('every open row carries an activity mark', marks.open===marks.rows,
        `${marks.open}/${marks.rows}`);
  await p.click('#p-conns [data-cmode="recent"]'); await p.waitForTimeout(700);
  check('closed rows carry no mark (their shape is finished)',
        await p.evaluate(()=>document.querySelectorAll('#p-conns .citem svg.spk').length===0));

  // --- quality view reads as a sentence with real numbers
  await p.click('#p-conns [data-cmode="quality"]'); await p.waitForTimeout(700);
  const q = await p.evaluate(()=>{
    const it=document.querySelector('#p-conns .citem');
    return it ? it.querySelector('.l2').textContent : '';
  });
  check('quality shows handshake timing', /handshake \d+(ms|\.\d+s)/.test(q), q);
  check('quality highlights loss counts',
        await p.evaluate(()=>!!document.querySelector('#p-conns .l2 b.warn')) || !/resent/.test(q), q);

  // --- clicking still filters the packet list
  await p.click('#p-conns [data-cmode="active"]'); await p.waitForTimeout(700);
  await p.click('#p-conns .citem');
  await p.waitForTimeout(700);
  const f = await p.inputValue('#find');
  check('click builds a conversation filter', /^ip == \S+ && port == \d+$/.test(f), f);
  const narrowed = await p.evaluate(()=>{
    const all=[...document.querySelectorAll('#rows tr')];
    return {shown: all.filter(t=>t.style.display!=='none').length, total: all.length};
  });
  check('the packet list actually narrows', narrowed.shown < narrowed.total,
        `${narrowed.shown}/${narrowed.total}`);

  // --- multi-adapter: "via" appears, still nothing clipped
  const multi = await p.evaluate(()=>{
    const mk=(iface,proc,host)=>({proto:'tcp',state:'ESTABLISHED',pid:1,process:proc,
      laddr:'10.4.0.6',lport:51000,raddr:'142.250.80.46',rport:443,iface,rhost:host,
      in:1234,out:5678,packets:9,age:12,idle:1,closed:false,spark:[1,5,2,9,3],
      rtt:null,tls_ms:null,resent:0,dup_ack:0});
    renderConns({connections:[
      mk('PIA OpenVPN WinTUN Adapter','chrome.exe','www.google.com'),
      mk('Wi-Fi','pia-openvpn.exe','181.214.1.9')],
      listening:[],closed:[],offline:false,demo:false,detached:false,supported:true,error:''});
    const its=[...document.querySelectorAll('#p-conns .citem')];
    const clipped=its.some(it=>['.who','.peer'].some(s=>{
      const e=it.querySelector(s); return e && e.scrollWidth>e.clientWidth+1;}));
    return {via: its.map(it=>/via/.test(it.querySelector('.l2').textContent)),
            clipped, pane: document.getElementById('p-conns').scrollWidth -
                           document.getElementById('p-conns').clientWidth};
  });
  check('"via" appears with two adapters', multi.via.every(Boolean), JSON.stringify(multi.via));
  check('...and identity still is not clipped', !multi.clipped);
  check('...and the panel still does not scroll', multi.pane<=1, multi.pane);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
