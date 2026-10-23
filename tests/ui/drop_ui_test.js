const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>60,null,{timeout:60000});

  // with nothing to report, say nothing
  check('no drop counter when stats are unavailable',
        await p.evaluate(()=>getComputedStyle(document.getElementById('kvDrop')).display==='none'));
  check('no drop warning in the status line',
        !/dropping/.test(await p.textContent('#statusText')));

  // a clean capture reports zero and still stays quiet
  const clean = await p.evaluate(()=>{
    renderStatus(Object.assign({}, lastStatus,
      {capture:{received:5000, dropped:0, buffer_dropped:0, iface_dropped:0, loss_pct:0}}));
    renderStats(lastStats);
    return {status: document.getElementById('statusText').textContent,
            shown: getComputedStyle(document.getElementById('kvDrop')).display!=='none'};
  });
  check('a clean capture shows no warning',
        !/dropping/.test(clean.status) && !clean.shown, JSON.stringify(clean));

  // losing packets: both places light up
  const bad = await p.evaluate(()=>{
    renderStatus(Object.assign({}, lastStatus, {capture:{received:102882,
      dropped:102672, buffer_dropped:102672, iface_dropped:0, loss_pct:49.95}}));
    renderStats(lastStats);
    const d = document.getElementById('sDrop');
    return {status: document.getElementById('statusText').textContent,
            shown: getComputedStyle(document.getElementById('kvDrop')).display!=='none',
            text: d.textContent, colour: getComputedStyle(d).color,
            plain: getComputedStyle(document.getElementById('sPk')).color};
  });
  check('the status line says it is dropping', /dropping 49\.95% of packets/.test(bad.status), bad.status);
  check('the footer shows the count', bad.shown && /102,672/.test(bad.text), JSON.stringify(bad));
  check('the footer shows the share', /49\.95%/.test(bad.text), bad.text);
  check('it is coloured differently from an ordinary stat',
        bad.colour !== bad.plain, bad.colour + ' vs ' + bad.plain);

  // Still losing them: the header gives the last minute's share, and the
  // tooltip breaks it down by adapter.
  const busy = await p.evaluate(()=>{
    renderStatus(Object.assign({}, lastStatus, {capture:{received:90000, dropped:10000,
      buffer_dropped:10000, iface_dropped:0, loss_pct:10,
      recent:{secs:60, received:7000, dropped:1000, loss_pct:12.5},
      adapters:[{name:'Ethernet', received:30000, dropped:0, buffer_dropped:0, iface_dropped:0, loss_pct:0},
                {name:'Wi-Fi', received:60000, dropped:10000, buffer_dropped:9990, iface_dropped:10, loss_pct:14.29}]}}));
    const n = document.getElementById('dropNote');
    return {text: n.textContent, cls: n.className, tip: n.title};
  });
  check('still losing packets: the header gives the last minute',
        busy.text === 'dropping 12.5% of packets' && busy.cls === 'dropnow', JSON.stringify(busy));
  check('...and the tooltip breaks it down by adapter, worst first',
        /Last minute: 1,000 lost of 8,000 \(12\.5%\)/.test(busy.tip) &&
        /Since capture started: 10,000 lost of 100,000 \(10%\)/.test(busy.tip) &&
        busy.tip.indexOf('Wi-Fi: 10,000 lost of 70,000 (14.29%)') > 0 &&
        busy.tip.indexOf('Wi-Fi') < busy.tip.indexOf('Ethernet: 0 lost') &&
        /9,990 buffer full, 10 by the adapter/.test(busy.tip), busy.tip);

  // Lost some earlier, nothing in the last minute: said, but not as an alarm.
  const past = await p.evaluate(()=>{
    renderStatus(Object.assign({}, lastStatus, {capture:{received:90000, dropped:10000,
      buffer_dropped:10000, iface_dropped:0, loss_pct:10,
      recent:{secs:60, received:7000, dropped:0, loss_pct:0}, adapters:[]}}));
    const n = document.getElementById('dropNote');
    return {text: n.textContent, cls: n.className};
  });
  check('only earlier losses read as earlier, not as now',
        past.text === 'dropped 10% earlier' && past.cls === 'droppast', JSON.stringify(past));

  // Several adapters: the header counts them; the names are in the tooltip.
  const multi = await p.evaluate(()=>{
    renderStatus(Object.assign({}, lastStatus, {demo:false, running:true, source:null, multi:true,
      ifaces:['Wi-Fi', 'Ethernet', 'PIA OpenVPN WinTUN Adapter'], capture:null}));
    const t = document.getElementById('statusText');
    return {text: t.textContent, tip: t.querySelector('b').title};
  });
  check('several adapters are counted, not listed',
        /^capturing on 3 interfaces/.test(multi.text) && !/Wi-Fi/.test(multi.text) &&
        multi.tip === 'Wi-Fi, Ethernet, PIA OpenVPN WinTUN Adapter', JSON.stringify(multi));

  // and it goes away again when the capture recovers
  const cleared = await p.evaluate(()=>{
    renderStatus(Object.assign({}, lastStatus, {capture:null}));
    renderStats(lastStats);
    return {shown: getComputedStyle(document.getElementById('kvDrop')).display!=='none',
            text: document.getElementById('sDrop').textContent};
  });
  check('it clears when there is nothing to report', !cleared.shown, JSON.stringify(cleared));
  check('and leaves no stale number behind', cleared.text === '', cleared.text);

  // the footer must not start shifting again
  const moved = await p.evaluate(()=>{
    const x1 = Math.round(document.getElementById('spark').getBoundingClientRect().x);
    renderStatus(Object.assign({}, lastStatus, {capture:{received:9, dropped:3,
      buffer_dropped:3, iface_dropped:0, loss_pct:25}}));
    renderStats(lastStats);
    const x2 = Math.round(document.getElementById('spark').getBoundingClientRect().x);
    return {x1, x2};
  });
  const x1 = moved.x1, x2 = moved.x2;
  check('the sparkline still does not move when the counter appears', x1===x2, `${x1} -> ${x2}`);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
