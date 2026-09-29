const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// The Timeline view: one lane per program or host, drawn from /api/timeline.
// The real endpoint is checked for shape first; then it is answered here with
// a fixed hour, so lane order and the "every ~Ns" mark are deterministic.
const NOW = Math.floor(Date.now()/1000);
const KEYS = [
  // program, host, remote, local, dir, proto, remote port, adapter
  ['chrome.exe',  'www.example.com', '93.184.216.34', '10.0.0.2', 'out', 'TLS', 443, 'eth0'],  // 0
  ['chrome.exe',  'www.example.com', '93.184.216.34', '10.0.0.2', 'in',  'TLS', 443, 'eth0'],  // 1
  ['beacon.exe',  'c2.example.net',  '203.0.113.9',   '10.0.0.2', 'out', 'TLS', 443, 'eth0'],  // 2
  ['beacon.exe',  'c2.example.net',  '203.0.113.9',   '10.0.0.2', 'in',  'TLS', 443, 'eth0'],  // 3
  ['random.exe',  '',                '198.51.100.7',  '10.0.0.2', 'out', 'UDP', 5000, 'eth0'], // 4
];
function payload(){
  const secs = new Map();
  const add = (t, k, b, p) => { if (!secs.has(t)) secs.set(t, []); secs.get(t).push([k, b, p]); };
  for (let t = NOW - 3599; t <= NOW; t++){
    add(t, 0, 4000, 4); add(t, 1, 90000, 60);           // steady and heavy
    if ((NOW - t) % 30 === 0){ add(t, 2, 1, 1); add(t, 3, 120, 1); }   // every 30 s, tiny
  }
  // Irregular: bursts at uneven gaps.
  let t = NOW - 3500;
  for (const g of [7, 41, 13, 90, 22, 5, 64, 31, 18, 77, 9, 50]){ t += g; add(t, 4, 300, 2); }
  return {gen: 7, full: true, kfrom: 0, keys: KEYS, now: NOW + 0.5, newest: NOW,
          offline: false, retain: 3600,
          buckets: [...secs.entries()].sort((a,b)=>a[0]-b[0])};
}

// A busy program that also checks in with one host every 45 s — the shape
// found on a real machine, where the Programs view tagged nothing because the
// program's other traffic filled the gaps. The host also sees irregular
// traffic from another program, so the host lane as a whole isn't regular
// either: only the program-and-host pair is.
const KEYS2 = [
  ['Claude.exe',   'api.example.com',       '192.0.2.10', '10.0.0.2', 'out', 'TLS', 443, 'eth0'], // 0
  ['Claude.exe',   'downloads.example.com', '192.0.2.20', '10.0.0.2', 'out', 'TLS', 443, 'eth0'], // 1
  ['(no socket)',  'downloads.example.com', '192.0.2.20', '10.0.0.2', 'in',  'TCP', 443, 'eth0'], // 2
  ['svchost.exe',  'downloads.example.com', '192.0.2.20', '10.0.0.2', 'out', 'TLS', 443, 'eth0'], // 3
];
function payload2(){
  const secs = new Map();
  const add = (t, k, b, p) => { if (!secs.has(t)) secs.set(t, []); secs.get(t).push([k, b, p]); };
  for (let t = NOW - 3599; t <= NOW; t++){
    add(t, 0, 20000, 20);                                  // never idle
    if ((NOW - t) % 45 === 0){ add(t, 1, 2000, 6); if (t + 2 <= NOW) add(t + 2, 2, 120, 2); }
  }
  // Uneven gaps of 20-200 s, from a fixed seed so every run is the same.
  let t = NOW - 3580, seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  while ((t += 20 + Math.floor(rnd() * 180)) < NOW) add(t, 3, 800, 4);
  return {gen: 8, full: true, kfrom: 0, keys: KEYS2, now: NOW + 0.5, newest: NOW,
          offline: false, retain: 3600,
          buckets: [...secs.entries()].sort((a,b)=>a[0]-b[0])};
}
let mode = 1;

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const ctx = await b.newContext({ viewport:{width:1680,height:900} });
  const p = await ctx.newPage();
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>5,null,{timeout:90000});

  // ---------------- the real endpoint ----------------
  const real = await p.evaluate(()=>api('/api/timeline').then(r=>r.json()));
  check('/api/timeline answers with keys and per-second buckets',
        real.full===true && real.keys.length>0 && real.buckets.length>0 &&
        real.keys[0].length===8 && Array.isArray(real.buckets[0][1][0]), JSON.stringify(real).slice(0,200));
  const again = await p.evaluate(g=>api('/api/timeline?gen='+g.gen+'&kfrom='+g.keys.length+'&since='+g.newest)
                                   .then(r=>r.json()), real);
  check('...and incrementally: only new seconds and new keys',
        again.full===false && again.kfrom===real.keys.length && again.buckets.every(x=>x[0]>=real.newest),
        JSON.stringify(again).slice(0,200));

  let fetches = 0;
  await p.route('**/api/timeline*', route => { fetches++;
    route.fulfill({status:200, contentType:'application/json', body: JSON.stringify(mode===1 ? payload() : payload2())}); });

  // ---------------- switching ----------------
  const twTopBefore = await p.evaluate(()=>{ const w=document.getElementById('tw'); return w.scrollHeight; });
  await p.click('#vTime');
  // Five minutes by default; the irregular program was only active long ago.
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length===2);
  const sw = await p.evaluate(()=>({
    tl: getComputedStyle(document.getElementById('tlview')).display!=='none',
    twH: document.getElementById('tw').offsetHeight,
    twW: document.getElementById('tw').clientWidth,
    cols: getComputedStyle(document.getElementById('colsBtn')).display,
    pressed: document.getElementById('vTime').getAttribute('aria-pressed'),
    hscroll: document.documentElement.scrollWidth > innerWidth}));
  check('Timeline replaces the table, which keeps its width at zero height',
        sw.tl && sw.twH===0 && sw.twW>500, JSON.stringify(sw));
  check('...hides the table-only Columns button, and says which view is on',
        sw.cols==='none' && sw.pressed==='true', JSON.stringify(sw));
  check('...with no sideways scroll', !sw.hscroll);

  // ---------------- lanes ----------------
  await p.click('#tlWin button[data-w="3600"]');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length===3);
  const lanes = await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>({
    name: b.dataset.name, rg: (b.querySelector('.rg')||{}).textContent||''})));
  check('one lane per program, busiest first',
        lanes.map(l=>l.name).join()==='chrome.exe,beacon.exe,random.exe', JSON.stringify(lanes));
  check('the program that checks in every 30 s is marked as such',
        lanes[1].rg==='every ~30s · c2.example.net', JSON.stringify(lanes));
  check('...a steady stream and an irregular one are not',
        lanes[0].rg==='' && lanes[2].rg==='', JSON.stringify(lanes));
  check('the note counts lanes and scheduled check-ins',
        await p.textContent('#tlNote')==='3 programs · 1 checks in on a schedule', await p.textContent('#tlNote'));

  // A 1-byte check-in still paints: find the beacon lane's marks on the canvas.
  const painted = await p.evaluate(()=>{
    const cv = document.getElementById('tlCanvas'), g = cv.getContext('2d');
    // Lane 2's midline is at 26 + 13; sent marks sit on the pixel row above.
    const dpr = cv.width / cv.clientWidth, y = Math.floor((26 + 13 - 1) * dpr);
    const row = g.getImageData(0, y, cv.width, 1).data;
    // Count the orange runs, not pixels: 120 check-ins should be ~120 marks.
    let runs = 0, prev = false;
    for (let i=0;i<row.length;i+=4){
      const on = row[i+3]>0 && row[i] > row[i+2] + 60;
      if (on && !prev) runs++; prev = on;
    }
    return runs;
  });
  check('a one-byte packet is still drawn (log scale, at least a pixel)', painted>=110 && painted<=121, painted+' marks');

  const align = await p.evaluate(()=>{
    const a = document.getElementById('tlAxis').getBoundingClientRect(),
          c = document.getElementById('tlCanvas').getBoundingClientRect();
    return {dl: Math.abs(a.left-c.left), dw: Math.abs(a.width-c.width)};
  });
  check('the time axis lines up with the lanes', align.dl<1 && align.dw<1, JSON.stringify(align));

  // Hover shows what a column holds.
  const cv = await p.locator('#tlCanvas').boundingBox();
  await p.mouse.move(cv.x + cv.width - 3, cv.y + 13);
  const tip = await p.evaluate(()=>({on: document.getElementById('tlTip').classList.contains('on'),
                                     t: document.getElementById('tlTip').textContent}));
  check('hovering a lane says whose it is and how much', tip.on && /^chrome\.exe/.test(tip.t) && /▲/.test(tip.t), JSON.stringify(tip));

  // ---------------- the display filter applies ----------------
  await p.fill('#find', 'process != "chrome.exe"');
  await p.waitForTimeout(100);
  check('the display filter removes lanes',
        (await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>b.dataset.name).join()))
        ==='beacon.exe,random.exe');
  await p.fill('#find', 'info ~ GET');
  await p.waitForTimeout(100);
  const unsup = await p.evaluate(()=>({note: document.getElementById('tlNote').textContent,
    warn: document.getElementById('tlNote').classList.contains('warn'),
    lanes: document.querySelectorAll('#tlLabels .ln').length,
    empty: document.getElementById('tlEmpty').style.display}));
  check("a filter on a per-packet field says it can't be applied, and draws nothing",
        unsup.warn && /uses Info/.test(unsup.note) && unsup.lanes===0 && unsup.empty==='block', JSON.stringify(unsup));
  await p.fill('#find', 'port == 5000');
  await p.waitForTimeout(100);
  check('...while a remote port filter works',
        (await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>b.dataset.name).join()))==='random.exe');
  await p.fill('#find', '');

  // ---------------- lanes act on the filter ----------------
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length===3);
  await p.click('#tlLabels .ln[data-name="beacon.exe"] .nm');
  check('clicking a lane filters to it', await p.inputValue('#find')==='process == "beacon.exe"', await p.inputValue('#find'));
  await p.fill('#find', '');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length===3);
  await p.click('#tlLabels .ln[data-name="beacon.exe"]', {button:'right'});
  const items = await p.evaluate(()=>[...document.querySelectorAll('#rowmenu button')].map(x=>x.textContent));
  check('right-clicking a lane offers to hide it or keep it out of History',
        items.join('|')==="Hide program beacon.exe|Don't record beacon.exe in History", JSON.stringify(items));
  await p.locator('#rowmenu button', {hasText:'Hide program'}).click();
  check('...and hiding writes the filter', await p.inputValue('#find')==='process != "beacon.exe"');
  await p.fill('#find', '');

  // ---------------- hosts ----------------
  await p.click('#tlGroup button[data-g="host"]');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length===3);
  const hosts = await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>b.dataset.name));
  check('grouped by host: named hosts, and the address where there is no name',
        hosts.join()==='www.example.com,c2.example.net,198.51.100.7', JSON.stringify(hosts));
  await p.click('#tlLabels .ln[data-name="198.51.100.7"] .nm');
  check('...and an address lane filters by ip', await p.inputValue('#find')==='ip == "198.51.100.7"', await p.inputValue('#find'));
  await p.fill('#find', '');

  // ---------------- a check-in hidden inside a busy program ----------------
  mode = 2;
  await p.click('#tlGroup button[data-g="process"]');
  await p.waitForFunction(()=>TL.gen===8 && document.querySelectorAll('#tlLabels .ln').length===3, null, {timeout:5000});
  const progs = await p.evaluate(()=>[...document.querySelectorAll('#tlLabels .ln')].map(b=>({
    name: b.dataset.name, title: b.title, rg: b.querySelector('.rg') ? b.querySelector('.rg').textContent : '',
    rgTitle: b.querySelector('.rg') ? b.querySelector('.rg').title : '',
    nmCut: (()=>{ const n=b.querySelector('.nm'); return n.scrollWidth > n.clientWidth; })(),
    fits: (()=>{ const r=b.getBoundingClientRect(), t=b.querySelector('.tot').getBoundingClientRect();
                 return t.right <= r.right + 0.5; })()})));
  const claude = progs.find(x=>x.name==='Claude.exe') || {};
  check('a busy program is marked for the host it checks in with',
        claude.rg==='every ~45s · downloads.example.com', JSON.stringify(progs));
  check('...the box says so in full',
        /Checks in with downloads\.example\.com every ~45s/.test(claude.rgTitle), claude.rgTitle);
  check("...the program's name isn't squeezed by it, and the size still fits",
        !claude.nmCut && progs.every(x=>x.fits), JSON.stringify(progs));
  check('the lane says where its traffic goes',
        /^Hosts: api\.example\.com \d+%, downloads\.example\.com/m.test(claude.title), claude.title);
  const svc = progs.find(x=>x.name==='svchost.exe') || {};
  check('an irregular program is not marked', svc.rg==='', JSON.stringify(svc));

  await p.click('#tlLabels .ln[data-name="Claude.exe"] .rg');
  check('clicking the box filters to that program and host',
        await p.inputValue('#find')==='process == "Claude.exe" && host == "downloads.example.com"',
        await p.inputValue('#find'));
  await p.fill('#find', '');

  await p.click('#tlGroup button[data-g="host"]');
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length===2);
  const dl = await p.evaluate(()=>{ const b = document.querySelector('#tlLabels .ln[data-name="downloads.example.com"]');
    return {title: b.title, rg: b.querySelector('.rg') ? b.querySelector('.rg').textContent : ''}; });
  check('a host lane names the programs behind it',
        /Programs: Claude\.exe \d+%, svchost\.exe \d+%, \(no socket\)/.test(dl.title), dl.title);
  const own = await p.evaluate(()=>TL.lanes.find(l=>l.name==='downloads.example.com').own);
  check('...and which of them checks in, even though the host as a whole is irregular',
        own===0 && dl.rg==='every ~45s · Claude.exe', own+' '+JSON.stringify(dl));
  const i = await p.evaluate(()=>TL.lanes.findIndex(l=>l.name==='downloads.example.com'));
  const box = await p.locator('#tlCanvas').boundingBox();
  await p.mouse.move(box.x + box.width - 2, box.y + i*26 + 13);
  const tip2 = await p.textContent('#tlTip');
  check('hovering the host lane lists its programs too', /Programs: Claude\.exe/.test(tip2) &&
        /Contacted on a schedule by Claude\.exe \(every ~45s\)/.test(tip2), tip2);
  await p.mouse.move(5, 5);
  mode = 1;
  await p.waitForFunction(()=>TL.gen===7 && document.querySelectorAll('#tlLabels .ln').length===3, null, {timeout:5000});

  // ---------------- pause ----------------
  await p.evaluate(()=>document.activeElement.blur());
  await p.keyboard.press(' ');
  const n0 = fetches;
  await p.waitForTimeout(2200);
  check('paused, the timeline stops fetching', fetches===n0, (fetches-n0)+' fetches');
  check('...and the pause message names it', /timeline is not updating/.test(await p.textContent('#fcount')));
  await p.keyboard.press(' ');
  await p.waitForTimeout(1600);
  check('resumed, it fetches again', fetches>n0);

  // ---------------- settings survive a reload ----------------
  await p.reload();
  await p.waitForFunction(()=>document.querySelectorAll('#tlLabels .ln').length===3, null, {timeout:30000});
  const kept = await p.evaluate(()=>({view: document.body.classList.contains('tlmode'),
    win: document.querySelector('#tlWin .on').dataset.w, g: document.querySelector('#tlGroup .on').dataset.g}));
  check('the view, window and grouping are remembered', kept.view && kept.win==='3600' && kept.g==='host', JSON.stringify(kept));

  // ---------------- back to the table ----------------
  await p.click('#vTable');
  await p.waitForTimeout(900);
  const back = await p.evaluate(()=>{ const w = document.getElementById('tw');
    return {h: w.offsetHeight, rows: document.querySelectorAll('#rows tr').length,
            atEnd: w.scrollHeight - w.clientHeight - w.scrollTop < 30,
            tl: getComputedStyle(document.getElementById('tlview')).display}; });
  check('Table brings the rows back, following the newest', back.h>300 && back.rows>0 && back.atEnd && back.tl==='none', JSON.stringify(back));

  // Light theme draws with the light series colours, no errors.
  await p.click('#vTime');
  await p.click('#theme');
  await p.waitForTimeout(200);

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
