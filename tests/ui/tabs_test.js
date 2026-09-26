const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};
// The side panel is 600px from 1750 up, 430 in the middle, 360 at 1400 and below.
const WIDTHS = [[1750, 1], [1600, 2], [1300, 2]];
// Segoe UI Variable is Windows 11's; Windows 10 falls back to plain Segoe UI.
const FONTS = [null, '"Segoe UI",sans-serif'];
// The margin either way: on one line, room left with the widest badges up;
// on two, how far the bare strip overshoots one line. 6px padding left 10px
// at 1750 and 5px left 0 at 1600 — either one font's metrics from a wrap.
const MIN_SLACK = 16;
(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const errs=[];

  for (const [w, want] of WIDTHS) {
    const p = await b.newPage({ viewport:{width:w, height:900} });
    p.on('pageerror',e=>errs.push(String(e)));
    await p.goto(process.argv[2]);
    await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>20,null,{timeout:90000});

    // Measured in one synchronous pass, so the 700 ms poll can't redraw the
    // badges in between: no badges at all, then the widest each can get.
    for (const font of FONTS) {
    const r = await p.evaluate(font=>{
      if (font) document.documentElement.style.setProperty('--sans', font);
      const lines = () => new Set([...document.querySelectorAll('.tabs .tab')].map(t=>t.offsetTop)).size;
      const ids = ['nPkt','nAlerts','nFiles','nDhcp'];
      ids.forEach(id => tabCount(document.getElementById(id), 0));
      const bare = lines();
      const all = [...document.querySelectorAll('.tabs .tab')];
      const oneLine = all.reduce((a,x)=>a+x.getBoundingClientRect().width,0) +
                      (parseFloat(getComputedStyle(all[0].parentNode).columnGap)||0)*(all.length-1);
      tabCount(document.getElementById('nAlerts'), 12345);
      tabCount(document.getElementById('nFiles'), 999);
      tabCount(document.getElementById('nDhcp'), 250);
      const pk = document.getElementById('nPkt');
      pk.classList.remove('zero');
      let worst = bare, widest = '';
      for (const seq of [9999, 99999, 999999, 9999999, 99999999, 1234567890]) {
        pk.textContent = frameBadge(seq);
        const n = lines();
        if (n > worst || pk.textContent.length > widest.length) widest = pk.textContent;
        worst = Math.max(worst, n);
      }
      // What is left on the fullest line, with the widest badges still up.
      const t = document.querySelector('.tabs'), cs = getComputedStyle(t);
      const avail = t.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
      const byLine = {};
      for (const x of t.querySelectorAll('.tab')){
        const r = x.getBoundingClientRect();
        byLine[x.offsetTop] = (byLine[x.offsetTop] || 0) + r.width;
      }
      const gap = parseFloat(cs.columnGap) || 0;
      const used = Math.max(...Object.entries(byLine).map(([top, wd]) =>
        wd + gap * ([...t.querySelectorAll('.tab')].filter(x=>String(x.offsetTop)===top).length - 1)));
      document.documentElement.style.removeProperty('--sans');
      return {bare, worst, widest, slack: Math.floor(avail - used), over: Math.floor(oneLine - avail)};
    }, font);
    const f = font ? ' in '+font.split(',')[0] : '';
    check(w+'px'+f+': the tab strip takes '+want+' line(s) with no badges', r.bare===want, String(r.bare));
    check(w+'px'+f+': ...and the same with the widest badges', r.worst===r.bare,
          r.worst+' lines, widest frame badge '+r.widest);
    if (want === 1)
      check(w+'px'+f+': ...with at least '+MIN_SLACK+'px to spare', r.slack>=MIN_SLACK, r.slack+'px');
    else
      check(w+'px'+f+': ...and the bare strip overshoots one line by '+MIN_SLACK+'px+', r.over>=MIN_SLACK, r.over+'px');
    }

    // The real path: clicking a packet must not wrap the strip.
    await p.waitForTimeout(900);          // let the poll restore the real badges
    const before = await p.evaluate(()=>new Set([...document.querySelectorAll('.tabs .tab')].map(t=>t.offsetTop)).size);
    await p.click('#rows tr:nth-child(3)');
    await p.waitForTimeout(300);
    const after = await p.evaluate(()=>new Set([...document.querySelectorAll('.tabs .tab')].map(t=>t.offsetTop)).size);
    check(w+'px: clicking a packet leaves the strip at '+before+' line(s)', after===before, before+' -> '+after);
    await p.close();
  }

  // The badge formats themselves.
  const p = await b.newPage();
  await p.goto(process.argv[2]);
  const f = await p.evaluate(()=>{
    const el = document.createElement('span');
    tabCount(el, 250);
    const capped = [el.textContent, el.title];
    tabCount(el, 7);
    return {frames: [1, 9999, 10000, 123456, 1234567, 99999999, 1234567890].map(frameBadge),
            capped, small: [el.textContent, el.title]};
  });
  check('frame badges are exact to 9999, then abbreviated',
        JSON.stringify(f.frames)==='["#1","#9999","#10k","#123k","#1.2M","#99.9M","#1234M"]', JSON.stringify(f.frames));
  check('counts past 99 read 99+ with the exact count as a tooltip',
        f.capped[0]==='99+' && f.capped[1]==='250', JSON.stringify(f.capped));
  check('...and smaller counts are shown as they are', f.small[0]==='7' && f.small[1]==='', JSON.stringify(f.small));

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
