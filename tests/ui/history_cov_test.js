const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// History since 1.40: one range for every figure, a coverage strip under the
// daily chart, the extras folded under More. The data is answered here so the
// strip has every case: before coverage, a full day, a part day.
const G = Math.pow(1024,3);
let asked = [];
function history(iface){
  const daily = [];
  for (let i = 0; i < 7; i++){
    const r = {day:'2026-10-' + String(25 + i).padStart(2,'0'), bytes_in:G, bytes_out:G/4, packets:10,
               expected: i < 2 ? 0 : 86400, ran: i < 2 ? 0 : 86400};
    if (i === 4) r.ran = 43200;
    daily.push(r);
  }
  return {enabled:true, days:7, iface: iface || '', ifaces:['VR', 'Ethernet', 'Wi-Fi'], daily, hosts:[{host:'a.example', bytes_in:G, bytes_out:1, packets:1, first_seen:1.8e9}],
          new_hosts:[], sessions:[{started:1.8e9, iface:'Ethernet', version:'1.40.0', packets:9}],
          processes:[{name:'chrome.exe', bytes_in:G, bytes_out:1, packets:1}],
          range:{bytes_in:3*G, bytes_out:G, packets:40, programs:3, hosts:7},
          alert_counts:{total:2, high:0, warn:2, info:0, newest:2},
          exclude:{programs:[],hosts:[]}, week_hours:{cells:Array.from({length:7},()=>Array.from({length:24},()=>[1,1])), counts:[1,1,1,1,1,1,1]},
          summary:{bytes_in:99*G, bytes_out:G, packets:1, processes:50, hosts:500, size:1024, retain_days:90,
                   alert_retain_days:30, since:'2026-10-27', path:'C:\\history.db',
                   reset_backup:'C:\\history.db.before-1.40'}};
}

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1680,height:900} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  const live = await (await fetch(process.argv[2].replace(/\/\?/, '/api/history?days=7&'))).json().catch(()=>null);
  check('the server answers with the range and the adapter list',
        live && (!live.enabled || (live.range && Array.isArray(live.ifaces) && live.daily[0].expected !== undefined)),
        JSON.stringify(live && Object.keys(live)));

  await p.route('**/api/history?*', r => {
    const ifc = new URL(r.request().url()).searchParams.get('iface');
    asked.push(ifc);
    r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history(ifc))});
  });
  await p.goto(process.argv[2]);
  await p.waitForSelector('#cw-daily svg', {timeout: 30000});

  const t = await p.evaluate(() => ({
    kpi: [...document.querySelectorAll('#p-history .kpi')].map(k => k.textContent),
    heads: [...document.querySelectorAll('#p-history h4')].map(h => h.textContent),
    tracks: document.querySelectorAll('#cw-daily .cvtrack').length,
    fills: [...document.querySelectorAll('#cw-daily .cvfill')].map(r => +r.getAttribute('width')),
    adapters: !!$('histAdapters'),
    hatch: !!document.querySelector('#cvhatch'),
    reset: !!$('histReset'),
    moreOpen: $('histMore') && $('histMore').open,
  }));
  check('totals are the range\'s, not all time', t.kpi[0].includes('4.0 GB'), t.kpi[0]);
  check('...and so is the program count', /Programs3/.test(t.kpi[3]) && /7 hosts/.test(t.kpi[3]), t.kpi[3]);
  check('a Captured figure covers the days with a record', /Captured90%of 5d/.test(t.kpi[4]), t.kpi[4]);
  check('By host follows the range', t.heads.includes('By host · last 7 days'), t.heads.join(' | '));
  check('nothing on the tab says all time', !t.heads.some(h => /all time/.test(h)));
  check('no strip before coverage began, one for each day after', t.tracks === 5, t.tracks);
  check('a part day has a shorter strip', t.fills[2] < t.fills[0] * 0.6, JSON.stringify(t.fills));
  check('no adapter is ever marked missed: no hatching, no adapter line', !t.hatch && !t.adapters);
  check('the strip is explained on the Captured figure, not in the page',
        await p.evaluate(() => /strip under each day/.test($('kpiCov').title) &&
          ![...document.querySelectorAll('#p-history .hint')].some(h => /strip under each day/.test(h.textContent))));
  check('the reset is explained', t.reset);
  check('More is folded at first', t.moreOpen === false);
  check('busy hours, alerts and sessions are inside it',
        await p.evaluate(() => ['cw-week', 'alertsJump'].every(id => $('histMore').contains($(id)))));

  // Hover the part day: the tooltip says how long NetScope was capturing.
  const box = await p.$eval('#cw-daily .hitrect[data-i="4"]', r => { const b = r.getBoundingClientRect(); return [b.x + b.width/2, b.y + b.height/2]; });
  await p.mouse.move(box[0], box[1]);
  const tip = await p.$eval('#tip-daily', x => x.textContent);
  check('the day\'s tooltip says how much was captured', /captured12h of 1d/.test(tip), tip);
  check('...and nothing about adapters', !/not captured/.test(tip), tip);
  const box0 = await p.$eval('#cw-daily .hitrect[data-i="0"]', r => { const b = r.getBoundingClientRect(); return [b.x + b.width/2, b.y + b.height/2]; });
  await p.mouse.move(box0[0], box0[1]);
  check('a day before coverage says so', /not recorded \(before 1\.40\)/.test(await p.$eval('#tip-daily', x => x.textContent)));
  await p.mouse.move(5, 5);

  // Opened, More stays open across the tab's own refresh.
  await p.click('#histMore > summary');
  await p.evaluate(() => { histSeen = ''; return loadHistory(true); });
  await p.waitForTimeout(300);
  check('More stays open across a refresh', await p.evaluate(() => $('histMore').open));
  check('the VPN erase button is gone', !(await p.$('#histVpn')));

  // History's own adapter filter: every adapter by default, one when picked.
  const hopts = await p.$$eval('#histIface option', o => o.map(x => x.value));
  check('History lists every adapter it has, after All adapters',
        hopts.join() === ',VR,Ethernet,Wi-Fi', hopts.join());
  check('...and asks for all of them by default', asked.every(a => a === ''), asked.join());
  await p.selectOption('#histIface', 'VR');
  await p.waitForFunction(() => document.querySelector('#p-history h4') &&
    /· VR/.test(document.querySelector('#p-history h4').textContent));
  check('picking one asks for that adapter', asked[asked.length - 1] === 'VR', asked.join());
  check('...says so in each heading', await p.evaluate(() =>
    ['Daily traffic', 'By program', 'By host'].every(n =>
      [...document.querySelectorAll('#p-history h4')].some(h => h.textContent.startsWith(n) && /· VR/.test(h.textContent)))));
  check('...keeps the choice across a refresh, outlined', await p.evaluate(async () => {
    histSeen = ''; await loadHistory(true);
    return $('histIface').value === 'VR' && $('histIface').classList.contains('on'); }));
  check('...and is separate from the live filter', await p.$eval('#iface', s => s.value) === '');
  await p.selectOption('#histIface', '');
  await p.waitForFunction(() => $('histIface').value === '' && !$('histIface').classList.contains('on'));
  check('All adapters goes back to the totals', asked[asked.length - 1] === '');

  check('no page errors', errs.length===0, errs.join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
