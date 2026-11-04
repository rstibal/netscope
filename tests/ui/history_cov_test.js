const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// History since 1.40: one range for every figure, the extras folded under
// More, a filter per adapter. Since 1.42 nothing says how long NetScope ran:
// no Captured figure, no strip under the days.
const G = Math.pow(1024,3);
let asked = [];
function history(iface){
  const daily = [];
  for (let i = 0; i < 7; i++){
    daily.push({day:'2026-10-' + String(25 + i).padStart(2,'0'), bytes_in:G, bytes_out:G/4, packets:10});
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
        live && (!live.enabled || (live.range && Array.isArray(live.ifaces) && live.daily[0].expected === undefined)),
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
    strips: document.querySelectorAll('#cw-daily .cvtrack, #cw-daily .cvfill').length,
    adapters: !!$('histAdapters'),
    text: $('p-history').textContent,
    reset: !!$('histReset'),
    moreOpen: $('histMore') && $('histMore').open,
  }));
  check('totals are the range\'s, not all time', t.kpi[0].includes('4.0 GB'), t.kpi[0]);
  check('...and so is the program count', /Programs3/.test(t.kpi[3]) && /7 hosts/.test(t.kpi[3]), t.kpi[3]);
  check('four figures: no Captured', t.kpi.length === 4 && !t.kpi.some(k => /Captured/.test(k)), t.kpi.join(' | '));
  check('By host follows the range', t.heads.includes('By host · last 7 days'), t.heads.join(' | '));
  check('nothing on the tab says all time', !t.heads.some(h => /all time/.test(h)));
  check('no strip under the days, no adapter line', t.strips === 0 && !t.adapters, t.strips);
  check('nothing on the tab mentions capture time', !/Captured|of 1d/.test(t.text));
  check('the reset is explained', t.reset);
  check('More is folded at first', t.moreOpen === false);
  check('busy hours, alerts and sessions are inside it',
        await p.evaluate(() => ['cw-week', 'alertsJump'].every(id => $('histMore').contains($(id)))));
  check('...and so is everything from Not recorded down',
        await p.evaluate(() => ['histEx', 'histFlush', 'histWipe'].every(id => $('histMore').contains($(id))) &&
          [...$('histMore').querySelectorAll('h4')].some(h => h.textContent === 'Start with Windows') &&
          $('histMore').closest('.sec') === $('p-history').lastElementChild));
  check('nothing beside the range buttons but the date and the adapter',
        await p.evaluate(() => !$('exJump') && /^7d30d90dsince /.test(document.querySelector('#p-history .dayrange').textContent)));

  // A day's tooltip: what moved, nothing about how long NetScope ran.
  const box = await p.$eval('#cw-daily .hitrect[data-i="4"]', r => { const b = r.getBoundingClientRect(); return [b.x + b.width/2, b.y + b.height/2]; });
  await p.mouse.move(box[0], box[1]);
  const tip = await p.$eval('#tip-daily', x => x.textContent);
  check('the day\'s tooltip has the traffic', /received/.test(tip) && /packets10/.test(tip), tip);
  check('...and no captured line', !/captured/i.test(tip), tip);
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
