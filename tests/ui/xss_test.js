const { chromium } = require('playwright');
const fails=[]; const check=(n,c,e='')=>{console.log((c?'PASS  ':'FAIL  ')+n+((!c&&e)?'  -- '+e:''));if(!c)fails.push(n);};

// Everything the dashboard shows about other machines — hostnames, HTTP start
// lines, SMB paths, FTP filenames, certificate subjects — is chosen by whoever
// is on the other end of the wire. This feeds the real demo API's answers back
// to the page with a payload on the end of every string, then opens every tab
// and detail view. Nothing may run and nothing may be injected into the page.
// The payload also closes a quote and a tag, to break out of attributes.
const PAYLOAD = `"'><img src=x onerror=window.__xss=1>`;
const B64_KEYS = new Set(['raw_b64', 'b64']);
// Fields the server fills from a fixed set (direction, protocol name, severity,
// rule id, TLS record type...) never carry anything from the wire, so they are
// left alone. Everything else could.
const FIXED = new Set(['dir','proto','transport','severity','rule','l2','hint','direction','state',
                       'record','handshake','opcode','msg_type','op','command','dialect','time','day']);

function taint(v, key){
  if (typeof v === 'string'){
    if (B64_KEYS.has(key)){                       // keep it valid base64, still carrying the payload
      return Buffer.concat([Buffer.from(v, 'base64'), Buffer.from(PAYLOAD)]).toString('base64');
    }
    return v && !FIXED.has(key) ? v + PAYLOAD : v;
  }
  if (Array.isArray(v)) return v.map(x => taint(x, key));
  if (v && typeof v === 'object'){
    const o = {}; for (const k of Object.keys(v)) o[k] = taint(v[k], k); return o;
  }
  return v;
}

const G = Math.pow(1024,3);
const tainted = s => s + PAYLOAD;
function history(){
  const daily = [];
  for (let i=0;i<30;i++) daily.push({day:'2026-09-'+String(i+1).padStart(2,'0'), bytes_in:G, bytes_out:G/4, packets:10});
  const row = (n, g) => ({name: tainted(n), host: tainted(n), bytes_in: g*G, bytes_out: g*G/4, packets: 9,
                          first_seen: 1700000000, last_seen: 1700000500});
  return {enabled:true, days:30, daily, hourly:[],
          hosts:[row('a.example',5), row('b.example',1)], new_hosts:[row('c.example',1)],
          processes:[row('evil.exe',50), row('x.exe',5), row('y.exe',1)],
          sessions:[{id:1, started:1700000000, ended:1700000900, iface:tainted('eth0'), packets:5, version:tainted('1.0')}],
          alert_counts:{total:1, high:1, warn:0, info:0, newest:1},
          exclude:{programs:[tainted('p')],hosts:[tainted('h')]},
          week_hours:{cells:Array.from({length:7},()=>Array.from({length:24},()=>[1,1])), counts:[4,4,4,4,4,4,4]},
          summary:{bytes_in:1, bytes_out:1, packets:1, processes:1, hosts:1, size:1024, retain_days:90,
                   since:'2026-09-01', path:tainted('C:\history.db'), error:tainted('boom')}};
}
const alertLog = {enabled:true, more:false, retain_days:30, counts:{total:1,high:1,warn:0,info:0,newest:1},
  alerts:[{id:1, ts:1700000000, severity:'high', rule:'cleartext_creds', title:tainted('Password sent'),
           detail:tainted('detail'), process:tainted('evil.exe'), peer:tainted('1.2.3.4'), subject:tainted('1.2.3.4')}]};

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport:{width:1750,height:950} });
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  p.on('dialog', d => d.dismiss());
  await p.route('**/api/history*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(history())}));
  await p.route('**/api/alert_log*', r => r.fulfill({status:200, contentType:'application/json', body: JSON.stringify(alertLog)}));
  // A web server picks the Content-Type of what it sends, and a type that starts
  // with image/ is shown as an <img>. The demo may hold no image to try this on.
  await p.route('**/api/object_preview*', r => r.fulfill({status:200, contentType:'application/json',
    body: JSON.stringify({name: 'pic.png' + PAYLOAD, ctype: 'image/png' + PAYLOAD, size: 70, textual: false,
      clipped: false, b64: Buffer.from('GIF89a').toString('base64')})}));
  await p.route(u => /\/api\/(state|packet|buffer|connections|alerts|streams|stream|objects|dhcp|interfaces|timeline)\b/.test(u.pathname), async r => {
    try {
      const resp = await r.fetch();
      const ct = resp.headers()['content-type'] || '';
      if (!ct.includes('json')) return r.fulfill({response: resp});
      const data = await resp.json();
      r.fulfill({status: resp.status(), contentType: 'application/json', body: JSON.stringify(taint(data))});
    } catch (e) { r.continue(); }
  });
  await p.goto(process.argv[2]);
  await p.waitForFunction(()=>document.querySelectorAll('#rows tr').length>20, null, {timeout:90000});

  const verdict = async (where) => {
    await p.waitForTimeout(1600);                  // a couple of polls
    const r = await p.evaluate(()=>({xss: window.__xss === 1,
      imgs: document.querySelectorAll('img[src="x"]').length,
      handlers: [...document.querySelectorAll('*')].filter(e=>e.hasAttribute('onerror')).length,
      payloadText: document.body.innerText.includes('onerror=window.__xss'),
      // Where it landed, so a failure points at the code that built it.
      where: [...new Set([...document.querySelectorAll('img[src="x"]')].map(i => {
        const p = i.parentElement, c = i.closest('[id]');
        return p.tagName.toLowerCase() + (p.className ? '.' + String(p.className).split(' ')[0] : '') +
               ' in #' + (c ? c.id : '?') + (i.closest('td') ? ' td' + [...i.closest('tr').children].indexOf(i.closest('td')) : '');
      }))].slice(0, 6) }));
    check(where + ': nothing ran', !r.xss, JSON.stringify(r));
    check(where + ': nothing injected', r.imgs === 0 && r.handlers === 0, JSON.stringify(r));
    return r;
  };

  const seen = await verdict('the packet list');
  check('the payload is shown as text, so the test is really exercising the page', seen.payloadText);

  // Open a row of each kind we can find: that fills the detail panel.
  for (const proto of ['HTTP', 'DNS', 'TLS', 'SMB2', 'FTP', 'DHCP', 'QUIC', 'NBNS', 'MDNS']) {
    const row = await p.$(`#rows tr:has-text("${proto}")`);
    if (row) { await row.click().catch(()=>{}); await verdict('packet detail (' + proto + ')'); }
  }

  const clicked = [];
  for (const tab of ['history', 'alerts', 'files', 'conns', 'streams', 'dhcp', 'talkers']) {
    await p.click(`.tabs .tab[data-p="${tab}"]`);
    await verdict('the ' + tab + ' tab');
    // Open whatever is clickable in it, so detail views render too.
    for (const sel of [`#p-${tab} .alert`, `#p-${tab} .item`, `#p-${tab} .citem`, `#p-${tab} summary`,
                       `#p-${tab} button:has-text("Preview")`, `#p-${tab} button:has-text("Stream")`]) {
      const el = await p.$(sel);
      if (!el) continue;
      clicked.push(sel);
      await el.click().catch(()=>{});
      await verdict(`${tab}: ${sel}`);
      await p.evaluate(()=>{ const o = document.getElementById('overlay'); if (o) o.classList.remove('on'); });
    }
  }

  // The log view in Alerts, and a display filter built from tainted values.
  await p.click('.tabs .tab[data-p="alerts"]');
  const logBtn = await p.$('#p-alerts [data-view="log"], #p-alerts button:has-text("log")');
  if (logBtn) { await logBtn.click().catch(()=>{}); await verdict('the alert log'); }
  const timeline = await p.$('button:has-text("Timeline"), [data-view="timeline"]');
  if (timeline) { await timeline.click().catch(()=>{}); await verdict('the Timeline'); }

  // The test is only worth something if it actually opened the detail views.
  for (const need of ['#p-files button:has-text("Preview")', '#p-files button:has-text("Stream")',
                      '#p-streams .item', '#p-alerts .alert', '#p-conns .citem'])
    check('opened ' + need, clicked.includes(need));
  check('no page errors', errs.length===0, errs.slice(0,3).join(' | '));
  console.log('\nFAILED:', fails.length?fails:'none');
  await b.close(); process.exit(fails.length?1:0);
})();
