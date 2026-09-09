/*
 * The packet table's column behaviour.
 *
 * This replaces three scripts that printed measurements without asserting
 * anything — useful while hunting the bugs, useless as a guard afterwards. A
 * suite that cannot fail is not a suite. Every bug they were written for is
 * asserted here instead:
 *
 *   - double-clicking a border auto-fits the column, and the fixed-width
 *     columns must not ellipsise afterwards
 *   - the table never scrolls sideways at any window width
 *   - hiding a column keeps ten cells in every row: `display:none` on a cell
 *     removes it from the row and shifts every later cell onto the wrong <col>
 *   - a drag does not jump on its first pixel
 */
const { chromium } = require('playwright');

const fails = [];
const check = (n, c, e = '') => {
  console.log((c ? 'PASS  ' : 'FAIL  ') + n + ((!c && e) ? '  -- ' + e : ''));
  if (!c) fails.push(n);
};

(async () => {
  const b = await chromium.launch({ executablePath: process.env.NETSCOPE_CHROMIUM || undefined });
  const p = await b.newPage({ viewport: { width: 1680, height: 900 } });
  const errs = [];
  p.on('pageerror', e => errs.push(String(e)));
  await p.goto(process.argv[2]);
  await p.waitForFunction(() => document.querySelectorAll('#rows tr').length > 120,
                          null, { timeout: 90000 });
  await p.evaluate(() => { try { localStorage.clear(); } catch (e) {} });
  await p.reload();
  await p.waitForFunction(() => document.querySelectorAll('#rows tr').length > 120,
                          null, { timeout: 90000 });
  await p.waitForTimeout(1200);

  // --- auto-fit every column, then nothing fixed-width may truncate.
  for (let i = 0; i < 9; i++) {
    const box = await p.evaluate(idx => {
      const h = document.querySelector('#hrow .rz[data-c="' + idx + '"]');
      if (!h) return null;
      const r = h.getBoundingClientRect();
      return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
    }, i);
    if (!box) continue;
    await p.mouse.dblclick(box.x, box.y);
    await p.waitForTimeout(150);
  }

  const cut = await p.evaluate(() => {
    // Columns 0/3/5/6/9 hold unbounded text and legitimately ellipsise when a
    // row longer than anything sampled arrives after the fit. The rest have
    // bounded contents and must always fit.
    const bounded = [1, 2, 4, 7, 8];
    const bad = [];
    const rows = [...document.querySelectorAll('#rows tr')];
    for (const i of bounded) {
      const th = document.querySelectorAll('#hrow th')[i];
      if (th && th.scrollWidth > th.clientWidth + 1) bad.push({ col: i, where: 'header' });
      for (const tr of rows) {
        const td = tr.children[i];
        if (td && td.scrollWidth > td.clientWidth + 1) {
          bad.push({ col: i, text: td.textContent.trim() });
          break;
        }
      }
    }
    return bad;
  });
  check('bounded columns never truncate after auto-fit', cut.length === 0, JSON.stringify(cut));

  // --- no sideways scrolling, at any width.
  for (const w of [1152, 1400, 1680, 1920]) {
    await p.setViewportSize({ width: w, height: 900 });
    await p.waitForTimeout(500);
    const over = await p.evaluate(() => {
      const tw = document.getElementById('tw'), d = document.documentElement;
      return { table: tw.scrollWidth - tw.clientWidth, doc: d.scrollWidth - d.clientWidth };
    });
    check('no horizontal scroll at ' + w + 'px',
          over.table <= 1 && over.doc <= 1, JSON.stringify(over));
  }
  await p.setViewportSize({ width: 1680, height: 900 });
  await p.waitForTimeout(400);

  // --- hiding a column must not shift the others onto the wrong <col>.
  const hidden = await p.evaluate(() => {
    hiddenCols.add(2); hiddenCols.add(3); applyColVis();
    const tr = document.querySelector('#rows tr');
    const cols = [...document.querySelectorAll('#cg col')].map(c => c.style.width);
    return { cells: tr.children.length, cols };
  });
  check('a hidden column keeps ten cells in the row', hidden.cells === 10, hidden.cells);
  check('hidden columns are zero-width, not removed',
        hidden.cols[2] === '0px' && hidden.cols[3] === '0px', JSON.stringify(hidden.cols));

  // --- the first pixel of a drag must not jump.
  const drag = await p.evaluate(() => {
    const h = document.querySelector('#hrow .rz[data-c="5"]');
    const r = h.getBoundingClientRect();
    return { x: r.x + r.width / 2, y: r.y + r.height / 2,
             w: document.querySelectorAll('#hrow th')[5].getBoundingClientRect().width };
  });
  await p.mouse.move(drag.x, drag.y);
  await p.mouse.down();
  await p.mouse.move(drag.x + 1, drag.y);
  await p.waitForTimeout(150);
  const after1 = await p.evaluate(
    () => document.querySelectorAll('#hrow th')[5].getBoundingClientRect().width);
  await p.mouse.move(drag.x + 60, drag.y);
  await p.waitForTimeout(150);
  const after60 = await p.evaluate(
    () => document.querySelectorAll('#hrow th')[5].getBoundingClientRect().width);
  await p.mouse.up();
  check('a drag does not jump on its first pixel',
        Math.abs(after1 - drag.w - 1) <= 2, `${Math.round(drag.w)} -> ${Math.round(after1)}`);
  check('and it tracks the pointer after that',
        Math.abs(after60 - drag.w - 60) <= 4, `${Math.round(drag.w)} -> ${Math.round(after60)}`);

  await p.evaluate(() => { hiddenCols.clear(); applyColVis(); });
  check('no page errors', errs.length === 0, errs.join(' | '));
  console.log('\nFAILED:', fails.length ? fails : 'none');
  await b.close();
  process.exit(fails.length ? 1 : 0);
})();
