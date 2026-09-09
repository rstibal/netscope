import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys; from netscope import safe_filename
cases = [
  ('report.pdf',                      'report.pdf'),
  ('evil"\r\nSet-Cookie: a=b',        'evil___Set-Cookie_ a=b'),   # ", CR, LF -> 3
  ('../../../etc/passwd',             '_.._.._etc_passwd'),        # dots stripped after
  (r'..\..\windows\system32\a.dll',   '_.._windows_system32_a.dll'),
  ('',                                'netscope-object'),
  ('...',                             'netscope-object'),
  ('a'*300,                           'a'*120),
  ('con:aux?.txt',                    'con_aux_.txt'),
  ('  spaced.bin  ',                  'spaced.bin'),
]
bad=0
for raw, want in cases:
    got = safe_filename(raw); ok = got == want; bad += not ok
    print(('PASS  ' if ok else 'FAIL  ')+repr(raw)[:40].ljust(42)+'-> '+repr(got)[:52]+('' if ok else '  want '+repr(want)))
for raw in ['x"y','a\r\nb','p/q','p\\q','\x00z','a\nb','.\\.\\x', 'x'*500]:
    g = safe_filename(raw)
    assert not any(c in g for c in '"\\/\r\n\x00'), (raw,g)
    assert not g.startswith('.') and 0 < len(g) <= 120, (raw,g)
print('\nproperty: no header/traversal chars, non-empty, <=120, no leading dot -- OK')
sys.exit(1 if bad else 0)
