# Tests

```
python tests/run_tests.py            everything available
python tests/run_tests.py --unit     no browser needed
python tests/run_tests.py --ui       dashboard only
python tests/run_tests.py -k conn    only matching filenames
python tests/run_tests.py -v         show each test's own output
```

**`unit/`** imports the modules directly and needs only Python: decoders, the
connection table and its quality metrics, alert rules and muting, filename
sanitising, pcap link types, the scheduled-task helpers.

**`ui/`** drives the real dashboard in a real browser via Playwright, against a
demo server the runner starts and stops:

```
pip install playwright && playwright install chromium
```

Skipped with a message if Playwright is absent. Set `NETSCOPE_CHROMIUM` to use a
specific browser binary.

`test_drops.py`, `test_stress.py` and `test_ifaces.py` open a real capture socket
and create adapters with `ip`, so they need Linux and root; they skip elsewhere.

Almost every bug in this project's history was a layout or timing fault only a
browser could see. Prefer adding to `ui/` over reasoning about the DOM.
