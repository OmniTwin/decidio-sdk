"""`python -m decidio` — the CLI door. UTF-8 out on BOTH streams BEFORE anything can print
(the reconfigure lived only under cli.py's own __main__ guard, which this door
never runs — so ✘/✔ mojibaked or died on cp1252 consoles for every packaged invocation). It
must run before the cli import too: cli.py can print its .env warnings at import time."""
import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 — a non-reconfigurable stream keeps its encoding
        pass

from .cli import main  # noqa: E402 — deliberately after the stream reconfigure (see above)

raise SystemExit(main())
