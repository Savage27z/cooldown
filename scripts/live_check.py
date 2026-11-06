"""Run Cooldown against the live registries, outside Hermes: python scripts/live_check.py [command ...]"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cooldown.hook import Checker  # noqa: E402

DEFAULT = [
    "pip install requests",
    "npm install react",
    "pip install mistralai==2.4.6",
    "npm install crossenv",
    "npm install typescript@next",
    "pip install cooldown-demo-no-such-package-zz",
]

checker = Checker(lambda key, default: default)
for cmd in sys.argv[1:] or DEFAULT:
    t = time.perf_counter()
    d = checker.check(cmd)
    took = time.perf_counter() - t
    print(f"$ {cmd}   [{took:.1f}s]")
    print("  -> runs silently" if d is None else f"  -> {d['action'].upper()}\n     " + d["message"].replace("\n", "\n     "))
    print()
