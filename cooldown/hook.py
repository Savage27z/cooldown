"""The pre_tool_call hook: check what a terminal command would install, before it runs."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

from .lookup import Facts, Lookup
from .parse import parse
from .policy import ASK, BLOCK, OK, Config, Finding, assess, decide, failed

log = logging.getLogger(__name__)

TOOLS = {"terminal"}
BUDGET_SECONDS = 20.0  # well inside Hermes's 30 s hook limit, past which the call is blocked anyway
CACHE_SECONDS = 600.0
MAX_PACKAGES = 12  # one command naming more is checked up to this many; the rest are reported


class Checker:
    def __init__(self, settings, lookup: Lookup | None = None, clock=None, record=None):
        self.settings = settings  # callable(key, default)
        self.lookup = lookup or Lookup()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.record = record  # callable(dict) for the recent-decisions log, or None
        self._cache: dict[tuple, tuple[float, Facts]] = {}
        self._lock = threading.Lock()

    def _facts(self, req) -> Facts:
        key = (req.ecosystem, req.name, req.version, req.tag)
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
                return hit[1]
        facts = self.lookup.facts(req.ecosystem, req.name, req.version, req.tag)
        with self._lock:
            self._cache[key] = (time.monotonic(), facts)
        return facts

    def check(self, command: str) -> dict | None:
        parsed = parse(command)
        if not parsed.requests:
            return None
        cfg = Config.from_settings(self.settings)
        now = self.clock()
        reqs = [r for r in parsed.requests if r.name not in cfg.allow]
        unchecked = list(parsed.unchecked)
        if len(reqs) > MAX_PACKAGES:
            unchecked += [r.spec for r in reqs[MAX_PACKAGES:]]
            reqs = reqs[:MAX_PACKAGES]

        findings: list[Finding] = []
        pool = ThreadPoolExecutor(max_workers=min(6, len(reqs) or 1))
        try:
            futures = {pool.submit(self._facts, r): r for r in reqs}
            done, pending = wait(futures, timeout=BUDGET_SECONDS)
            for fut, req in futures.items():
                if fut in pending:
                    findings.append(failed(req, cfg, TimeoutError("timed out")))
                    continue
                try:
                    findings.append(assess(req, fut.result(), now, cfg))
                except Exception as e:  # a lookup error is a finding, never a crash
                    log.info("cooldown: lookup for %s failed: %s", req.name, e)
                    findings.append(failed(req, cfg, e))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        directive = decide(findings, unchecked)
        if self.record:
            try:
                self.record({
                    "at": now.isoformat(timespec="seconds"),
                    "command": command[:300],
                    "decision": {None: OK, "approve": ASK, "block": BLOCK}[directive and directive["action"]],
                    "packages": [
                        {"name": f.request.name, "version": f.version, "level": f.level, "why": f.reasons}
                        for f in findings
                    ],
                })
            except Exception as e:
                log.debug("cooldown: could not record decision: %s", e)
        return directive

    def hook(self, tool_name: str = "", args: dict | None = None, task_id: str = "", **kwargs):
        if tool_name not in TOOLS or not isinstance(args, dict):
            return None
        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            return None
        try:
            return self.check(command)
        except Exception as e:  # never let an error wave an install through unchecked
            log.warning("cooldown: check failed: %s", e)
            return {
                "action": "approve",
                "message": f"Cooldown could not check this command ({type(e).__name__}). Approve only if you trust what it installs.",
                "rule_key": "cooldown:error",
            }
