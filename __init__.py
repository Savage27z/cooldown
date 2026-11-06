"""Cooldown: check every package Hermes is about to install, before the command runs.

Registers one pre_tool_call hook on the terminal tool and a /cooldown slash command. Uses
only the Python standard library.
"""

from __future__ import annotations

import logging

from .cooldown.hook import Checker

log = logging.getLogger(__name__)

RECENT_KEY = "recent"
RECENT_MAX = 50


def _settings(ctx):
    def get(key, default):
        try:
            value = ctx.get_config(key, default=default)
        except Exception:
            return default
        return default if value is None else value

    return get


def _recorder(ctx):
    state = getattr(ctx, "state", None)
    if state is None:
        return None

    def record(entry):
        recent = state.get(RECENT_KEY, default=[]) or []
        recent.append(entry)
        state.set(RECENT_KEY, recent[-RECENT_MAX:])

    return record


def _command(ctx, checker):
    def handle(raw_args: str = "") -> str:
        args = (raw_args or "").strip()
        if args.startswith("check "):
            command = args[len("check "):].strip()
            d = checker.check(command)
            if d is None:
                return f"Cooldown: `{command}` would run without a prompt."
            return d["message"]
        if args in {"", "recent", "log"}:
            recent = (getattr(ctx, "state", None) and ctx.state.get(RECENT_KEY, default=[])) or []
            if not recent:
                return "Cooldown has not checked any installs yet."
            lines = ["Cooldown, most recent first:"]
            for e in reversed(recent[-10:]):
                pkgs = ", ".join(
                    f"{p['name']}{'@' + p['version'] if p.get('version') else ''} ({p['level']})" for p in e["packages"]
                )
                lines.append(f"- {e['at']}  {e['decision'].upper()}  {pkgs}")
            return "\n".join(lines)
        return "Usage: /cooldown (recent decisions) or /cooldown check <install command> (dry run, runs nothing)."

    return handle


def register(ctx):
    checker = Checker(_settings(ctx), record=_recorder(ctx))
    ctx.register_hook("pre_tool_call", checker.hook)
    try:
        ctx.register_command(
            "cooldown",
            _command(ctx, checker),
            description="Recent install checks, or `check <command>` to dry-run one",
        )
    except Exception as e:  # the hook is what matters; the command is a convenience
        log.info("cooldown: slash command not registered: %s", e)
