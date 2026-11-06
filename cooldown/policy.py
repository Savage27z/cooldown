"""Turn registry facts into a decision, in words a person can act on.

block  OSV lists the exact version as malicious.
ask    The version is younger than the cooldown, the package itself is new, the name is not on
       the public registry, or the lookup failed (unless `on_lookup_failure` is "allow").
ok     Everything else, silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .lookup import Facts
from .parse import NPM, Request

OK, ASK, BLOCK = "ok", "ask", "block"
_RANK = {OK: 0, ASK: 1, BLOCK: 2}


@dataclass
class Config:
    min_age_days: float = 3.0  # Hermes's own rule for its dependencies
    new_package_days: float = 30.0
    on_lookup_failure: str = "ask"  # "ask" or "allow"
    allow: tuple[str, ...] = ()  # package names never checked (internal packages, for example)

    @classmethod
    def from_settings(cls, get):
        def num(key, default):
            try:
                return float(get(key, default))
            except (TypeError, ValueError):
                return default

        mode = str(get("on_lookup_failure", "ask")).strip().lower()
        allow = get("allow", []) or []
        if isinstance(allow, str):
            allow = [a for a in allow.replace(",", " ").split() if a]
        return cls(
            min_age_days=max(0.0, num("min_age_days", 3.0)),
            new_package_days=max(0.0, num("new_package_days", 30.0)),
            on_lookup_failure="allow" if mode == "allow" else "ask",
            allow=tuple(str(a).lower() for a in allow),
        )


@dataclass
class Finding:
    request: Request
    level: str
    reasons: list[str] = field(default_factory=list)
    suggestion: str | None = None
    version: str | None = None


def ago(delta: timedelta) -> str:
    s = max(0, int(delta.total_seconds()))
    if s < 3600:
        n, unit = max(1, s // 60), "minute"
    elif s < 86400 * 2:
        n, unit = s // 3600, "hour"
    else:
        n, unit = s // 86400, "day"
    return f"{n} {unit}{'' if n == 1 else 's'} ago"


def label(req: Request, version: str | None) -> str:
    sep = "@" if req.ecosystem == NPM else "=="
    return f"{req.name}{sep}{version}" if version else req.name


def assess(req: Request, facts: Facts, now: datetime, cfg: Config) -> Finding:
    f = Finding(req, OK, version=facts.version)
    name = label(req, facts.version)

    if facts.malicious:  # checked first: a pulled malicious release is still malicious
        vid, summary = facts.malicious[0]
        f.level = BLOCK
        f.reasons.append(f"OSV lists {name} as malicious ({vid}: {summary.rstrip('.')})")
        return f

    if not facts.exists:
        f.level = ASK
        where = "npm" if req.ecosystem == NPM else "PyPI"
        if facts.package_known:
            f.reasons.append(f"{name} is not on {where}: that version was never published, or has been removed")
        else:
            f.reasons.append(f"{name} is not on the public {where} registry: a typo, or a name anyone could register")
        return f

    min_age = timedelta(days=cfg.min_age_days)
    if not facts.indexed:
        f.level = ASK
        f.reasons.append(f"{name} was published so recently that the public index has not caught up yet")
    elif facts.published and now - facts.published < min_age:
        f.level = ASK
        f.reasons.append(
            f"{name} was published {ago(now - facts.published)}; Cooldown waits "
            f"{cfg.min_age_days:g} days, the same rule Hermes uses for its own dependencies"
        )

    new_package = bool(
        facts.first_published and now - facts.first_published < timedelta(days=cfg.new_package_days)
    )
    if new_package:
        f.level = ASK
        f.reasons.append(f"{req.name} itself first appeared {ago(now - facts.first_published)}")

    if f.level == ASK and facts.install_scripts:
        f.reasons.append(f"it runs code during install ({', '.join(facts.install_scripts)})")

    if f.level == ASK and not new_package:  # an older release of a new package is no safer
        safe = [v for v, t in facts.versions if now - t >= min_age and v != facts.version]
        if safe:
            older = safe[-1]
            published = dict(facts.versions)[older]
            f.suggestion = f"{label(req, older)} (published {ago(now - published)})"
    return f


def failed(req: Request, cfg: Config, err: Exception) -> Finding:
    level = OK if cfg.on_lookup_failure == "allow" else ASK
    kind = "timed out" if "timed out" in str(err).lower() or isinstance(err, TimeoutError) else "failed"
    return Finding(req, level, [f"the lookup for {req.name} {kind}, so it could not be checked"])


def decide(findings: list[Finding], unchecked: list[str]) -> dict | None:
    """The pre_tool_call directive for the whole command, or None to let it run."""
    worst = max((f.level for f in findings), key=_RANK.get, default=OK)
    if worst == OK:
        return None
    lines = []
    for f in findings:
        if f.level == OK:
            continue
        line = "; ".join(f.reasons)
        if f.suggestion and f.level != BLOCK:
            line += f". Older version that has passed the cooldown: {f.suggestion}"
        lines.append(f"- {line}.")
    if unchecked:
        lines.append(f"- Not checked: {', '.join(unchecked)}.")
    if worst == BLOCK:
        # Name the plugin and say the command did not run: a live run showed a model crediting npm
        return {
            "action": "block",
            "message": "Blocked by the Cooldown plugin before the command ran (nothing was installed):\n"
            + "\n".join(lines),
        }
    names = ",".join(sorted(f.request.name for f in findings if f.level != OK))
    return {
        "action": "approve",
        "message": "The Cooldown plugin is holding this install until you approve it:\n" + "\n".join(lines),
        "rule_key": f"cooldown:{names}",
    }
