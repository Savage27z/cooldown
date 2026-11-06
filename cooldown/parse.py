"""Find the packages a shell command would install from a public registry.

Only what can be read from the command line itself is reported. Installs from a lockfile
(`npm ci`, a bare `npm install`, `uv sync`) are left alone: the project already chose those
versions. Requirement files, URLs and local paths are reported as `unchecked` so the caller
can say plainly what was not looked at.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

PYPI = "PyPI"
NPM = "npm"


@dataclass(frozen=True)
class Request:
    """One package the command asks for."""

    ecosystem: str  # PYPI or NPM
    name: str
    version: str | None  # an exact version when the command pins one, else None
    spec: str  # what was typed, for messages
    tag: str | None = None  # an npm release channel such as `next` or `canary`


@dataclass
class Parsed:
    requests: list[Request] = field(default_factory=list)
    unchecked: list[str] = field(default_factory=list)  # requirement files, URLs, paths


# Separators between commands on one line. Pipes count too: `curl ... | sh` is not ours, but
# `echo y | pip install x` is.
_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")

# Options that take a value, so the value is not mistaken for a package name.
_PIP_VALUE_OPTS = {
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-c", "--constraint",
    "-t", "--target", "--prefix", "--root", "--python", "--platform", "--python-version",
    "--implementation", "--abi", "--src", "--upgrade-strategy", "--cache-dir", "--log",
    "--progress-bar", "--trusted-host", "--proxy", "--timeout", "--retries", "--group",
    "--extra", "--index", "--default-index", "--with", "-p", "--from",
}
_NPM_VALUE_OPTS = {
    "--registry", "--prefix", "-C", "--dir", "--workspace", "-w", "--tag", "--save-prefix",
    "--cache", "--userconfig", "--filter", "-p", "--package", "--cwd", "--omit", "--include",
}

_PY_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:  # unbalanced quotes: fall back to whitespace, dropping the stray quotes
        return [t.strip("'\"") for t in segment.split()]


def _strip_env_and_sudo(tok: list[str]) -> list[str]:
    i = 0
    while i < len(tok) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok[i]) or tok[i] in {"sudo", "env", "command", "time", "nice"}):
        i += 1
    return tok[i:]


def _is_url_or_path(arg: str) -> bool:
    return (
        "://" in arg
        or arg.startswith(("git+", "file:", "github:", "./", "../", "/", "~"))
        or arg.endswith((".whl", ".tar.gz", ".zip", ".tgz"))
        or (len(arg) > 2 and arg[1] == ":" and arg[2] in "\\/")  # C:\path
    )


def _pypi(spec: str) -> Request | None:
    m = _PY_NAME.match(spec.strip())
    if not m:
        return None
    name, rest = m.group(1), m.group(3).strip()
    version = None
    exact = re.match(r"^===?\s*([A-Za-z0-9._+!-]+)$", rest)
    if exact:
        version = exact.group(1)
    return Request(PYPI, name.lower().replace("_", "-"), version, spec)


def _npm(spec: str) -> Request | None:
    # @scope/name@range, name@range, name
    if spec.startswith("@"):
        at = spec.find("@", 1)
    else:
        at = spec.find("@")
    name, rng = (spec, "") if at <= 0 else (spec[:at], spec[at + 1 :])
    if not re.match(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", name, re.I):
        return None
    version = rng if re.match(r"^\d+\.\d+\.\d+([-+][\w.-]+)?$", rng or "") else None
    tag = rng if not version and re.match(r"^[A-Za-z][\w.-]*$", rng or "") and rng != "latest" else None
    return Request(NPM, name.lower(), version, spec, tag)


def _collect(args: list[str], value_opts: set[str], make, out: Parsed) -> None:
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in {"-r", "--requirement", "-e", "--editable"}:
            skip = True
            out.unchecked.append(a)
            continue
        if a.startswith("-"):
            if "=" not in a and a in value_opts:
                skip = True
            continue
        if _is_url_or_path(a) or a.endswith((".txt", ".in", ".toml")):
            out.unchecked.append(a)
            continue
        req = make(a)
        if req:
            out.requests.append(req)


def parse(command: str) -> Parsed:
    out = Parsed()
    for seg in _SPLIT.split(command or ""):
        tok = _strip_env_and_sudo(_tokens(seg))
        if not tok:
            continue
        head = tok[0].rsplit("/", 1)[-1].lower().removesuffix(".exe")

        # python -m pip install ... / py -m pip install ...
        if head.startswith(("python", "py")) and len(tok) > 3 and tok[1] == "-m" and tok[2] in {"pip", "pip3"}:
            tok, head = tok[2:], "pip"

        if head in {"pip", "pip3"} and len(tok) > 1 and tok[1] == "install":
            _collect(tok[2:], _PIP_VALUE_OPTS, _pypi, out)
        elif head == "uv" and len(tok) > 2 and tok[1] == "pip" and tok[2] == "install":
            _collect(tok[3:], _PIP_VALUE_OPTS, _pypi, out)
        elif head == "uv" and len(tok) > 1 and tok[1] == "add":
            _collect(tok[2:], _PIP_VALUE_OPTS, _pypi, out)
        elif head == "uv" and len(tok) > 2 and tok[1] == "tool" and tok[2] in {"install", "run"}:
            _collect(tok[3:4], _PIP_VALUE_OPTS, _pypi, out)  # only the tool itself; the rest are its arguments
        elif head in {"uvx", "pipx"} and len(tok) > 1:
            rest = tok[2:] if head == "pipx" and tok[1] in {"install", "run"} else tok[1:]
            first = next((a for a in rest if not a.startswith("-")), None)
            if first:
                _collect([first], _PIP_VALUE_OPTS, _pypi, out)
        elif head == "poetry" and len(tok) > 1 and tok[1] == "add":
            _collect(tok[2:], _PIP_VALUE_OPTS, _pypi, out)
        elif head in {"npm", "pnpm", "yarn", "bun"} and len(tok) > 1 and tok[1] in {"install", "i", "add", "isntall"}:
            _collect(tok[2:], _NPM_VALUE_OPTS, _npm, out)  # a bare `npm install` installs the lockfile: nothing to check
        elif head in {"npx", "bunx"} or (head in {"pnpm", "yarn"} and len(tok) > 1 and tok[1] == "dlx"):
            rest = tok[2:] if head in {"pnpm", "yarn"} else tok[1:]
            pkg = None
            skip = False
            for a in rest:  # npx -p pkg cmd, npx --yes pkg args
                if skip:
                    pkg, skip = a, False
                    break
                if a in {"-p", "--package"}:
                    skip = True
                    continue
                if a.startswith("--package="):
                    pkg = a.split("=", 1)[1]
                    break
                if a.startswith("-"):
                    continue
                pkg = a
                break
            if pkg and not _is_url_or_path(pkg):
                req = _npm(pkg)
                if req:
                    out.requests.append(req)
    # one entry per package
    seen, unique = set(), []
    for r in out.requests:
        if (r.ecosystem, r.name, r.version) not in seen:
            seen.add((r.ecosystem, r.name, r.version))
            unique.append(r)
    out.requests = unique
    return out
