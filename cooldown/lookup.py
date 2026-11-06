"""Free, keyless lookups: when a version was published, what the latest version is, and
whether OSV lists the version as malicious.

Sources: deps.dev (publish dates for npm and PyPI), the npm registry (latest version, install
scripts, existence of a version), PyPI's per-version JSON (upload time of a release too new for
deps.dev) and OSV.dev (malicious-package advisories). Every request has its own timeout.
"""

from __future__ import annotations

import gzip
import json
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .parse import NPM, PYPI

USER_AGENT = "hermes-cooldown/0.1 (+https://github.com/Savage27z/hermes-cooldown)"


class NotFound(Exception):
    pass


def http_json(url: str, timeout: float, body: dict | None = None):
    """GET (or POST `body` as JSON) and decode JSON. Raises NotFound on 404."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, headers={"User-Agent": USER_AGENT, "Accept": "application/json", "Accept-Encoding": "gzip"}
    )
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - https URLs built below
            raw = r.read()
            if r.headers.get("Content-Encoding", "").lower() == "gzip":
                raw = gzip.decompress(raw)
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise NotFound(url) from e
        raise


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _q(name: str) -> str:
    return urllib.parse.quote(name, safe="")


@dataclass
class Facts:
    """What the registries say about one requested package."""

    exists: bool = True  # False: this package (or this version of it) is not on the registry
    package_known: bool = False  # with exists False: the package is there, just not this version
    version: str | None = None  # the version that would be installed
    published: datetime | None = None  # when that version was published
    first_published: datetime | None = None  # when the package itself first appeared
    indexed: bool = True  # False: the registry has it but deps.dev does not yet (very fresh)
    versions: list[tuple[str, datetime]] = field(default_factory=list)  # (version, published), oldest first
    install_scripts: list[str] = field(default_factory=list)  # npm preinstall/install/postinstall
    malicious: list[tuple[str, str]] = field(default_factory=list)  # (advisory id, summary)


class Lookup:
    def __init__(self, fetch=http_json, timeout: float = 6.0):
        self.fetch = fetch
        self.timeout = timeout

    # --- registries -----------------------------------------------------------------------
    def _depsdev_versions(self, eco: str, name: str) -> list[dict]:
        system = "npm" if eco == NPM else "pypi"
        d = self.fetch(f"https://api.deps.dev/v3/systems/{system}/packages/{_q(name)}", self.timeout)
        return d.get("versions", [])

    def _npm_latest(self, name: str, tag: str | None = None) -> str:
        d = self.fetch(f"https://registry.npmjs.org/-/package/{_q(name)}/dist-tags", self.timeout)
        if tag and tag not in d:
            raise NotFound(f"{name}@{tag}")
        return d[tag or "latest"]

    def _npm_version_doc(self, name: str, version: str) -> dict:
        return self.fetch(f"https://registry.npmjs.org/{_q(name)}/{_q(version)}", self.timeout)

    def _pypi_version_doc(self, name: str, version: str) -> dict:
        return self.fetch(f"https://pypi.org/pypi/{_q(name)}/{_q(version)}/json", self.timeout)

    def _pypi_latest(self, name: str) -> str:
        return self.fetch(f"https://pypi.org/pypi/{_q(name)}/json", self.timeout)["info"]["version"]

    # --- OSV --------------------------------------------------------------------------------
    def malicious(self, eco: str, name: str, version: str | None) -> list[tuple[str, str]]:
        body = {"package": {"name": name, "ecosystem": eco}}
        if version:
            body["version"] = version
        try:
            d = self.fetch("https://api.osv.dev/v1/query", self.timeout, body)
        except NotFound:  # OSV answers {} for unknown packages; treat a 404 the same way
            return []
        out = []
        for v in d.get("vulns", []) or []:
            vid, summary = v.get("id", ""), v.get("summary", "") or ""
            text = (summary + " " + (v.get("details", "") or "")[:400]).lower()
            if vid.startswith("MAL-") or "malware" in text or "malicious" in text:
                out.append((vid, summary or "listed as malicious"))
        return out

    # --- everything about one package -------------------------------------------------------
    @staticmethod
    def _or_none(fn, *a):
        try:
            return fn(*a)
        except NotFound:
            return None

    def facts(self, eco: str, name: str, version: str | None, tag: str | None = None) -> Facts:
        """Everything Cooldown needs about one package, with independent requests in parallel."""
        f = Facts()
        pool = ThreadPoolExecutor(max_workers=3)
        try:
            j_list = pool.submit(self._or_none, self._depsdev_versions, eco, name)
            j_target = pool.submit(self._or_none, self._npm_latest, name, tag) if eco == NPM and not version else None
            j_osv = pool.submit(self.malicious, eco, name, version) if version else None

            raw = j_list.result() or []
            f.versions = sorted(
                ((v["versionKey"]["version"], _ts(v.get("publishedAt"))) for v in raw if v.get("publishedAt")),
                key=lambda x: x[1],
            )
            f.first_published = f.versions[0][1] if f.versions else None

            # Which version would be installed
            if version:
                f.version = version
            elif eco == NPM:
                f.version = j_target.result()
            else:
                f.version = next((v["versionKey"]["version"] for v in raw if v.get("isDefault")), None) or self._or_none(
                    self._pypi_latest, name
                )
            if f.version is None:  # the package is not on the registry at all
                f.exists = False
                f.malicious = self.malicious(eco, name, None)  # removed typosquats keep their advisories
                return f

            if j_osv is None:
                j_osv = pool.submit(self.malicious, eco, name, f.version)
            known = dict(f.versions)
            j_doc = None
            if eco == NPM:
                j_doc = pool.submit(self._or_none, self._npm_version_doc, name, f.version)
            elif f.version not in known:
                j_doc = pool.submit(self._or_none, self._pypi_version_doc, name, f.version)
            doc = j_doc.result() if j_doc else None

            if f.version in known:
                f.published = known[f.version]
            elif doc is None:  # this version is not on the registry: never published, or removed
                f.exists = False
                f.package_known = bool(f.versions)
            elif eco == NPM:
                f.indexed = False  # the registry has it, the index does not yet: minutes or hours old
            else:
                times = [t for t in (_ts(u.get("upload_time_iso_8601")) for u in doc.get("urls", [])) if t]
                if times:
                    f.published = min(times)
                else:
                    f.indexed = False
                if not f.versions:
                    f.first_published = f.published

            if eco == NPM and doc:
                scripts = doc.get("scripts", {}) or {}
                f.install_scripts = [k for k in ("preinstall", "install", "postinstall") if k in scripts]

            # OSV is asked every time, even for a version the registry no longer serves: mirrors
            # and caches can still hand out a release that was pulled for being malicious.
            f.malicious = j_osv.result()
            return f
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
