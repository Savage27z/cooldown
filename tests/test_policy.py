import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cooldown.hook import Checker  # noqa: E402
from cooldown.lookup import Facts, Lookup, NotFound  # noqa: E402

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def at(**kw):
    return NOW - timedelta(**kw)


def established(version, published):
    """A package that has been around for years, with an older release."""
    return Facts(
        version=version,
        published=published,
        first_published=at(days=2000),
        versions=[("1.0.0", at(days=2000)), ("1.9.0", at(days=40)), (version, published)],
    )


class FakeLookup:
    def __init__(self, table):
        self.table = table
        self.calls = 0

    def facts(self, eco, name, version, tag=None):
        self.calls += 1
        v = self.table[name]
        if isinstance(v, Exception):
            raise v
        return v


def checker(table, **settings):
    return Checker(lambda k, d: settings.get(k, d), lookup=FakeLookup(table), clock=lambda: NOW)


class DecisionTests(unittest.TestCase):
    def test_old_version_runs_silently(self):
        c = checker({"flask": established("3.0.0", at(days=90))})
        self.assertIsNone(c.check("pip install flask"))

    def test_fresh_release_asks_and_offers_older_version(self):
        c = checker({"left-pad": established("2.0.0", at(hours=2))})
        d = c.check("npm install left-pad")
        self.assertEqual(d["action"], "approve")
        self.assertIn("left-pad@2.0.0 was published 2 hours ago", d["message"])
        self.assertIn("left-pad@1.9.0 (published 40 days ago)", d["message"])
        self.assertEqual(d["rule_key"], "cooldown:left-pad")

    def test_cooldown_length_is_configurable(self):
        c = checker({"left-pad": established("2.0.0", at(hours=2))}, min_age_days=0)
        self.assertIsNone(c.check("npm install left-pad"))

    def test_malicious_is_blocked(self):
        f = established("2.4.6", at(days=200))
        f.malicious = [("GHSA-wx9m-wx4f-4cmg", "Malicious dropper in mistralai 2.4.6 PyPI package")]
        d = checker({"mistralai": f}).check("pip install mistralai==2.4.6")
        self.assertEqual(d["action"], "block")
        self.assertIn("OSV lists mistralai==2.4.6 as malicious (GHSA-wx9m-wx4f-4cmg", d["message"])

    def test_name_not_on_registry_asks(self):
        d = checker({"reqeusts": Facts(exists=False)}).check("pip install reqeusts")
        self.assertEqual(d["action"], "approve")
        self.assertIn("not on the public PyPI registry", d["message"])

    def test_removed_malicious_release_is_blocked_not_just_held(self):
        f = Facts(exists=False, package_known=True, version="2.4.6",
                  malicious=[("GHSA-wx9m-wx4f-4cmg", "Malicious dropper")])
        self.assertEqual(checker({"mistralai": f}).check("pip install mistralai==2.4.6")["action"], "block")

    def test_removed_release_says_so(self):
        f = Facts(exists=False, package_known=True, version="1.0.9")
        d = checker({"flask": f}).check("pip install flask==1.0.9")
        self.assertIn("never published, or has been removed", d["message"])

    def test_new_package_asks_without_suggesting_an_older_release(self):
        f = Facts(version="0.3.0", published=at(days=8), first_published=at(days=10),
                  versions=[("0.1.0", at(days=10)), ("0.3.0", at(days=8))])
        d = checker({"shiny-new": f}).check("npm i shiny-new")
        self.assertIn("shiny-new itself first appeared 10 days ago", d["message"])
        self.assertNotIn("Older version", d["message"])

    def test_not_yet_indexed_asks_and_mentions_install_scripts(self):
        f = Facts(version="9.9.9", indexed=False, first_published=at(days=900),
                  versions=[("9.9.8", at(days=60))], install_scripts=["postinstall"])
        d = checker({"widget": f}).check("npm i widget")
        self.assertIn("so recently that the public index has not caught up", d["message"])
        self.assertIn("runs code during install (postinstall)", d["message"])

    def test_lookup_failure_asks_by_default_and_can_be_allowed(self):
        table = {"httpx": TimeoutError("timed out")}
        d = checker(table).check("pip install httpx")
        self.assertEqual(d["action"], "approve")
        self.assertIn("lookup for httpx timed out", d["message"])
        self.assertIsNone(checker(table, on_lookup_failure="allow").check("pip install httpx"))

    def test_allow_list_skips_the_lookup(self):
        c = checker({"acme-internal": Facts(exists=False)}, allow="acme-internal")
        self.assertIsNone(c.check("pip install acme-internal"))
        self.assertEqual(c.lookup.calls, 0)

    def test_block_wins_and_message_lists_everything(self):
        bad = established("1.0.1", at(days=30))
        bad.malicious = [("MAL-2026-1", "malicious code")]
        d = checker({"bad": bad, "fresh": established("2.0.0", at(hours=5))}).check(
            "npm i bad fresh && pip install -r requirements.txt"
        )
        self.assertEqual(d["action"], "block")
        self.assertIn("bad@1.0.1", d["message"])
        self.assertIn("fresh@2.0.0 was published 5 hours ago", d["message"])
        self.assertIn("Not checked: -r", d["message"])

    def test_results_are_cached(self):
        c = checker({"flask": established("3.0.0", at(days=90))})
        c.check("pip install flask")
        c.check("pip install flask")
        self.assertEqual(c.lookup.calls, 1)


class HookTests(unittest.TestCase):
    def test_only_terminal_commands_are_checked(self):
        c = checker({})
        self.assertIsNone(c.hook(tool_name="write_file", args={"content": "pip install x"}))
        self.assertIsNone(c.hook(tool_name="terminal", args={"command": "ls"}))
        self.assertIsNone(c.hook(tool_name="terminal", args="not a dict"))

    def test_unexpected_errors_ask_instead_of_letting_the_install_through(self):
        c = checker({})  # KeyError inside the fake lookup is caught as a lookup failure...
        d = c.hook(tool_name="terminal", args={"command": "pip install x"})
        self.assertEqual(d["action"], "approve")

        class Boom(Checker):
            def check(self, command):
                raise RuntimeError("bug")

        d = Boom(lambda k, d: d).hook(tool_name="terminal", args={"command": "pip install x"})
        self.assertEqual(d["action"], "approve")
        self.assertIn("could not check", d["message"])


class LookupTests(unittest.TestCase):
    """The real Lookup class against a fake HTTP layer."""

    def make(self, routes):
        calls = []

        def fetch(url, timeout, body=None):
            calls.append(url)
            key = url if body is None else (url, body["package"]["name"])
            if key not in routes:
                raise NotFound(url)
            return routes[key]

        return Lookup(fetch=fetch), calls

    def test_npm_latest_scoped_name_and_install_scripts(self):
        routes = {
            "https://api.deps.dev/v3/systems/npm/packages/%40scope%2Fpkg": {"versions": [
                {"versionKey": {"version": "1.0.0"}, "publishedAt": "2026-01-01T00:00:00Z"},
                {"versionKey": {"version": "1.1.0"}, "publishedAt": "2026-11-06T10:00:00Z", "isDefault": True},
            ]},
            "https://registry.npmjs.org/-/package/%40scope%2Fpkg/dist-tags": {"latest": "1.1.0"},
            "https://registry.npmjs.org/%40scope%2Fpkg/1.1.0": {"scripts": {"postinstall": "node x.js", "test": "t"}},
            ("https://api.osv.dev/v1/query", "@scope/pkg"): {"vulns": []},
        }
        lk, _ = self.make(routes)
        f = lk.facts("npm", "@scope/pkg", None)
        self.assertEqual(f.version, "1.1.0")
        self.assertEqual(f.published.isoformat(), "2026-11-06T10:00:00+00:00")
        self.assertEqual(f.install_scripts, ["postinstall"])
        self.assertEqual(f.first_published.year, 2026)

    def test_pypi_version_too_new_for_depsdev_uses_pypi_upload_time(self):
        routes = {
            "https://api.deps.dev/v3/systems/pypi/packages/mistralai": {"versions": [
                {"versionKey": {"version": "2.4.5"}, "publishedAt": "2026-04-01T00:00:00Z", "isDefault": True},
            ]},
            "https://pypi.org/pypi/mistralai/2.4.6/json": {"urls": [{"upload_time_iso_8601": "2026-05-12T08:00:00.000000Z"}]},
            ("https://api.osv.dev/v1/query", "mistralai"): {"vulns": [
                {"id": "GHSA-wx9m-wx4f-4cmg", "summary": "Malicious dropper in mistralai 2.4.6 PyPI package"}
            ]},
        }
        lk, _ = self.make(routes)
        f = lk.facts("PyPI", "mistralai", "2.4.6")
        self.assertEqual(f.published.day, 12)
        self.assertEqual(f.malicious[0][0], "GHSA-wx9m-wx4f-4cmg")

    def test_malicious_release_removed_from_the_registry_is_still_caught(self):
        routes = {
            "https://api.deps.dev/v3/systems/pypi/packages/mistralai": {"versions": [
                {"versionKey": {"version": "2.4.5"}, "publishedAt": "2026-04-01T00:00:00Z", "isDefault": True},
            ]},
            ("https://api.osv.dev/v1/query", "mistralai"): {"vulns": [
                {"id": "GHSA-wx9m-wx4f-4cmg", "summary": "Malicious dropper in mistralai 2.4.6 PyPI package"}
            ]},
        }  # PyPI no longer serves 2.4.6: its per-version JSON is a 404
        lk, _ = self.make(routes)
        f = lk.facts("PyPI", "mistralai", "2.4.6")
        self.assertFalse(f.exists)
        self.assertTrue(f.package_known)
        self.assertEqual(f.malicious[0][0], "GHSA-wx9m-wx4f-4cmg")

    def test_ordinary_vulnerabilities_are_not_called_malicious(self):
        routes = {("https://api.osv.dev/v1/query", "requests"): {"vulns": [
            {"id": "GHSA-9hjg-9r4m-mvj7", "summary": "Requests leaks Proxy-Authorization headers"},
            {"id": "MAL-2026-77", "summary": "Typosquat"},
        ]}}
        lk, _ = self.make(routes)
        self.assertEqual([m[0] for m in lk.malicious("PyPI", "requests", "2.0")], ["MAL-2026-77"])

    def test_missing_package_is_reported_not_raised(self):
        lk, _ = self.make({})
        self.assertFalse(lk.facts("PyPI", "reqeusts", None).exists)
        self.assertFalse(lk.facts("npm", "lefft-pad", None).exists)


if __name__ == "__main__":
    unittest.main()
