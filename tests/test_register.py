import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_plugin():
    """Import the plugin directory as a package, the way Hermes does."""
    spec = importlib.util.spec_from_file_location(
        "cooldown_plugin_under_test", os.path.join(ROOT, "__init__.py"), submodule_search_locations=[ROOT]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeState:
    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value


class FakeCtx:
    def __init__(self, settings=None):
        self.settings = settings or {}
        self.state = FakeState()
        self.hooks, self.commands = {}, {}

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_command(self, name, fn, description=""):
        self.commands[name] = fn


class RegisterTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        load_plugin().register(self.ctx)

    def test_registers_exactly_the_declared_hook_and_a_command(self):
        self.assertEqual(list(self.ctx.hooks), ["pre_tool_call"])
        self.assertIn("cooldown", self.ctx.commands)

    def test_hook_ignores_commands_that_install_nothing(self):
        self.assertIsNone(self.ctx.hooks["pre_tool_call"](tool_name="terminal", args={"command": "git status"}, task_id="t"))

    def test_command_usage_empty_log_and_dry_run(self):
        cmd = self.ctx.commands["cooldown"]
        self.assertIn("not checked any installs yet", cmd(""))
        self.assertIn("would run without a prompt", cmd("check ls -la"))
        self.assertIn("Usage", cmd("what"))

    def test_recent_decisions_are_listed_newest_first(self):
        self.ctx.state.set("recent", [
            {"at": "2026-11-06T10:00:00+00:00", "decision": "ok", "packages": [{"name": "flask", "version": "3.0.0", "level": "ok"}]},
            {"at": "2026-11-06T11:00:00+00:00", "decision": "block", "packages": [{"name": "crossenv", "version": None, "level": "block"}]},
        ])
        out = self.ctx.commands["cooldown"]("")
        self.assertLess(out.index("crossenv"), out.index("flask@3.0.0"))


class ManifestTests(unittest.TestCase):
    def test_manifest_declares_what_register_registers(self):
        with open(os.path.join(ROOT, "plugin.yaml"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("provides_tools: []", text)
        self.assertIn("  - pre_tool_call", text)
        self.assertIn('requires_hermes: ">=0.23.0"', text)


if __name__ == "__main__":
    unittest.main()
