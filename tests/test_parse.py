import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cooldown.parse import NPM, PYPI, parse  # noqa: E402


def reqs(cmd):
    return [(r.ecosystem, r.name, r.version) for r in parse(cmd).requests]


class PipTests(unittest.TestCase):
    def test_plain_and_pinned(self):
        self.assertEqual(reqs("pip install requests"), [(PYPI, "requests", None)])
        self.assertEqual(reqs("pip install requests==2.32.3"), [(PYPI, "requests", "2.32.3")])
        self.assertEqual(reqs("pip3 install 'mistralai==2.4.6'"), [(PYPI, "mistralai", "2.4.6")])

    def test_ranges_and_extras_are_unpinned(self):
        self.assertEqual(reqs('pip install "requests>=2,<3"'), [(PYPI, "requests", None)])
        self.assertEqual(reqs("pip install uvicorn[standard]==0.30.1"), [(PYPI, "uvicorn", "0.30.1")])

    def test_names_are_normalised(self):
        self.assertEqual(reqs("pip install Typing_Extensions"), [(PYPI, "typing-extensions", None)])

    def test_options_with_values_are_not_packages(self):
        self.assertEqual(
            reqs("pip install --index-url https://pypi.org/simple -t vendor --upgrade flask"),
            [(PYPI, "flask", None)],
        )

    def test_python_dash_m_pip_and_sudo_and_env(self):
        self.assertEqual(reqs("python -m pip install httpx"), [(PYPI, "httpx", None)])
        self.assertEqual(reqs("py -m pip install httpx"), [(PYPI, "httpx", None)])
        self.assertEqual(reqs("sudo PIP_NO_CACHE_DIR=1 pip install rich"), [(PYPI, "rich", None)])

    def test_requirement_files_urls_and_paths_are_unchecked(self):
        p = parse("pip install -r requirements.txt ./local git+https://github.com/a/b.git dist/x.whl")
        self.assertEqual(p.requests, [])
        self.assertEqual(len(p.unchecked), 4)

    def test_uv_poetry_pipx_uvx(self):
        self.assertEqual(reqs("uv pip install pydantic"), [(PYPI, "pydantic", None)])
        self.assertEqual(reqs("uv add fastapi==0.115.0"), [(PYPI, "fastapi", "0.115.0")])
        self.assertEqual(reqs("poetry add numpy"), [(PYPI, "numpy", None)])
        self.assertEqual(reqs("pipx install black"), [(PYPI, "black", None)])
        self.assertEqual(reqs("uvx ruff check ."), [(PYPI, "ruff", None)])
        self.assertEqual(reqs("uv tool run httpie https://example.com"), [(PYPI, "httpie", None)])

    def test_lockfile_installs_are_left_alone(self):
        for cmd in ["pip install", "uv sync", "poetry install", "pip install -e ."]:
            self.assertEqual(reqs(cmd), [], cmd)


class NpmTests(unittest.TestCase):
    def test_install_forms(self):
        self.assertEqual(reqs("npm install left-pad"), [(NPM, "left-pad", None)])
        self.assertEqual(reqs("npm i -D left-pad@1.3.0"), [(NPM, "left-pad", "1.3.0")])
        self.assertEqual(reqs("pnpm add @types/node@^22"), [(NPM, "@types/node", None)])
        self.assertEqual(reqs("yarn add @scope/pkg@2.0.0-beta.1"), [(NPM, "@scope/pkg", "2.0.0-beta.1")])
        self.assertEqual(reqs("bun add zod@latest"), [(NPM, "zod", None)])

    def test_release_channels_are_kept(self):
        r = parse("npm install typescript@next").requests[0]
        self.assertEqual((r.name, r.version, r.tag), ("typescript", None, "next"))
        self.assertIsNone(parse("npm i zod@latest").requests[0].tag)
        self.assertIsNone(parse("npm i zod@^3.2.0").requests[0].tag)

    def test_registry_option_value_is_not_a_package(self):
        self.assertEqual(reqs("npm install --registry https://r.example express"), [(NPM, "express", None)])

    def test_npx_and_dlx(self):
        self.assertEqual(reqs("npx --yes create-vite@5.2.0 app"), [(NPM, "create-vite", "5.2.0")])
        self.assertEqual(reqs("npx -p typescript tsc --init"), [(NPM, "typescript", None)])
        self.assertEqual(reqs("pnpm dlx shadcn@latest init"), [(NPM, "shadcn", None)])

    def test_lockfile_installs_are_left_alone(self):
        for cmd in ["npm install", "npm ci", "pnpm install", "yarn", "bun install"]:
            self.assertEqual(reqs(cmd), [], cmd)


class CommandShapeTests(unittest.TestCase):
    def test_chained_commands_and_duplicates(self):
        self.assertEqual(
            reqs("cd app && npm install express && pip install flask; npm i express"),
            [(NPM, "express", None), (PYPI, "flask", None)],
        )

    def test_unrelated_commands(self):
        for cmd in ["ls -la", "git commit -m 'pip install x'", "echo npm install", "pytest -q", ""]:
            self.assertEqual(reqs(cmd), [], cmd)

    def test_unbalanced_quotes_do_not_crash(self):
        self.assertEqual(reqs("pip install 'requests"), [(PYPI, "requests", None)])


if __name__ == "__main__":
    unittest.main()
