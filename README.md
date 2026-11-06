# Cooldown

**Hermes waits three days before it trusts a new release of its own dependencies. Cooldown gives
everything Hermes installs for you the same rule.**

When the agent runs `pip install`, `npm install`, `npx`, `uvx` and friends, Cooldown looks up each
package before the command runs:

| What it finds | What happens |
|---|---|
| OSV lists that exact version as malicious | **Blocked.** The agent is told why. |
| The version was published less than 3 days ago | **Asks you first**, through Hermes's own approval prompt, and names an older version that has passed the cooldown. |
| The package itself first appeared less than 30 days ago | **Asks you first.** |
| The name is not on the registry (a typo, or a removed release) | **Asks you first.** |
| A registry could not be reached in time | **Asks you first** (configurable). |
| Anything else | Runs silently. You never notice Cooldown. |

Hijacked and typosquatted releases are usually caught and pulled within days. An agent that
installs on its own does not wait. Cooldown makes it wait.

```text
$ npm install typescript@next
Cooldown: this install needs your OK.
- typescript@7.1.0-dev.20261106.1 was published 5 hours ago; Cooldown waits 3 days, the same rule
  Hermes uses for its own dependencies. Older version that has passed the cooldown:
  typescript@7.1.0-dev.20261103.1 (published 3 days ago).

$ pip install mistralai==2.4.6
Cooldown blocked this install:
- OSV lists mistralai==2.4.6 as malicious (GHSA-wx9m-wx4f-4cmg: Malicious dropper in mistralai
  2.4.6 PyPI package).
```

Approvals go wherever your Hermes approvals already go: the terminal, Hermes Desktop, or your phone
through the messaging gateway. A denied or timed-out approval fails closed.

## Install

```bash
hermes plugins install cooldown
hermes plugins enable cooldown
```

Or from this repository: `hermes plugins install https://github.com/Savage27z/cooldown`.

## Use

Nothing to do: Cooldown checks every terminal command the agent runs. In a chat:

- `/cooldown` lists the most recent checks.
- `/cooldown check npm install some-package` dry-runs a command: it reports what Cooldown would do
  and runs nothing.

## Settings

Under `plugins.entries.cooldown.settings` in `config.yaml`, or in Hermes Desktop under
Settings → Plugins → Cooldown:

| Key | Default | Meaning |
|---|---|---|
| `min_age_days` | `3` | Ask before installing a release younger than this. |
| `new_package_days` | `30` | Ask before installing a package that first appeared more recently than this. |
| `on_lookup_failure` | `ask` | `ask` or `allow` when a registry cannot be reached in time. |
| `allow` | `[]` | Package names never checked, such as your own internal packages. |

## What it covers

- **Python:** `pip install`, `python -m pip install`, `uv pip install`, `uv add`, `uv tool install|run`,
  `uvx`, `pipx install|run`, `poetry add`.
- **JavaScript:** `npm install|i|add`, `pnpm add`, `yarn add`, `bun add`, `npx`, `bunx`, `pnpm dlx`,
  `yarn dlx`, including release channels such as `@next` and `@canary`.
- Several commands chained with `&&`, `;` or pipes, `sudo` and environment-variable prefixes.

**Not covered**, and said so in the prompt when it applies:

- Requirement files (`-r requirements.txt`), URLs, Git and local paths are reported as "not checked".
- Lockfile installs (`npm ci`, a bare `npm install`, `uv sync`) are left alone: the project already
  chose those versions.
- A version range such as `requests>=2` is checked as the latest release, which is what an installer
  normally picks.
- Only the `terminal` tool. Code run through `execute_code` that calls pip itself is not seen.
- Private registries: add internal package names to `allow`.

## Disclosure

- **Network calls.** For each package in an install command, Cooldown sends the package name and
  version (never your code, files or prompts) to: `api.deps.dev` (publish dates),
  `registry.npmjs.org` (latest version, install scripts), `pypi.org` (upload time of very new
  releases) and `api.osv.dev` (malicious-package advisories). All are free public APIs; no account,
  key or credential is used.
- **What it reads.** Only the text of terminal commands the agent is about to run, to find install
  commands. It reads no files.
- **What it stores.** The last 50 decisions (time, command, packages, verdict) in this plugin's own
  state under `HERMES_HOME/plugin-data/`, for `/cooldown`. Nothing is sent anywhere else.
  No telemetry.
- **What it runs.** No shell commands and no background processes. It never approves anything on
  your behalf: it only adds a block or an approval request, and Hermes's approval system decides.
- **Dependencies.** None: Python standard library only.

## Develop

```bash
python -m unittest discover -s tests     # 41 offline tests
python scripts/live_check.py              # live run against the real registries
python scripts/live_check.py "npm install left-pad"
```

## License

MIT
