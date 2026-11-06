#!/usr/bin/env bash
# Set up Hermes Agent in a GitHub Codespace (or any Linux box) and check this plugin with
# Hermes's own tools: bash scripts/codespace-setup.sh
set -uo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.local/bin:$PATH"

step() { printf '\n==== %s\n' "$*"; }

if ! command -v hermes >/dev/null 2>&1; then
  step "Installing Hermes Agent (no browser, no computer-use driver)"
  curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --skip-browser --skip-computer-use --non-interactive
  export PATH="$HOME/.local/bin:$PATH"
fi

step "Hermes version"
hermes --version

step "Cooldown's own tests"
python3 -m unittest discover -s "$here/tests" 2>&1 | tail -3

step "hermes plugins validate (what the catalog CI runs)"
hermes plugins validate "$here" --install-deps
validate=$?

step "hermes plugins doctor"
hermes plugins doctor "$here" --ci
doctor=$?

step "Installing and enabling Cooldown from GitHub"
hermes plugins install Savage27z/cooldown --enable --force </dev/null
hermes plugins list 2>/dev/null | grep -i cooldown

step "Summary"
echo "validate exit: $validate   doctor exit: $doctor"
echo "Next: connect a model with 'hermes model' (or 'hermes setup'), then start 'hermes' and ask it to"
echo "install something, for example: install typescript@next with npm"
