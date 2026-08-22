#!/usr/bin/env bash
# Preflight for a fresh machine or a fresh clone: are the tools there, do the
# pins agree, are the demo ports free.
#
# Deliberately plain bash - it has to work before `make setup` has ever run.
# Not part of `make check`: a busy port is a local fact, not a broken build.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; OFF=$'\033[0m'
errors=0
warnings=0

ok()   { printf '  %sOK%s   %s\n' "$GREEN" "$OFF" "$1"; }
warn() { printf '  %sWARN%s %s\n' "$YELLOW" "$OFF" "$1"; warnings=$((warnings + 1)); }
bad()  { printf '  %sFAIL%s %s\n' "$RED" "$OFF" "$1"; errors=$((errors + 1)); }

printf '\n%sTools%s\n' "$DIM" "$OFF"

want_node="$(tr -d '[:space:]' < .nvmrc 2>/dev/null)"
got_node="$(node --version 2>/dev/null | tr -d 'v')"
if [ -z "$got_node" ]; then
  bad "node: not found (CI uses .nvmrc = ${want_node:-?})"
elif [ "${got_node%%.*}" = "$want_node" ]; then
  ok "node $got_node (matches .nvmrc)"
else
  warn "node $got_node - .nvmrc and CI say ${want_node}.x; vite 8 needs >=22.12"
fi

if command -v uv >/dev/null 2>&1; then
  ok "uv $(uv --version 2>/dev/null | awk '{print $2}')"
else
  bad "uv: not found - the backend is uv-only (https://docs.astral.sh/uv/)"
fi

if command -v npm >/dev/null 2>&1; then
  ok "npm $(npm --version 2>/dev/null)"
else
  bad "npm: not found"
fi

# clang is not optional: `make oracle-build` and app/oracle.py both shell out to
# it. Without it the agent's filter is never actually verified.
if command -v clang >/dev/null 2>&1; then
  ok "clang $(clang --version 2>/dev/null | head -1 | awk '{print $NF}')"
else
  bad "clang: not found - the oracle cannot compile a filter (macOS: xcode-select --install)"
fi

printf '\n%sInstalled%s\n' "$DIM" "$OFF"
if [ -d backend/.venv ]; then ok "backend/.venv present"
else warn "no backend/.venv - run: make setup"; fi
if [ -d dashboard/node_modules ]; then ok "dashboard/node_modules present"
else warn "no dashboard/node_modules - run: make setup"; fi

printf '\n%sPorts%s\n' "$DIM" "$OFF"
check_port() { # port, what-uses-it
  local port="$1" what="$2" pid owner
  pid="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -1)"
  if [ -z "$pid" ]; then
    ok "$port free ($what)"
    return
  fi
  owner="$(ps -o comm= -p "$pid" 2>/dev/null | xargs basename 2>/dev/null)"
  warn "$port taken by '${owner:-unknown}' (pid $pid) - $what"
}
# The dashboard hardcodes ws://localhost:8000/live unless VITE_WS_URL is set,
# so a backend on a different port means a silently dead live feed.
check_port 8000 "backend uvicorn; the dashboard's default VITE_WS_URL points here"
check_port 5173 "vite dev server"

printf '\n'
if [ "$errors" -gt 0 ]; then
  printf '%sErrors: %d, warnings: %d%s\n' "$RED" "$errors" "$warnings" "$OFF"
  exit 1
fi
printf '%sEnvironment ready%s (warnings: %d)\n' "$GREEN" "$OFF" "$warnings"
