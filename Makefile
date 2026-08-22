# Local CI — the single gate. Run `make check` before finishing any task.
# Fast tools only (hackathon): ruff, ty, pytest, oxlint, tsc, vitest, clang.

BACKEND := backend
DASH := dashboard

.PHONY: check fix \
        back-lint back-types back-test back-fix \
        front-lint front-types front-test \
        oracle-build \
        setup

## check: run EVERYTHING (this is the gate)
check: back-lint back-types back-test oracle-build front-lint front-types front-test
	@echo "\n✅ all checks passed"

## fix: auto-fix what can be auto-fixed
fix: back-fix
	cd $(DASH) && npm run lint -- --fix || true

# --- backend (Python via uv) ---------------------------------------------
back-lint:
	cd $(BACKEND) && uv run ruff check . && uv run ruff format --check .

back-types:
	cd $(BACKEND) && uv run ty check app

back-test:
	cd $(BACKEND) && uv run pytest

back-fix:
	cd $(BACKEND) && uv run ruff format . && uv run ruff check --fix .

# --- dashboard (React/Vite) ----------------------------------------------
front-lint:
	cd $(DASH) && npm run lint

front-types:
	cd $(DASH) && npm run typecheck

front-test:
	cd $(DASH) && npm run test

# --- oracle (C) — compile the harness against the sample filter ----------
oracle-build:
	@tmp=$$(mktemp -d); \
	cp $(BACKEND)/oracle/harness.c $$tmp/harness.c; \
	cp $(BACKEND)/oracle/filters/deauth.c $$tmp/filter.c; \
	clang -Wall -Werror -std=c11 $$tmp/harness.c -o $$tmp/test && \
	$$tmp/test $(BACKEND)/oracle/fixtures/attack.hex $(BACKEND)/oracle/fixtures/benign.hex; \
	rc=$$?; rm -rf $$tmp; \
	if [ $$rc -ne 0 ]; then echo "❌ oracle harness failed"; exit 1; fi; \
	echo "✅ oracle harness OK"

# --- first-time setup ----------------------------------------------------
setup:
	cd $(BACKEND) && uv sync
	cd $(DASH) && npm install
