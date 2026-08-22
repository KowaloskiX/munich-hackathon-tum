# Local CI — the single gate. Run `make check` before finishing any task.
# Fast tools only (hackathon): ruff, ty, pytest, oxlint, tsc, vitest, clang.

BACKEND := backend
DASH := dashboard
ORACLE_CC ?= clang

.PHONY: check fix \
        back-lint back-types back-test back-fix \
        front-lint front-types front-test \
        oracle-build red-esp-test \
        setup doctor

## check: run EVERYTHING (this is the gate)
check: back-lint back-types back-test oracle-build red-esp-test front-lint front-types front-test
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
	$(ORACLE_CC) -Wall -Werror -std=c11 $$tmp/harness.c -o $$tmp/test && \
	$$tmp/test $(BACKEND)/oracle/fixtures/attack.hex $(BACKEND)/oracle/fixtures/benign.hex; \
	rc=$$?; rm -rf $$tmp; \
	if [ $$rc -ne 0 ]; then echo "❌ oracle harness failed"; exit 1; fi; \
	echo "✅ oracle harness OK"

# --- red ESP attack-profile core (host build, no board required) ---------
red-esp-test:
	@tmp=$$(mktemp -d); \
	$(CXX) -Wall -Wextra -Werror -pedantic -std=c++17 \
		-Iesp-attacker/lib/attack_core/include \
		-Iesp-common/demo_protocol/include \
		esp-attacker/lib/attack_core/src/attack_core.cpp \
		esp-common/demo_protocol/src/demo_protocol.cpp \
		esp-attacker/test/test_attack_core.cpp \
		-o $$tmp/red-esp-test && $$tmp/red-esp-test; \
	rc=$$?; rm -rf $$tmp; \
	if [ $$rc -ne 0 ]; then echo "❌ red ESP core tests failed"; exit 1; fi; \
	echo "✅ red ESP core tests OK"

## doctor: is this machine able to run the demo at all (tools, pins, ports)
doctor:
	@./scripts/doctor.sh

# --- first-time setup ----------------------------------------------------
setup:
	cd $(BACKEND) && uv sync
	cd $(DASH) && npm install
