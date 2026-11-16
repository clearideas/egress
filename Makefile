PYTHON ?= python3

.PHONY: test test-docker unit lint e2e perf e2e-baseline docker-e2e docker-smoke

# Everything, in one command: unit tests, E2E (bubblewrap sandbox, or Docker when bwrap can't run
# here) and the image smoke test (when Docker is available). Fails instead of skipping when no E2E
# runner can work. See scripts/test.sh (EGRESS_TEST_RUNNER=auto|bwrap|docker|none).
test:
	scripts/test.sh

# Same, forcing the Docker runner (E2E inside a container built from the production image).
test-docker:
	EGRESS_TEST_RUNNER=docker EGRESS_TEST_SMOKE=1 scripts/test.sh

unit:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests/unit -t . -v

lint:
	$(PYTHON) -m compileall -q src tests

# End-to-end tests in a bubblewrap sandbox (no root, no Docker). Downloads the pinned toolchain on first run.
e2e:
	tests/e2e/run.sh -v

# End-to-end tests inside a container built from the production image (Alpine Squid, installed package).
docker-e2e:
	tests/docker/e2e.sh -v

# Black-box test of the production image on a private Docker network (read-only, no capabilities).
docker-smoke:
	$(PYTHON) tests/docker/smoke.py

# Load test in the same sandbox (make perf EGRESS_PERF_SECONDS=8); prints throughput and latency.
perf:
	EGRESS_E2E_SUITE=tests/perf tests/e2e/run.sh -v

# Run the regression tests against a checkout of the pre-remediation code, e.g.
#   make e2e-baseline BASELINE=/path/to/old/checkout
e2e-baseline:
	EGRESS_E2E_TARGET=baseline EGRESS_E2E_BASELINE_DIR=$(BASELINE) tests/e2e/run.sh -v
