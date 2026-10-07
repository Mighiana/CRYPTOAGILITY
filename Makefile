PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
RESULTS ?= results
ITERATIONS ?= 20
WARMUPS ?= 3

.PHONY: help setup lint test test-fast lab benchmark report docker-build docker-lab \
	compose-interop clean

help:
	@echo "make setup            create .venv, install pinned deps, build pinned OpenSSL 3.5.9 into .tools/"
	@echo "make lint             ruff check + ruff format --check + mypy"
	@echo "make test             full test suite (unit + loopback TLS integration)"
	@echo "make test-fast        unit tests only (no OpenSSL handshakes)"
	@echo "make lab              full synthetic-scenario pipeline into $(RESULTS)/ (+ report.html)"
	@echo "make benchmark        benchmarks only into $(RESULTS)/benchmark.json"
	@echo "make report           re-render $(RESULTS)/report.html from existing evidence"
	@echo "make docker-build     build the lab image (builds OpenSSL inside the image)"
	@echo "make docker-lab       run the lab pipeline in a container into ./$(RESULTS)"
	@echo "make compose-interop  classical/hybrid/PQC servers + strict client over a container network"
	@echo "make clean            remove results, caches and the venv (keeps the OpenSSL build cache)"

$(BIN)/cryptoagility: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip==25.2
	$(BIN)/pip install --quiet -e ".[dev]"
	@touch $@

setup: $(BIN)/cryptoagility
	BUILD_JOBS=$$(nproc 2>/dev/null || echo 4) scripts/setup-openssl.sh
	$(BIN)/cryptoagility --openssl-version

lint: $(BIN)/cryptoagility
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/mypy cryptoagility tests

test: $(BIN)/cryptoagility
	$(BIN)/pytest -q

test-fast: $(BIN)/cryptoagility
	$(BIN)/pytest -q -m "not integration"

lab: $(BIN)/cryptoagility
	RESULTS=$(RESULTS) ITERATIONS=$(ITERATIONS) WARMUPS=$(WARMUPS) scripts/run-lab.sh

benchmark: $(BIN)/cryptoagility
	$(BIN)/cryptoagility benchmark --iterations $(ITERATIONS) --warmups $(WARMUPS) \
		-o $(RESULTS)/benchmark.json

report: $(BIN)/cryptoagility
	$(BIN)/cryptoagility report $(RESULTS)

docker-build:
	docker compose build

docker-lab: docker-build
	mkdir -p $(RESULTS)
	docker compose run --rm cryptoagility-tool lab /results \
		--iterations $(ITERATIONS) --warmups $(WARMUPS)

compose-interop: docker-build
	docker compose up --abort-on-container-exit --exit-code-from test-client \
		classical-server hybrid-server pqc-server test-client
	docker compose down --volumes

clean:
	rm -rf $(RESULTS) $(VENV) build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache
	find . -name __pycache__ -type d -prune -not -path "./.tools/*" -exec rm -rf {} +
