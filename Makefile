.PHONY: up down install test unit sim load serve worker openapi demo inventory inventory-report

up:          ## start Postgres (TimescaleDB) + Redis
	docker compose up -d --wait
down:
	docker compose down
install:
	uv sync
unit:        ## no Docker needed
	uv run pytest tests/test_httpsig.py tests/test_tokens.py tests/test_scorer.py -q
test: up     ## unit + integration
	uv run pytest -q
sim: up      ## 30 simulated minutes of mixed traffic -> reports/sim-report.md
	uv run python -m sim.run --minutes 30
load: up     ## latency at 2000 rps, then saturation at 1000 concurrent clients
	uv run python -m loadtest.run --mode open --rps 2000 --concurrency 1000 --duration 30
	uv run python -m loadtest.run --mode closed --concurrency 1000 --duration 30
serve: up
	uv run uvicorn ffpverify.api.app:app --reload --port 8000
worker: up
	uv run python -m ffpverify.risk.worker
openapi:
	uv run python -c "import json; from ffpverify.api.app import create_app; print(json.dumps(create_app().openapi(), indent=2))" > docs/openapi.json

demo: up     ## wipe the dev DB, seed simulated traffic, print UI credentials
	uv run python -m sim.demo

inventory: up ## (re)seed simulated redemption inventory for the airlines already in the dev DB
	uv run python -m sim.inventory
inventory-report: up ## what redemption space is available / missing -> reports/inventory-coverage.md
	uv run python -m sim.inventory_report
