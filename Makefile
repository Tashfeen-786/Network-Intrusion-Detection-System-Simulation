.PHONY: setup dataset train evaluate test backend frontend demo clean
setup:
	python -m venv .venv && .venv/bin/pip install -r requirements.txt
	cd frontend && npm install
dataset:
	python -m simulator.generate_dataset --count 5000 --output data/network_traffic.csv
train:
	python -m ml.train_model
evaluate:
	python -m ml.evaluate && python -m ml.tune
test:
	pytest -q
backend:
	uvicorn backend.app:app --host 0.0.0.0 --port 8000
frontend:
	cd frontend && npm run dev -- --host 0.0.0.0
demo:
	python -m simulator.traffic_simulator --mode mixed --speed fast --count 30
clean:
	rm -f data/ids.db data/ids.db-* && rm -rf frontend/dist .pytest_cache
