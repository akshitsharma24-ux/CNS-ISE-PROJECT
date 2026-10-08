.PHONY: setup test demo retrain clean lint

setup:
	python -m pip install --upgrade pip
	python -m pip install -r requirements.txt
	python -m scripts.seed_registry

test:
	python -m pytest tests/ -v

demo:
	python -m scripts.seed_registry
	python -m uvicorn qrshield.app.api:app --host 0.0.0.0 --port 8000 --reload

retrain:
	python -m scripts.retrain

lint:
	python -m pytest --version
