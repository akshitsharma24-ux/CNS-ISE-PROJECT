# QRshield - convenience targets for Linux / macOS / WSL. On Windows use run_demo.bat or `python -m qrshield ...`.
PY ?= python
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: setup demo https test data train-url train-cv evaluate demo-assets doctor clean

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -r requirements-dev.txt
	$(BIN)/python -m qrshield setup

demo:
	$(BIN)/python -m qrshield serve

https:
	$(BIN)/python -m qrshield serve --https --host 0.0.0.0

test:
	$(BIN)/python -m pytest

doctor:
	$(BIN)/python -m qrshield doctor

data:
	$(BIN)/python -m pip install -r requirements-train.txt
	$(BIN)/python -m qrshield data

train-url:
	$(BIN)/python -m qrshield train-url

train-cv:
	$(BIN)/python -m qrshield train-cv

evaluate:
	$(BIN)/python -m qrshield evaluate

demo-assets:
	$(BIN)/python -m qrshield demo-assets

clean:
	rm -rf .pytest_cache .qrshield data/cv_cache demo_assets
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
