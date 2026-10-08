# Local development for the Teger AI platform (v1). Legacy backend/dashboard keep
# their own instructions in README.md.
PYTHON ?= python3
LINT_PATHS = packages services ml backend

.PHONY: install test lint eval schemas audit api web-install web

install:
	$(PYTHON) -m pip install -r requirements-platform.txt -r backend/requirements.txt -r backend/requirements-dev.txt

test:
	$(PYTHON) -m pytest -q packages services ml/evaluation backend dataset

lint:
	$(PYTHON) -m flake8 $(LINT_PATHS) --max-line-length=120
	$(PYTHON) -m teger_contracts.export_schemas --check

eval:
	$(PYTHON) ml/evaluation/harness.py

schemas:
	$(PYTHON) -m teger_contracts.export_schemas

audit:
	$(PYTHON) -m pip_audit -r backend/requirements.txt
	$(PYTHON) -m pip_audit --skip-editable

# Development server with the MOCK reputation provider (never use mock in production).
api:
	TEGER_ENV=development TEGER_REPUTATION_PROVIDER=mock $(PYTHON) -m uvicorn teger_api.main:app --reload --port 8100

web-install:
	cd apps/web && npm ci

web:
	cd apps/web && npm run dev
