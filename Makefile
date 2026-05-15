build:
	uv build

install:
	uv sync

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

test:
	pytest

style_check:
	isort --check-only slip10/ tests/
	black slip10/ tests/ --check

style:
	isort slip10/ tests/
	black slip10/ tests/


.PHONY: clean clean-build clean-pyc clean-test test style_check style
