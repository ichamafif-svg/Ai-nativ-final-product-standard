.PHONY: check layers test
PYTHON ?= python3

check: layers test

layers:
	$(PYTHON) tools/check_layers.py

test:
	$(PYTHON) -W error::ResourceWarning -m unittest discover -s tests -p 'test_*.py' -v
