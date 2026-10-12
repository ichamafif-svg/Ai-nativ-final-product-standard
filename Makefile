.PHONY: check layers test
PYTHON ?= python3

check: layers test

layers:
	$(PYTHON) tools/check_layers.py

test:
	GIT_AUTHOR_NAME="$${GIT_AUTHOR_NAME:-standard-tests}" \
	GIT_AUTHOR_EMAIL="$${GIT_AUTHOR_EMAIL:-tests@standard.invalid}" \
	GIT_COMMITTER_NAME="$${GIT_COMMITTER_NAME:-standard-tests}" \
	GIT_COMMITTER_EMAIL="$${GIT_COMMITTER_EMAIL:-tests@standard.invalid}" \
	$(PYTHON) -W error::ResourceWarning -m unittest discover -s tests -p 'test_*.py' -v
