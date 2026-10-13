.PHONY: check layers coverage test lock
PYTHON ?= python3

check: layers test

layers:
	$(PYTHON) tools/check_layers.py

coverage:
	$(PYTHON) -m tools.coverage

test:
	GIT_AUTHOR_NAME="$${GIT_AUTHOR_NAME:-standard-tests}" \
	GIT_AUTHOR_EMAIL="$${GIT_AUTHOR_EMAIL:-tests@standard.invalid}" \
	GIT_COMMITTER_NAME="$${GIT_COMMITTER_NAME:-standard-tests}" \
	GIT_COMMITTER_EMAIL="$${GIT_COMMITTER_EMAIL:-tests@standard.invalid}" \
	$(PYTHON) -W error::ResourceWarning -m unittest discover -s tests -p 'test_*.py' -v

# The dependency closure Standard installs: exact pins (measured by Standard's own floors) and the same closure with
# hashes (what installations and CI install with --require-hashes). Review it like code: it is part of T01.
LOCK = uv pip compile requirements.in --python-version 3.11 --python-platform x86_64-unknown-linux-gnu --no-header -q
lock:
	$(LOCK) --no-annotate -o requirements.txt
	$(LOCK) --generate-hashes -o requirements.hashes
