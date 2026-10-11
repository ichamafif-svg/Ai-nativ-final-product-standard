.PHONY: check budget test

check: budget test

budget:
	python3 tools/check_tcb.py

test:
	cd tests && python3 -W error::ResourceWarning -m unittest -v test_kernel test_trusted test_maintenance test_coverage test_install test_hosting test_agent test_web test_run test_isolation test_build test_boundary
