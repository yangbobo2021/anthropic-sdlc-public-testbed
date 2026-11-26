.PHONY: verify lint typecheck build test e2e-serve
PYTHON ?= python3
verify: lint typecheck build test
lint:
	$(PYTHON) -B -m tabnanny src tests
typecheck:
	$(PYTHON) -B -c 'from typing import get_type_hints; from src.service import response; assert get_type_hints(response) == {"path": str, "return": tuple[int, str]}'
build:
	$(PYTHON) -B -c 'from pathlib import Path; p = Path("src/service.py"); compile(p.read_text(), str(p), "exec")'
test:
	$(PYTHON) -B -m unittest discover -s tests
e2e-serve:
	$(PYTHON) -B src/service.py

.PHONY: package
package:
	mkdir -p dist
	git archive --format=tar HEAD src/service.py fixtures/release/input.txt | gzip -n > dist/release.tar.gz

.PHONY: monitor-dependency-feed monitor-container-feed monitor-secret-feed monitor-cloud-feed
monitor-dependency-feed monitor-container-feed monitor-secret-feed monitor-cloud-feed:
	@python3 test-fixtures/monitor-feed.py $(word 2,$(subst -, ,$@))

.PHONY: test-api test-client test-integration test-full-unit test-full-integration
test-api test-client test-integration:
	@python3 test-fixtures/check-groups.py impact $(patsubst test-%,%,$@)
test-full-unit test-full-integration:
	@python3 test-fixtures/check-groups.py full $(patsubst test-full-%,%,$@)

.PHONY: staging-deploy smoke-health smoke-key-path staging-security-report
staging-deploy:
	@python3 test-fixtures/staging-control.py deploy
smoke-health smoke-key-path:
	@python3 test-fixtures/staging-control.py smoke $(patsubst smoke-%,%,$@)
staging-security-report:
	@python3 test-fixtures/staging-control.py report

.PHONY: canary-verify-promotion canary-deploy canary-observe canary-advance canary-rollback
canary-verify-promotion canary-deploy canary-observe canary-advance canary-rollback:
	@python3 test-fixtures/canary-adapter.py $(patsubst canary-%,%,$@)
