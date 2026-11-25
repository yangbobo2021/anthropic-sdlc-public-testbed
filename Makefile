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
