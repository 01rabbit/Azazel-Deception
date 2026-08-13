.PHONY: test validate plan capabilities digest seal canonical-payload compose-smoke mac-preflight

PACKAGE ?= examples/packages/municipal-linux-v1/package.yaml

test:
	pytest

validate:
	python -m azazel_deception validate $(PACKAGE)

plan:
	python -m azazel_deception plan $(PACKAGE) --tier lite

capabilities:
	python -m azazel_deception capabilities

digest:
	python -m azazel_deception digest $(PACKAGE)

canonical-payload:
	python -m azazel_deception canonical-payload $(PACKAGE)

# Emits a sealed package to stdout; never rewrites $(PACKAGE) in place.
seal:
	python -m azazel_deception seal $(PACKAGE)

compose-smoke:
	bash scripts/dev/reference-compose-smoke.sh

mac-preflight:
	bash scripts/dev/macos-arm64-preflight.sh
