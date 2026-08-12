.PHONY: test validate plan capabilities compose-smoke mac-preflight

test:
	pytest

validate:
	python -m azazel_deception validate examples/packages/municipal-linux-v1/package.yaml

plan:
	python -m azazel_deception plan examples/packages/municipal-linux-v1/package.yaml --tier lite

capabilities:
	python -m azazel_deception capabilities

compose-smoke:
	bash scripts/dev/reference-compose-smoke.sh

mac-preflight:
	bash scripts/dev/macos-arm64-preflight.sh
