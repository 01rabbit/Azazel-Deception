.PHONY: test validate plan capabilities digest seal canonical-payload compose-smoke mac-preflight virtual-lab so08-virtual-lab

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

# Controlled software lifecycle simulation on a real container. Uses the real
# GitHub attestation verifier by default; requires Docker + an authenticated gh.
# The lab runs with the strict reference-deployment posture by default, so
# --sbom-verify and --authenticate configure the gates it now requires.
virtual-lab:
	python scripts/dev/virtual_phase1_lab.py --sbom-verify --authenticate --output artifacts/lab/virtual-phase1-lab.json

# SO-08 isolation-drift detection, namespace virtual lab. Linux + root only
# (in a container: --privileged). A regression signal, never a gate: the record
# is class virtual-lab-regression, gate false, verdict never pass. Exit 2 means
# the lab did not run, which is never green. See docs/so08-isolation-drift.md.
so08-virtual-lab:
	python scripts/dev/so08_drift_lab.py --output artifacts/so08/so08-virtual-lab.json

mac-preflight:
	bash scripts/dev/macos-arm64-preflight.sh
