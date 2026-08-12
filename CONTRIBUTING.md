# Contributing

Azazel-Deception is an attacker-facing execution plane. Changes must preserve deterministic authority and fail-closed safety.

## Required design rules

- Edge remains the activation and transition authority.
- Fabric owns canonical shared wire contracts.
- Knowledge remains advisory-only.
- LLM output cannot select or execute live actions.
- No unrestricted decoy egress or production access.
- No `privileged` attacker-facing containers, Docker socket mounts, or host networking in reference profiles.
- ARM64 and AMD64 portability must be considered for Phase 1 changes.
- Required narrative components may not be silently omitted to fit weaker hardware.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
python -m azazel_deception validate examples/packages/municipal-linux-v1/package.yaml
```

Bootstrap commands are non-executing. Do not add live execution without an issue that identifies the Fabric contract version, Edge authorization path, isolation tests, termination semantics, and reset proof.
