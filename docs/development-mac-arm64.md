# Development profile: Apple Silicon MacBook Pro

This profile treats an Apple Silicon MacBook Pro as the primary developer workstation while keeping Linux as the attacker-facing AZ-06 runtime target.

## What this workstation can prove

On the local Mac with Docker Desktop or a compatible Linux-container runtime:

- native ARM64 Python/package/contract behavior
- canonical Fabric package validation
- canonical package content digest, seal, and payload reconstruction
  (`make digest`, `make seal`, `make canonical-payload`), which are
  representation-invariant and computed on the Mac without any Linux runtime
- host capability discovery
- deterministic `lite` placement against the Docker runtime
- native ARM64 reference-container startup inside the Linux VM
- no published host ports in the reference Compose profile
- internal-only Compose network
- read-only root filesystem
- non-root container user
- all Linux capabilities dropped
- `no-new-privileges`
- CPU, memory, and PID limits
- machine-readable portability evidence

The reference image is pulled by immutable GHCR digest. If the package is not
publicly readable in your local Docker session, authenticate to `ghcr.io`
before running the preflight using a GitHub token with package read access.
Do not store that token in the repository or pass it as a Docker build argument.

Run:

```bash
make mac-preflight
```

## Virtual Phase-1 Lab

`make virtual-lab` (`scripts/dev/virtual_phase1_lab.py`) drives the full AZ-06
software lifecycle against a real container:

```text
package -> placement -> runtime preflight -> controlled activation
        -> status/evidence -> termination -> reset
```

It passes `live_enabled=True` explicitly (it changes no default) and uses the
real `GitHubAttestationPackageVerifier` by default, so package authenticity is
genuinely verified against the GitHub artifact attestation; it fails closed if
`gh`, the network, or the attestation is unavailable. Synthetic Edge decisions
are generated locally and carry no real Edge authority. A dev-only
`--simulated-verification` flag exists for offline runs; it lives only in the
script, prints a loud warning, and is never importable by the shippable package.

The lab writes an evidence report to `artifacts/lab/virtual-phase1-lab.json` and
asserts the `activated`/`terminated`/`reset_completed` lifecycle events and
one-shot decision consumption. It proves the **software** lifecycle on an
internal-only network with no published host ports. It does **not** prove
physical NIC/VLAN isolation, protected-network route denial, or any real-
hardware property — those remain HIL gates.

Evidence is written to:

```text
artifacts/portability/macos-arm64-local.json
```

The `artifacts/` directory is intentionally ignored by Git.

## What GitHub Actions supplies instead of a local AMD64 machine

The `Portability` workflow runs the same contract/package tests natively on:

- `ubuntu-24.04` (`amd64`)
- `ubuntu-24.04-arm` (`arm64`)
- `macos-15` (`arm64` host logic)

The two Linux jobs also start the same digest-pinned isolated reference Compose
runtime and archive a JSON evidence artifact. This provides continuous native
Linux ARM64/AMD64 software portability evidence without requiring a physical
AMD64 workstation.

The `Reference Image` workflow separately builds the reference web image on
native Linux AMD64 and ARM64 runners, combines the platform manifests into one
immutable multi-architecture OCI manifest, and records GitHub/Sigstore build
provenance.

## What this does not prove

Neither Docker Desktop nor GitHub-hosted runners replace final field/HIL validation. The following remain hardware/lab gates:

- physical NIC/VLAN behavior
- protected-network route isolation under realistic topology
- Edge-to-AZ-06 management-network separation
- power loss and host thermal behavior
- physical storage behavior
- long-duration resource exhaustion
- real attacker-flow channeling through an Edge appliance
- production-style reset after attacker modification

A physical AMD64 host is therefore **not a current development blocker**. It remains an optional later certification target. The required Phase-1 software portability proof is native Linux ARM64 + native Linux AMD64 in CI plus the local Apple Silicon ARM64 development run.

## macOS boundary

macOS host capability reports are descriptive. They deliberately report no KVM, Linux network namespace, or nftables capability. Docker Desktop runs Linux containers inside its own Linux VM; AZ-06 must not claim that the macOS host itself provides Linux HIL isolation.

Live attacker-facing activation remains disabled until the repository's live-gate checklist is satisfied.
