# Architecture

## Product identity

Azazel-Deception Host is AZ-06, codename `THEATRE`, and provides the Azazel series' Engagement Environment Plane.

The product is **container-first, capability-aware, and hardware-independent**. Raspberry Pi 5 is the minimum reference host for `lite`; x86 mini PCs and larger hosts increase capacity without changing package identity or Edge authority.

## Responsibility rule

> Engage expresses intent. Knowledge advises. Fabric describes. Edge decides and enforces. Deception Host materializes, transitions, records, and resets.

AZ-06 is never a second decision authority.

## Planes

1. **Package plane** — immutable narrative, environment, artifact, credential, transition, and safety declarations.
2. **Control plane** — capability detection, package validation, placement planning, lifecycle, evidence, reset.
3. **Runtime adapter plane** — Docker Compose initially; Podman and KVM/libvirt later; cluster adapters only after single-node safety is proven.
4. **Execution plane** — isolated attacker-facing container/VM workloads.

## Portable baseline

Phase 1 targets OCI images on `linux/arm64` and `linux/amd64`. The same signed package identity must survive movement between hardware classes. Runtime-specific IDs are evidence metadata only.

## Authority

Edge may approve a target node or capability class, package/profile, deployment tier, resource budget, network exposure, transition, and termination. AZ-06 performs local placement inside that approved boundary.

AZ-06 must not infer authority from a Fabric payload, Knowledge advisory, package content, capability report, or local resource availability.

## Runtime adaptation

Runtime adaptation is a finite-state process. Free-form autonomous planning is prohibited. Live package mutation by LLM is prohibited.

The bootstrap implementation intentionally stops at deterministic placement planning and does not start containers.
