# Opt-in actual-container canary regression (#31/#74)

`tests/test_canary_docker.py` extends the existing Docker lifecycle harness with
actual static canary presentation in the pinned reference nginx image. It is
skipped unless `AZAZEL_DECEPTION_DOCKER_TESTS=1` and Docker is reachable. The exact
reference image must already be staged locally; image absence fails, and the
generated test Compose uses `pull_policy: never`. The test performs no pulls,
package downloads, host Docker changes, external HTTP requests or port publishing.

```sh
PYTHONPATH=src:. AZAZEL_DECEPTION_DOCKER_TESTS=1 python -m pytest -q tests/test_canary_docker.py
```

The test retains the existing package, placement, one-shot ledger, validity,
supply-chain-reference, runtime policy and Compose/image binding checks. Its
**local lab admission** additionally checks the exact canonical package SHA-256
and reference image pin, and signs decisions using a fresh per-run HMAC key.
The package/SBOM callbacks check fixture identity only; they do not verify GitHub
attestations or SBOM authenticity/content. This is explicitly not production
admission or genuine Edge approval. No production verifier or adapter default is
changed. Existing real verifiers remain unavailable/fail-closed when their
network/attestation prerequisites are absent; this test does not introduce an
offline production trust mechanism.

A generated test-only Compose mounts a synthetic web directory and nginx config
read-only into the same reference component. It retains user 101, read-only
rootfs, all capabilities dropped, no-new-privileges, existing CPU/memory/PID
limits, one internal network and no host ports. Actual container/network inspect
readback checks those settings and the read-only mounts. No runtime socket is
mounted. The private host parent directory is mode 0700; the readable leaf alone
is mounted into the decoy. Access logging is disabled before the first request.

A separate `docker exec` client reads actual nginx HTTP status and body over
container-local `127.0.0.1:8080`. The token-bearing path is passed over stdin,
not host command arguments. Exact presentation bytes and marker status/body
must match before the owning registry reports a presentation and projects the
matched touch through the existing InteractionObserver and observation export.
This is a controlled local client, not an unsolicited attacker-intake adapter.
Real TTL expiry removes the served marker; another actual HTTP request must
return 404, and the expired token must fail registry matching. The test waits
approximately 30 seconds for real expiry rather than advancing a test clock.

Actual container logs and the evidence chain must omit the token. The final
result includes only status codes/counts and explicit
`production_admission: false`; it contains no token, document, request path or
raw logs. Signed termination must remove the container and network, registry
reset must reject old tokens, and reset must preserve exported observations and
an intact evidence chain. A replacement registry also rejects the old token.
A separate failure test injects an evidence error after actual HTTP readback:
it must produce no success result, independently confirm actual teardown and
remove the secret artifacts. Every runtime exit path attempts project cleanup
and independently checks for remaining containers/networks; cleanup failure
fails the test. Compose teardown, independent container/network absence checks,
marker removal and document removal are each attempted even if earlier steps
fail. A failed marker unlink cannot skip document cleanup. Aggregate cleanup
errors retain the original runtime error and individual failed steps; error
messages omit secret filenames and raw artifact contents.

These are local container/static-canary plumbing checks. They do not certify
production package trust, Edge routing, protected-network isolation, independent
host/UID observation, attack attribution, AI identity, deception effectiveness,
Knowledge receipt, portability or hardware/HIL acceptance. They do not enable a
product listener or change the reference Compose. Default skip and fixture-pin
checks can run without Docker; an executed runtime result must be recorded
separately before claiming the two actual-container tests passed.

## Explicit strict offline supply-chain mode

The legacy fixture-pin mode above remains the default and the two Docker tests
remain skipped without the existing explicit Docker opt-in. Set
`AZ06_CANARY_STRICT_OFFLINE=1` to replace **both** fixture callbacks with the real
`OfflineGitHubAttestationPackageVerifier` and `OfflineGitHubSbomVerifier`. An
invalid flag, missing material, failed cryptographic proof or failed guard
refuses; there is no fixture fallback. This test-only wiring changes no product
adapter, policy, reference Compose, dependency or authorization default.

Strict execution requires an independently reviewed fresh disposable Linux VM,
root, and the protected literal marker `/etc/az06-canary-disposable-vm` containing
`az06-canary-disposable-vm-v1` plus a newline. The protected-reader checks the
marker's owner, writable permissions, single-link regular-file identity and
physical ancestors; provision it root-owned mode 0644. VM identity is checked
with `systemd-detect-virt --vm`. Both root IPv4/IPv6 default routes must be absent
before execution. The test does not remove routes or provision the marker.
These gates constrain a local lab; they do not prove global host isolation or
that a compromised host has no alternate escape path.

Prestage the exact reference image, platform-native independently pinned GitHub
CLI, reviewed trusted-root snapshot, genuine canonical-package bundle and the
complete raw OCI index/attestation/SPDX graph plus genuine SPDX bundle. Supply
these existing interfaces:

- `AZ06_OFFLINE_GH_PATH`, `AZ06_OFFLINE_GH_SHA256`;
- `AZ06_OFFLINE_ROOT_PATH`, `AZ06_OFFLINE_ROOT_SHA256`;
- `AZ06_OFFLINE_BUNDLE_PATH`, `AZ06_OFFLINE_TEMP_PARENT`;
- `AZ06_OFFLINE_SPDX_MAP` using the exact protected image/artifact map in
  [offline SPDX verification](OFFLINE_SBOM_VERIFICATION.md).

The map itself is bounded, strictly parsed and protected-read. All verifier
inputs retain their existing physical-path/owner/permission/identity/pin checks.
The explicit verification workspace **and** pytest's `--basetemp` must be under
protected physical ancestors such as a new `/opt/az06-canary-run-*` directory;
`/tmp`, symlinked paths and group/world-writable ancestors refuse. Public staging
and pin review happen separately, before the VM is disconnected. Nothing here
fetches material, substitutes a publisher/root or repairs missing artifacts.

The pure strict preflight actually runs both callbacks before Docker planning,
canary issuance or activation. The adapter then runs those same actual
callbacks again through its existing strict activation gates before consuming
the synthetic decision or starting nginx. The private web directory/config are
prepared before activation, with access logging disabled. In strict mode the
30-second token TTL starts and the files are planted only **after** successful
activation, so cryptographic verification cannot silently consume their TTL.
A missing or rejected input cannot bind/start a decoy or consume the decision.

Strict planning reads the local VM's actual Docker `Architecture`, `NCPU`,
`MemTotal`, `KernelVersion`, `DockerRootDir` and identity. Controller architecture
and kernel must agree; free storage is measured on that local Docker directory.
The Docker context must be `default` pointing to `unix:///var/run/docker.sock`;
remote hosts/contexts refuse before a daemon connection. An incompatible
`DOCKER_DEFAULT_PLATFORM` refuses before any Docker command. The actual
prestaged image architecture must agree with the daemon, and strict Compose
explicitly pins `platform: linux/<measured daemon architecture>`. After startup,
independent container/image inspection must show the same native image ID,
Linux OS and architecture; prestart metadata alone cannot establish which
variant actually ran. There is no fixed amd64 host plan in strict mode. Reports separate controller, daemon and image platform,
actual resources and supply-chain verification from the synthetic HMAC lab
signer. The real kernel boot UUID is used in the scoped canary registry.

```sh
# Provision all protected material/pins and disconnect this fresh VM first.
AZAZEL_DECEPTION_DOCKER_TESTS=1 AZ06_CANARY_STRICT_OFFLINE=1 \
PYTHONPATH=src:. python -m pytest -q tests/test_canary_docker.py \
  --basetemp=/opt/new-protected-canary-run
```

Successful strict reports explicitly distinguish verified offline package
signature and authenticated SPDX/platform binding from
`edge_decision_authority: synthetic_lab_HMAC_only`. They retain
`production_admission: false`, `genuine_edge_approval: false` and
`protected_host_isolation_verified: false`. Genuine Edge approval/routing,
protected-host isolation/escape, SBOM content policy, runtime image attestation,
efficacy and hardware/HIL remain open. An actual root-run result must be retained
before claiming strict-container execution passed. Pure refusal/host-readback
unit tests use no Docker start and make no cryptographic-positive claim.
