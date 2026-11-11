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
fails the test.

These are local container/static-canary plumbing checks. They do not certify
production package trust, Edge routing, protected-network isolation, independent
host/UID observation, attack attribution, AI identity, deception effectiveness,
Knowledge receipt, portability or hardware/HIL acceptance. They do not enable a
product listener or change the reference Compose. Default skip and fixture-pin
checks can run without Docker; an executed runtime result must be recorded
separately before claiming the two actual-container tests passed.
