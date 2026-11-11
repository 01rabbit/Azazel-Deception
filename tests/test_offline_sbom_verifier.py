"""Synthetic graph policy tests; opt-in real Sigstore evidence stays separate."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

from azazel_deception.package import (
    load_package,
    parse_package,
    calculate_package_digest,
)
from azazel_deception.runtime import offline_sbom_verifier as sbom

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def graph():
    root = Path(tempfile.mkdtemp(prefix="az06-spdx-test-", dir=Path.home().resolve()))
    try:
        state = SimpleNamespace(root=root)
        state.platforms = {"amd64": "sha256:" + "a" * 64, "arm64": "sha256:" + "b" * 64}
        state.predicates = {
            arch: dict(
                SPDXID="SPDXRef-DOCUMENT",
                spdxVersion="SPDX-2.3",
                documentNamespace="https://example.invalid/" + arch,
                packages=[],
                files=[],
            )
            for arch in state.platforms
        }
        state.layers = {
            arch: dict(
                _type="https://in-toto.io/Statement/v0.1",
                subject=[
                    dict(
                        name="not-used-for-platform-inference",
                        digest={"sha256": digest[7:]},
                    )
                ],
                predicateType=sbom.SPDX,
                predicate=state.predicates[arch],
            )
            for arch, digest in state.platforms.items()
        }
        state.layer_extra = None
        state.layer_size_delta = 0
        state.manifest_subject = None

        def provision():
            mapping = {}
            descriptors = []
            for arch, digest in state.platforms.items():
                blob = encoded(state.layers[arch])
                blob_digest = sha(blob)
                blob_path = root / (arch + ".blob")
                blob_path.write_bytes(blob)
                mapping[blob_digest] = blob_path
                layer = dict(
                    mediaType=sbom.INTOTO,
                    digest=blob_digest,
                    size=len(blob) + (state.layer_size_delta if arch == "amd64" else 0),
                    annotations={"in-toto.io/predicate-type": sbom.SPDX},
                )
                layers = [layer]
                if state.layer_extra is not None:
                    layers.append(state.layer_extra)
                manifest = dict(
                    schemaVersion=2,
                    mediaType=sbom.MANIFEST,
                    layers=layers,
                    subject=dict(
                        mediaType=sbom.MANIFEST,
                        digest=state.manifest_subject
                        if arch == "amd64" and state.manifest_subject
                        else digest,
                        size=123,
                    ),
                )
                raw = encoded(manifest)
                manifest_digest = sha(raw)
                path = root / (arch + ".manifest")
                path.write_bytes(raw)
                mapping[manifest_digest] = path
                descriptors.append(
                    dict(
                        mediaType=sbom.MANIFEST,
                        digest=digest,
                        size=123,
                        platform=dict(architecture=arch, os="linux"),
                    )
                )
                descriptors.append(
                    dict(
                        mediaType=sbom.MANIFEST,
                        digest=manifest_digest,
                        size=len(raw),
                        platform=dict(architecture="unknown", os="unknown"),
                        annotations={
                            "vnd.docker.reference.digest": digest,
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                    )
                )
            state.index = dict(
                schemaVersion=2, mediaType=sbom.INDEX, manifests=descriptors
            )
            state.mapping = mapping
            reindex()

        def reindex():
            state.index_bytes = encoded(state.index)
            state.image = "ghcr.io/01rabbit/test-reference@" + sha(state.index_bytes)
            index_path = root / "index.json"
            index_path.write_bytes(state.index_bytes)
            bundle = root / "bundle.jsonl"
            bundle.write_bytes(b"not-real-signatures")
            state.material = sbom.OfflineImageArtifacts(
                index_path, bundle, state.mapping
            )
            state.results = [
                dict(
                    verificationResult=dict(
                        statement=dict(
                            subject=[
                                dict(
                                    name=state.image.split("@")[0],
                                    digest={"sha256": state.image.split("@sha256:")[1]},
                                )
                            ],
                            predicateType=sbom.SPDX,
                            predicate=state.predicates[arch],
                        )
                    )
                )
                for arch in state.platforms
            ]
            cli = root / "gh"
            if not cli.exists():
                cli.write_bytes(b"not-a-real-cli")
            cli.chmod(0o500)
            trust = root / "trusted_root.jsonl"
            trust.write_bytes(b"not-a-real-root")
            state.verifier = sbom.OfflineGitHubSbomVerifier(
                cli,
                hashlib.sha256(cli.read_bytes()).hexdigest(),
                trust,
                hashlib.sha256(trust.read_bytes()).hexdigest(),
                root,
                {state.image: state.material},
            )
            raw = load_package(PACKAGE)
            info = raw["components"][0]["image"]
            info.update(
                image=state.image,
                manifest_digest=sha(state.index_bytes),
                platforms=[
                    dict(architecture=a, digest=d) for a, d in state.platforms.items()
                ],
            )
            raw["package_digest"] = calculate_package_digest(raw)
            state.package = parse_package(raw)

        state.provision = provision
        state.reindex = reindex
        provision()
        yield state
    finally:
        shutil.rmtree(root)


def graph_predicates(state):
    return sbom._platform_predicates(
        state.index_bytes, state.image, state.platforms, state.material
    )


def test_synthetic_complete_byte_chain_and_full_verified_predicates_match(graph):
    assert graph_predicates(graph) == sbom._verified_predicates(
        encoded(graph.results), graph.image
    )
    assert len(graph_predicates(graph)) == 2


@pytest.mark.parametrize(
    "fault",
    [
        "index_hash",
        "platform",
        "attachment_target",
        "duplicate_attachment",
        "descriptor_size",
        "manifest_subject",
        "unmapped",
        "blob_hash",
        "blob_size",
        "subject",
        "layer_type",
        "no_layer",
        "duplicate_layer",
        "predicate_changed",
    ],
)
def test_missing_ambiguous_or_changed_graph_refuses(graph, fault):
    s = graph
    if fault == "index_hash":
        s.index_bytes += b" "
    elif fault == "platform":
        s.index["manifests"][0]["digest"] = "sha256:" + "f" * 64
        s.reindex()
    elif fault == "attachment_target":
        s.index["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = (
            "sha256:" + "f" * 64
        )
        s.reindex()
    elif fault == "duplicate_attachment":
        s.index["manifests"][3]["annotations"]["vnd.docker.reference.digest"] = (
            s.platforms["amd64"]
        )
        s.reindex()
    elif fault == "descriptor_size":
        s.index["manifests"][1]["size"] += 1
        s.reindex()
    elif fault == "manifest_subject":
        s.manifest_subject = "sha256:" + "f" * 64
        s.provision()
    elif fault == "unmapped":
        s.mapping.pop(next(iter(s.mapping)))
    elif fault == "blob_hash":
        (s.root / "amd64.blob").write_bytes(b"changed")
    elif fault == "blob_size":
        s.layer_size_delta = 1
        s.provision()
    elif fault == "subject":
        s.layers["amd64"]["subject"][0]["digest"] = {"sha256": "f" * 64}
        s.provision()
    elif fault == "layer_type":
        s.layers["amd64"]["predicateType"] = "wrong"
        s.provision()
    elif fault == "no_layer":
        s.layers["amd64"]["_type"] = "unknown"
        s.provision()
    elif fault == "duplicate_layer":
        s.layer_extra = dict(
            mediaType=sbom.INTOTO,
            digest="sha256:" + "f" * 64,
            size=1,
            annotations={"in-toto.io/predicate-type": sbom.SPDX},
        )
        s.provision()
    else:
        # Index/blob graph can be valid while the actual verified predicate is different.
        output = json.loads(encoded(s.results))
        output[0]["verificationResult"]["statement"]["predicate"]["packages"] = [
            {"name": "different"}
        ]
        assert graph_predicates(s) != sbom._verified_predicates(
            encoded(output), s.image
        )
        return
    with pytest.raises((ValueError, OSError)):
        graph_predicates(s)


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b"{"]
)
def test_duplicate_nonfinite_and_malformed_json_refuses(raw):
    with pytest.raises(ValueError):
        sbom._json(raw)


@pytest.mark.parametrize(
    "fault",
    [
        "subject_digest",
        "subject_name",
        "predicate_type",
        "duplicate",
        "unsigned",
        "count",
    ],
)
def test_verified_output_requires_exact_subject_and_distinct_complete_predicates(
    graph, fault
):
    rows = json.loads(encoded(graph.results))
    if fault == "subject_digest":
        rows[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = (
            "f" * 64
        )
    elif fault == "subject_name":
        rows[0]["verificationResult"]["statement"]["subject"][0]["name"] = (
            "ghcr.io/other/image"
        )
    elif fault == "predicate_type":
        rows[0]["verificationResult"]["statement"]["predicateType"] = "wrong"
    elif fault == "duplicate":
        rows[1] = rows[0]
    elif fault == "unsigned":
        rows[0] = {"statement": rows[0]["verificationResult"]["statement"]}
    else:
        rows.pop()
    with pytest.raises(ValueError):
        sbom._verified_predicates(encoded(rows), graph.image)


def test_wrapper_fixed_policy_clean_environment_and_protected_snapshots(
    graph, monkeypatch
):
    calls = []
    monkeypatch.setenv("GH_TOKEN", "not-real")
    monkeypatch.setenv("HTTPS_PROXY", "http://invalid.local")

    def invoke(command, *, directory, environment):
        calls.append(command)
        assert directory.parent == graph.root
        assert command[0] == str(directory / "gh")
        assert Path(command[3]).read_bytes() == graph.index_bytes
        assert command[command.index("--repo") + 1] == "01rabbit/Azazel-Deception"
        assert command[command.index("--predicate-type") + 1] == sbom.SPDX
        assert "--deny-self-hosted-runners" in command and "--format" in command
        assert "--source-ref" not in command  # Preserve the existing SBOM policy.
        assert not any(x.startswith("oci://") for x in command)
        assert not {"GH_TOKEN", "GITHUB_TOKEN", "HTTPS_PROXY"} & environment.keys()
        assert not list(Path(environment["HOME"]).iterdir())
        return encoded(graph.results)

    monkeypatch.setattr(sbom, "_run_cli", invoke)
    assert graph.verifier(graph.package) is True  # Mocked CLI, no crypto claim.
    assert len(calls) == 1 and not Path(calls[0][0]).exists()


@pytest.mark.parametrize(
    "fault", ["cli_pin", "root_pin", "temp", "unsupported_map", "cli_failure"]
)
def test_wrapper_failures_never_become_approval(graph, monkeypatch, fault):
    verifier = graph.verifier
    if fault == "cli_pin":
        verifier = replace(verifier, gh_sha256="0" * 64)
    elif fault == "root_pin":
        verifier = replace(verifier, trusted_root_sha256="0" * 64)
    elif fault == "temp":
        verifier = replace(verifier, temporary_parent=Path("/tmp"))
    elif fault == "unsupported_map":
        verifier = replace(verifier, images={})

    def refuse(*a, **k):
        raise OSError("CLI refused")

    monkeypatch.setattr(sbom, "_run_cli", refuse)
    assert verifier(graph.package) is False


def test_streamed_cli_output_cap_kills_and_reaps(monkeypatch, children):
    monkeypatch.setattr(sbom, "MAX_OUTPUT_BYTES", 64)
    with pytest.raises(ValueError, match="byte bound"):
        sbom._run_cli(
            [
                sys.executable,
                "-c",
                'import os,time;os.write(1,b"x"*1000);time.sleep(10)',
            ],
            directory=Path.cwd(),
            environment={},
        )


def test_streamed_cli_absolute_deadline_does_not_reset_per_chunk(monkeypatch, children):
    monkeypatch.setattr(sbom, "CLI_SECONDS", 0.15)
    with pytest.raises(TimeoutError):
        sbom._run_cli(
            [
                sys.executable,
                "-c",
                'import os,time\nwhile True: os.write(1,b"x");time.sleep(.02)',
            ],
            directory=Path.cwd(),
            environment={},
        )


def test_streamed_cli_nonzero_refuses(children):
    with pytest.raises(ValueError, match="verification failed"):
        sbom._run_cli(
            [sys.executable, "-c", "raise SystemExit(1)"],
            directory=Path.cwd(),
            environment={},
        )


def test_real_prestaged_offline_spdx_verification(graph):
    if os.environ.get("AZ06_OFFLINE_SPDX_TEST") != "1":
        pytest.skip(
            "requires genuine prestaged Sigstore/OCI graph and pinned Linux CLI; run network-disabled"
        )
    mapping = sbom._json(Path(os.environ["AZ06_OFFLINE_SPDX_MAP"]).read_bytes())
    images = {
        image: sbom.OfflineImageArtifacts(
            Path(value["index_path"]),
            Path(value["bundle_path"]),
            {digest: Path(path) for digest, path in value["artifacts"].items()},
        )
        for image, value in mapping.items()
    }
    verifier = sbom.OfflineGitHubSbomVerifier(
        gh_path=Path(os.environ["AZ06_OFFLINE_GH_PATH"]),
        gh_sha256=os.environ["AZ06_OFFLINE_GH_SHA256"],
        trusted_root_path=Path(os.environ["AZ06_OFFLINE_ROOT_PATH"]),
        trusted_root_sha256=os.environ["AZ06_OFFLINE_ROOT_SHA256"],
        temporary_parent=Path(os.environ["AZ06_OFFLINE_TEMP_PARENT"]),
        images=images,
    )
    assert verifier(parse_package(load_package(PACKAGE))) is True
    assert (
        replace(verifier, trusted_root_sha256="0" * 64)(
            parse_package(load_package(PACKAGE))
        )
        is False
    )

    image, original = next(iter(images.items()))
    bad_material = replace(original, bundle_path=graph.material.bundle_path)
    # The real CLI, not a synthetic verification-result JSON, rejects this bundle.
    assert (
        replace(verifier, images={image: bad_material})(
            parse_package(load_package(PACKAGE))
        )
        is False
    )
    bad_material = replace(original, index_path=graph.material.index_path)
    assert (
        replace(verifier, images={image: bad_material})(
            parse_package(load_package(PACKAGE))
        )
        is False
    )


@pytest.fixture
def children(monkeypatch):
    real = sbom.subprocess.Popen
    processes = []

    def launch(*args, **kwargs):
        process = real(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(sbom.subprocess, "Popen", launch)
    yield processes
    assert processes
    assert all(p.poll() is not None and p.stdout.closed for p in processes)


def test_cleanup_failure_still_closes_stdout(monkeypatch):
    reader, writer = os.pipe()
    os.write(writer, b"[]")
    os.close(writer)
    output = os.fdopen(reader, "rb")
    calls = []

    def wait(**kwargs):
        calls.append("wait")
        raise subprocess.TimeoutExpired("fixed-cli", kwargs["timeout"])

    def kill():
        calls.append("kill")
        raise OSError("injected cleanup failure")

    process = SimpleNamespace(stdout=output, poll=lambda: None, kill=kill, wait=wait)
    monkeypatch.setattr(sbom.subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(subprocess.TimeoutExpired):
        sbom._run_cli(["fixed-cli"], directory=Path.cwd(), environment={})
    assert calls == ["wait", "kill", "wait"] and output.closed


def test_multiple_unique_subject_names_never_replace_exact_digest_binding(graph):
    original = graph.layers["amd64"]["subject"][0]
    graph.layers["amd64"]["subject"].append(
        {**original, "name": "an-unrelated-looking-name"}
    )
    graph.provision()
    assert len(graph_predicates(graph)) == 2
    graph.layers["amd64"]["subject"][1]["digest"] = {"sha256": "f" * 64}
    graph.provision()
    with pytest.raises(ValueError, match="subject"):
        graph_predicates(graph)


def test_duplicate_subject_names_refuse_even_with_matching_digests(graph):
    graph.layers["amd64"]["subject"].append(dict(graph.layers["amd64"]["subject"][0]))
    graph.provision()
    with pytest.raises(ValueError, match="subject"):
        graph_predicates(graph)


def test_graph_subject_name_can_never_substitute_for_platform_digest(graph):
    # A convincing architecture name cannot rescue a wrong cryptographic link.
    subject = graph.layers["amd64"]["subject"][0]
    subject["name"] = "pkg:docker/trusted/amd64?platform=linux%2Famd64"
    subject["digest"] = {"sha256": graph.platforms["arm64"][7:]}
    graph.provision()
    with pytest.raises(ValueError, match="subject"):
        graph_predicates(graph)
