"""Optional offline SPDX authentication and OCI platform binding, not admission."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time

from azazel_fabric.deception_contracts import DeceptionPackage
from azazel_fabric.deception_integrity import assert_package_content_digest
from .offline_package_verifier import (
    REPOSITORY,
    MAX_GH_BYTES,
    MAX_ROOT_BYTES,
    MAX_BUNDLE_BYTES,
    _pinned,
    _protected_directory,
    _read_protected,
)

SPDX = "https://spdx.dev/Document"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INTOTO = "application/vnd.in-toto+json"
MAX_GRAPH_BYTES = 20 * 1024 * 1024
MAX_SMALL_BYTES = 1024 * 1024
MAX_SPDX_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
CLI_SECONDS = 30


def _json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("nonfinite JSON")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite JSON number")
        return number

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float
    )


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _digest(value):
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("exact SHA256 descriptor required")
    return value


def _descriptor(value, maximum):
    if (
        type(value) is not dict
        or type(value.get("size")) is not int
        or not 0 < value["size"] <= maximum
    ):
        raise ValueError("bounded descriptor required")
    _digest(value.get("digest"))
    return value


def _spdx(value):
    if (
        type(value) is not dict
        or value.get("SPDXID") != "SPDXRef-DOCUMENT"
        or value.get("spdxVersion") != "SPDX-2.3"
        or type(value.get("documentNamespace")) is not str
        or not value["documentNamespace"]
        or type(value.get("packages")) is not list
        or len(value["packages"]) > 4096
        or type(value.get("files", [])) is not list
        or len(value.get("files", [])) > 20000
    ):
        raise ValueError("unsupported SPDX document")
    return _canonical(value)


@dataclass(frozen=True)
class OfflineImageArtifacts:
    index_path: Path
    bundle_path: Path
    artifacts: Mapping[str, Path]


def _platform_predicates(raw_index, image, platform_digests, material):
    """Follow only byte-authenticated links, never architecture-like names."""
    if not _pinned(raw_index, image.rsplit("@sha256:", 1)[1]):
        raise ValueError("index digest mismatch")
    index = _json(raw_index)
    if (
        type(index) is not dict
        or index.get("schemaVersion") != 2
        or index.get("mediaType") != INDEX
    ):
        raise ValueError("unsupported OCI index")
    descriptors = index.get("manifests")
    if type(descriptors) is not list or len(descriptors) != 4:
        raise ValueError("exact two-platform index required")
    if (
        not isinstance(material.artifacts, Mapping)
        or not 4 <= len(material.artifacts) <= 8
    ):
        raise ValueError("bounded explicit artifact map required")
    for digest in material.artifacts:
        _digest(digest)
    platforms, attachments = {}, {}
    for raw in descriptors:
        desc = _descriptor(raw, MAX_SMALL_BYTES)
        if desc.get("mediaType") != MANIFEST:
            raise ValueError("unsupported index descriptor")
        platform = desc.get("platform")
        if type(platform) is not dict or set(platform) != {"architecture", "os"}:
            raise ValueError("explicit platform required")
        architecture, system = platform["architecture"], platform["os"]
        if system == "linux" and architecture in platform_digests:
            if (
                architecture in platforms
                or desc["digest"] != platform_digests[architecture]
            ):
                raise ValueError("ambiguous or mismatched platform")
            platforms[architecture] = desc
        elif system == architecture == "unknown":
            annotations = desc.get("annotations")
            if (
                type(annotations) is not dict
                or annotations.get("vnd.docker.reference.type")
                != "attestation-manifest"
            ):
                raise ValueError("explicit attestation annotation required")
            target = _digest(annotations.get("vnd.docker.reference.digest"))
            if target in attachments:
                raise ValueError("ambiguous attestation attachment")
            attachments[target] = desc
        else:
            raise ValueError("undeclared platform")
    if set(platforms) != set(platform_digests) or set(attachments) != set(
        platform_digests.values()
    ):
        raise ValueError("incomplete platform attachments")
    consumed = len(raw_index)

    def load(desc, maximum):
        nonlocal consumed
        path = material.artifacts.get(desc["digest"])
        if path is None:
            raise ValueError("unmapped artifact")
        raw = _read_protected(path, maximum)
        consumed += len(raw)
        if (
            consumed > MAX_GRAPH_BYTES
            or len(raw) != desc["size"]
            or not _pinned(raw, desc["digest"][7:])
        ):
            raise ValueError("artifact byte chain mismatch")
        return _json(raw)

    predicates = set()
    for architecture, platform_digest in platform_digests.items():
        attached = load(attachments[platform_digest], MAX_SMALL_BYTES)
        if (
            type(attached) is not dict
            or attached.get("schemaVersion") != 2
            or attached.get("mediaType") != MANIFEST
        ):
            raise ValueError("unsupported attestation manifest")
        own_subject = _descriptor(attached.get("subject"), MAX_SMALL_BYTES)
        if (
            own_subject.get("mediaType") != MANIFEST
            or own_subject["digest"] != platform_digest
            or own_subject["size"] != platforms[architecture]["size"]
        ):
            raise ValueError("attestation manifest subject mismatch")
        layers = attached.get("layers")
        if type(layers) is not list or not 1 <= len(layers) <= 4:
            raise ValueError("bounded attestation layers required")
        spdx_layers = []
        for raw in layers:
            layer = _descriptor(raw, MAX_SPDX_BYTES)
            annotations = layer.get("annotations", {})
            if type(annotations) is not dict:
                raise ValueError("malformed layer annotations")
            if annotations.get("in-toto.io/predicate-type") == SPDX:
                if layer.get("mediaType") != INTOTO:
                    raise ValueError("unsupported SPDX layer media type")
                spdx_layers.append(layer)
        if len(spdx_layers) != 1:
            raise ValueError("exactly one explicit SPDX layer required")
        statement = load(spdx_layers[0], MAX_SPDX_BYTES)
        if (
            type(statement) is not dict
            or statement.get("_type")
            not in (
                "https://in-toto.io/Statement/v0.1",
                "https://in-toto.io/Statement/v1",
            )
            or statement.get("predicateType") != SPDX
        ):
            raise ValueError("unsupported SPDX statement")
        subjects = statement.get("subject")
        if type(subjects) is not list or not 1 <= len(subjects) <= 4:
            raise ValueError("bounded platform subjects required")
        names = set()
        for subject in subjects:
            if (
                type(subject) is not dict
                or subject.get("digest") != {"sha256": platform_digest[7:]}
                or type(subject.get("name")) is not str
                or not 0 < len(subject["name"]) <= 2048
                or subject["name"] in names
            ):
                raise ValueError("SPDX subject is not the declared platform manifest")
            names.add(subject["name"])
        canonical = _spdx(statement.get("predicate"))
        if canonical in predicates:
            raise ValueError("ambiguous duplicate platform predicate")
        predicates.add(canonical)
    return predicates


def _verified_predicates(raw, image):
    results = _json(raw)
    if type(results) is not list or len(results) != 2:
        raise ValueError("two distinct verified predicates required")
    name, digest = image.rsplit("@sha256:", 1)
    predicates = set()
    for result in results:
        if (
            type(result) is not dict
            or type(result.get("verificationResult")) is not dict
        ):
            raise ValueError("unverified statement output")
        statement = result["verificationResult"].get("statement")
        if (
            type(statement) is not dict
            or statement.get("predicateType") != SPDX
            or statement.get("subject")
            != [{"name": name, "digest": {"sha256": digest}}]
        ):
            raise ValueError("verified subject or predicate mismatch")
        canonical = _spdx(statement.get("predicate"))
        if canonical in predicates:
            raise ValueError("duplicate verified predicate")
        predicates.add(canonical)
    return predicates


def _run_cli(command, *, directory, environment):
    """One absolute deadline, bounded streaming, and cleanup on every exit."""
    deadline = time.monotonic() + CLI_SECONDS
    process = subprocess.Popen(
        command,
        cwd=directory,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("offline verification deadline")
                chunk = os.read(
                    process.stdout.fileno(),
                    min(65536, MAX_OUTPUT_BYTES + 1 - len(data)),
                )
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_OUTPUT_BYTES:
                    raise ValueError("verification output exceeds byte bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise ValueError("offline verification failed")
        return bytes(data)
    finally:
        primary_error = sys.exc_info()[0] is not None
        errors = []
        try:
            if process.poll() is None:
                process.kill()
        except OSError as exc:
            errors.append(exc)
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(exc)
        finally:
            if process.stdout is not None:
                process.stdout.close()
        if errors and not primary_error:
            raise OSError("offline verifier cleanup failed") from errors[0]


@dataclass(frozen=True)
class OfflineGitHubSbomVerifier:
    """Reference-only optional gate: one unique image, amd64+arm64, no fetch."""

    gh_path: Path
    gh_sha256: str
    trusted_root_path: Path
    trusted_root_sha256: str
    temporary_parent: Path
    images: Mapping[str, OfflineImageArtifacts]

    def __call__(self, package: DeceptionPackage) -> bool:
        try:
            assert_package_content_digest(package)
            if not isinstance(self.images, Mapping) or len(self.images) != 1:
                return False
            targets = {}
            for component in package.components:
                if not component.image.verified:
                    continue
                info = component.image
                image = info.image
                if (
                    re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}", image
                    )
                    is None
                ):
                    return False
                if info.manifest_digest != "sha256:" + image.rsplit("@sha256:", 1)[1]:
                    return False
                platforms = {p.architecture: _digest(p.digest) for p in info.platforms}
                if (
                    len(info.platforms) != 2
                    or set(platforms) != {"amd64", "arm64"}
                    or len(set(platforms.values())) != 2
                ):
                    return False
                if image in targets and targets[image] != platforms:
                    return False
                targets[image] = platforms
            if len(targets) != 1 or set(targets) != set(self.images):
                return False
            parent = _protected_directory(self.temporary_parent)
            cli = _read_protected(self.gh_path, MAX_GH_BYTES, executable=True)
            root = _read_protected(self.trusted_root_path, MAX_ROOT_BYTES)
            if not _pinned(cli, self.gh_sha256) or not _pinned(
                root, self.trusted_root_sha256
            ):
                return False
            image, platforms = next(iter(targets.items()))
            material = self.images[image]
            index = _read_protected(material.index_path, MAX_SMALL_BYTES)
            expected = _platform_predicates(index, image, platforms, material)
            bundle = _read_protected(material.bundle_path, MAX_BUNDLE_BYTES)
            if not bundle or not root:
                return False
            with tempfile.TemporaryDirectory(
                prefix="az06-offline-sbom-", dir=parent
            ) as temp:
                directory = Path(temp)
                for name, data in (
                    ("gh", cli),
                    ("index.json", index),
                    ("bundle.jsonl", bundle),
                    ("trusted_root.jsonl", root),
                ):
                    path = directory / name
                    with path.open("xb") as stream:
                        stream.write(data)
                    path.chmod(0o500 if name == "gh" else 0o400)
                home, config = directory / "home", directory / "config"
                home.mkdir(mode=0o700)
                config.mkdir(mode=0o700)
                environment = dict(
                    HOME=str(home),
                    GH_CONFIG_DIR=str(config),
                    PATH="/usr/bin:/bin",
                    LANG="C",
                    LC_ALL="C",
                    GH_HOST="github.com",
                    GH_PROMPT_DISABLED="1",
                    GH_NO_UPDATE_NOTIFIER="1",
                    GH_NO_EXTENSION_UPDATE_NOTIFIER="1",
                )
                output = _run_cli(
                    [
                        str(directory / "gh"),
                        "attestation",
                        "verify",
                        str(directory / "index.json"),
                        "--bundle",
                        str(directory / "bundle.jsonl"),
                        "--custom-trusted-root",
                        str(directory / "trusted_root.jsonl"),
                        "--repo",
                        REPOSITORY,
                        "--predicate-type",
                        SPDX,
                        "--deny-self-hosted-runners",
                        "--hostname",
                        "github.com",
                        "--format",
                        "json",
                    ],
                    directory=directory,
                    environment=environment,
                )
                return _verified_predicates(output, image) == expected
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            IndexError,
            RecursionError,
            subprocess.SubprocessError,
        ):
            return False
