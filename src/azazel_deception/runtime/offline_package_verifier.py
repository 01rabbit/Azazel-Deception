"""Opt-in offline package authenticity only; no SBOM or activation authority."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from azazel_fabric.deception_contracts import DeceptionPackage
from azazel_fabric.deception_integrity import (
    PackageIntegrityError,
    assert_package_content_digest,
    canonical_package_signing_bytes,
)

REPOSITORY = "01rabbit/Azazel-Deception"
WORKFLOW = REPOSITORY + "/.github/workflows/reference-package.yml"
SOURCE_REF = "refs/heads/main"
PREDICATE = "https://slsa.dev/provenance/v1"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_ROOT_BYTES = 1024 * 1024
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_GH_BYTES = 128 * 1024 * 1024


def _fingerprint(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_protected(path: Path, maximum: int, *, executable: bool = False) -> bytes:
    """Pin every parent with no-follow opens; reject writable trust paths."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise ValueError("absolute physical trust path required")
    owner = os.geteuid()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent = os.open("/", flags | os.O_DIRECTORY)
    fd = None
    try:
        for name in path.parts[1:-1]:
            info = os.fstat(parent)
            if info.st_uid not in (0, owner) or info.st_mode & 0o022:
                raise ValueError("untrusted artifact ancestor")
            child = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        info = os.fstat(parent)
        if info.st_uid not in (0, owner) or info.st_mode & 0o022:
            raise ValueError("untrusted artifact parent")
        fd = os.open(path.name, flags | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in (0, owner)
            or before.st_nlink != 1
            or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or before.st_size > maximum
            or (executable and not before.st_mode & 0o111)
        ):
            raise ValueError("unsafe or oversized public artifact")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            len(data) > maximum
            or len(data) != before.st_size
            or _fingerprint(before) != _fingerprint(after)
            or _fingerprint(after) != _fingerprint(named)
        ):
            raise ValueError("public artifact changed during read")
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _pinned(data: bytes, expected: str) -> bool:
    return (
        type(expected) is str
        and re.fullmatch(r"[0-9a-f]{64}", expected) is not None
        and hashlib.sha256(data).hexdigest() == expected
    )


@dataclass(frozen=True)
class OfflineGitHubAttestationPackageVerifier:
    """Verify exact canonical bytes with staged Sigstore material and trusted gh.

    The CLI and trusted-root digests are independent operator-provisioned trust
    anchors, never taken from the package/bundle. Fixed policy matches the
    existing reference package verifier. No online fallback or default wiring.
    """

    gh_path: Path
    gh_sha256: str
    bundle_path: Path
    trusted_root_path: Path
    trusted_root_sha256: str

    def __call__(self, package: DeceptionPackage) -> bool:
        if package.signer_ref != "github:" + WORKFLOW:
            return False
        if not package.signature_ref.startswith("github-attestation:"):
            return False
        if any(
            type(pin) is not str or re.fullmatch(r"[0-9a-f]{64}", pin) is None
            for pin in (self.gh_sha256, self.trusted_root_sha256)
        ):
            return False
        try:
            assert_package_content_digest(package)
            payload = canonical_package_signing_bytes(package)
            if len(payload) > MAX_PAYLOAD_BYTES:
                return False
            cli = _read_protected(self.gh_path, MAX_GH_BYTES, executable=True)
            root = _read_protected(self.trusted_root_path, MAX_ROOT_BYTES)
            if not _pinned(cli, self.gh_sha256) or not _pinned(
                root, self.trusted_root_sha256
            ):
                return False
            bundle = _read_protected(self.bundle_path, MAX_BUNDLE_BYTES)
            if not bundle or not root:
                return False
            with tempfile.TemporaryDirectory(prefix="az06-offline-package-") as temp:
                directory = Path(temp)
                # Snapshot even the executable: never hash one pathname and
                # later execute replacement bytes at that pathname.
                paths = {}
                for name, data in (
                    ("gh", cli),
                    ("package.signing.json", payload),
                    ("package.bundle.jsonl", bundle),
                    ("trusted_root.jsonl", root),
                ):
                    path = directory / name
                    with path.open("xb") as stream:
                        stream.write(data)
                    path.chmod(0o500 if name == "gh" else 0o400)
                    paths[name] = path
                home, config = directory / "home", directory / "config"
                home.mkdir(mode=0o700)
                config.mkdir(mode=0o700)
                result = subprocess.run(
                    [
                        str(paths["gh"]),
                        "attestation",
                        "verify",
                        str(paths["package.signing.json"]),
                        "--bundle",
                        str(paths["package.bundle.jsonl"]),
                        "--custom-trusted-root",
                        str(paths["trusted_root.jsonl"]),
                        "--repo",
                        REPOSITORY,
                        "--signer-workflow",
                        WORKFLOW,
                        "--source-ref",
                        SOURCE_REF,
                        "--deny-self-hosted-runners",
                        "--predicate-type",
                        PREDICATE,
                        "--hostname",
                        "github.com",
                    ],
                    cwd=directory,
                    env={
                        "HOME": str(home),
                        "GH_CONFIG_DIR": str(config),
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "GH_HOST": "github.com",
                        "GH_PROMPT_DISABLED": "1",
                        "GH_NO_UPDATE_NOTIFIER": "1",
                        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
                    },
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                    close_fds=True,
                )
                return result.returncode == 0
        except (
            OSError,
            ValueError,
            TypeError,
            PackageIntegrityError,
            subprocess.SubprocessError,
        ):
            return False
