"""The Fabric pin is documented in one place; prove the document is not stale.

`docs/fabric-pin.md` declares itself the description of a value whose single
source of truth is `pyproject.toml`. That claim was unenforced: the two drifted
apart with nothing to notice, which is the same failure the document itself
records for `__version__` (Deception#38 item 1). Stating a discipline and
checking it are different things, so this checks it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
PIN_DOC = ROOT / "docs" / "fabric-pin.md"

# Read by line rather than with `tomllib`: this package supports Python 3.10,
# where `tomllib` is not in the standard library, and a TOML dependency added
# for a test would be a dependency added.
_PIN_LINE = re.compile(r'"azazel-fabric\s*@\s*git\+[^"@]+@(?P<tag>[^"]+)"')


def _declared_pin() -> str:
    tags = _PIN_LINE.findall(PYPROJECT.read_text("utf-8"))
    assert len(tags) == 1, f"expected exactly one azazel-fabric pin, found {tags}"
    return tags[0]


def test_the_pin_is_an_exact_tag_not_a_branch_or_commit():
    tag = _declared_pin()

    assert re.fullmatch(r"v\d+\.\d+\.\d+(rc\d+|a\d+|b\d+)?", tag), (
        f"Fabric must be pinned to an exact release tag, got {tag!r}. "
        "A branch or commit is not a release and cannot be depended on."
    )


def test_the_pin_document_names_the_tag_that_is_actually_installed():
    tag = _declared_pin()
    doc = PIN_DOC.read_text("utf-8")

    section = doc.split("## Fabric pin", 1)
    assert len(section) == 2, "docs/fabric-pin.md lost its '## Fabric pin' section"
    heading, rest = section[1].split("##", 1)

    assert f"`{tag}`" in heading, (
        f"docs/fabric-pin.md does not name the pinned tag {tag!r}. "
        "The document describes pyproject.toml; a bump updates both."
    )


def test_a_candidate_pin_carries_a_recorded_reason():
    """A prerelease promises no stability, so pinning one is never silent."""
    tag = _declared_pin()
    if re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        pytest.skip("stable pin; no deviation to justify")

    doc = PIN_DOC.read_text("utf-8")
    assert "### Why a release candidate" in doc, (
        f"{tag} is a prerelease but docs/fabric-pin.md records no reason for it"
    )


def test_the_pin_history_records_the_current_pin_as_current():
    tag = _declared_pin()
    doc = PIN_DOC.read_text("utf-8")

    current = [line for line in doc.splitlines() if "(current)" in line]
    assert len(current) == 1, f"pin history must mark exactly one row current: {current}"
    assert tag in current[0], f"pin history marks a stale row current: {current[0]}"


def test_the_installed_distribution_matches_the_pinned_tag():
    """Catches an environment built from a different pin than the tree declares."""
    from importlib.metadata import version

    tag = _declared_pin()
    installed = version("azazel-fabric")

    assert installed == tag.lstrip("v"), (
        f"installed azazel_fabric {installed} does not match the pin {tag}; "
        "reinstall before trusting a green run"
    )
