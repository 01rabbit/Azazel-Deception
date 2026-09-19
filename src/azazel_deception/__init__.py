"""AZ-06 Azazel-Deception bootstrap control plane."""

from importlib.metadata import PackageNotFoundError, version as _metadata_version

# Derived, never hand-written. A second literal copy of the version drifted from
# ``pyproject.toml`` once already (Azazel-Deception#38 item 1: the module said
# ``0.1.0.dev0`` while the distribution said ``0.2.0.dev0``), and a documentation
# gate cannot honestly claim one product version while the module reports
# another. Reading it from the installed distribution metadata makes that class
# of drift structurally impossible.
try:
    __version__ = _metadata_version("azazel-deception")
except PackageNotFoundError:  # pragma: no cover - source tree without an install
    # Running straight from a source checkout that was never installed. There is
    # no metadata to read and no second copy to fall back to, so say so rather
    # than inventing a number that could disagree with pyproject.toml.
    __version__ = "0+unknown"
