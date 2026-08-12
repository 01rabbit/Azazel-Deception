"""AZ-06 runtime adapters.

Runtime adapters are local execution mechanics. They never infer authority from
a package, capability report, or placement plan; live lifecycle operations
require an explicit Azazel-Edge decision.
"""

from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.state import RuntimeStateStore

__all__ = ["DockerComposeAdapter", "RuntimeStateStore"]
