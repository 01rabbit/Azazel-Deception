"""AZ-06 runtime adapters.

Runtime adapters are local execution mechanics. They never infer authority from
a package, capability report, or placement plan; live lifecycle operations
require an explicit Azazel-Edge decision.
"""

from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.observation import (
    InteractionObserver,
    build_runtime_context,
)
from azazel_deception.runtime.posture import (
    DEV_RELAXED_POSTURE_ENV_VAR,
    build_reference_adapter,
    dev_relaxed_posture_requested,
)
from azazel_deception.runtime.shadow_server import (
    ShadowReplayHTTPServer,
    ShadowReplayService,
)
from azazel_deception.runtime.state import RuntimeStateStore

__all__ = [
    "DEV_RELAXED_POSTURE_ENV_VAR",
    "DockerComposeAdapter",
    "InteractionObserver",
    "RuntimeStateStore",
    "ShadowReplayHTTPServer",
    "ShadowReplayService",
    "build_reference_adapter",
    "build_runtime_context",
    "dev_relaxed_posture_requested",
]
