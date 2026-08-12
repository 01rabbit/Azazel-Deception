from pathlib import Path

import yaml

from azazel_deception.package import load_package, parse_package
from azazel_deception.runtime.policy import validate_compose_policy

REFERENCE = Path("runtime/compose/reference-linux.compose.yaml")
PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def test_reference_compose_is_fail_closed_safe():
    assert validate_compose_policy(REFERENCE) == []


def test_reference_compose_image_is_immutable_digest_pinned():
    document = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
    for name, service in document["services"].items():
        image = service.get("image", "")
        assert "@sha256:" in image, (name, image)
        assert not image.endswith(":latest"), (name, image)
        assert service.get("build") is None, name


def test_reference_compose_image_exactly_matches_package_manifest():
    package = parse_package(load_package(PACKAGE))
    document = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
    package_images = {c.component_id: c.image.image for c in package.components}
    for name, service in document["services"].items():
        assert name in package_images, name
        assert service["image"] == package_images[name], name
        # The pinned manifest digest must be embedded in the live image reference.
        component = next(c for c in package.components if c.component_id == name)
        assert component.image.manifest_digest.split(":", 1)[1] in service["image"], name


def test_published_port_is_rejected(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  decoy:
    image: example.invalid/decoy:1
    user: "1000:1000"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 64
    mem_limit: 128m
    cpus: 0.25
    ports: [\"8080:80\"]
    networks: [decoy_internal]
networks:
  decoy_internal:
    internal: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    assert "service:decoy:published_ports" in validate_compose_policy(compose)


def test_runtime_socket_and_external_network_are_rejected(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  decoy:
    image: example.invalid/decoy:1
    user: "1000:1000"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 64
    mem_limit: 128m
    cpus: 0.25
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks: [outside]
networks:
  outside: {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    violations = validate_compose_policy(compose)
    assert "service:decoy:runtime_socket_mount" in violations
    assert "network_not_internal:outside" in violations
    assert "service:decoy:non_internal_network:outside" in violations


def test_host_namespaces_and_privileged_are_rejected(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  decoy:
    image: example.invalid/decoy:1
    user: "1000:1000"
    privileged: true
    network_mode: host
    pid: host
    ipc: host
    userns_mode: host
    networks: [decoy_internal]
networks:
  decoy_internal:
    internal: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    violations = validate_compose_policy(compose)
    assert "service:decoy:privileged" in violations
    assert "service:decoy:host_network" in violations
    assert "service:decoy:host_pid_namespace" in violations
    assert "service:decoy:host_ipc_namespace" in violations
    assert "service:decoy:host_user_namespace" in violations


def test_local_build_is_rejected_even_when_image_is_present(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  decoy:
    image: example.invalid/decoy:1
    build: .
    user: "1000:1000"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 64
    mem_limit: 128m
    cpus: 0.25
    networks: [decoy_internal]
networks:
  decoy_internal:
    internal: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    assert "service:decoy:local_build_forbidden" in validate_compose_policy(compose)


def test_root_user_and_capability_readdition_are_rejected(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  decoy:
    image: example.invalid/decoy:1
    user: "0:0"
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: [no-new-privileges:true]
    pids_limit: 64
    mem_limit: 128m
    cpus: 0.25
    networks: [decoy_internal]
networks:
  decoy_internal:
    internal: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    violations = validate_compose_policy(compose)
    assert "service:decoy:non_root_user_required" in violations
    assert "service:decoy:capability_readdition_forbidden" in violations
