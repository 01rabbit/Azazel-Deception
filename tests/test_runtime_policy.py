from pathlib import Path

from azazel_deception.runtime.policy import validate_compose_policy

REFERENCE = Path("runtime/compose/reference-linux.compose.yaml")


def test_reference_compose_is_fail_closed_safe():
    assert validate_compose_policy(REFERENCE) == []


def test_published_port_is_rejected(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  decoy:
    image: example.invalid/decoy:1
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
