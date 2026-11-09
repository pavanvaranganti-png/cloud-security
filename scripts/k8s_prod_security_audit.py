#!/usr/bin/env python3
"""Read-only baseline security audit for Kubernetes workloads.

Requires Python 3 and kubectl configured for the cluster to audit. This script
only reads cluster resources; it does not apply changes or restart workloads.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any


RESOURCE_TYPES = "pods,deployments,statefulsets,daemonsets,jobs,cronjobs"


def get_pod_spec(item: dict[str, Any]) -> dict[str, Any] | None:
    """Return the pod spec for a Pod or a supported workload template."""
    kind = item.get("kind")
    spec = item.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return ((spec.get("template") or {}).get("spec"))


def add(findings: list[tuple[str, str, str]], severity: str, resource: str, message: str) -> None:
    findings.append((severity, resource, message))


def audit_item(item: dict[str, Any], findings: list[tuple[str, str, str]]) -> None:
    metadata = item.get("metadata") or {}
    name = metadata.get("name", "<unnamed>")
    namespace = metadata.get("namespace", "default")
    resource = f"{namespace}/{item.get('kind', 'Resource')}/{name}"
    pod_spec = get_pod_spec(item)
    if not isinstance(pod_spec, dict):
        return

    pod_security = pod_spec.get("securityContext") or {}
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(key) is True:
            add(findings, "HIGH", resource, f"{key}=true exposes host namespaces/network")

    if pod_spec.get("automountServiceAccountToken") is True:
        add(findings, "MEDIUM", resource, "service-account token is explicitly automounted; disable it unless required")
    if pod_spec.get("serviceAccountName", "default") == "default":
        add(findings, "LOW", resource, "uses the default service account; use a dedicated least-privilege account")

    for volume in pod_spec.get("volumes") or []:
        if "hostPath" in volume:
            add(findings, "HIGH", resource, f"hostPath volume {volume.get('name', '<unnamed>')} mounts node filesystem")

    pod_run_as_non_root = pod_security.get("runAsNonRoot") is True
    pod_seccomp = pod_security.get("seccompProfile") or {}
    containers = []
    for container_type in ("initContainers", "containers", "ephemeralContainers"):
        for container in pod_spec.get(container_type) or []:
            containers.append((container_type, container))

    if not containers:
        add(findings, "MEDIUM", resource, "pod spec has no declared containers to audit")

    for container_type, container in containers:
        cname = container.get("name", "<unnamed>")
        subject = f"{resource} container/{cname} ({container_type})"
        security = container.get("securityContext") or {}
        if security.get("privileged") is True:
            add(findings, "CRITICAL", subject, "privileged container is enabled")
        if security.get("allowPrivilegeEscalation") is not False:
            add(findings, "HIGH", subject, "set allowPrivilegeEscalation: false")
        if security.get("runAsNonRoot") is not True and not pod_run_as_non_root:
            add(findings, "HIGH", subject, "runAsNonRoot is not enforced at container or pod level")
        if security.get("readOnlyRootFilesystem") is not True:
            add(findings, "MEDIUM", subject, "readOnlyRootFilesystem is not enabled")

        capabilities = security.get("capabilities") or {}
        dropped = {str(cap).upper() for cap in capabilities.get("drop") or []}
        if "ALL" not in dropped:
            add(findings, "MEDIUM", subject, "drop all Linux capabilities, then add back only those required")

        seccomp = security.get("seccompProfile") or pod_seccomp
        if seccomp.get("type") not in ("RuntimeDefault", "Localhost"):
            add(findings, "MEDIUM", subject, "set seccompProfile.type to RuntimeDefault or an approved Localhost profile")

        for port in container.get("ports") or []:
            if port.get("hostPort"):
                add(findings, "HIGH", subject, f"hostPort {port['hostPort']} binds a container port on the node")

        resources = container.get("resources") or {}
        limits = resources.get("limits") or {}
        missing_limits = [key for key in ("cpu", "memory") if key not in limits]
        if missing_limits:
            add(findings, "MEDIUM", subject, "missing resource limits: " + ", ".join(missing_limits))
        requests = resources.get("requests") or {}
        missing_requests = [key for key in ("cpu", "memory") if key not in requests]
        if missing_requests:
            add(findings, "LOW", subject, "missing resource requests: " + ", ".join(missing_requests))

        image = str(container.get("image", ""))
        if not image:
            add(findings, "MEDIUM", subject, "container image is not specified")
        elif image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
            add(findings, "MEDIUM", subject, f"image {image!r} is not pinned to an explicit version tag or digest")


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Kubernetes workload security baseline audit")
    parser.add_argument("--namespace", help="audit one namespace (default: all namespaces)")
    parser.add_argument("--context", help="kubectl context to use")
    args = parser.parse_args()

    command = ["kubectl"]
    if args.context:
        command.extend(["--context", args.context])
    command.extend(["get", RESOURCE_TYPES])
    command.extend(["-n", args.namespace] if args.namespace else ["-A"])
    command.extend(["-o", "json"])

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
        payload = json.loads(result.stdout)
    except FileNotFoundError:
        print("ERROR: kubectl was not found. Install kubectl and configure cluster access.", file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired:
        print("ERROR: kubectl timed out while reading cluster resources.", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        print(f"ERROR: kubectl could not read resources: {detail}", file=sys.stderr)
        return 2
    except (json.JSONDecodeError, TypeError) as exc:
        print(f"ERROR: could not parse kubectl JSON output: {exc}", file=sys.stderr)
        return 2

    findings: list[tuple[str, str, str]] = []
    for item in payload.get("items", []):
        audit_item(item, findings)

    if not findings:
        print("No findings in the checked baseline. This is not a comprehensive security certification.")
        return 0

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda finding: (order.get(finding[0], 4), finding[1], finding[2]))
    for severity, resource, message in findings:
        print(f"[{severity}] {resource}: {message}")
    print(f"\n{len(findings)} finding(s). Review and remediate through your normal change process.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
