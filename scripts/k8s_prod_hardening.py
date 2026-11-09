#!/usr/bin/env python3
"""Kubernetes production hardening helper.

This script inspects common workload types (Deployment, StatefulSet, DaemonSet,
Job, CronJob) and optionally applies a conservative hardening baseline:

- runAsNonRoot: true
- allowPrivilegeEscalation: false
- privileged: false
- seccompProfile: RuntimeDefault
- capabilities.drop: ["ALL"]
- automountServiceAccountToken: false
- readOnlyRootFilesystem: true (only applied when safe and explicitly enabled)

Default behavior is REPORT-ONLY. Use --apply to patch resources in-cluster.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any


WORKLOAD_TYPES = ["deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"]


def run_kubectl(arguments: list[str], allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = ["kubectl", *arguments]
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print("ERROR: kubectl is not installed or not on PATH.", file=sys.stderr)
        raise SystemExit(2)
    except subprocess.TimeoutExpired:
        print("ERROR: kubectl command timed out.", file=sys.stderr)
        raise SystemExit(2)

    if result.returncode != 0 and not allow_failure:
        print(f"ERROR: kubectl {' '.join(cmd)} failed: {result.stderr.strip() or result.stdout.strip()}", file=sys.stderr)
        raise SystemExit(result.returncode)
    return result


def load_workloads(namespace: str | None, context: str | None) -> list[dict[str, Any]]:
    args = []
    if context:
        args.extend(["--context", context])
    args.extend(["get"])
    if namespace:
        args.extend(["-n", namespace])
    else:
        args.extend(["-A"])
    for resource in WORKLOAD_TYPES:
        args.append(resource)
    args.extend(["-o", "json"])
    result = run_kubectl(args)
    payload = json.loads(result.stdout)
    items = payload.get("items", [])
    if not items:
        print("No Kubernetes workloads were found in the selected scope.")
    return items


def resolve_pod_spec(workload: dict[str, Any]) -> tuple[dict[str, Any], str, str, Any]:
    kind = workload.get("kind", "Unknown")
    metadata = workload.get("metadata") or {}
    name = metadata.get("name", "<unnamed>")
    namespace = metadata.get("namespace", "default")

    if kind == "CronJob":
        pod_spec = ((workload.get("spec") or {}).get("jobTemplate") or {}).get("spec", {}).get("template", {}).get("spec")
        return pod_spec, kind, namespace, name
    spec = workload.get("spec") or {}
    template = spec.get("template") or {}
    pod_spec = template.get("spec") or {}
    return pod_spec, kind, namespace, name


def update_dict(target: dict[str, Any], updates: dict[str, Any]) -> None:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            update_dict(target[key], value)
        else:
            target[key] = value


def build_hardening_patch(pod_spec: dict[str, Any], enforce_readonly_rootfs: bool) -> dict[str, Any]:
    patch: dict[str, Any] = {}
    if not isinstance(pod_spec, dict):
        return patch

    pod_security = pod_spec.setdefault("securityContext", {})
    if pod_security.get("runAsNonRoot") is not True:
        pod_security["runAsNonRoot"] = True
    if pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        pod_security["seccompProfile"] = {"type": "RuntimeDefault"}
    if pod_spec.get("automountServiceAccountToken") is not False:
        pod_spec["automountServiceAccountToken"] = False
    if pod_spec.get("hostNetwork") is not False:
        pod_spec["hostNetwork"] = False
    if pod_spec.get("hostPID") is not False:
        pod_spec["hostPID"] = False
    if pod_spec.get("hostIPC") is not False:
        pod_spec["hostIPC"] = False

    for container_type in ("initContainers", "containers", "ephemeralContainers"):
        for container in pod_spec.get(container_type) or []:
            security = container.setdefault("securityContext", {})
            if security.get("privileged") is not False:
                security["privileged"] = False
            if security.get("allowPrivilegeEscalation") is not False:
                security["allowPrivilegeEscalation"] = False
            if security.get("runAsNonRoot") is not True:
                security["runAsNonRoot"] = True
            if security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
                security["seccompProfile"] = {"type": "RuntimeDefault"}
            capabilities = security.setdefault("capabilities", {})
            if capabilities.get("drop") != ["ALL"]:
                capabilities["drop"] = ["ALL"]
            if enforce_readonly_rootfs:
                if security.get("readOnlyRootFilesystem") is not True:
                    security["readOnlyRootFilesystem"] = True

    return patch


def printable_patch(pod_spec: dict[str, Any], enforce_readonly_rootfs: bool) -> dict[str, Any]:
    """Return a patch object that reflects the intended security changes."""
    patch: dict[str, Any] = {}
    target = patch
    pod = target
    pod["securityContext"] = {}
    pod["automountServiceAccountToken"] = False
    pod["hostNetwork"] = False
    pod["hostPID"] = False
    pod["hostIPC"] = False
    pod["securityContext"]["runAsNonRoot"] = True
    pod["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}

    containers = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for item in pod_spec.get(key) or []:
            containers.append(item)

    if containers:
        pod["containers"] = []
        for container in containers:
            c = {
                "name": container.get("name", "<unnamed>"),
                "securityContext": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "runAsNonRoot": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                    "capabilities": {"drop": ["ALL"]},
                },
            }
            if enforce_readonly_rootfs:
                c["securityContext"]["readOnlyRootFilesystem"] = True
            pod["containers"].append(c)

    return patch


def patch_workload(kind: str, namespace: str, name: str, pod_spec: dict[str, Any], apply: bool, enforce_readonly_rootfs: bool, context: str | None) -> tuple[bool, dict[str, Any]]:
    patch = build_hardening_patch(pod_spec, enforce_readonly_rootfs)
    if not patch:
        return False, {}

    if not apply:
        return True, printable_patch(pod_spec, enforce_readonly_rootfs)

    resource = kind.lower()
    if resource.endswith("s") and resource not in {"daemonsets", "statefulsets", "deployments", "jobs"}:
        pass

    # kubectl uses singular resource names for patching; map common workload names.
    resource_map = {
        "Deployment": "deployment",
        "StatefulSet": "statefulset",
        "DaemonSet": "daemonset",
        "Job": "job",
        "CronJob": "cronjob",
    }
    resource_name = resource_map.get(kind, kind.lower())
    patch_json = json.dumps(patch)
    cmd = ["patch", resource_name, name, "-n", namespace, "--type", "merge", "-p", patch_json]
    if context:
        cmd = ["--context", context] + cmd
    result = run_kubectl(["kubectl", *cmd], allow_failure=False)
    return result.returncode == 0, patch


def find_pod_spec_from_item(item: dict[str, Any]) -> dict[str, Any]:
    if item.get("kind") == "CronJob":
        return ((item.get("spec") or {}).get("jobTemplate") or {}).get("spec", {}).get("template", {}).get("spec", {})
    return ((item.get("spec") or {}).get("template") or {}).get("spec", {})


def workload_candidate_items(payload: list[dict[str, Any]]) -> list[tuple[str, str, str, dict[str, Any]]]:
    candidates = []
    for item in payload:
        kind = item.get("kind", "Unknown")
        metadata = item.get("metadata") or {}
        name = metadata.get("name", "<unnamed>")
        namespace = metadata.get("namespace", "default")
        pod_spec = find_pod_spec_from_item(item)
        if isinstance(pod_spec, dict):
            candidates.append((kind, namespace, name, pod_spec))
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Conservative Kubernetes production hardening helper")
    parser.add_argument("--namespace", help="Namespace to scan; default: all namespaces")
    parser.add_argument("--context", help="kubectl context to use")
    parser.add_argument("--apply", action="store_true", help="Apply the hardening baseline to matching workloads")
    parser.add_argument("--enforce-readonly-rootfs", action="store_true", help="Also set readOnlyRootFilesystem=true where appropriate")
    parser.add_argument("--dry-run", action="store_true", help="Alias for report-only behavior (default)")
    args = parser.parse_args()

    payload = []
    for resource in WORKLOAD_TYPES:
        current = run_kubectl([
            "get", resource,
            *( ["-n", args.namespace] if args.namespace else ["-A"]),
            *( ["--context", args.context] if args.context else []),
            "-o", "json"
        ], allow_failure=True)
        if current.returncode != 0:
            continue
        try:
            data = json.loads(current.stdout)
        except json.JSONDecodeError:
            continue
        for item in data.get("items", []):
            payload.append(item)

    if not payload:
        print("No workload resources were found in scope.")
        return 0

    changed = 0
    print(f"Scanning {len(payload)} workload(s) for production hardening issues...")
    for kind, namespace, name, pod_spec in workload_candidate_items(payload):
        patch = build_hardening_patch(pod_spec, args.enforce_readonly_rootfs)
        if not patch:
            continue
        print(f"{kind}/{namespace}/{name}: would apply hardening baseline")
        changed += 1

        if args.apply:
            # Rebuild a patch because kubectl requires actual mutation content.
            resource_name = {
                "Deployment": "deployment",
                "StatefulSet": "statefulset",
                "DaemonSet": "daemonset",
                "Job": "job",
                "CronJob": "cronjob",
            }.get(kind, kind.lower())
            patch_json = json.dumps({
                "spec": {
                    "template": {"spec": {
                        "securityContext": pod_spec.get("securityContext", {}),
                        "automountServiceAccountToken": False,
                        "hostNetwork": False,
                        "hostPID": False,
                        "hostIPC": False,
                        "containers": [],
                        "initContainers": [],
                    }}
                }
            })
            if kind == "CronJob":
                patch_json = json.dumps({
                    "spec": {
                        "jobTemplate": {
                            "spec": {
                                "template": {"spec": {
                                    "securityContext": pod_spec.get("securityContext", {}),
                                    "automountServiceAccountToken": False,
                                    "hostNetwork": False,
                                    "hostPID": False,
                                    "hostIPC": False,
                                    "containers": [],
                                    "initContainers": [],
                                }}
                            }
                        }
                    }
                })

            # Build concrete container list to patch.
            containers = []
            for key in ("containers", "initContainers", "ephemeralContainers"):
                for c in pod_spec.get(key) or []:
                    sc = c.get("securityContext") or {}
                    sc["privileged"] = False
                    sc["allowPrivilegeEscalation"] = False
                    sc["runAsNonRoot"] = True
                    sc["seccompProfile"] = {"type": "RuntimeDefault"}
                    sc.setdefault("capabilities", {})["drop"] = ["ALL"]
                    if args.enforce_readonly_rootfs:
                        sc["readOnlyRootFilesystem"] = True
                    containers.append({"name": c.get("name", "<unnamed>"), "securityContext": sc})

            if kind == "CronJob":
                patch_json = json.dumps({
                    "spec": {
                        "jobTemplate": {
                            "spec": {
                                "template": {
                                    "spec": {
                                        "securityContext": pod_spec.get("securityContext", {}),
                                        "automountServiceAccountToken": False,
                                        "hostNetwork": False,
                                        "hostPID": False,
                                        "hostIPC": False,
                                        "containers": containers,
                                        "initContainers": [],
                                    }
                                }
                            }
                        }
                    }
                })
            else:
                patch_json = json.dumps({
                    "spec": {
                        "template": {
                            "spec": {
                                "securityContext": pod_spec.get("securityContext", {}),
                                "automountServiceAccountToken": False,
                                "hostNetwork": False,
                                "hostPID": False,
                                "hostIPC": False,
                                "containers": containers,
                                "initContainers": [],
                            }
                        }
                    }
                })

            cmd = ["patch", resource_name, name, "-n", namespace, "--type", "merge", "-p", patch_json]
            if args.context:
                cmd = ["--context", args.context] + cmd

            result = run_kubectl(cmd, allow_failure=True)
            if result.returncode == 0:
                print(f"  PATCHED: {kind}/{namespace}/{name}")
            else:
                print(f"  PATCH FAILED: {kind}/{namespace}/{name}: {result.stderr.strip() or result.stdout.strip()}", file=sys.stderr)

    if args.apply:
        print(f"\nApplied baseline to {changed} workload(s).")
    else:
        print(f"\n{changed} workload(s) are eligible for hardening. Re-run with --apply to patch them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
