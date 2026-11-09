#!/usr/bin/env python3
"""Generate a secure Kubernetes starter workload manifest.

This is for a workload that has not been created yet. It generates a
reviewable multi-document JSON/YAML file containing a dedicated ServiceAccount,
a Deployment, and an internal ClusterIP Service. It does not connect to or
change a cluster. The generated Deployment uses a restricted container
security context, resource requests/limits, and HTTP health probes.

Example:
  python3 scripts/k8s_prod_hardening.py \\
    --name my-app --namespace production --image registry.example.com/my-app:1.2.3 \\
    --output my-app.json
  kubectl apply --dry-run=server -f my-app.json
  # After reviewing the server-side dry run:
  kubectl apply -f my-app.json

Choose an image built to run as UID 10001, listen on the configured port, and
write only to mounted writable paths (the script mounts /tmp as an emptyDir).
Review probes, resource sizing, ports, network policy, and storage needs for
your application before applying to production.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$ ".strip())


def valid_name(value: str) -> bool:
    return len(value) <= 63 and bool(DNS_LABEL.fullmatch(value))


def image_is_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    last_component = image.rsplit("/", 1)[-1]
    return ":" in last_component and not last_component.endswith(":latest")


def build_manifest(name: str, namespace: str, image: str, port: int, health_path: str, replicas: int) -> list[dict[str, Any]]:
    labels = {"app.kubernetes.io/name": name}
    common = {"namespace": namespace}
    return [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {**common, "name": name, "labels": labels},
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {**common, "name": name, "labels": labels},
            "spec": {
                "replicas": replicas,
                "revisionHistoryLimit": 3,
                "selector": {"matchLabels": labels},
                "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1}},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "serviceAccountName": name,
                        "automountServiceAccountToken": False,
                        "terminationGracePeriodSeconds": 30,
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [
                            {
                                "name": name,
                                "image": image,
                                "imagePullPolicy": "IfNotPresent",
                                "ports": [{"name": "http", "containerPort": port, "protocol": "TCP"}],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "privileged": False,
                                    "readOnlyRootFilesystem": True,
                                    "runAsNonRoot": True,
                                    "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "capabilities": {"drop": ["ALL"]},
                                    "seccompProfile": {"type": "RuntimeDefault"},
                                },
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                                "startupProbe": {
                                    "httpGet": {"path": health_path, "port": "http"},
                                    "periodSeconds": 5,
                                    "failureThreshold": 30,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": health_path, "port": "http"},
                                    "periodSeconds": 5,
                                    "failureThreshold": 3,
                                },
                                "livenessProbe": {
                                    "httpGet": {"path": health_path, "port": "http"},
                                    "periodSeconds": 10,
                                    "failureThreshold": 3,
                                },
                                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                            }
                        ],
                        "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {**common, "name": name, "labels": labels},
            "spec": {
                "type": "ClusterIP",
                "selector": labels,
                "ports": [{"name": "http", "port": port, "targetPort": "http", "protocol": "TCP"}],
            },
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a hardened Kubernetes Deployment starter manifest")
    parser.add_argument("--name", default="my-app", help="Kubernetes app name (default: my-app)")
    parser.add_argument("--namespace", default="production", help="target namespace (default: production; it must already exist)")
    parser.add_argument("--image", required=True, help="container image pinned to a version tag or sha256 digest")
    parser.add_argument("--port", type=int, default=8080, help="container and Service port (default: 8080)")
    parser.add_argument("--health-path", default="/healthz", help="HTTP startup/readiness/liveness endpoint (default: /healthz)")
    parser.add_argument("--replicas", type=int, default=2, help="initial replica count (default: 2)")
    parser.add_argument("--output", help="write manifest to this file; default: standard output")
    args = parser.parse_args()

    if not valid_name(args.name) or not valid_name(args.namespace):
        parser.error("--name and --namespace must be lowercase Kubernetes DNS labels (up to 63 characters)")
    if not image_is_pinned(args.image):
        parser.error("--image must use an explicit non-latest tag or an @sha256 digest")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.replicas < 1:
        parser.error("--replicas must be at least 1")
    if not args.health_path.startswith("/") or "\n" in args.health_path:
        parser.error("--health-path must be an HTTP path starting with '/'")

    documents = build_manifest(args.name, args.namespace, args.image, args.port, args.health_path, args.replicas)
    rendered = "\n---\n".join(json.dumps(document, indent=2) for document in documents) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"Wrote manifest to {args.output}. Review it before applying.", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
