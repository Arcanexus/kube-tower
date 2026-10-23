# kube-tower

Read-only dashboard that tells you, across all your Kubernetes clusters, which **container images**
and **Helm charts** (including subcharts) have a newer version available. Think watchtower,
Renovate or jetstack version-checker, **without automatic updates**.

- **Images**: every image of Pods, Deployments, StatefulSets, DaemonSets and CronJobs (running or
  not) plus images cached on nodes, checked against the registry they come from (Docker Hub,
  ghcr.io, quay.io, any OCI registry). Floating tags (`latest`) are checked by digest.
- **Helm charts**: charts deployed by ArgoCD Applications, from Helm repositories, OCI registries
  or git paths, with their subcharts.
- **Multi-cluster**: register clusters with Secrets in the ArgoCD format, or reuse ArgoCD's own.
- **Stateless**: no database, the inventory is rebuilt periodically.
- UI with Images / Helm charts / Clusters / Settings tabs, JSON API and Prometheus metrics.

## Install

```sh
helm install kube-tower oci://ghcr.io/arcanexus/charts/kube-tower -n kube-tower --create-namespace
kubectl -n kube-tower port-forward svc/kube-tower 8080:80
```

Or with an ArgoCD Application pointing at `charts/kube-tower` in this repository.
See [docs/configuration.md](docs/configuration.md) and [docs/clusters.md](docs/clusters.md).

## Endpoints

| Path | Description |
| --- | --- |
| `/images`, `/charts`, `/clusters`, `/settings` | UI |
| `/api/snapshot` | last scan as JSON |
| `POST /api/refresh` | start a scan now |
| `/metrics` | `kube_tower_image_outdated`, `kube_tower_chart_outdated`, `kube_tower_cluster_reachable`, `kube_tower_last_scan_timestamp_seconds` |
| `/api/docs` | OpenAPI documentation |

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r src/requirements.txt -r tests/requirements.txt
pytest
ruff check src tests && ruff format src tests

# Run against the cluster of your current kubeconfig
KUBE_TOWER_CONFIG=dev-config.yaml PYTHONPATH=src uvicorn --factory kube_tower.main:create_app --reload --port 8080
```

Code layout and design choices are described in [docs/adr/0001-architecture.md](docs/adr/0001-architecture.md).
UI pages are plain Jinja2 templates in `src/kube_tower/web/templates` (htmx + Pico CSS, no
JavaScript build step).

## Release

Push a `vX.Y.Z` tag: CI publishes `ghcr.io/arcanexus/kube-tower:X.Y.Z` (amd64, arm64, arm/v7)
and the chart `oci://ghcr.io/arcanexus/charts/kube-tower` version `X.Y.Z`.
