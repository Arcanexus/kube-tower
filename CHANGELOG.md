# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Inventory of container images from Pods, Deployments, StatefulSets, DaemonSets, CronJobs and nodes.
- Version check against the source registry (OCI distribution API), with tag shape matching and
  digest check for floating tags.
- Helm charts and subcharts deployed by ArgoCD Applications (Helm repositories, OCI, git paths).
- Multi-cluster support with ArgoCD-style cluster Secrets, optional reuse of ArgoCD cluster Secrets.
- Per registry credentials for container registries and Helm repositories.
- Web UI (Images, Helm charts, Clusters, Settings), JSON API and Prometheus metrics.
- Helm chart, multi-arch image (amd64, arm64, arm/v7), CI with coverage.
- Documentation: complete ArgoCD `Application` example (OCI chart, ingress, ArgoCD clusters, registry credentials).
- Prometheus exporter: update type (`major`/`minor`/`patch`/`digest`), workloads and node counts per image,
  subcharts, cluster info, scan duration, errors and counters, build info.
- Grafana dashboard (`charts/kube-tower/dashboards/kube-tower.json`), optionally deployed as a ConfigMap for the
  Grafana sidecar (`grafanaDashboard.enabled`); ServiceMonitor `honorLabels`, extra labels and relabelings.

### Changed

- `kube_tower_image_outdated` gains an `update` label; `kube_tower_chart_outdated` gains `destination_namespace`,
  `source` and `update` labels.
- License changed from GPL-3.0 to Apache-2.0.
