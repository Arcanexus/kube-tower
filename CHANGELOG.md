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
- Helm chart: cluster, registry (per registry and dockerconfigjson) and git credentials can be
  created by the chart from the values or taken from existing Secrets; existing cluster Secrets
  are referenced by name (`clusters[].existingSecret`, new `clusters.secretNames` setting).
- Helm chart rendering tests.
- UI: Logs page following the application and scanner logs; light/dark theme switch; status counters
  filter the results; detail panels for images (digest comparison, registry links, usages) and charts;
  subcharts shown as an expanded tree, with the subcharts of subcharts; `latest` tags highlighted in red.

### Fixed

- Pod restarting in a loop during long scans: scans run in a dedicated worker thread so the web
  server and `/healthz` stay responsive, each cluster is collected in its own thread (in parallel),
  Kubernetes lists are paginated, the chart adds a
  `startupProbe` and longer probe timeouts (`startupProbe`, `livenessProbe`, `readinessProbe` values).
- The UI reloads itself when the scan it shows as in progress is over.
- The UI works however it is exposed (http, https behind an ingress terminating TLS, port-forward,
  sub-path): every UI link is relative (no more mixed content errors), and uvicorn trusts the
  `X-Forwarded-*` headers.
- Version check errors (image, chart, subchart) are logged as warnings (Logs page, pod logs) and listed with the scan
  errors in the UI and the `kube_tower_last_scan_errors` metric; they were only shown in the tables.

### Changed

- `kube_tower_image_outdated` gains an `update` label; `kube_tower_chart_outdated` gains `destination_namespace`,
  `source` and `update` labels.
- License changed from GPL-3.0 to Apache-2.0.
