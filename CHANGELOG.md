# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Vulnerabilities (CVE) of every image on a new Vulnerabilities page, in the image details and in the
  Prometheus metrics: read from Trivy Operator `VulnerabilityReports` when present, else scanned with
  the Trivy CLI (standalone, or client/server with the optional Trivy server of the chart,
  `trivy.server.enabled`). End of life OS releases are flagged. The Trivy CLI is not in the
  kube-tower image: the chart copies it from the official Trivy image with an init container
  (`trivy.enabled`, `trivy.image`).
- Vulnerabilities on the Synthesis page (critical CVEs tile and per cluster, images by worst severity,
  most vulnerable images) and a Vulnerabilities row in the Grafana dashboard.

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
- UI: Synthesis home page (status distributions, pending updates, registries, most used outdated images,
  per cluster figures); the version shown by the UI and `kube_tower_build_info` comes from the image tag.

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
- More detailed logs, each at the right level: HTTP requests, check results and objects listed
  (`DEBUG`), clusters, per cluster collection and check summaries (`INFO`), non fatal problems such
  as an unreachable cluster or a forbidden resource (`WARNING`). See the log levels in `docs/usage.md`.
- Explicit error messages: each one says what failed, the HTTP or Kubernetes status and what to do
  (e.g. `HTTP 429 Too Many Requests - rate limited by registry-1.docker.io: add credentials for it`,
  `403 Forbidden - the ServiceAccount used for this cluster is not allowed to list pods…`), for
  registries, Helm repositories, git hosts, clusters and cluster secrets.

### Changed

- `kube_tower_image_outdated` gains an `update` label; `kube_tower_chart_outdated` gains `destination_namespace`,
  `source` and `update` labels.
- License changed from GPL-3.0 to Apache-2.0.
