# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Chart: optional NetworkPolicies (`networkPolicy.enabled`) for the kube-tower pod and the Trivy
  server: only the `http` port is reachable (from `networkPolicy.ingress.from`), egress limited to DNS,
  the Trivy server and `networkPolicy.egress.ports` (443, 6443).
- Versioning scheme detection: each tag is told `semver`, `calver` (`2024.10.1`), `date` (`20241024`)
  or `build` (`4521`) and only compared with tags of the same scheme, so `redis:7` is no longer
  reported outdated because of a CI build number tag. The scheme is shown in the image details;
  updates that are not semver are reported as `newer` (metrics, Synthesis page, Grafana dashboard).
- UI: scan status redesigned as a pill at the top right (age of the last scan, errors menu, Refresh);
  on list pages only the list scrolls (title, filters, counters and column headers stay); sortable
  columns; CVE filter on the Vulnerabilities page (all or part of one or several IDs), matching
  vulnerabilities listed first in the detail panel. Documentation, README and screenshots refreshed.
- Vulnerabilities (CVE) of every image on a new Vulnerabilities page, in the image details and in the
  Prometheus metrics: read from Trivy Operator `VulnerabilityReports` when present, else scanned with
  the Trivy CLI (standalone, or client/server with the optional Trivy server of the chart,
  `trivy.server.enabled`). End of life OS releases are flagged. The Trivy CLI is not in the
  kube-tower image: the chart copies it from the official Trivy image with an init container
  (`trivy.enabled`, `trivy.image`).
- Rescan of one image (version and/or vulnerabilities) or one Helm chart from its detail panel, or
  with `POST /api/rescan/image` and `POST /api/rescan/chart`, without waiting for the next scan. An
  image rescan (version or vulnerabilities) covers every image with its name: all tags, used or only on
  nodes, including the new ones found on the clusters, which are read again first.
- Maintenance page: full scan, retry of what failed in the last scan, Trivy database status and
  update, Trivy results cache clearing, connectivity test of the clusters, registries, Helm
  repositories and Trivy server, and the list of unused node images with their `crictl rmi`
  command (kube-tower stays read-only). Also in the API under `/api/maintenance/…`.
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

- Pre-release versions are ordered like semver (`includePrerelease: true`): numeric identifiers are
  compared as numbers, so `1.0.0-rc.10` is newer than `1.0.0-rc.9` (it was compared as text).
- Security: the image given to Trivy comes after `--` and an image reference starting with `-` is
  refused, so an image name read from the clusters can never be taken as a Trivy option.
- Security: requests that change something (`POST`, `DELETE`) coming from another site through a
  browser are refused (403, from `Sec-Fetch-Site` or `Origin`), so a page on another site cannot start
  scans or clear the Trivy cache through the browser of someone who can reach kube-tower.
- Faster image collection on big clusters: an image used by thousands of pods or present on
  hundreds of nodes made each new usage slower to record (20,000 pods of one image: 30 s of CPU,
  now 0.1 s).
- Clusters are probed in parallel at the start of each scan and connectivity test: an unreachable
  cluster no longer delays the next ones by `clusters.requestTimeout` (30 s) each.
- Remote cluster clients are reused from one scan to the next while their Secret is unchanged
  (same `resourceVersion`). Before, each scan and connectivity test created new clients without
  closing the old ones (connection pools left open) and wrote the CA, client certificate and private
  key again to new files in `/tmp`, never deleted. Clients of changed or removed Secrets are closed
  and their files deleted; exec plugins also run less often (their token is reused until it expires).
- Security: registry credentials and tokens are never sent over plain `http://` any more. A token
  service (`realm`) or a registry redirect in `http://`, an `http://` Helm repository with
  credentials and an `http://` git raw URL template with a git token are refused with an explicit
  error. After a registry redirect to another host, the registry's credentials are no longer sent
  to that host: it gets the credentials configured for it, or anonymous access.
- Security: a cluster Secret holding a kubeconfig could make kube-tower run any command of its
  image (exec plugin), read files of the pod (`tokenFile`, `client-certificate`...) or use an
  `auth-provider`. Exec plugins now run only when their command is listed in the new
  `clusters.execCommands` setting (empty by default), so managed clusters (EKS, GKE, AKS) can still
  use their cloud identity; file paths and auth providers are refused. New chart values
  `extraInitContainers`, `extraEnv`, `extraVolumes`, `extraVolumeMounts` and `podLabels` to add the
  plugin to the pod. EKS, GKE and AKS examples and the list of supported authentication methods in
  docs/clusters.md.
- Registry tokens are renewed when they expire: a token refused with a 401 (e.g. a Docker Hub token,
  valid 5 minutes, during a long scan) is no longer sent again, and tokens are renewed before the end
  of the lifetime given by the registry (`expires_in`). Before, every later check of the repository
  failed with HTTP 401 until the end of the scan.
- Bursts of timeouts / disconnections in the middle of a scan: big Helm repository indexes
  (index.yaml) were parsed in the scan event loop, stalling every other request for up to minutes on
  small nodes. They are now parsed in a thread with libyaml, and downloaded once per repository
  even when several charts come from it.
- registry.k8s.io images in error with `HTTP 307 Temporary Redirect`: registry redirects are followed
  and authenticated against the target registry (regional Artifact Registry).
- Charts deployed with a `v` prefixed `targetRevision` (`v4.11.0`) for a chart published as `4.11.0`
  were reported as not published.
- Registry requests are retried (`registries.retries`, default 2, growing delay) after a timeout, a
  connection error or a 502/503/504, so a few dropped requests (Docker Hub bursts) no longer leave
  images in error. Timeout errors say whether the connection could not be opened, the registry did
  not answer, or too many requests were waiting.
- Releases tagged on the coverage badge commit published nothing: the badge commit no longer
  carries `[skip ci]` (which also skipped the tag push workflows); the Tests and Docker workflows
  ignore pushes to main that only change `.github/badges` instead.
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

- The Maintenance page is renamed Administration: page `administration` (the old `maintenance` URL
  redirects to it) and JSON API `/api/administration/...` (was `/api/maintenance/...`).
- Images page: an icon in front of each image tells whether a pod runs it (green play) or not (grey
  pause: workload scaled to zero, CronJob between two runs, image only cached on nodes).
- Performance: images and charts of the snapshot are looked up by key (detail panels, rescans, API)
  instead of scanning the whole list at each request and each poll of a rescan.
- Documentation: client/server Trivy mode recommended beyond a few dozen images (standalone mode
  downloads and analyses the shared base layers again for every image).
- Performance: the `index.yaml` of HTTP Helm repositories is kept between scans (only the chart
  versions and archive URLs) and downloaded again only when the repository says it changed
  (`ETag` / `Last-Modified`, HTTP 304): big indexes are no longer downloaded and parsed at each scan.
- Scans: the Trivy phase of a scan has its own lock. Once the versions are checked, a new scan,
  *Retry what failed* and the rescans can start without waiting for the vulnerability scans; a new
  scan waits only for the Trivy phase before running its own (skipped when a newer scan replaced it).
  The Trivy database update still waits for both phases. The status shows *Vulnerability scan in
  progress…* during the Trivy phase.
- Maintenance page: an *In progress* section first lists what runs (each scan phase, the scans
  waiting for a Trivy phase, the rescans and the maintenance actions) with their start time; the scan
  status at the top of every page links to it.
- Security: cluster Secrets are read by name only by default (`get` on these Secrets), instead of
  listing the Secrets of the namespace, which gave read access to all of them. The chart names
  the Secrets it creates and the `existingSecret` ones itself. **Labelled cluster Secrets created
  outside the chart are no longer found**: reference them with `clusters[].existingSecret` /
  `config.clusters.secretNames`, or set `config.clusters.listSecrets: true` to list them as before.
- New `config.clusters.argocdSecretNames`: with `useArgocdSecrets`, read only these ArgoCD cluster
  Secrets instead of listing every Secret of the ArgoCD namespace (still the default, with a
  warning in the docs and values.yaml).
- Smaller image: 31 MB compressed instead of 65 MB (amd64), 178 MB on disk instead of 373 MB. It is
  based on `python:3.13-alpine` and leaves out the unused asyncio client of the `kubernetes` package
  and its aiohttp dependencies. Dependencies are installed for each architecture without QEMU
  emulation, so the multi-arch build is faster.
- `kube_tower_image_outdated` gains an `update` label; `kube_tower_chart_outdated` gains `destination_namespace`,
  `source` and `update` labels.
- License changed from GPL-3.0 to Apache-2.0.
