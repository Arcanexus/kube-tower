# Usage

## The dashboards

The left sidebar gives access to four pages. The bar at the top shows when the last scan
finished, a **Refresh now** button that starts a scan immediately, and the errors of the last scan,
if any: collection errors (e.g. a missing permission on a cluster) and version check errors
(e.g. a registry that cannot be queried). Each error is also logged as a warning in the pod logs.

### Images

![Images](images/images.png)

One line per image reference (`registry/repository:tag`), whatever the number of workloads using
it. The counters at the top summarize the statuses; filter by text, status or cluster (filters
are kept in the URL, so a filtered view can be bookmarked or shared).

| Column | Meaning |
| --- | --- |
| Image | Normalized name: `nginx` becomes `docker.io/library/nginx` |
| Current | Tag (and digest) used by the workloads |
| Latest | Highest tag of the same shape published in the registry, or the published digest for floating tags |
| Status | See [statuses](#statuses) |
| Used by | Every workload, pod and node using the image, per cluster |

### Helm charts

![Helm charts](images/charts.png)

One line per Helm source of every ArgoCD Application (multi-source Applications give several
lines). Subcharts are listed under each chart; the status used by the counters and filters is the
worst one of the chart and its subcharts, so a chart whose subchart is outdated shows up when
filtering on `outdated`.

| Source type | Current version | Latest version |
| --- | --- | --- |
| `helm` (HTTP repository) | Application `targetRevision` | from the repository `index.yaml` |
| `oci` | Application `targetRevision` | from the registry tags |
| `git` (chart in a git path) | `version` of `Chart.yaml` at `targetRevision` | n/a: the chart follows git, only its subcharts are checked |

### Clusters

Every cluster kube-tower knows, where it comes from (`in-cluster`, `secret`, `argocd-secret`), its
Kubernetes version and whether it answered. Unreachable clusters are skipped during the scan and
show the connection error.

### Settings

![Settings](images/settings.png)

The effective configuration (with the same camelCase keys as `config.yaml`) and the registry
credentials that were loaded. Secret values are never displayed: only the registry, where the
credentials come from, the username and whether they could be read.

## Statuses

| Status | Meaning |
| --- | --- |
| 🟢 `up-to-date` | Nothing newer is published (or, for floating tags, the running digest is the published one) |
| 🟠 `outdated` | A newer version, or a newer image under the same floating tag, is available |
| ⚪ `unknown` | Cannot be compared: image pinned by digest only, floating tag without known digest, version constraint (`1.x`), local subchart (`file://`) |
| 🔴 `error` | The registry or repository could not be queried: the message tells why (authentication, not found, timeout…) |

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/snapshot` | The last scan: images, charts, clusters, errors, timestamps |
| `POST /api/refresh` | Start a scan now (`{"started": false}` if one is already running) |
| `GET /healthz` | Liveness |
| `GET /readyz` | 200 once the first scan has finished |
| `GET /api/docs` | Interactive OpenAPI documentation |

```sh
# Outdated images, as "image current -> latest"
curl -s http://kube-tower/api/snapshot \
  | jq -r '.images[] | select(.status=="outdated") | "\(.image.ref) -> \(.latest_tag // .latest_digest)"'
```

## Prometheus metrics and Grafana

`GET /metrics` is a Prometheus exporter for the result of the last scan: current and latest
version of every image and chart, update type (major, minor, patch), workloads and clusters,
scan duration and errors. A ready-made Grafana dashboard ships with the chart.

See [Metrics and Grafana](metrics.md) for the metric reference, PromQL examples, alerts and the dashboard.
