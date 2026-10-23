# Usage

## The dashboards

The left sidebar gives access to five pages, and its bottom button switches the theme between
auto (follows the system), light and dark; the choice is remembered by the browser. The bar at the
top shows when the last scan finished, a **Refresh now** button that starts a scan immediately,
and the errors of the last scan, if any: collection errors (e.g. a missing permission on a
cluster) and version check errors (e.g. a registry that cannot be queried). Each error is also
logged as a warning, visible on the Logs page and in the pod logs.

On the Images and Helm charts pages, the counters at the top are buttons: clicking one shows only
that status (click it again to show everything). Clicking a line opens a detail panel on the
right; close it with its button, a click outside or `Esc`.

### Images

![Images](images/images.png)

One line per image reference (`registry/repository:tag`), whatever the number of workloads using
it. The counters at the top summarize the statuses; filter by text, status or cluster (filters
are kept in the URL, so a filtered view can be bookmarked or shared). Images using `latest` (or no
tag at all, which means `latest`) are shown in red: the running version changes on every pull, pin
a version instead.

| Column | Meaning |
| --- | --- |
| Image | Normalized name: `nginx` becomes `docker.io/library/nginx` |
| Current | Tag (and digest) used by the workloads |
| Latest | Highest tag of the same shape published in the registry, or the published digest for floating tags |
| Status | See [statuses](#statuses) |
| Used by | Number of workloads, pods and nodes using the image, and their clusters |

The detail panel of an image shows the upgrade target, links to the image page on its registry
(Docker Hub, GitHub Packages, Quay, ECR Public, Microsoft Artifact Registry), every place where it
is used, and compares digests: the digests reported by the running pods, the digest currently
published for the same tag (a difference means the tag was pushed again since the pods started),
and the digest of the latest tag. Published digests are read with `images.fetchTagDigests`
(enabled by default).

![Image details](images/image-detail.png)

### Helm charts

![Helm charts](images/charts.png)

One line per Helm source of every ArgoCD Application (multi-source Applications give several
lines). The subcharts are shown as a tree under each chart, always expanded, including the
subcharts of subcharts (down to 3 levels). The status used by the counters and filters is the
worst one of the chart and its whole subchart tree, so a chart whose subchart is outdated shows up
when filtering on `outdated`. The detail panel of a chart shows its source, the ArgoCD Application,
links to the repository and Artifact Hub, and the subchart tree with each subchart repository.

| Source type | Current version | Latest version |
| --- | --- | --- |
| `helm` (HTTP repository) | Application `targetRevision` | from the repository `index.yaml` |
| `oci` | Application `targetRevision` | from the registry tags |
| `git` (chart in a git path) | `version` of `Chart.yaml` at `targetRevision` | n/a: the chart follows git, only its subcharts are checked |

### Clusters

Every cluster kube-tower knows, where it comes from (`in-cluster`, `secret`, `argocd-secret`), its
Kubernetes version and whether it answered. Unreachable clusters are skipped during the scan and
show the connection error.

### Logs

![Logs](images/logs.png)

The last 2000 log lines of kube-tower (scans, registries, clusters), kept in memory and followed
live, like `kubectl logs -f`. Filter by text or minimum level, and pause the stream to read. Only
the lines logged at the configured `logs.level` or above are kept: set it to `DEBUG` to debug a
scan.

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
