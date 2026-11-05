# API

Everything the pages show is also available as JSON, for scripts and other tools. The interactive
OpenAPI documentation is served by kube-tower itself on `/api/docs`; the API tab of the
[Administration](ui-administration.md#api) page links to it. Prometheus metrics are on `/metrics`, see
[Metrics and Grafana](metrics.md).

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /api/snapshot` | The last scan: images, charts, clusters, errors, timestamps |
| `POST /api/refresh` | Start a scan now (`{"started": false}` if one is already running) |
| `POST /api/rescan/image?ref=…` | Check an image again (`ref` as in the snapshot, e.g. `docker.io/library/nginx:1.25`): every image with its name is checked (all tags, including the new ones found on the clusters); `versions=false` or `vulnerabilities=false` to skip one part. 202 when started, 409 with a `reason` if a scan is running, 404 if unknown |
| `POST /api/rescan/chart?cluster=…&namespace=…&app=…&chart=…` | Check one Helm chart and its subcharts again (`namespace` is the Application's namespace) |
| `POST /api/administration/retry-failed` | Check again everything that failed in the last scan (202, or 409 with a `reason`) |
| `POST /api/administration/trivy-db` | Update the Trivy databases when a newer one is published (standalone mode) |
| `DELETE /api/administration/trivy-cache` | Forget the cached Trivy results (`{"cleared": n}`) |
| `POST /api/administration/connectivity` | Start a connectivity test; results with `GET /api/administration/connectivity` |
| `GET /api/administration/unused-images` | Images cached on nodes that no workload of their cluster uses |
| `GET /healthz` | Liveness |
| `GET /readyz` | 200 once the first scan has finished |
| `GET /api/docs` | Interactive OpenAPI documentation |

## Authentication

With the login on (the default), the API needs a session or the Basic auth of a local account: `GET`
for every role, each `POST` and `DELETE` for the roles with its permission (others get a 403 naming
it, see [RBAC](rbac.md)). A role limited to some clusters only gets those in
`/api/snapshot` and the other answers. `/healthz`,
`/readyz` and `/metrics` stay open (see [authentication](authentication.md#api-and-metrics)).

Requests that change something (`POST`, `DELETE`) are refused with a 403 when a browser says they come
from another site (`Sec-Fetch-Site`, else `Origin` compared with the host, or `X-Forwarded-Host` behind a
proxy): a page on another site cannot start scans through the browser of someone who can reach
kube-tower. The UI itself and clients that are not browsers (curl, scripts) are not affected.

## Examples

```sh
# Outdated images, as "image current -> latest"
curl -s -u admin:$PASSWORD http://kube-tower/api/snapshot \
  | jq -r '.images[] | select(.status=="outdated") | "\(.image.ref) -> \(.latest_tag // .latest_digest)"'
```

```sh
# Images with critical vulnerabilities, with the number of them
curl -s -u admin:$PASSWORD http://kube-tower/api/snapshot \
  | jq -r '.images[] | {ref: .image.ref, n: ([.vulnerabilities.vulnerabilities[]? | select(.severity=="critical")] | length)}
           | select(.n > 0) | "\(.ref) \(.n)"'

# Start a scan, then check one image again once it is over
curl -s -u admin:$PASSWORD -X POST http://kube-tower/api/refresh
curl -s -u admin:$PASSWORD -X POST "http://kube-tower/api/rescan/image?ref=docker.io/library/nginx:1.25"
```
