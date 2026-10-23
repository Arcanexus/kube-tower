# Vulnerabilities (CVE)

kube-tower lists the known vulnerabilities of every image it found (workloads and node images) on
the **Vulnerabilities** page, in the image details and in the Prometheus metrics. It reads them
from two sources, for each image:

1. **Trivy Operator reports**: when [Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
   runs in a cluster, kube-tower reads its `VulnerabilityReports` (`aquasecurity.github.io/v1alpha1`).
   Nothing is scanned by kube-tower for these images. Reports of every cluster are merged per image
   reference; the newest report of a digest that actually runs wins.
2. **Trivy, run by kube-tower**: the other images (no operator, images only cached on nodes, a
   workload the operator has not scanned yet) are scanned with the [Trivy](https://trivy.dev) CLI
   shipped in the kube-tower image. Trivy pulls the image layers from the registry itself (no
   container runtime needed), with the [registry credentials](configuration.md#registry-authentication)
   of kube-tower.

![Vulnerabilities](images/vulnerabilities.png)

The vulnerability scan runs after the version checks of each scan: versions show up first, and
the Vulnerabilities page says when the vulnerability scan is still in progress. Trivy results
are kept in memory and reused until `rescanInterval` (24h by default), so a scan every 6h does not
download every image again; images whose scan failed are retried at the next scan.

## The page

One line per image, the most vulnerable first: counts per severity (`C`ritical, `H`igh,
`M`edium, `L`ow, `U`nknown), how many vulnerabilities have a fix in a newer package version, and
where the result comes from. The counters at the top give the number of images with at least one
vulnerability of each severity; click one to show only those images. An image whose OS release is
**end of life** (no more security fixes, e.g. `alpine 3.18`) is flagged in red.

Clicking an image opens the list of its vulnerabilities: ID (linked to its advisory), severity and
CVSS score, package, installed version and the version that fixes it.

## Trivy modes

| Mode | When | Database |
| --- | --- | --- |
| **Standalone** (default) | `trivy.server.enabled: false` | Downloaded by kube-tower at each scan into an `emptyDir` (~1.6 GB, 3 GiB limit by default) |
| **Client/server** | `trivy.server.enabled: true` | Held and refreshed by a Trivy server Deployment of the chart; the kube-tower pod stays small |

With the Helm chart:

```yaml
trivy:
  server:
    enabled: true        # deploys aquasec/trivy as a server, kube-tower scans in client mode
```

`config.vulnerabilities.trivy.serverUrl` is set automatically to the chart's server; set it yourself
to use a Trivy server you already run.

By default the Java database (~1.5 GB more) is not downloaded and Java archives (`.jar`, `.war`,
`.ear`, `.par`) are skipped: set `config.vulnerabilities.trivy.javaDb: true` to scan them.

## Trivy Operator

Nothing to configure: kube-tower reads the reports when the CRD exists (the chart's ClusterRole and
[`deploy/remote-cluster-rbac.yaml`](../deploy/remote-cluster-rbac.yaml) grant `get`/`list` on
`vulnerabilityreports.aquasecurity.github.io`). Without the operator, the CRD is simply not found
and Trivy scans every image. Set `config.vulnerabilities.trivyOperator: false` to always scan with
Trivy.

## Settings

```yaml
vulnerabilities:
  enabled: true
  trivyOperator: true          # read Trivy Operator VulnerabilityReports
  trivy:
    enabled: true              # scan the other images with the Trivy CLI
    binary: trivy
    serverUrl: ""              # client/server mode, e.g. http://kube-tower-trivy:4954
    cacheDir: /tmp/trivy
    timeout: 10m               # per image
    concurrency: 2             # images scanned at the same time
    rescanInterval: 24h
    ignoreUnfixed: false       # only report vulnerabilities that have a fix
    javaDb: false
    extraArgs: []              # extra `trivy image` arguments
  ignore:                      # images never scanned (fnmatch on registry/repository[:tag])
    - registry.k8s.io/pause*
```

## Metrics

| Metric | Labels | Value |
| --- | --- | --- |
| `kube_tower_image_vulnerabilities` | `image`, `tag`, `severity`, `source` | number of vulnerabilities of that severity |
| `kube_tower_image_vulnerabilities_fixable` | `image`, `tag`, `severity` | those with a fixed version |
| `kube_tower_image_os_eosl` | `image`, `tag`, `os` | 1 if the OS of the image is end of life |
| `kube_tower_image_vulnerability_scan_failed` | `image`, `tag` | 1 if the scan failed |
| `kube_tower_last_vulnerability_scan_timestamp_seconds` | | end of the last vulnerability scan |

```promql
# Images with critical vulnerabilities that have a fix, in cluster "prod"
kube_tower_image_vulnerabilities_fixable{severity="critical"} > 0
  and on (image, tag) kube_tower_image_workload_info{cluster="prod"}
```

## Troubleshooting

- **`trivy binary 'trivy' not found`**: the image does not ship Trivy (custom image): install it or
  set `vulnerabilities.trivy.binary`.
- **`cannot download the Trivy database`**: the pod cannot reach `mirror.gcr.io` / `ghcr.io`
  (database registries). Allow them, or use a Trivy server that can.
- **`remote error: ... UNAUTHORIZED` / `DENIED`**: private image: add credentials for its registry.
- **The pod is OOMKilled or evicted**: standalone mode needs memory and disk for the database. Raise
  `resources.limits.memory` / `trivy.cacheSizeLimit`, lower `concurrency`, or enable `trivy.server`.
