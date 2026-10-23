# ADR 0001: kube-tower architecture

- Status: accepted
- Date: 2026-10-23

## Context

We want a single place to see, across several Kubernetes clusters, which container images and
Helm charts are outdated, in the spirit of watchtower, Renovate or jetstack version-checker,
but **without any automatic update**. Constraints:

- The maintainer knows Python, not Go, and has no frontend skills.
- Any cluster must be registrable, the way ArgoCD registers clusters.
- Images: every image of every workload (running or not) and every image cached on nodes.
- The latest version is looked up in the registry referenced by the manifest.
- Helm charts are deployed with ArgoCD Applications, from Helm repositories, OCI registries or
  git paths (e.g. `Arcanexus/helm-charts`), and have subcharts.
- Stateless: no database.

## Decision

### Runtime

A single Python 3.13 process (FastAPI + uvicorn) packaged as one multi-arch image
(`ghcr.io/arcanexus/kube-tower`, amd64/arm64/arm-v7), deployed with the Helm chart in
`charts/kube-tower`.

```
            ┌─────────────────────────── kube-tower pod ───────────────────────────┐
 Secrets ──►│ ClusterRegistry ─► collectors (images, helm) ─► checkers ─► Snapshot │──► UI / API / metrics
            │                                     │                                │
            └─────────────────────────────────────┼────────────────────────────────┘
                                                  ▼
                         OCI registries · Helm repos (index.yaml) · git raw files
```

| Module | Role |
| --- | --- |
| `clusters.py` | Discovers clusters: the local one plus Secrets labelled `kube-tower.arcanexus.com/secret-type=cluster` (ArgoCD cluster-secret layout or a raw kubeconfig), optionally ArgoCD's own cluster Secrets. |
| `collectors/images.py` | Lists images from Pods, Deployments, StatefulSets, DaemonSets, CronJobs and `node.status.images`, deduplicated by reference, with running digests. |
| `collectors/helm.py` | Reads ArgoCD `Application` objects (single and multi-source) and extracts Helm sources. |
| `registry/oci.py` | Minimal OCI distribution client (token auth, tag pagination, digests, blobs). |
| `registry/helm.py` | Helm repositories (`index.yaml`), OCI charts, and `Chart.yaml` read from git through raw URLs. |
| `checkers.py` | Computes the status of each image / chart / subchart, querying each repository once per scan. |
| `scanner.py` | Runs a full scan periodically and keeps the last `Snapshot` in memory. |
| `web/` | Server-rendered UI, JSON API (`/api/snapshot`, `/api/refresh`), Prometheus `/metrics`. |

New sources (e.g. Flux HelmReleases, plain Helm release secrets) are added as a new collector,
new registries types as a new client, without touching the rest.

### Version comparison

- Image tags are compared only with tags of the **same shape**: same `v` prefix, same number of
  numeric components, same suffix (`1.25.3-alpine` only competes with `x.y.z-alpine`).
  Pre-releases are ignored unless enabled.
- Floating tags (`latest`, `stable`...) are checked watchtower-style: the digest published for the
  tag is compared with the digest the nodes actually run.
- Charts use semver ordering. A `targetRevision` that is a constraint (`1.x`, `*`) is reported as
  `unknown`. Charts deployed from a git path follow the git revision, so only their subcharts can
  be outdated.

### UI

Jinja2 templates + [htmx](https://htmx.org) + [Pico CSS](https://picocss.com), served by FastAPI
and vendored in the image. No Node.js toolchain, no build step: a page is an HTML file with
Jinja placeholders, which a Python developer can maintain. Tabs: Images, Helm charts, Clusters,
Settings. Filtering is done server-side with htmx partial updates.

Alternatives considered: React/Vue SPA (needs a JS toolchain and skills we don't have),
Streamlit/NiceGUI (fast to start but harder to deploy behind an ingress and to customize).

### Configuration and state

- Settings: a YAML file rendered from Helm values into a ConfigMap; secrets (registry
  credentials, git token, cluster tokens) only come from Kubernetes Secrets.
- No database. The inventory is rebuilt at startup and every `refreshInterval` (default 6h), or
  on demand. One replica is enough; a restart only costs one scan.

## Consequences

- Simple to run and to reason about; restarts lose nothing that cannot be recomputed.
- Large fleets mean longer scans; registry lookups are deduplicated, cached per scan and run
  concurrently (`registries.concurrency`).
- Docker Hub anonymous rate limits may be hit on big clusters: configure credentials.
- Clusters using exec-based auth (EKS/GKE plugins) need a ServiceAccount token instead.
- Private git repositories other than GitHub/GitLab need a `git.rawUrlTemplates` entry.
