<p align="center">
  <img src="docs/images/logo.svg" alt="kube-tower logo" width="120">
</p>

<h1 align="center">kube-tower</h1>

<p align="center">
  <strong>See what is outdated in your Kubernetes clusters, in one place, without touching anything.</strong>
</p>

<p align="center">
  <a href="https://github.com/Arcanexus/kube-tower/actions/workflows/docker-publish.yml"><img src="https://github.com/Arcanexus/kube-tower/actions/workflows/docker-publish.yml/badge.svg?branch=main" alt="Build"></a>
  <a href="https://github.com/Arcanexus/kube-tower/actions/workflows/tests.yml"><img src="https://github.com/Arcanexus/kube-tower/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests"></a>
  <a href="https://github.com/Arcanexus/kube-tower/actions/workflows/tests.yml"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Arcanexus/kube-tower/badges/coverage.json" alt="Coverage"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Arcanexus/kube-tower" alt="License"></a>
  <a href="https://github.com/Arcanexus/kube-tower/pkgs/container/kube-tower"><img src="https://img.shields.io/badge/image-ghcr.io-blue?logo=docker&logoColor=white" alt="Image"></a>
</p>

---

kube-tower connects to all your Kubernetes clusters, inventories every **container image** and every
**Helm chart** (with its subcharts), and tells you which ones have a newer version available in their
registry. Think [watchtower](https://containrrr.dev/watchtower/), [Renovate](https://docs.renovatebot.com/)
or [version-checker](https://github.com/jetstack/version-checker), as a **read-only dashboard**: kube-tower
never updates anything, you stay in control of your GitOps workflow.

![Images dashboard](docs/images/images.png)

## Features

| | |
| --- | --- |
| 📦 **Every image** | Pods, Deployments, StatefulSets, DaemonSets and CronJobs (running or not) plus the images cached on nodes. |
| 🔎 **Checked at the source** | Each image is compared with the registry referenced in the manifest: Docker Hub, ghcr.io, quay.io, Harbor, GitLab or any OCI registry. |
| 🏷️ **Smart tag matching** | `1.25.3-alpine` is only compared with `x.y.z-alpine` tags; pre-releases are ignored unless you ask for them. |
| 🔁 **Floating tags too** | `latest`, `stable`… are checked by digest, like watchtower: you know when a newer image was pushed under the same tag. |
| ⎈ **Helm charts and subcharts** | Charts deployed by ArgoCD Applications, from Helm repositories, OCI registries or git paths, with every dependency checked. |
| 🌐 **Multi-cluster** | Register clusters ArgoCD-style with a Secret, or reuse the cluster Secrets ArgoCD already has. |
| 🔐 **Registry authentication** | Per registry credentials for private registries, private Helm repositories and Docker Hub rate limits. |
| 🪶 **Stateless** | No database. One small pod, rebuilt inventory every few hours or on demand. |
| 📈 **Observable** | JSON API and Prometheus metrics, ready for Grafana dashboards and alerts. |

![Helm charts dashboard](docs/images/charts.png)

## Quick start

```sh
helm install kube-tower oci://ghcr.io/arcanexus/charts/kube-tower \
  --namespace kube-tower --create-namespace

kubectl -n kube-tower port-forward svc/kube-tower 8080:80
```

Open http://localhost:8080: the first scan of the local cluster starts right away.

Then, as needed:

- [register other clusters](docs/clusters.md),
- [add registry credentials](docs/configuration.md#registry-authentication),
- [expose the UI with an ingress or deploy with ArgoCD](docs/installation.md).

## How it works

```
 cluster Secrets ─┐
                  ▼
 ┌───────────────────────── kube-tower ─────────────────────────┐
 │ discover clusters → collect images & ArgoCD charts → check   │──► UI · /api · /metrics
 └──────────────────────────────────────────────────┬───────────┘
                                                    ▼
                    OCI registries · Helm repositories · git (Chart.yaml)
```

Every `refreshInterval` (6h by default), kube-tower lists the workloads, nodes and ArgoCD
Applications of every reachable cluster with a read-only ServiceAccount, asks each registry for
its published versions (each repository once per scan) and keeps the result in memory.
Design choices are explained in [ADR 0001](docs/adr/0001-architecture.md).

## Documentation

| Guide | Content |
| --- | --- |
| [Installation](docs/installation.md) | Helm, ArgoCD, ingress, upgrades, requirements |
| [Configuration](docs/configuration.md) | every setting, registry authentication, secrets |
| [Clusters](docs/clusters.md) | registering remote clusters, reusing ArgoCD clusters |
| [Usage](docs/usage.md) | the dashboards, statuses, API, Prometheus metrics and alerts |
| [Development](docs/development.md) | run locally, tests and coverage, project layout, releases |
| [Troubleshooting](docs/troubleshooting.md) | common errors and how to fix them |

## Compared to similar tools

| | kube-tower | watchtower | Renovate | version-checker |
| --- | --- | --- | --- | --- |
| Updates things for you | ❌ never | ✅ containers | ✅ pull requests | ❌ |
| Container images | ✅ | ✅ Docker only | ✅ from git | ✅ |
| Helm charts and subcharts | ✅ from ArgoCD | ❌ | ✅ from git | ❌ |
| Several clusters in one view | ✅ | ❌ | n/a | ❌ one per cluster |
| Web UI | ✅ | ❌ | ❌ | ❌ (Grafana) |

## Contributing

Issues and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), the [development guide](docs/development.md) and the [changelog](CHANGELOG.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

[GPL-3.0](LICENSE). Icons by [Lucide](https://lucide.dev) (ISC), styles by [Pico CSS](https://picocss.com) (MIT), [htmx](https://htmx.org) (0BSD).
