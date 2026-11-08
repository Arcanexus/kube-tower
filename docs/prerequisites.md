# Prerequisites

What kube-tower needs before you [install](installation.md) it: a cluster, a few tools, network access
to the registries, and some CPU, memory and disk, which depend on the size of your inventory.

## Cluster and tools

| Need | Version | Notes |
| --- | --- | --- |
| Kubernetes | 1.25+ | Any distribution: k3s, kubeadm, GKE, EKS, AKS... Nodes `linux/amd64`, `linux/arm64` or `linux/arm/v7`; the Trivy image of the chart exists for amd64 and arm64 only (on arm/v7, see [Trivy setups](vulnerabilities.md#trivy-setups)) |
| Helm | 3.8+ | The chart is an OCI artifact (`oci://ghcr.io/arcanexus/charts/kube-tower`), or deploy it with ArgoCD |
| kubectl | | To read the admin password, port-forward, create the Secrets of clusters and registries |
| Rights to install | | Creating a namespace, a ClusterRole and its binding (see [permissions](permissions.md)) |

Optional, for the features that use them:

| Component | Used for |
| --- | --- |
| [ArgoCD](https://argo-cd.readthedocs.io/) or [Flux](https://fluxcd.io/) | The Helm charts page: charts are read from ArgoCD `Application` objects and Flux `HelmRelease` objects (and, with `helm.releases`, from the releases installed with the helm command, see [chart sources](chart-sources.md)). The ArgoCD cluster Secrets can be reused to scan its clusters |
| [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) | Its vulnerability reports (else kube-tower scans with Trivy itself) and the [Security](security.md) page |
| An ingress controller (and cert-manager) | Exposing the UI over HTTPS (else `kubectl port-forward`) |
| An OIDC provider (Authentik, Keycloak, Entra ID...) | [Single sign-on](authentication.md#single-sign-on-oidc); the chart can also deploy Dex |
| The Prometheus operator, Grafana with its dashboard sidecar | The ServiceMonitor and the Grafana dashboard (see [metrics](metrics.md)) |
| A CNI that enforces NetworkPolicies (Calico, Cilium...) | `networkPolicy.enabled` (see [network policies](network.md#network-policies)) |
| Redis or Valkey | Only in [distributed mode](scaling.md), and the chart can deploy a Valkey |

## Network

kube-tower needs outbound HTTPS from its pod to:

- the API servers of the clusters you register (often port `443` or `6443`);
- the registries, Helm repositories and git hosts your workloads and charts come from;
- for the vulnerability scans with Trivy, the Trivy database registries (`mirror.gcr.io`, `ghcr.io`),
  unless a Trivy server or a mirror does it for it.

Every connection is listed in [network and ports](network.md). Behind a proxy or with a private
registry CA, see [registries](registries.md#tls-private-cas-and-insecure-registries).

## Hardware guidelines

kube-tower is light: a scan mostly waits for the registries, and the inventory lives in memory. The
heavy part is **Trivy** when kube-tower scans the images itself (standalone mode, the default): it
downloads a vulnerability database and analyses the layers of every image.

### Defaults of the chart

| Pod | CPU request | Memory request | Memory limit | Ephemeral storage |
| --- | --- | --- | --- | --- |
| kube-tower (single mode, every role) | 50m | 256Mi | 1536Mi | up to 3Gi (`trivy.cacheSizeLimit`) for the Trivy database |
| Trivy server (`trivy.server.enabled`) | 100m | 256Mi | 1Gi | up to 3Gi (`trivy.server.cacheSizeLimit`) |
| Distributed mode: controller (×2) | 50m | 256Mi | 512Mi | |
| Distributed mode: ui (×1, autoscaling optional) | 100m | 192Mi | 512Mi | |
| Distributed mode: worker (×2, autoscaling optional) | 100m | 256Mi | 768Mi | |
| Distributed mode: trivy (×1, always) | 100m | 512Mi | 1536Mi | up to 3Gi |
| Valkey of the chart (`redis.valkey.enabled`) | 20m | 64Mi | 256Mi | |
| Dex of the chart (`dex.enabled`) | 10m | 32Mi | 128Mi | |

No CPU limit is set: scans use the CPU in bursts, then the pods stay nearly idle (an idle ui pod uses
about 5m of CPU and 150Mi of memory, an idle worker about 3m).

### By size of inventory

| Inventory | Setup | Plan for |
| --- | --- | --- |
| **Lab**: up to ~200 images, 1 to 3 clusters, a few users | Single mode, the defaults | 0.5 CPU core and 2 GiB of memory free on one node, 3 GiB of ephemeral storage |
| **Medium**: ~200 to ~1000 images, a few clusters | Single mode with the Trivy server (`trivy.server.enabled: true`) | 1 CPU core, 2 to 3 GiB of memory over both pods, 3 GiB of ephemeral storage on the node of the Trivy server |
| **Large**: 1000+ images, many clusters or users | [Distributed mode](scaling.md) with Valkey; more ui pods for the users, more workers for many clusters | 2 CPU cores and 4 GiB of memory and more; raise the memory limits of the controller and ui pods with the inventory (below) |

These are starting points, not limits: watch the pods with `kubectl top pods -n kube-tower` after the
first scans and adjust `resources` (or `distributed.groups.<name>.resources`).

### What grows with what

| Resource | Grows with | Guideline |
| --- | --- | --- |
| Memory of the controller and of each ui pod | Number of images and of their vulnerabilities (the inventory is in memory) | About 150 MiB, plus about 0.2 MiB per image with ~400 vulnerabilities; leave twice that as limit for the copies made when the inventory is sent to the ui pods, Valkey or `/api/snapshot` |
| Memory of Trivy (standalone, or the trivy pod) | `vulnerabilities.trivy.concurrency` (2 images at a time by default) and the size of the images | Keep the 1536Mi limit for 2 images at a time; raise it, lower the concurrency or use the Trivy server if the pod is OOMKilled |
| Ephemeral storage of Trivy | The databases | ~1.6 GB for the vulnerability database, ~1.5 GB more with `javaDb: true`: raise `trivy.cacheSizeLimit` to about 5Gi with the Java database |
| Duration of a scan | Number of distinct repositories, speed and rate limits of the registries | Credentials (higher rate limits), `registries.concurrency`, more workers in distributed mode |
| CPU of the ui pods | Number of users | One ui pod serves about 10 users (measured CPU per page in [scaling](scaling.md#sizing)) |
| Valkey memory | Inventory (one compressed copy) and the queued tasks | Small: the compressed inventory is about 5 MiB for 1000 images with ~400 vulnerabilities each |

The memory figures were measured on a synthetic inventory (images with 3 workloads and 400
vulnerabilities each); real inventories with fewer vulnerabilities per image use less.
