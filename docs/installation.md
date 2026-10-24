# Installation

## Requirements

- Kubernetes 1.25+ (any distribution: k3s, kubeadm, GKE, EKS, AKS…).
- Outbound HTTPS from the kube-tower pod to the registries, Helm repositories and git hosts your
  workloads use, and to the API servers of the remote clusters you register.
- [ArgoCD](https://argo-cd.readthedocs.io/) only if you want the Helm charts dashboard (charts are
  discovered from ArgoCD `Application` objects).

kube-tower runs as a single stateless pod (requests: 50m CPU, 256Mi memory; 1536Mi memory limit).
The vulnerability scans with Trivy (on by default) also need:

- an outbound access to the Trivy database registries (`mirror.gcr.io`, `ghcr.io`) and to the
  registries of the scanned images;
- up to 3 GiB of ephemeral storage for the database (`trivy.cacheSizeLimit`), unless you use the
  [Trivy server](#vulnerability-scanning-trivy) of the chart;
- nodes able to pull `ghcr.io/aquasecurity/trivy` (amd64 or arm64).

See [vulnerability scanning](#vulnerability-scanning-trivy) to change or disable this.

## With Helm

The chart is published as an OCI artifact on ghcr.io:

```sh
helm install kube-tower oci://ghcr.io/arcanexus/charts/kube-tower \
  --namespace kube-tower --create-namespace \
  --values my-values.yaml
```

A typical `my-values.yaml`:

```yaml
ingress:
  enabled: true
  className: traefik
  hosts:
    - host: kube-tower.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts: [kube-tower.example.com]
      secretName: kube-tower-tls

config:
  refreshInterval: 6h
  images:
    ignore:
      - registry.k8s.io/pause*
  clusters:
    useArgocdSecrets: true       # also scan the clusters ArgoCD knows
    argocdSecretNames:           # read only these ArgoCD Secrets (else every Secret of argocd is readable)
      - cluster-prod.example.com-1234567890

registries:
  credentials:
    - registry: docker.io
      existingSecret: dockerhub-credentials
      usernameKey: username
      passwordKey: password

serviceMonitor:
  enabled: true                  # needs the Prometheus operator
grafanaDashboard:
  enabled: true                  # ConfigMap for the Grafana dashboard sidecar
```

kube-tower has no authentication of its own: put it behind your ingress authentication
(oauth2-proxy, Authentik, Traefik forward auth…) if the UI must not be public. It only reads
data and never shows secret values.

### Vulnerability scanning (Trivy)

kube-tower lists the vulnerabilities of every image: it reads the reports of Trivy Operator when it
runs in a cluster, and scans the other images with the Trivy CLI (see
[Vulnerabilities](vulnerabilities.md)). The Trivy CLI is not in the kube-tower image: the chart adds
an init container that copies it from `trivy.image` at pod start. Choose one of these setups:

**Standalone (default)**: kube-tower downloads the vulnerability database (~1.6 GB) into an
`emptyDir` and scans the images itself. Nothing to set; size the pod if needed:

```yaml
trivy:
  cacheSizeLimit: 3Gi            # emptyDir of the database
resources:
  limits:
    memory: 1536Mi               # raise it, or lower config.vulnerabilities.trivy.concurrency, if OOMKilled
```

**Client/server**: the chart deploys a Trivy server that holds and refreshes the database;
kube-tower scans in client mode and its pod stays small. `config.vulnerabilities.trivy.serverUrl` is
set automatically.

```yaml
trivy:
  server:
    enabled: true
    resources:
      limits:
        memory: 1Gi
    nodeSelector:
      kubernetes.io/arch: amd64
```

To use a Trivy server you already run, keep `trivy.server.enabled: false` and set
`config.vulnerabilities.trivy.serverUrl: http://trivy.trivy-system:4954`.

**Which one?** Standalone suits a few dozen images. Beyond that, prefer client/server. In standalone
mode each scan keeps the image layers in memory only (`--cache-backend memory`, so that concurrent scans
do not fail with "cache may be in use"): the base layers shared by many images (Debian, Alpine,
distroless…) are downloaded and analysed again for every image, at every scan. The Trivy server keeps
the analysis of each layer: a layer already seen, in another image or in a previous scan, is neither
downloaded nor analysed again, so scans are faster and pull much less from the registries (rate
limits). The database is also downloaded once by the server instead of by each kube-tower pod.

**Trivy Operator only**: no Trivy in kube-tower, only the operator's reports are shown (images
only cached on nodes are not scanned):

```yaml
trivy:
  enabled: false                 # no init container
```

**No vulnerabilities at all**: `config.vulnerabilities.enabled: false`.

On `linux/arm/v7` nodes (no official Trivy image), use the Trivy Operator setup, a Trivy server on
other nodes, or `trivy.image` pointing to an image of yours holding `/usr/local/bin/trivy`. A
private `trivy.image` is pulled with `imagePullSecrets` (kube-tower pod and Trivy server). Upgrade Trivy by changing
`trivy.image.tag`, without a new kube-tower release.

Scan settings (`concurrency`, `rescanInterval`, `ignoreUnfixed`, `javaDb`, `ignore`…) are in
`config.vulnerabilities`, see [configuration](configuration.md#vulnerabilities-trivy).

## With ArgoCD

The chart is a Helm OCI chart: in the `Application`, `repoURL` is the registry path **without**
the `oci://` prefix and `chart` is the chart name.

### Minimal Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kube-tower
  namespace: argocd
spec:
  destination:
    name: in-cluster
    namespace: kube-tower
  project: default
  source:
    repoURL: ghcr.io/arcanexus/charts
    chart: kube-tower
    targetRevision: 0.1.0
  syncPolicy:
    automated: {}
    syncOptions:
      - CreateNamespace=true
```

This scans the cluster ArgoCD runs in and the ArgoCD `Application` objects of the `argocd`
namespace, with the UI reachable only through `kubectl port-forward -n kube-tower svc/kube-tower 8080:80`.

### Complete example

A typical homelab setup: the UI behind Traefik with a cert-manager certificate and an
authentication middleware, every cluster ArgoCD manages scanned too, Docker Hub and GitHub
credentials to avoid rate limits, and Prometheus metrics.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kube-tower
  namespace: argocd
spec:
  destination:
    name: in-cluster
    namespace: kube-tower
  project: default
  source:
    repoURL: ghcr.io/arcanexus/charts
    chart: kube-tower
    targetRevision: 0.1.0
    helm:
      valuesObject:
        config:
          refreshInterval: 6h
          clusters:
            # Scan the clusters registered in ArgoCD, reusing their cluster Secrets (by name, see
            # docs/clusters.md: without argocdSecretNames every Secret of argocd is readable)
            useArgocdSecrets: true
            argocdNamespace: argocd
            argocdSecretNames:
              - cluster-prod.example.com-1234567890
          images:
            ignore:
              - registry.k8s.io/pause*
          helm:
            # Namespaces holding ArgoCD Application objects
            applicationNamespaces:
              - argocd

        # Each Secret must exist in the kube-tower namespace (see below)
        registries:
          credentials:
            - registry: docker.io
              existingSecret: dockerhub-credentials
              usernameKey: username
              passwordKey: password
            - registry: ghcr.io
              existingSecret: ghcr-token
              passwordKey: token

        ingress:
          enabled: true
          className: traefik
          annotations:
            cert-manager.io/cluster-issuer: le-wildcard-issuer
            # kube-tower has no authentication of its own: protect the UI
            traefik.ingress.kubernetes.io/router.middlewares: authentik-ak-outpost-authentik-embedded-outpost@kubernetescrd
          hosts:
            - host: kube-tower.example.com
              paths:
                - path: /
                  pathType: Prefix
          tls:
            - hosts: [kube-tower.example.com]
              secretName: kube-tower-tls

        serviceMonitor:
          enabled: true   # needs the Prometheus operator CRDs
        grafanaDashboard:
          enabled: true   # picked up by the Grafana sidecar (kube-prometheus-stack)
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

Adapt the host, the cluster issuer and the middleware to your cluster, and drop the blocks you
do not need.

**Credential Secrets.** Keep tokens out of git: create the Secrets referenced in
`registries.credentials` by hand, with ExternalSecrets or Sealed Secrets, in the `kube-tower`
namespace. (The chart can also create them from inline values, `password:` instead of
`existingSecret:`, see [Secrets](configuration.md#secrets), but the tokens then sit in the
Application.) For example:

```sh
kubectl create namespace kube-tower
kubectl -n kube-tower create secret generic dockerhub-credentials \
  --from-literal=username=<docker-hub-user> --from-literal=password=<access-token>
kubectl -n kube-tower create secret generic ghcr-token --from-literal=token=<github-pat-read-packages>
```

A missing Secret keeps the pod in `ContainerCreating`: create the Secrets before the first sync,
or remove the matching entries.

**ArgoCD clusters.** With `useArgocdSecrets: true`, the chart adds a Role in the `argocd`
namespace so kube-tower can read the ArgoCD cluster Secrets: the remote clusters ArgoCD deploys
to appear in the dashboards without registering them twice. Name them in `argocdSecretNames`:
otherwise the Role lists Secrets, which gives read access to every Secret of the ArgoCD namespace
(see [clusters](clusters.md#reusing-argocd-cluster-secrets)). The credentials ArgoCD uses must be
allowed to list pods, nodes, workloads and Applications, see [clusters](clusters.md).

**OCI repository in ArgoCD.** Depending on your ArgoCD version, an OCI Helm source may need a
repository declared with OCI enabled. The chart is public, so no credentials are needed:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: repo-ghcr-arcanexus-charts
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  name: arcanexus-charts
  url: ghcr.io/arcanexus/charts
  enableOCI: "true"
```

**Upgrades.** Bump `targetRevision` to the new chart version: kube-tower is stateless, so the
upgrade only triggers a new scan. kube-tower itself shows when a new chart version is available
in its Helm charts dashboard.

### Development version

To follow the development version, point `source` at the git repository instead:
`repoURL: https://github.com/Arcanexus/kube-tower.git`, `path: charts/kube-tower`,
`targetRevision: main` and set `image.tag: main`.

## Chart values

| Value | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/arcanexus/kube-tower` | Image (amd64, arm64, arm/v7) |
| `image.tag` / `image.pullPolicy` | chart `appVersion` / `IfNotPresent` | Image tag (also the version shown by the UI) |
| `replicaCount` | `1` | Keep 1: the inventory lives in memory |
| `config` | see [configuration](configuration.md) | Application settings, rendered into a ConfigMap |
| `clusters` | `[]` | Remote clusters: Secrets created by the chart or `existingSecret`, see [clusters](clusters.md#registering-clusters-with-the-helm-chart) |
| `registries.credentials` | `[]` | Per registry credentials, existing Secret, inline password or cloud `provider` (`aws`, `gcp`, `azure`), see [registries](registries.md) |
| `registries.existingSecret` | `""` | A `kubernetes.io/dockerconfigjson` Secret |
| `registries.dockerConfigJson` | `{}` | Content of a `kubernetes.io/dockerconfigjson` Secret the chart creates |
| `registries.ca.existingConfigMap` / `.key` / `.pem` | `""` / `ca.crt` / `""` | CA certificates of internal registries, trusted by kube-tower and Trivy, see [registries](registries.md#tls-private-cas-and-insecure-registries) |
| `config.registries.useImagePullSecrets` | `false` | Reuse the image pull secrets of the workloads (adds `get` on secrets to the ClusterRole), see [registries](registries.md#reusing-the-image-pull-secrets) |
| `git.existingSecret` / `git.secretKey` | `""` / `token` | Existing Secret with a token for private git repositories holding charts |
| `git.token` | `""` | The same token inline, the chart creates the Secret |
| `rbac.create` | `true` | Read-only ClusterRole and Role for cluster Secrets |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / `""` / `{}` | ServiceAccount |
| `service.type` / `service.port` | `ClusterIP` / `80` | Service |
| `ingress.*` | disabled | Standard ingress settings |
| `serviceMonitor.enabled` / `.interval` / `.scrapeTimeout` | `false` / `5m` / `""` | Prometheus operator ServiceMonitor (`honorLabels: true`) |
| `serviceMonitor.labels` / `.metricRelabelings` | `{}` / `[]` | Extra labels (e.g. `release: kube-prometheus-stack`) and relabelings |
| `grafanaDashboard.enabled` | `false` | ConfigMap holding the [Grafana dashboard](metrics.md#grafana-dashboard) |
| `grafanaDashboard.namespace` / `.labels` / `.annotations` | release ns / `grafana_dashboard: "1"` / `{}` | Where and how the Grafana sidecar finds it |
| `trivy.enabled` | `true` | Init container copying the Trivy CLI into the pod, see [vulnerability scanning](#vulnerability-scanning-trivy) |
| `trivy.image.repository` / `.tag` / `.pullPolicy` | `ghcr.io/aquasecurity/trivy` / `0.75.0` / `IfNotPresent` | Image the Trivy CLI is copied from (amd64, arm64) |
| `trivy.cacheSizeLimit` | `3Gi` | `emptyDir` holding the Trivy database (standalone mode) |
| `trivy.server.enabled` | `false` | Trivy server Deployment and Service; kube-tower then scans in client mode |
| `trivy.server.image` | `{}` (= `trivy.image`) | Image of the Trivy server, merged over `trivy.image` |
| `trivy.server.port` | `4954` | Port of the Trivy server Service |
| `trivy.server.cacheSizeLimit` | `3Gi` | `emptyDir` holding the database of the Trivy server |
| `trivy.server.resources` | 100m CPU / 256Mi requests, 1Gi memory limit | Trivy server resources |
| `trivy.server.nodeSelector` / `.tolerations` / `.affinity` | | Trivy server scheduling |
| `config.vulnerabilities.*` | see [configuration](configuration.md#vulnerabilities-trivy) | Trivy Operator reports, scan settings, ignored images |
| `startupProbe` / `livenessProbe` / `readinessProbe` | 5 min to start, then every 20s / 10s | Probes on `/healthz` (the chart sets `httpGet`); `null` disables one |
| `resources` | 50m CPU / 256Mi requests, 1536Mi memory limit | kube-tower pod resources (Trivy scans in standalone mode need the memory) |
| `nodeSelector`, `tolerations`, `affinity`, `podAnnotations`, `podLabels`, `imagePullSecrets` | | Usual pod settings |
| `extraInitContainers`, `extraEnv`, `extraVolumes`, `extraVolumeMounts` | `[]` | Added to the kube-tower pod, e.g. to copy an [exec plugin](clusters.md#managed-clusters-eks-gke-aks-exec-plugins) |
| `podSecurityContext`, `securityContext` | non-root, read-only root FS | Hardened by default |
| `networkPolicy.enabled` | `false` | NetworkPolicies of the kube-tower pod and the Trivy server, see [network policies](#network-policies) |
| `networkPolicy.ingress.from` | `[]` (any pod) | Who may reach the UI, API and `/metrics` (port `http` only) |
| `networkPolicy.egress.ports` / `.to` / `.extra` | `443`, `6443` / anywhere / `[]` | What kube-tower may reach besides DNS and the Trivy server |

## Network policies

`networkPolicy.enabled: true` restricts the network of the kube-tower pod (and of the Trivy server)
with NetworkPolicies, enforced by CNIs such as Calico or Cilium:

- **Ingress**: only the `http` port of kube-tower, from `networkPolicy.ingress.from` (any pod when
  empty). The Trivy server only accepts kube-tower.
- **Egress**: DNS, the Trivy server, and `networkPolicy.egress.ports` (`443` and `6443`) towards
  `networkPolicy.egress.to` (anywhere when empty). kube-tower reaches the Kubernetes API servers, the
  registries, the Helm repositories, the git hosts and, in standalone mode, the Trivy database
  registries. Add the ports of registries or API servers that use other ones, or rules of your own
  with `networkPolicy.egress.extra`.

```yaml
networkPolicy:
  enabled: true
  ingress:
    from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: monitoring      # Prometheus scraping /metrics
  egress:
    ports:
      - port: 443
        protocol: TCP
      - port: 6443
        protocol: TCP
      - port: 5000                                       # a private registry on port 5000
        protocol: TCP
```

## Permissions

On the cluster it runs in, kube-tower gets a ClusterRole with `get`/`list` on pods, nodes,
deployments, statefulsets, daemonsets, cronjobs, `applications.argoproj.io` and
`vulnerabilityreports.aquasecurity.github.io` (Trivy Operator), plus `get` on the cluster Secrets
of its namespace named in `clusters[]` and `config.clusters.secretNames`, and on nothing else.
Install it in a namespace of its own.

Two options widen this, each reading **every** Secret of a namespace (Kubernetes RBAC cannot
restrict `list` to a label):

- `config.clusters.listSecrets: true`: `list` on the Secrets of its namespace, to find labelled
  cluster Secrets;
- `config.clusters.useArgocdSecrets: true` without `argocdSecretNames`: `list` on the Secrets of
  the ArgoCD namespace. With `argocdSecretNames`, only `get` on these Secrets.

Nothing is ever created, patched or deleted.

## Upgrading

```sh
helm upgrade kube-tower oci://ghcr.io/arcanexus/charts/kube-tower -n kube-tower --reuse-values --version <new>
```

kube-tower is stateless: an upgrade simply triggers a new scan.

## Uninstalling

```sh
helm uninstall kube-tower -n kube-tower
kubectl delete namespace kube-tower
```

On remote clusters, remove the reader account with `kubectl delete -f deploy/remote-cluster-rbac.yaml`.
