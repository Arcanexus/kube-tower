# Installation

## Requirements

- Kubernetes 1.25+ (any distribution: k3s, kubeadm, GKE, EKS, AKS…).
- Outbound HTTPS from the kube-tower pod to the registries, Helm repositories and git hosts your
  workloads use, and to the API servers of the remote clusters you register.
- [ArgoCD](https://argo-cd.readthedocs.io/) only if you want the Helm charts dashboard (charts are
  discovered from ArgoCD `Application` objects).

kube-tower runs as a single, small, stateless pod (requests: 50m CPU, 128Mi memory).

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
            # Scan every cluster registered in ArgoCD, reusing its cluster Secrets
            useArgocdSecrets: true
            argocdNamespace: argocd
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
namespace so kube-tower can read the ArgoCD cluster Secrets: every remote cluster ArgoCD deploys
to appears in the dashboards without registering it twice. The credentials ArgoCD uses must be
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
| `image.tag` | chart `appVersion` | Image tag |
| `config` | see [configuration](configuration.md) | Application settings, rendered into a ConfigMap |
| `clusters` | `[]` | Remote clusters: Secrets created by the chart or `existingSecret`, see [clusters](clusters.md#registering-clusters-with-the-helm-chart) |
| `registries.credentials` | `[]` | Per registry credentials, existing Secret or inline password, see [configuration](configuration.md#registry-authentication) |
| `registries.existingSecret` | `""` | A `kubernetes.io/dockerconfigjson` Secret |
| `registries.dockerConfigJson` | `{}` | Content of a `kubernetes.io/dockerconfigjson` Secret the chart creates |
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
| `trivy.enabled` / `trivy.image` | `true` / `ghcr.io/aquasecurity/trivy:0.75.0` | Init container copying the Trivy CLI from this image (amd64, arm64; disable on arm/v7), see [vulnerabilities](vulnerabilities.md#where-the-trivy-cli-comes-from) |
| `trivy.cacheSizeLimit` | `3Gi` | `emptyDir` holding the Trivy database (standalone mode), see [vulnerabilities](vulnerabilities.md) |
| `trivy.server.enabled` | `false` | Trivy server Deployment and Service; kube-tower then scans in client mode |
| `trivy.server.image` / `.resources` / `.cacheSizeLimit` | `trivy.image` / 1Gi limit / `3Gi` | Trivy server settings (also `nodeSelector`, `tolerations`, `affinity`) |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | | Usual pod settings |
| `podSecurityContext`, `securityContext` | non-root, read-only root FS | Hardened by default |

## Permissions

On the cluster it runs in, kube-tower gets a ClusterRole with `get`/`list` on pods, nodes,
deployments, statefulsets, daemonsets, cronjobs, `applications.argoproj.io` and
`vulnerabilityreports.aquasecurity.github.io` (Trivy Operator), plus `list` on
Secrets **of its own namespace only** (cluster registration), plus `get` on the existing cluster
Secrets named in `clusters[].existingSecret`. With
`config.clusters.useArgocdSecrets: true` it can also list Secrets in the ArgoCD namespace.
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
