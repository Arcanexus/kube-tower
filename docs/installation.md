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
```

kube-tower has no authentication of its own: put it behind your ingress authentication
(oauth2-proxy, Authentik, Traefik forward auth…) if the UI must not be public. It only reads
data and never shows secret values.

## With ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kube-tower
  namespace: argocd
spec:
  project: default
  destination:
    name: in-cluster
    namespace: kube-tower
  source:
    repoURL: ghcr.io/arcanexus/charts
    chart: kube-tower
    targetRevision: 0.1.0
    helm:
      valuesObject:
        config:
          clusters:
            useArgocdSecrets: true
  syncPolicy:
    automated: {}
    syncOptions:
      - CreateNamespace=true
```

To follow the development version, point `source` at the git repository instead:
`repoURL: https://github.com/Arcanexus/kube-tower.git`, `path: charts/kube-tower`,
`targetRevision: main` and set `image.tag: main`.

## Chart values

| Value | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/arcanexus/kube-tower` | Image (amd64, arm64, arm/v7) |
| `image.tag` | chart `appVersion` | Image tag |
| `config` | see [configuration](configuration.md) | Application settings, rendered into a ConfigMap |
| `clusters` | `[]` | Remote clusters to register, see [clusters](clusters.md) |
| `registries.credentials` | `[]` | Per registry credentials, see [configuration](configuration.md#registry-authentication) |
| `registries.existingSecret` | `""` | A `kubernetes.io/dockerconfigjson` Secret |
| `git.existingSecret` / `git.secretKey` | `""` / `token` | Token for private git repositories holding charts |
| `rbac.create` | `true` | Read-only ClusterRole and Role for cluster Secrets |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / `""` / `{}` | ServiceAccount |
| `service.type` / `service.port` | `ClusterIP` / `80` | Service |
| `ingress.*` | disabled | Standard ingress settings |
| `serviceMonitor.enabled` / `.interval` | `false` / `5m` | Prometheus operator ServiceMonitor |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | | Usual pod settings |
| `podSecurityContext`, `securityContext` | non-root, read-only root FS | Hardened by default |

## Permissions

On the cluster it runs in, kube-tower gets a ClusterRole with `get`/`list` on pods, nodes,
deployments, statefulsets, daemonsets, cronjobs and `applications.argoproj.io`, plus `list` on
Secrets **of its own namespace only** (cluster registration). With
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
