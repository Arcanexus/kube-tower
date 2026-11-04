# Installation

kube-tower is installed with its Helm chart, directly or through an ArgoCD Application. For a first
try in a few commands, see the [quick start](quick-start.md); to update an installation, see
[upgrading](upgrading.md).

## Requirements

- Kubernetes 1.25+ (any distribution: k3s, kubeadm, GKE, EKS, AKS…).
- Outbound HTTPS from the kube-tower pod to the registries, Helm repositories and git hosts your
  workloads use, and to the API servers of the remote clusters you register.
- [ArgoCD](https://argo-cd.readthedocs.io/) only if you want the Helm charts dashboard (charts are
  discovered from ArgoCD `Application` objects).

kube-tower runs as a single stateless pod (requests: 50m CPU, 256Mi memory; 1536Mi memory limit),
or as several Deployments scaled apart (see [scaling](scaling.md)).
The vulnerability scans with Trivy (on by default) also need:

- an outbound access to the Trivy database registries (`mirror.gcr.io`, `ghcr.io`) and to the
  registries of the scanned images;
- up to 3 GiB of ephemeral storage for the database (`trivy.cacheSizeLimit`), unless you use the
  [Trivy server](vulnerabilities.md#trivy-setups) of the chart;
- nodes able to pull `ghcr.io/aquasecurity/trivy` (amd64 or arm64).

See [Trivy setups](vulnerabilities.md#trivy-setups) to change or disable this, and
[network and ports](network.md) for every outbound connection.

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

kube-tower asks for a login: log in as `admin`, with the password kube-tower generates in the
Secret `kube-tower-auth` at its first start, then add local accounts, single sign-on or Dex (see
[authentication](authentication.md)). It only reads data and never shows secret values.

Every value of the chart is listed in [chart values](chart-values.md). Vulnerability scanning with Trivy
is on by default: [Trivy setups](vulnerabilities.md#trivy-setups) explains the choices (standalone,
Trivy server, Trivy Operator only, none). To restrict the network of the pods, see
[network policies](network.md#network-policies).

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
    targetRevision: 1.1.0
  syncPolicy:
    automated: {}
    syncOptions:
      - CreateNamespace=true
```

This scans the cluster ArgoCD runs in and the ArgoCD `Application` objects of the `argocd`
namespace, with the UI reachable only through `kubectl port-forward -n kube-tower svc/kube-tower 8080:80`.

### Complete example

A typical homelab setup: the UI behind Traefik with a cert-manager certificate, the login with
Authentik (single sign-on), every cluster ArgoCD manages scanned too, Docker Hub and GitHub
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
    targetRevision: 1.1.0
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

        # Login: the admin account, and single sign-on with Authentik (docs/authentication.md)
        auth:
          url: https://kube-tower.example.com/
          oidc:
            name: Authentik
            issuer: https://auth.example.com/application/o/kube-tower/
            existingSecret: kube-tower-oidc   # keys clientId and clientSecret
            adminGroups: [kube-tower-admins]

        ingress:
          enabled: true
          className: traefik
          annotations:
            cert-manager.io/cluster-issuer: le-wildcard-issuer
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

Adapt the host, the cluster issuer and the Authentik provider to your cluster, and drop the blocks you
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
kubectl -n kube-tower create secret generic kube-tower-oidc \
  --from-literal=clientId=kube-tower --from-literal=clientSecret=<authentik-client-secret>
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

**Upgrades.** Bump `targetRevision`, see [upgrading](upgrading.md).

### Distributed mode with ArgoCD

One pod per role and the chart's Valkey, its password in a Secret created beforehand (or synced by
ExternalSecrets like the registry credentials):

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
    targetRevision: 1.1.0
    helm:
      valuesObject:
        mode: distributed
        distributed:
          groups:
            controller:
              replicas: 1   # 2: a standby takes over in about 15 s if the active one stops
            ui:
              replicas: 1
            worker:
              replicas: 1
        redis:
          valkey:
            enabled: true
          existingSecret: kube-tower-valkey   # key: password
        config:
          clusters:
            useArgocdSecrets: true
        ingress:
          enabled: true
          hosts:
            - host: kube-tower.example.com
              paths:
                - path: /
                  pathType: Prefix
        serviceMonitor:
          enabled: true   # scrapes the active controller
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

Every pod becomes ready (standby controllers too), so ArgoCD shows the Application healthy once the
pods started. The [complete example](#complete-example) above gives the other values (registry credentials, TLS,
single sign-on). See [scaling](scaling.md) for the groups, sizing and Valkey.

### Development version

To follow the development version, point `source` at the git repository instead:
`repoURL: https://github.com/Arcanexus/kube-tower.git`, `path: charts/kube-tower`,
`targetRevision: main` and set `image.tag: main`.

## Uninstalling

```sh
helm uninstall kube-tower -n kube-tower
kubectl delete namespace kube-tower
```

On remote clusters, remove the reader account with `kubectl delete -f deploy/remote-cluster-rbac.yaml`.

Next: [register other clusters](clusters.md), [connect private registries](registries.md),
[add accounts and single sign-on](authentication.md).
