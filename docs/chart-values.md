# Chart values

Every value of the Helm chart `oci://ghcr.io/arcanexus/charts/kube-tower`. The application settings
under `config` are listed in [configuration](configuration.md); the guides explain each feature
([installation](installation.md), [clusters](clusters.md), [registries](registries.md),
[authentication](authentication.md), [vulnerabilities](vulnerabilities.md), [scaling](scaling.md)).
The full list with comments is the chart's
[values.yaml](../charts/kube-tower/values.yaml).

| Value | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/arcanexus/kube-tower` | Image (amd64, arm64, arm/v7) |
| `image.tag` / `image.pullPolicy` | chart `appVersion` / `IfNotPresent` | Image tag (also the version shown by the UI) |
| `mode` | `single` | `single`: one pod with every role; `distributed`: one Deployment per group of roles, see [scaling](scaling.md) |
| `replicaCount` | `1` | Single mode: keep 1, the inventory lives in memory |
| `distributed.groups.<name>.roles` / `.replicas` / `.resources` / `.autoscaling` | controller ×2, ui ×1, worker ×2, trivy ×1 | Distributed mode: the Deployments and their roles; the trivy group always has 1 replica; `autoscaling` (ui, worker) from 1 to 4 pods with a damped `behavior`, see [scaling](scaling.md#sizing) |
| `distributed.groups.<name>.nodeSelector` / `.tolerations` / `.affinity` | top-level values | Scheduling of a group |
| `redis.valkey.enabled` | `false` | A Valkey Deployment through which the pods of the distributed mode talk, also keeping a copy of the inventory, see [scaling](scaling.md#redis--valkey). Distributed mode: this or `redis.url` is required |
| `redis.valkey.image` / `.port` / `.resources` | `docker.io/valkey/valkey:8.1.1` / `6379` / 20m CPU, 64Mi | Valkey settings |
| `redis.url` | `""` | An existing Redis / Valkey instead (`redis://` or `rediss://`) |
| `redis.existingSecret` / `.passwordKey` / `.password` | `""` / `password` / `""` | Optional Redis password, also set on the chart's Valkey |
| `redis.keyPrefix` | `""` | Prefix of the keys of the distributed mode (empty: the release name) |
| `config` | see [configuration](configuration.md) | Application settings, rendered into a ConfigMap |
| `clusters` | `[]` | Remote clusters: Secrets created by the chart or `existingSecret`, see [clusters](clusters.md#registering-clusters-with-the-helm-chart) |
| `registries.credentials` | `[]` | Per registry credentials, existing Secret, inline password or cloud `provider` (`aws`, `gcp`, `azure`), see [registries](registries.md) |
| `registries.existingSecret` | `""` | A `kubernetes.io/dockerconfigjson` Secret |
| `registries.dockerConfigJson` | `{}` | Content of a `kubernetes.io/dockerconfigjson` Secret the chart creates |
| `registries.ca.existingConfigMap` / `.key` / `.pem` | `""` / `ca.crt` / `""` | CA certificates of internal registries, trusted by kube-tower and Trivy, see [registries](registries.md#tls-private-cas-and-insecure-registries) |
| `config.registries.useImagePullSecrets` | `false` | Reuse the image pull secrets of the workloads (adds `get` on secrets to the ClusterRole), see [registries](registries.md#reusing-the-image-pull-secrets) |
| `git.existingSecret` / `git.secretKey` | `""` / `token` | Existing Secret with a token for private git repositories holding charts or Helm value files (`$values/...`) |
| `git.token` | `""` | The same token inline, the chart creates the Secret |
| `auth.enabled` | `true` | Login on the UI and the API, see [authentication](authentication.md) |
| `auth.admin` / `.users` / `.anonymousRole` | `true` / `[]` / `""` | Built-in `admin` account, local accounts (`name`, `role`, `existingSecret`, `passwordKey`), role of the visitors not logged in |
| `auth.roles` | `{}` | Roles besides `readonly` and `admin`: `{name: {permissions: [...], clusters: [...]}}`, see [roles](authentication.md#roles) |
| `auth.existingSecret` | `""` | Secret with `admin.password` and `session.key`; empty: `<release>-auth`, created by kube-tower when missing |
| `auth.url` | `""` | URL users open kube-tower with, required by the SSO |
| `auth.oidc.issuer` / `.existingSecret` / `.clientIdKey` / `.clientSecretKey` / `.clientId` | `""` / `""` / `clientId` / `clientSecret` / `""` | Single sign-on with an OIDC provider, see [authentication](authentication.md#single-sign-on-oidc) |
| `auth.oidc.adminGroups` / `.readonlyGroups` / `.roleGroups` / `.defaultRole` | `[]` / `[]` / `{}` / `readonly` | Roles from the groups of the user |
| `auth.oidc.name` / `.scopes` / `.usernameClaim` / `.groupsClaim` / `.caFile` | `SSO` / `openid profile email groups` / `preferred_username` / `groups` / `""` | Login button, claims, private CA |
| `dex.enabled` / `.name` / `.connectors` / `.env` / `.envFrom` | `false` / `Dex` / `[]` / `[]` / `[]` | Dex served by kube-tower on `<auth.url>api/dex`, like ArgoCD, see [authentication](authentication.md#dex-of-the-chart) |
| `dex.image` / `.resources` / `.nodeSelector` / `.tolerations` / `.affinity` | `ghcr.io/dexidp/dex:v2.41.1` / 10m CPU, 32Mi | Dex pod |
| `auth.sessionDuration` / `.metricsPublic` | `24h` / `true` | Session length; `/metrics` open for Prometheus or behind the login |
| `rbac.create` | `true` | Read-only ClusterRole and Role for cluster Secrets (and, with `auth.enabled`, `get` / `create` on the auth Secret) |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / `""` / `{}` | ServiceAccount |
| `service.type` / `service.port` | `ClusterIP` / `80` | Service |
| `ingress.*` | disabled | Standard ingress settings |
| `serviceMonitor.enabled` / `.interval` / `.scrapeTimeout` | `false` / `5m` / `""` | Prometheus operator ServiceMonitor (`honorLabels: true`) |
| `serviceMonitor.labels` / `.metricRelabelings` | `{}` / `[]` | Extra labels (e.g. `release: kube-prometheus-stack`) and relabelings |
| `grafanaDashboard.enabled` | `false` | ConfigMap holding the [Grafana dashboard](metrics.md#grafana-dashboard) |
| `grafanaDashboard.namespace` / `.labels` / `.annotations` | release ns / `grafana_dashboard: "1"` / `{}` | Where and how the Grafana sidecar finds it |
| `trivy.enabled` | `true` | Init container copying the Trivy CLI into the pod, see [Trivy setups](vulnerabilities.md#trivy-setups) |
| `trivy.image.repository` / `.tag` / `.pullPolicy` | `ghcr.io/aquasecurity/trivy` / `0.75.0` / `IfNotPresent` | Image the Trivy CLI is copied from (amd64, arm64) |
| `trivy.cacheSizeLimit` | `3Gi` | `emptyDir` holding the Trivy database (standalone mode) |
| `trivy.server.enabled` | `false` | Trivy server Deployment and Service; kube-tower then scans in client mode |
| `trivy.server.image` | `{}` (= `trivy.image`) | Image of the Trivy server, merged over `trivy.image` |
| `trivy.server.port` | `4954` | Port of the Trivy server Service |
| `trivy.server.cacheSizeLimit` | `3Gi` | `emptyDir` holding the database of the Trivy server |
| `trivy.server.resources` | 100m CPU / 256Mi requests, 1Gi memory limit | Trivy server resources |
| `trivy.server.nodeSelector` / `.tolerations` / `.affinity` | | Trivy server scheduling |
| `config.vulnerabilities.*` | see [configuration](configuration.md#vulnerabilities-trivy) | Trivy Operator reports, scan settings, ignored images |
| `config.security.*` | `enabled: true`, `exposedSecrets: true` | Trivy Operator security reports of the [Security](security.md) page |
| `startupProbe` / `livenessProbe` / `readinessProbe` | 5 min to start, then every 20s / 10s | Probes on `/healthz` (the chart sets `httpGet`); `null` disables one |
| `resources` | 50m CPU / 256Mi requests, 1536Mi memory limit | kube-tower pod resources (Trivy scans in standalone mode need the memory) |
| `nodeSelector`, `tolerations`, `affinity`, `podAnnotations`, `podLabels`, `imagePullSecrets` | | Usual pod settings |
| `extraInitContainers`, `extraEnv`, `extraVolumes`, `extraVolumeMounts` | `[]` | Added to the kube-tower pod, e.g. to copy an [exec plugin](clusters.md#managed-clusters-eks-gke-aks-exec-plugins) |
| `podSecurityContext`, `securityContext` | non-root, read-only root FS | Hardened by default |
| `networkPolicy.enabled` | `false` | NetworkPolicies of the kube-tower pod and the Trivy server, see [network policies](network.md#network-policies) |
| `networkPolicy.ingress.from` | `[]` (any pod) | Who may reach the UI, API and `/metrics` (port `http` only) |
| `networkPolicy.egress.ports` / `.to` / `.extra` | `443`, `6443` / anywhere / `[]` | What kube-tower may reach besides DNS and the Trivy server |
