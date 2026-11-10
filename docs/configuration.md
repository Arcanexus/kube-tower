# Configuration

The reference of every setting of kube-tower. The guides explain what each section is for and give
examples (see the table below); the values of the Helm chart are in [chart values](chart-values.md).

kube-tower reads `/etc/kube-tower/config.yaml` (override with `KUBE_TOWER_CONFIG`). With the Helm
chart, this file is rendered from `.Values.config`. Keys are camelCase; unknown keys are rejected
at startup so typos are caught early.

```yaml
roles: [all]                   # what this process runs: all, or a list of ui, controller, worker, trivy
refreshInterval: 6h            # 30s, 15m, 6h, 1d or seconds
logs:
  level: INFO                  # DEBUG, INFO, WARNING, ERROR
  format: json                 # json, logfmt, custom
clusters:
  inCluster: true              # scan the cluster kube-tower runs in
  inClusterName: in-cluster
  namespace: ""                # where cluster Secrets live (default: pod namespace)
  secretNames: []              # cluster Secrets of that namespace, read by name
  listSecrets: false           # also list the labelled ones (reads every Secret of the namespace)
  secretLabelSelector: kube-tower.arcanexus.com/secret-type=cluster
  useArgocdSecrets: false      # also use ArgoCD cluster Secrets
  argocdNamespace: argocd
  argocdSecretNames: []        # ArgoCD cluster Secrets read by name; empty: listed (every Secret of argocd)
  requestTimeout: 30
  execCommands: []             # commands kubeconfig exec plugins may run (EKS, GKE, AKS), see clusters.md
  nodePoolLabels:              # node labels naming the node group of a node (Clusters page), first found wins
    - eks.amazonaws.com/nodegroup
    - cloud.google.com/gke-nodepool
    - kubernetes.azure.com/agentpool
    - karpenter.sh/nodepool
    - node.kubernetes.io/pool
images:
  enabled: true
  includeNodeImages: true      # images cached on nodes (node.status.images); the nodes give the image sizes either way
  includePrerelease: false
  checkFloatingDigests: true   # compare digests for latest/stable tags
  fetchTagDigests: true        # published digests of the current/latest tags (image details)
  fetchReleaseDates: true      # when the current and latest tags were built (Docker Hub API, OCI annotation or image config)
  ignore:                      # fnmatch patterns on registry/repository[:tag]
    - registry.k8s.io/pause*
  maxTagPages: 50              # 1000 tags per page
helm:
  enabled: true
  applicationNamespaces: [argocd]   # [] = all namespaces
  includePrerelease: false
  checkDependencies: true     # subcharts, and their own subcharts (3 levels)
  fetchReleaseDates: true     # when the latest versions were published (index.yaml, OCI annotation)
  flux: true                  # Flux HelmReleases, see chart-sources.md
  releases: false             # releases installed with the helm command (needs list secrets)
  repositories: {}            # chart name or pattern -> repository, for those releases
  artifactHubUrl: https://artifacthub.io   # else looked up there; "" = no lookup
kubernetesVersions:            # end of life and CVEs of the Kubernetes and containerd versions, see ui-clusters.md
  enabled: true
  endOfLifeUrl: https://endoflife.date/api/kubernetes.json   # or a mirror with the same format
  osvUrl: https://api.osv.dev/v1/query                       # or a mirror of the OSV API
  warnDays: 90                 # a release that ends within this many days is a warning
  timeout: 20
  deprecatedApis: true         # deprecated APIs still requested (API server /metrics, needs get /metrics)
resources:                     # CPU and memory recommendations of krr, see "Resources (krr)" below
  enabled: false               # the chart sets it with krr.enabled
  serverUrl: ""                # the krr pod of the chart (set by the chart)
  strategy: simple
  namespaces: []               # empty: every namespace
  interval: 24h
  timeout: 15m
  prometheus: []               # per cluster: url, clusterLabel, authHeaderEnv...
# Security: Trivy and Trivy Operator, see "Security" below
vulnerabilities:               # CVEs of the images
  enabled: true
  trivyOperator: true          # read Trivy Operator VulnerabilityReports
  trivy:
    enabled: true              # scan the other images with the Trivy CLI
    binary: trivy              # set by the Helm chart to the copied binary
    serverUrl: ""              # Trivy server (client/server mode), set by the chart with trivy.server
    cacheDir: /tmp/trivy
    timeout: 10m
    concurrency: 2
    rescanInterval: 24h
    ignoreUnfixed: false
    javaDb: false
    extraArgs: []
  ignore: []
security:                      # audit: the other Trivy Operator reports (Security page)
  enabled: true
  exposedSecrets: true         # false: leave the exposed secrets out
registries:
  dockerConfigPath: /etc/kube-tower/dockerconfig/config.json
  credentials:                 # per registry, override the docker config.json
    - registry: docker.io      # a host, or an fnmatch pattern of hosts
      usernameFile: /etc/kube-tower/registries/0/username   # or username / usernameEnv
      passwordFile: /etc/kube-tower/registries/0/password   # or passwordEnv
    - registry: "*.dkr.ecr.*.amazonaws.com"
      provider: aws            # static (default), aws, gcp or azure: tokens from the pod identity
  mirrors: {}                  # e.g. {docker.io: mirror.example.com}
  useImagePullSecrets: false   # also use the image pull secrets of the workloads
  caFile: ""                   # PEM CA certificates trusted in addition to the public ones
  insecure: []                 # registries whose TLS is not verified (plain http:// fallback)
  concurrency: 8
  timeout: 20                  # seconds, per request (connect, read)
  retries: 2                   # extra attempts after a timeout, a connection error or a 502/503/504
git:
  rawUrlTemplates:
    github.com: https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}
    gitlab.com: https://gitlab.com/{owner}/{repo}/-/raw/{ref}/{path}
  tokenEnv: GIT_TOKEN
internal:                      # between the processes, when the roles run apart
  taskTimeout: 30m             # a task not answered by then is given to another process
  batchSize: 50                # images or charts per task: a scan is shared by the worker and trivy processes
  leaderElection: false        # several controller replicas: one active, elected through a Lease
  leaseName: kube-tower-controller
  labelPod: false              # the active controller labels its pod (for a Service selecting its /metrics)
redis:                         # Redis / Valkey: required when the roles are apart, optional otherwise
  url: ""                      # redis://host:6379/0 or rediss:// (TLS); empty: the snapshot stays in memory
  passwordEnv: KUBE_TOWER_REDIS_PASSWORD
  key: kube-tower:snapshot     # change it when several installations share one Redis
  keyPrefix: kube-tower        # prefix of the keys of the distributed mode; change it likewise
auth:                          # login on the UI and the API, see authentication.md
  enabled: false               # the chart sets true (auth.enabled, on by default)
  admin: true                  # built-in admin account, password in the auth Secret (admin.password)
  users: []                    # local accounts: name, role (readonly | admin | a role of roles), passwordFile or passwordEnv
  roles: {}                    # other roles, their permissions and clusters, see rbac.md
  anonymousRole: ""            # "" (login required) | readonly | a role of roles
  sessionDuration: 24h
  secretName: kube-tower-auth  # admin.password and session.key, created with random values when missing
  secretDir: /etc/kube-tower/auth
  metricsPublic: true          # false: /metrics needs the Basic auth of a local account
  url: ""                      # URL users open kube-tower with (needed by the SSO)
  oidc:                        # single sign-on, see authentication.md#single-sign-on-oidc
    issuer: ""                 # empty: no SSO
    clientId: ""               # empty: from $KUBE_TOWER_OIDC_CLIENT_ID (the chart reads it from auth.oidc.existingSecret)
    adminGroups: []
    roleGroups: {}             # {role: [groups]}
    defaultRole: readonly
  dexUrl: ""                   # Dex served on <url>api/dex (Helm chart: dex.enabled)
```

Durations (`refreshInterval`, `timeout`, `rescanInterval`…) accept `30s`, `15m`, `6h`, `1d` or seconds.

Environment overrides: `KUBE_TOWER_LOG_LEVEL`, `KUBE_TOWER_REFRESH_INTERVAL`, `KUBE_TOWER_ROLES`
(comma-separated), `KUBE_TOWER_REDIS_URL`, `KUBE_TOWER_REDIS_KEY_PREFIX`.

`roles` and the `internal` and `redis` sections split kube-tower in processes: see
[scaling](scaling.md#without-the-chart-the-roles-in-configyaml).

## Where each section is explained

| Section | Guide |
| --- | --- |
| `clusters` | [clusters](clusters.md) |
| `images`, `helm` | [statuses and versions](statuses.md), [Images page](ui-images.md), [Helm charts page](ui-charts.md), [where charts are found](chart-sources.md) |
| `registries` | [registries](registries.md) |
| `git` | [Helm charts read from git](ui-charts.md), [troubleshooting](troubleshooting.md#helm-charts) |
| `vulnerabilities`, `security` | [Security](#security) below: [Trivy configuration](#trivy-configuration), [vulnerabilities](#vulnerabilities), [audit](#audit) |
| `resources` | [Resources (krr)](#resources-krr) below |
| `auth` | [authentication](authentication.md) |
| `roles`, `internal`, `redis` | [scaling](scaling.md) |
| `logs` | [Logs tab](ui-administration.md#logs) |

## Security

Trivy feeds two parts of kube-tower:

- **Vulnerabilities**: the CVEs of every image, on the [Images](ui-images.md) page and in the image details.
  They come from the reports of Trivy Operator when it runs in a cluster, else from the Trivy CLI run by
  kube-tower.
- **Audit**: the other reports of Trivy Operator (misconfigurations, exposed secrets, RBAC, infrastructure,
  compliance), on the [Security](ui-security.md) page. Only Trivy Operator writes them: kube-tower never runs
  these checks.

| You want | Trivy in kube-tower | Trivy Operator in the clusters |
| --- | --- | --- |
| The CVEs of every image, nothing else to install | yes (default) | no |
| The CVEs and the audit | yes, for the images the operator has not scanned | yes |
| The CVEs and the audit, no Trivy in kube-tower | no | yes |
| Nothing | `config.vulnerabilities.enabled: false` and `config.security.enabled: false` | |

### Trivy configuration

Choose one mode. The values below are those of the Helm chart; `config.*` goes in `config.yaml`
without the chart.

| Mode | What runs | Values |
| --- | --- | --- |
| **Embedded, standalone** (default) | The kube-tower pod runs the Trivy CLI and downloads the vulnerability database (~1.6 GB) into an `emptyDir` | nothing |
| **Embedded, client/server** | The chart adds a Trivy server pod that holds the database and the layers already analysed; kube-tower scans in client mode | `trivy.server.enabled: true` |
| **Your own Trivy server** | kube-tower scans in client mode against a server you already run | `config.vulnerabilities.trivy.serverUrl: http://trivy.trivy-system:4954` |
| **External Trivy Operator only** | No Trivy in kube-tower: only the operator's reports are read (images only cached on nodes are not scanned) | `trivy.enabled: false` and `config.vulnerabilities.trivy.enabled: false` |

Trivy Operator needs no setting in every mode: kube-tower reads its reports wherever it is installed, and
the embedded Trivy only scans the images without a report.

**Embedded, standalone** suits a few dozen images. Size the pod if needed:

```yaml
trivy:
  cacheSizeLimit: 3Gi            # emptyDir of the database
resources:
  limits:
    memory: 1536Mi               # raise it, or lower config.vulnerabilities.trivy.concurrency, if OOMKilled
```

**Embedded, client/server** is better beyond that: the server keeps the analysis of each layer (base
layers shared by many images are pulled once) and downloads the database once. The chart sets
`config.vulnerabilities.trivy.serverUrl` itself.

```yaml
trivy:
  server:
    enabled: true
    resources:
      limits:
        memory: 1Gi
```

**External Trivy Operator only**:

```yaml
trivy:
  enabled: false                 # no init container copying the Trivy CLI
config:
  vulnerabilities:
    trivy:
      enabled: false             # do not look for the Trivy CLI
```

The settings of the Trivy CLI and server (`config.vulnerabilities.trivy`):

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Scan the images without a Trivy Operator report. `false`: external Trivy Operator only |
| `serverUrl` | `""` | Trivy server URL (client/server mode). Empty: standalone. Set by the chart with `trivy.server.enabled` |
| `binary` | `trivy` | Path of the Trivy CLI. The chart sets it to the binary its init container copies (`/opt/trivy/bin/trivy`) |
| `cacheDir` | `/tmp/trivy` | Where the database is downloaded in standalone mode: an `emptyDir` with the chart (`trivy.cacheSizeLimit`) |
| `timeout` | `10m` | Maximum duration of the scan of one image |
| `concurrency` | `2` | Images scanned at the same time. More is faster but needs more memory and bandwidth |
| `extraArgs` | `[]` | Extra `trivy image` arguments, e.g. `["--db-repository", "registry.example.com/aquasec/trivy-db"]` for a mirror of the database |

And in the values of the chart: `trivy.enabled` (init container copying the CLI), `trivy.image`
(`ghcr.io/aquasecurity/trivy:0.76.2`), `trivy.cacheSizeLimit`, and `trivy.server.*` (see
[chart values](chart-values.md)). How the modes compare, arm/v7 nodes and the database mirrors:
[vulnerabilities](vulnerabilities.md#trivy-setups).

### Vulnerabilities

What is collected and shown on the Images page (`config.vulnerabilities`):

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Collect vulnerabilities at all. `false`: none is collected, and the chart does not add the Trivy init container |
| `trivyOperator` | `true` | Read the Trivy Operator `VulnerabilityReports` (nothing happens without the CRD). `false`: always scan with the Trivy CLI |
| `ignore` | `[]` | fnmatch patterns on `registry/repository` or `registry/repository:tag` of images never scanned, e.g. `registry.k8s.io/pause*` |
| `trivy.ignoreUnfixed` | `false` | Only report the vulnerabilities that have a fixed version |
| `trivy.rescanInterval` | `24h` | An image is scanned again after this delay (results are kept meanwhile). Failed scans are retried at the next scan |
| `trivy.javaDb` | `false` | Download the Java DB (~1.5 GB) and scan Java archives (`.jar`, `.war`, `.ear`, `.par`); skipped otherwise |

```yaml
# Only report what can be fixed, scan once a week, skip some images
vulnerabilities:
  ignore:
    - registry.k8s.io/pause*
  trivy:
    ignoreUnfixed: true
    rescanInterval: 7d
```

See [vulnerabilities](vulnerabilities.md) for how the two sources are merged, the CVE search and the metrics.

### Audit

The Trivy Operator reports of the Security page (`config.security`). They need Trivy Operator in the
cluster: clusters without it are skipped.

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Read the config audit, exposed secret, RBAC, infrastructure and compliance reports |
| `exposedSecrets` | `true` | Show the lines where Trivy found a secret (masked by Trivy). `false`: leave the exposed secrets out |

kube-tower needs `get` and `list` on the report CRDs: the chart's ClusterRole has them, apply
[`deploy/remote-cluster-rbac.yaml`](../deploy/remote-cluster-rbac.yaml) on remote clusters. See
[security](security.md) for the report types.

## Resources (krr)

The CPU and memory recommendations of the [Resources](ui-resources.md) page. They need Prometheus and
the chart's krr pod:

```yaml
krr:
  enabled: true                  # the krr pod; sets config.resources.enabled and serverUrl
```

Choose how krr reaches Prometheus, per cluster:

| Mode | When | Setting |
| --- | --- | --- |
| **Found in the cluster** (default) | Prometheus runs in the cluster with its usual labels (kube-prometheus-stack, Prometheus Operator, VictoriaMetrics...) | nothing: krr finds it and reaches it through the API server (`services/proxy`) |
| **Given URL** | Discovery fails, Prometheus is outside the cluster, or one Prometheus (Thanos, Mimir) serves several clusters | an entry in `config.resources.prometheus` |

```yaml
config:
  resources:
    prometheus:
      - clusters: [in-cluster]       # names or patterns; the first matching entry wins
        url: http://kube-prometheus-stack-prometheus.monitoring.svc:9090
      - clusters: ["prod-*"]         # one Thanos for several clusters
        url: https://thanos.example.com
        clusterLabel: cluster        # the label telling the clusters apart (value: the cluster name)
        authHeaderEnv: PROMETHEUS_AUTH   # "Bearer <token>", put on the pods with extraEnv
```

`config.resources`:

| Key | Default | Description |
| --- | --- | --- |
| `strategy` | `simple` | `simple` (no CPU limit) or `simple_limit` (a CPU limit too) |
| `namespaces` | `[]` | Namespaces to analyse; empty: all |
| `interval` | `24h` | The recommendations of a cluster are reused this long before krr runs again |
| `timeout` | `15m` | Per cluster |
| `args` | `[]` | Other krr options, e.g. `["--history_duration", "168"]` |
| `prometheus[]` | `[]` | `clusters`, `url`, `clusterLabel`, `clusterValue`, `authHeaderEnv` or `authHeaderFile`, `headers` |
| `enabled`, `serverUrl` | set by the chart | On with `krr.enabled`, and the address of its krr pod |

The krr pod itself is set with `krr.*` in the values (image, resources, concurrency, NetworkPolicy ports):
see [chart values](chart-values.md). How krr runs and its errors: [resources](resources.md).

## Secrets

Every credential can come from an existing Secret or be given in the values, the chart then
creates the Secret. An existing Secret always wins. Values end up in git with ArgoCD: prefer
existing Secrets (ExternalSecrets, Sealed Secrets) outside a lab.

| Need | Existing Secret | Created by the chart | Secret content |
| --- | --- | --- | --- |
| Registry credentials, one Secret per registry | `registries.credentials[].existingSecret` (+ `usernameKey`, `passwordKey`) | `registries.credentials[].password` (+ `username`) | username / password or token |
| Registry credentials, several at once | `registries.existingSecret` | `registries.dockerConfigJson` | a `kubernetes.io/dockerconfigjson` Secret |
| Private git repositories holding charts | `git.existingSecret` / `git.secretKey` | `git.token` | a token |
| Login: admin password and session key | `auth.existingSecret` (keys `admin.password`, `session.key`) | no: created by kube-tower at startup, see [authentication](authentication.md) | random values |
| OIDC client (SSO) | `auth.oidc.existingSecret` (+ `clientIdKey`, `clientSecretKey`) | no | the client id and the client secret |
| Passwords of the local accounts | `auth.users[].existingSecret` (+ `passwordKey`) | no | a password |
| Remote clusters | `clusters[].existingSecret` or `config.clusters.secretNames` (labelled Secrets with `config.clusters.listSecrets: true`) | `clusters[]` with `server`/`config` or `kubeconfig` | see [clusters.md](clusters.md) |

A change to a Secret created by the chart restarts the pod.
