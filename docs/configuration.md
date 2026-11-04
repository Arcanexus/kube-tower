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
images:
  enabled: true
  includeNodeImages: true      # images cached on nodes (node.status.images); the nodes give the image sizes either way
  includePrerelease: false
  checkFloatingDigests: true   # compare digests for latest/stable tags
  fetchTagDigests: true        # published digests of the current/latest tags (image details)
  ignore:                      # fnmatch patterns on registry/repository[:tag]
    - registry.k8s.io/pause*
  maxTagPages: 50              # 1000 tags per page
helm:
  enabled: true
  applicationNamespaces: [argocd]   # [] = all namespaces
  includePrerelease: false
  checkDependencies: true     # subcharts, and their own subcharts (3 levels)
security:                      # Trivy Operator security reports, see security.md
  enabled: true
  exposedSecrets: true         # false: leave the exposed secrets out
vulnerabilities:               # see "Vulnerabilities (Trivy)" below
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
  users: []                    # local accounts: name, role (readonly | admin), passwordFile or passwordEnv
  anonymousRole: ""            # "" (login required) | readonly
  sessionDuration: 24h
  secretName: kube-tower-auth  # admin.password and session.key, created with random values when missing
  secretDir: /etc/kube-tower/auth
  metricsPublic: true          # false: /metrics needs the Basic auth of a local account
  url: ""                      # URL users open kube-tower with (needed by the SSO)
  oidc:                        # single sign-on, see authentication.md#single-sign-on-oidc
    issuer: ""                 # empty: no SSO
    clientId: ""               # empty: from $KUBE_TOWER_OIDC_CLIENT_ID (the chart reads it from auth.oidc.existingSecret)
    adminGroups: []
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
| `images`, `helm` | [statuses and versions](statuses.md), [usage](usage.md) |
| `registries` | [registries](registries.md) |
| `git` | [Helm charts read from git](usage.md#helm-charts), [troubleshooting](troubleshooting.md#helm-charts) |
| `vulnerabilities` | [vulnerabilities](vulnerabilities.md), and the table below |
| `security` | [security](security.md) |
| `auth` | [authentication](authentication.md) |
| `roles`, `internal`, `redis` | [scaling](scaling.md) |
| `logs` | [Logs tab](usage.md#logs) |

## Vulnerabilities (Trivy)

kube-tower reads the reports of [Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
when it runs in a cluster, and scans the other images with the [Trivy](https://trivy.dev) CLI. See
[vulnerabilities](vulnerabilities.md) for how it works and examples.

| Key | Default | Description |
| --- | --- | --- |
| `vulnerabilities.enabled` | `true` | Collect vulnerabilities at all. `false`: no vulnerability is collected, and the chart does not add the Trivy init container |
| `vulnerabilities.trivyOperator` | `true` | Read Trivy Operator `VulnerabilityReports` (nothing happens when the CRD does not exist). `false`: always scan with the Trivy CLI |
| `vulnerabilities.ignore` | `[]` | fnmatch patterns on `registry/repository` or `registry/repository:tag` of images never scanned by the Trivy CLI, e.g. `registry.k8s.io/pause*` |
| `vulnerabilities.trivy.enabled` | `true` | Scan the images without an operator report with the Trivy CLI. `false`: only operator reports are shown |
| `vulnerabilities.trivy.binary` | `trivy` | Path of the Trivy CLI. The Helm chart sets it to the binary copied by its init container (`/opt/trivy/bin/trivy`) |
| `vulnerabilities.trivy.serverUrl` | `""` | Trivy server URL (client/server mode), e.g. `http://kube-tower-trivy:4954`. Empty: standalone mode. The chart sets it when `trivy.server.enabled` is `true`; set it yourself to use a Trivy server you already run |
| `vulnerabilities.trivy.cacheDir` | `/tmp/trivy` | Where the vulnerability database is downloaded in standalone mode (~1.6 GB, ~3.1 GB with the Java DB). An `emptyDir` with the chart (`trivy.cacheSizeLimit`) |
| `vulnerabilities.trivy.timeout` | `10m` | Maximum duration of the scan of one image |
| `vulnerabilities.trivy.concurrency` | `2` | Images scanned at the same time. More is faster but needs more memory and bandwidth |
| `vulnerabilities.trivy.rescanInterval` | `24h` | Results are kept in memory and an image is scanned again after this delay. Failed scans are retried at the next scan |
| `vulnerabilities.trivy.ignoreUnfixed` | `false` | Only report the vulnerabilities that have a fixed version |
| `vulnerabilities.trivy.javaDb` | `false` | Download the Java DB (~1.5 GB) and scan Java archives (`.jar`, `.war`, `.ear`, `.par`). When `false`, they are skipped |
| `vulnerabilities.trivy.extraArgs` | `[]` | Extra `trivy image` arguments, e.g. `["--db-repository", "registry.example.com/aquasec/trivy-db"]` for a mirror of the database |

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
