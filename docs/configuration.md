# Configuration

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
  includeNodeImages: true      # images cached on nodes (node.status.images)
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
  port: 8081                   # internal API of the controller
  controllerUrl: ""            # where worker and trivy processes reach it
  tokenEnv: KUBE_TOWER_INTERNAL_TOKEN
  taskTimeout: 30m             # a task not answered by then is given to another process
  batchSize: 50                # images or charts per task: a scan is shared by the worker and trivy processes
  leaderElection: false        # several controller replicas: one active, elected through a Lease
  leaseName: kube-tower-controller
redis:                         # optional Redis / Valkey keeping the snapshot across controller restarts
  url: ""                      # redis://host:6379/0 or rediss:// (TLS); empty: the snapshot stays in memory
  passwordEnv: KUBE_TOWER_REDIS_PASSWORD
  key: kube-tower:snapshot     # change it when several installations share one Redis
```

Durations (`refreshInterval`, `timeout`, `rescanInterval`…) accept `30s`, `15m`, `6h`, `1d` or seconds.

Environment overrides: `KUBE_TOWER_LOG_LEVEL`, `KUBE_TOWER_REFRESH_INTERVAL`, `KUBE_TOWER_ROLES`
(comma-separated), `KUBE_TOWER_CONTROLLER_URL`, `KUBE_TOWER_REDIS_URL`.

`roles` is the horizontal scaling (see [scaling](scaling.md) and
[ADR 0002](adr/0002-horizontal-scaling.md)): one image whose pods run any combination of the `ui`,
`controller`, `worker` and `trivy` roles, all in one pod or apart and scaled independently. By default
a process runs every role (`all`). The chart sets all of this with `mode: distributed`; when the roles
run apart:

- the process with `controller` schedules the scans and serves its internal API on `internal.port`;
  the tasks of the roles it does not run wait there;
- processes with `worker` and/or `trivy` (and no `controller`) pull these tasks from
  `internal.controllerUrl`, run them and send the results back; a `worker` reads the cluster list itself.
  The version checks and Trivy scans of a scan are split in tasks of `internal.batchSize` images or
  charts (the tags of one image stay together), so several processes share them;
- a process with `ui` and no `controller` shows the state of the controller, read every 2 seconds
  from `internal.controllerUrl`, and sends it the actions of the users; any number of them can serve
  the pages. The metrics of the snapshot are served by the process with `controller` only;
- with `internal.leaderElection: true`, several replicas can run the `controller` role: they share
  the `internal.leaseName` Lease of their namespace (RBAC: get, create and update `leases` in
  `coordination.k8s.io`). The holder schedules the scans and serves the internal API; the others wait,
  answer 503 on `/readyz` and `/leaderz` (no Service routes to them) and take over about 15 seconds after the active
  one stopped. A controller that cannot renew its Lease in time stops and is restarted as a standby.
  The new controller starts with a full scan, unless `redis.url` is set (below), and the worker and
  trivy processes pull from it;
- with `redis.url`, the controller also writes the snapshot to Redis or Valkey (compressed, at each
  change, the last version only) and reads it back when it becomes the active controller: a restarted
  controller, or a standby taking over, shows the last inventory at once and waits for the rest of
  `refreshInterval` before scanning. Only the controller connects to it. A scan in progress is not kept: it starts again;
- every process reads the shared token from `$KUBE_TOWER_INTERNAL_TOKEN`, which is required as soon as
  the roles are apart. The internal API carries registry credentials: keep its port inside the cluster.

The Logs page shows the lines of the controller, with the warnings and errors of the worker and
trivy processes, prefixed with their pod name. When Trivy runs in trivy processes, the Administration
page reads the status of one of them; a database update runs in one of them and the others refresh
theirs before their next task, and a cleared cache is forgotten by each one at its next task. The
connectivity test runs in the controller.

## Vulnerabilities (Trivy)

kube-tower reads the reports of [Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
when it runs in a cluster, and scans the other images with the [Trivy](https://trivy.dev) CLI. See
[Vulnerabilities](vulnerabilities.md) for how it works.

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

The Trivy CLI uses the [registry credentials](#registry-authentication) of kube-tower to pull the
layers of private images. In standalone mode, the pod must reach the database registries
(`mirror.gcr.io` and `ghcr.io`, or the mirror given in `extraArgs`); in client/server mode, only the
Trivy server needs them.

Examples:

```yaml
# Only report what can be fixed, scan once a week, skip some images
vulnerabilities:
  ignore:
    - registry.k8s.io/pause*
    - docker.io/library/busybox*
  trivy:
    ignoreUnfixed: true
    rescanInterval: 7d
```

```yaml
# Trivy Operator already scans every workload: do not run Trivy in kube-tower
# (node images without an operator report are then not scanned)
vulnerabilities:
  trivy:
    enabled: false
```

## Registry authentication

Each registry can have its own credentials, used for private images, private Helm charts and to
raise the Docker Hub rate limits, which are much lower for anonymous clients. Cloud registries (ECR,
Artifact Registry, ACR) can use the identity of the pod instead, and the image pull secrets of the
clusters can be reused: [registries.md](registries.md) explains the method for each kind of registry
(Harbor, Artifactory, Nexus, private CAs...). Credentials apply to:

- container registries and OCI Helm registries (token exchange or basic auth),
- classic HTTP Helm repositories (`index.yaml` and chart downloads, basic auth).

With the Helm chart, each registry gets one Secret, either an existing one or one the chart
creates from the values. The chart mounts it read-only and writes only the file paths in the
ConfigMap:

```yaml
registries:
  credentials:
    - registry: docker.io            # docker.io, ghcr.io, quay.io, harbor.example.com, charts.example.com...
      existingSecret: dockerhub-credentials
      usernameKey: username          # omit for token-only registries
      passwordKey: password          # password or access token (default key: password)
    - registry: ghcr.io
      existingSecret: ghcr-token
      passwordKey: token
    - registry: quay.io              # no existingSecret: the chart creates the Secret
      username: robot                # optional, written in the ConfigMap
      password: <token>
```

`existingSecret` wins when both are set.

```sh
kubectl -n kube-tower create secret generic dockerhub-credentials \
  --from-literal=username=<user> --from-literal=password=<access token>
```

A `kubernetes.io/dockerconfigjson` Secret (`registries.existingSecret`) is also supported, e.g. an
existing image pull secret, or its content in `registries.dockerConfigJson` (an object or a JSON
string) for the chart to create it; per registry entries win when both define the same host.
The Settings page lists the loaded credentials (never their values), flags invalid ones and tells
whether each registry accepted them.

Credentials and tokens are only sent over `https://`. kube-tower refuses a registry token service
(`realm`) or a registry redirect in `http://`, an `http://` Helm repository that has credentials,
and an `http://` git raw URL template when a git token is set: the check fails with a message
saying what was refused. Public `http://` Helm repositories (no credentials) still work.

Credentials are chosen by the host that asks for them, like Docker and containerd do: a registry's
credentials only go to that registry (or its mirror in `registries.mirrors`) and to the token
service it names. When a registry redirects to another host (e.g. `registry.k8s.io` to Artifact
Registry), that host gets the credentials configured for it, or anonymous access: if a private
registry redirects to another private host, add an entry for that host in
`registries.credentials`.

## Secrets

Every credential can come from an existing Secret or be given in the values, the chart then
creates the Secret. An existing Secret always wins. Values end up in git with ArgoCD: prefer
existing Secrets (ExternalSecrets, Sealed Secrets) outside a lab.

| Need | Existing Secret | Created by the chart | Secret content |
| --- | --- | --- | --- |
| Registry credentials, one Secret per registry | `registries.credentials[].existingSecret` (+ `usernameKey`, `passwordKey`) | `registries.credentials[].password` (+ `username`) | username / password or token |
| Registry credentials, several at once | `registries.existingSecret` | `registries.dockerConfigJson` | a `kubernetes.io/dockerconfigjson` Secret |
| Private git repositories holding charts | `git.existingSecret` / `git.secretKey` | `git.token` | a token |
| Remote clusters | `clusters[].existingSecret` or `config.clusters.secretNames` (labelled Secrets with `config.clusters.listSecrets: true`) | `clusters[]` with `server`/`config` or `kubeconfig` | see [clusters.md](clusters.md) |

A change to a Secret created by the chart restarts the pod.
