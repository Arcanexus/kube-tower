# Configuration

kube-tower reads `/etc/kube-tower/config.yaml` (override with `KUBE_TOWER_CONFIG`). With the Helm
chart, this file is rendered from `.Values.config`. Keys are camelCase; unknown keys are rejected
at startup so typos are caught early.

```yaml
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
  maxTagPages: 10              # 1000 tags per page
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
    - registry: docker.io
      usernameFile: /etc/kube-tower/registries/0/username   # or username / usernameEnv
      passwordFile: /etc/kube-tower/registries/0/password   # or passwordEnv
  mirrors: {}                  # e.g. {docker.io: mirror.example.com}
  concurrency: 8
  timeout: 20                  # seconds, per request (connect, read)
  retries: 2                   # extra attempts after a timeout, a connection error or a 502/503/504
git:
  rawUrlTemplates:
    github.com: https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}
    gitlab.com: https://gitlab.com/{owner}/{repo}/-/raw/{ref}/{path}
  tokenEnv: GIT_TOKEN
```

Durations (`refreshInterval`, `timeout`, `rescanInterval`…) accept `30s`, `15m`, `6h`, `1d` or seconds.

Environment overrides: `KUBE_TOWER_LOG_LEVEL`, `KUBE_TOWER_REFRESH_INTERVAL`.

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
raise the Docker Hub rate limits, which are much lower for anonymous clients. They apply to:

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
The Settings page lists the loaded credentials (never their values) and flags invalid ones.

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
