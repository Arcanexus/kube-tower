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
  secretLabelSelector: kube-tower.arcanexus.com/secret-type=cluster
  secretNames: []              # extra cluster Secrets of that namespace, read by name
  useArgocdSecrets: false      # also use ArgoCD cluster Secrets
  argocdNamespace: argocd
  requestTimeout: 30
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
registries:
  dockerConfigPath: /etc/kube-tower/dockerconfig/config.json
  credentials:                 # per registry, override the docker config.json
    - registry: docker.io
      usernameFile: /etc/kube-tower/registries/0/username   # or username / usernameEnv
      passwordFile: /etc/kube-tower/registries/0/password   # or passwordEnv
  mirrors: {}                  # e.g. {docker.io: mirror.example.com}
  concurrency: 8
  timeout: 20
git:
  rawUrlTemplates:
    github.com: https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}
    gitlab.com: https://gitlab.com/{owner}/{repo}/-/raw/{ref}/{path}
  tokenEnv: GIT_TOKEN
```

Environment overrides: `KUBE_TOWER_LOG_LEVEL`, `KUBE_TOWER_REFRESH_INTERVAL`.

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

## Secrets

Every credential can come from an existing Secret or be given in the values, the chart then
creates the Secret. An existing Secret always wins. Values end up in git with ArgoCD: prefer
existing Secrets (ExternalSecrets, Sealed Secrets) outside a lab.

| Need | Existing Secret | Created by the chart | Secret content |
| --- | --- | --- | --- |
| Registry credentials, one Secret per registry | `registries.credentials[].existingSecret` (+ `usernameKey`, `passwordKey`) | `registries.credentials[].password` (+ `username`) | username / password or token |
| Registry credentials, several at once | `registries.existingSecret` | `registries.dockerConfigJson` | a `kubernetes.io/dockerconfigjson` Secret |
| Private git repositories holding charts | `git.existingSecret` / `git.secretKey` | `git.token` | a token |
| Remote clusters | `clusters[].existingSecret`, or any Secret labelled `kube-tower.arcanexus.com/secret-type=cluster` | `clusters[]` with `server`/`config` or `kubeconfig` | see [clusters.md](clusters.md) |

A change to a Secret created by the chart restarts the pod.
