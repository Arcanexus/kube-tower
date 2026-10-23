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
  useArgocdSecrets: false      # also use ArgoCD cluster Secrets
  argocdNamespace: argocd
  requestTimeout: 30
images:
  enabled: true
  includeNodeImages: true      # images cached on nodes (node.status.images)
  includePrerelease: false
  checkFloatingDigests: true   # compare digests for latest/stable tags
  ignore:                      # fnmatch patterns on registry/repository[:tag]
    - registry.k8s.io/pause*
  maxTagPages: 10              # 1000 tags per page
helm:
  enabled: true
  applicationNamespaces: [argocd]   # [] = all namespaces
  includePrerelease: false
  checkDependencies: true
registries:
  dockerConfigPath: /etc/kube-tower/registries/config.json
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

## Secrets

| Need | Helm value | Secret content |
| --- | --- | --- |
| Registry credentials (private registries, Docker Hub rate limits) | `registries.existingSecret` | a `kubernetes.io/dockerconfigjson` Secret |
| Private git repositories holding charts | `git.existingSecret` / `git.secretKey` | a token |
| Remote clusters | `clusters` or your own Secrets | see [clusters.md](clusters.md) |
