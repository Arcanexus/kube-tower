# Troubleshooting

Start with the **scan errors** (the count next to the scan status, top right of every page) (collection and version check
errors) and the `message` under each `error` status. Each message says what failed, the HTTP or
Kubernetes status, and what to do; the Logs page and the pod logs
(`kubectl -n kube-tower logs deploy/kube-tower`) give the details (set `logs.level: DEBUG` to see
every request).

| Symptom | Cause | Fix |
| --- | --- | --- |
| `cannot list pods: 403 Forbidden` | The ServiceAccount used for that cluster lacks a permission | Apply `deploy/remote-cluster-rbac.yaml` on remote clusters; check `rbac.create` locally |
| Cluster `unreachable` | Wrong `server`, network policy or firewall, expired token, bad CA | Test from the pod: `kubectl -n kube-tower exec deploy/kube-tower -- python -c "import urllib.request,ssl;print(urllib.request.urlopen('https://<server>/version', context=ssl._create_unverified_context()).read())"` |
| `exec / AWS auth is not supported` | The cluster Secret uses an exec plugin (EKS, GKE) | Use a ServiceAccount token (`bearerToken`) instead |
| Images in `error` with `cannot get a pull token …: HTTP 401` or `cannot list the tags of …: HTTP 401/403` | Private repository or wrong credentials | Add [registry credentials](configuration.md#registry-authentication); check the Settings page shows them as `loaded` |
| Images in `error` with `… did not answer before registries.timeout` | Slow or throttling registry (often Docker Hub with many anonymous requests) | Add Docker Hub credentials, lower `registries.concurrency`, increase `registries.timeout`; requests are already retried `registries.retries` times |
| Images in `error` with `cannot open a connection to … before registries.timeout` | No route from the pod to the registry: egress network policy, firewall, proxy, or IPv6 without connectivity | Test from the pod: `kubectl -n kube-tower exec deploy/kube-tower -- python -c "import httpx;print(httpx.get('https://registry-1.docker.io/v2/').status_code)"` (401 means reachable) |
| Many Docker Hub images in `error` with `429` | Docker Hub rate limit | Add Docker Hub credentials (`registry: docker.io`) |
| A chart in `error` with `cannot read the index.yaml of the Helm repository …: HTTP 401` | Private Helm repository | Add credentials for the repository host |
| A git chart in `error` with `cannot read <path>/Chart.yaml at <ref> in <repo>: HTTP 404` | Private git repository, wrong `path`, or the Application is not a Helm chart | Set `git.existingSecret` with a token; for non GitHub/GitLab hosts add a `git.rawUrlTemplates` entry |
| `no raw URL template for git host …` | Self-hosted git (Gitea, Bitbucket…) | Add a template, e.g. `gitea.example.com: https://gitea.example.com/{owner}/{repo}/raw/{ref}/{path}` |
| A tag reported `up-to-date` although a newer version exists | The newer version has a different tag shape (`1.2.3` vs `1.3.0-alpine`) or is a pre-release | Expected: kube-tower only compares tags of the same shape; enable `includePrerelease` for pre-releases |
| Floating tag (`latest`) always `unknown` | No running digest known (workload not running, image not on nodes) | Expected; it becomes checkable once the image runs |
| No Helm charts at all | ArgoCD Applications live in another namespace, or ArgoCD is not installed | Set `config.helm.applicationNamespaces` (`[]` = all namespaces) |
| `unknown setting 'xxx'` at startup | Typo in `config` | Keys are camelCase, see [configuration](configuration.md) |
| Scan takes long | Many images or slow registries | Increase `registries.concurrency`, ignore irrelevant images with `images.ignore` |
