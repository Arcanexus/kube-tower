# Comparison with other tools

kube-tower **shows** the versions, the lifecycle and the vulnerabilities of what runs in your clusters;
it never updates anything. Other tools update for you, or look at your git repositories instead of the
clusters. Many of them work well **together** with kube-tower.

## At a glance

| | kube-tower | watchtower | Renovate | version-checker | Nova | Argo CD Image Updater |
| --- | --- | --- | --- | --- | --- | --- |
| What it is | Dashboard of the clusters | Updater of Docker containers | Bot opening pull requests | Prometheus exporter | Command line report | Updater of ArgoCD Applications |
| Updates things for you | ❌ never | ✅ restarts containers | ✅ pull requests | ❌ | ❌ | ✅ images of Applications |
| Looks at | what runs in the clusters | the containers of one Docker host | git repositories | the pods of one cluster | the Helm releases and pods of one cluster | ArgoCD Applications |
| Container images | ✅ workloads (running or not) and node caches | ✅ Docker only | ✅ declared in git | ✅ running pods | ✅ | ✅ the ones it manages |
| Helm charts and subcharts | ✅ from ArgoCD Applications, Flux HelmReleases and Helm releases, with subcharts | ❌ | ✅ declared in git | ❌ | ✅ Helm releases (not the charts ArgoCD renders) | ❌ |
| Vulnerabilities (CVE) | ✅ Trivy Operator reports or Trivy | ❌ | ❌ (security advisories of dependencies) | ❌ | ❌ | ❌ |
| Misconfigurations, secrets, compliance | ✅ Trivy Operator reports | ❌ | ❌ | ❌ | ❌ | ❌ |
| CPU and memory recommendations | ✅ runs krr | ❌ | ❌ | ❌ | ❌ | ❌ |
| Several clusters in one view | ✅ | ❌ | n/a | ❌ one per cluster | ❌ one per run | per ArgoCD instance |
| Web UI | ✅ | ❌ | ❌ (pull requests, dashboard issue) | ❌ (Grafana) | ❌ | ❌ (ArgoCD) |
| Metrics and alerts | ✅ Prometheus, Grafana dashboard | ❌ | ❌ | ✅ | ❌ | ❌ |

The other tools change fast: check their own documentation before choosing.

## watchtower

[watchtower](https://containrrr.dev/watchtower/) watches the containers of a Docker host and restarts
them when a newer image is pushed under their tag. kube-tower checks floating tags the same way (by
digest), but for Kubernetes workloads, and only tells: the update stays a change in git, reviewed and
deployed by your GitOps workflow.

## Renovate

[Renovate](https://docs.renovatebot.com/) reads the image tags and chart versions **declared in git**
and opens pull requests to update them. kube-tower reads **what runs**: images that are not in your
repositories (pods created by operators, images cached on nodes, charts of third-party Applications),
the subcharts of each chart, and the vulnerabilities and end of life OS of each image.

Together: Renovate keeps git up to date, kube-tower shows what is still behind in the clusters and what
is urgent (critical CVEs with a fix, major updates) across every cluster.

## version-checker

[version-checker](https://github.com/jetstack/version-checker) exports Prometheus metrics of the current
and latest versions of the images running in one cluster, shown in Grafana. kube-tower exports similar
metrics (see [metrics](metrics.md)) and adds a UI, several clusters in one view, the Helm charts of
ArgoCD with their subcharts, and the vulnerabilities.

## Nova

[Nova](https://github.com/FairwindsOps/nova) is a command line tool that lists the outdated or
deprecated Helm releases of a cluster, and its outdated container images. It reads the Helm release
Secrets: charts deployed by ArgoCD, which renders them without a Helm release, are not seen. kube-tower
also reads the charts of ArgoCD Applications and Flux HelmReleases (Helm releases too, with
`helm.releases`), with their subcharts, across clusters, and runs as a service with a UI.

## Argo CD Image Updater

[Argo CD Image Updater](https://argocd-image-updater.readthedocs.io/) updates the images of ArgoCD
Applications automatically, writing the new tags back to git or to the Applications. Use it for the
images you want updated without review; kube-tower shows the rest, and the Helm charts.

## Trivy Operator

[Trivy Operator](https://aquasecurity.github.io/trivy-operator/) scans the workloads of a cluster and
writes its reports as Kubernetes resources, without a UI of its own. kube-tower reads these reports for
every cluster: the vulnerabilities next to the versions of each image, and the misconfigurations,
exposed secrets, RBAC and compliance reports on its [Security](security.md) page. See
[vulnerabilities](vulnerabilities.md).

## krr

[krr](https://github.com/robusta-dev/krr) (Robusta's Kubernetes Resource Recommender) reads the CPU and
memory usage of the containers in Prometheus and recommends their requests and limits, in a terminal or
a file. kube-tower runs krr itself, in a pod of the chart, for every registered cluster, and shows its
recommendations next to the rest of the inventory, with totals per cluster, metrics and the resources
block to paste in each manifest. See [resources](resources.md).
