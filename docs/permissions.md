# Permissions

kube-tower only reads: nothing is ever created, patched or deleted in the scanned clusters. This page
lists every Kubernetes permission it uses, where it runs and on the remote clusters, and the options
that widen them.

## On the cluster kube-tower runs in

On the cluster it runs in, kube-tower gets a ClusterRole with `get`/`list` on pods, nodes,
deployments, statefulsets, daemonsets, cronjobs, `applications.argoproj.io` and
the Trivy Operator reports (`vulnerabilityreports`, `configauditreports`, `exposedsecretreports`,
`rbacassessmentreports`, `infraassessmentreports`, their cluster-scoped variants and
`clustercompliancereports`, all `aquasecurity.github.io`), plus `get` on the cluster Secrets
of its namespace named in `clusters[]` and `config.clusters.secretNames`, and on nothing else.
Install it in a namespace of its own.

`rbac.create: false` skips the RBAC of the chart: give the ServiceAccount the same rules yourself.

## On remote clusters

[`deploy/remote-cluster-rbac.yaml`](../deploy/remote-cluster-rbac.yaml) creates the `kube-tower-reader`
ServiceAccount, its token Secret and a ClusterRole with the same read-only rules (pods, nodes,
workloads, ArgoCD Applications, Trivy Operator reports). See [clusters](clusters.md) for the cluster
Secret built from its token. With an exec plugin (EKS, GKE, AKS), the cloud identity must be bound to
the same ClusterRole, see [managed clusters](clusters.md#managed-clusters-eks-gke-aks-exec-plugins).

## Options that widen the permissions

Three options widen them. The first two read **every** Secret of a namespace (Kubernetes RBAC cannot
restrict `list` to a label):

- `config.clusters.listSecrets: true`: `list` on the Secrets of its namespace, to find labelled
  cluster Secrets;
- `config.clusters.useArgocdSecrets: true` without `argocdSecretNames`: `list` on the Secrets of
  the ArgoCD namespace. With `argocdSecretNames`, only `get` on these Secrets.
- `config.registries.useImagePullSecrets: true`: `get` on Secrets in every namespace, to read the image
  pull secrets of the workloads (see [registries](registries.md#reusing-the-image-pull-secrets)). The
  chart adds it to the ClusterRole; on remote clusters, uncomment the rule of
  `deploy/remote-cluster-rbac.yaml`.

## Login

With `auth.enabled` (the default), a Role gives `get` on the auth Secret `<release>-auth` and, unless
`auth.existingSecret` is set, `create` on Secrets: the controller creates that Secret with random values
at its first start (see [authentication](authentication.md#the-admin-account)).

## Trivy Operator reports

kube-tower needs `get` and `list` on the report CRDs, for the vulnerabilities and the
[Security](security.md) page. The ClusterRole of the chart and `deploy/remote-cluster-rbac.yaml` hold this rule (re-apply the file on
remote clusters set up before 1.0, which only read the `vulnerabilityreports`):

```yaml
- apiGroups: ["aquasecurity.github.io"]
  resources: [vulnerabilityreports, configauditreports, clusterconfigauditreports, exposedsecretreports,
              rbacassessmentreports, clusterrbacassessmentreports, infraassessmentreports,
              clusterinfraassessmentreports, clustercompliancereports]
  verbs: ["get", "list"]
```

A `403` on one of them is shown in the scan errors (status pill) with the CRD that could not be listed;
the other types are still shown.

## Distributed mode

The pods running `controller` or `worker` (and `trivy`, for the cloud identities of
[registries](registries.md)) use the ServiceAccount of the chart, with the permissions above, plus `create` on `leases`, `get` / `update` on the
`<release>-controller` Lease and `patch` on the pods of the release namespace (the active controller
labels its own pod) in distributed mode.
