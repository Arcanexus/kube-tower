# Registering clusters

kube-tower always scans the cluster it runs in (disable with `clusters.inCluster: false`).
Other clusters are registered the way ArgoCD does it: one Secret per cluster.

## 1. Create a read-only ServiceAccount on the remote cluster

```sh
kubectl --context prod apply -f deploy/remote-cluster-rbac.yaml
TOKEN=$(kubectl --context prod -n kube-tower get secret kube-tower-reader-token -o jsonpath='{.data.token}' | base64 -d)
CA=$(kubectl --context prod -n kube-tower get secret kube-tower-reader-token -o jsonpath='{.data.ca\.crt}')
```

## 2. Create the cluster Secret where kube-tower runs

See [deploy/cluster-secret.example.yaml](../deploy/cluster-secret.example.yaml). The Secret must
carry the label `kube-tower.arcanexus.com/secret-type: cluster` and contain:

| Key | Content |
| --- | --- |
| `name` | display name |
| `server` | API server URL |
| `config` | JSON, ArgoCD format: `bearerToken` (or `username`/`password`) and `tlsClientConfig` (`caData`, `certData`, `keyData`, `insecure`, `serverName`) |

Alternatively, put a full kubeconfig under a `kubeconfig` key. It must hold its credentials
itself (`token`, `client-certificate-data`, `certificate-authority-data`...): paths of local files
(`tokenFile`, `client-certificate`, `certificate-authority`...) and `auth-provider` are refused.
Exec plugins are refused too, unless their command is allowed (see
[managed clusters](#managed-clusters-eks-gke-aks-exec-plugins)).

## Registering clusters with the Helm chart

The `clusters` value either creates the Secret or references one you manage yourself:

```yaml
clusters:
  # The chart creates the Secret, ArgoCD format
  - name: prod
    server: https://prod.example.com:6443
    config:
      bearerToken: <token>
      tlsClientConfig:
        caData: <base64 PEM>
  # The chart creates the Secret from a kubeconfig
  - name: lab
    kubeconfig: |
      apiVersion: v1
      kind: Config
      ...
  # Existing Secret (ExternalSecrets, Sealed Secrets, by hand...), read by name
  - existingSecret: staging-cluster
```

An existing Secret must live in the kube-tower namespace and hold the keys above (`name`,
`server`, `config`, or `kubeconfig`); it does not need the label. The chart adds it to
`config.clusters.secretNames` and grants `get` on that Secret only. Labelled Secrets of the
namespace are always picked up, without listing them.

Inline tokens end up in your values, hence in git with ArgoCD: prefer `existingSecret` with
ExternalSecrets or Sealed Secrets for anything but a lab.

## Reusing ArgoCD cluster Secrets

If ArgoCD already knows your clusters, set `config.clusters.useArgocdSecrets: true`: the chart
grants kube-tower read access to Secrets in the ArgoCD namespace and every ArgoCD cluster is
scanned too. The ArgoCD credentials must allow listing pods, nodes, workloads and Applications.

The Clusters tab shows each cluster and whether it is reachable.

## Managed clusters (EKS, GKE, AKS): exec plugins

The simplest way to scan a managed cluster is a ServiceAccount token, as above: it works on EKS,
GKE and AKS alike, with no plugin.

To use the cloud identity instead (IRSA or EKS Pod Identity, GKE Workload Identity, Azure Workload
Identity), use a kubeconfig whose user runs an exec plugin (`aws-iam-authenticator`,
`gke-gcloud-auth-plugin`, `kubelogin`...). kube-tower runs an exec command only when it is listed in
`config.clusters.execCommands`, written exactly as in the kubeconfig: anyone able to create a
cluster Secret could otherwise run any command in the kube-tower pod. The plugin is not in the
kube-tower image: copy it with an init container, the way the chart copies Trivy. It must run on
Alpine (musl): static binaries do.

```yaml
config:
  clusters:
    execCommands:
      - /opt/kube-tower/bin/kubelogin
extraInitContainers:
  - name: kubelogin
    image: <an image holding the kubelogin binary>
    command: ["cp", "/path/in/the/image/kubelogin", "/opt/kube-tower/bin/kubelogin"]
    volumeMounts:
      - name: plugins
        mountPath: /opt/kube-tower/bin
extraVolumes:
  - name: plugins
    emptyDir: {}
extraVolumeMounts:
  - name: plugins
    mountPath: /opt/kube-tower/bin
    readOnly: true
# Cloud identity of the kube-tower pod, e.g. Azure Workload Identity
serviceAccount:
  annotations:
    azure.workload.identity/client-id: <client id>
clusters:
  - name: aks-prod
    kubeconfig: |
      apiVersion: v1
      kind: Config
      clusters: [{name: aks-prod, cluster: {server: "https://...", certificate-authority-data: "..."}}]
      users:
        - name: kube-tower
          user:
            exec:
              apiVersion: client.authentication.k8s.io/v1beta1
              command: /opt/kube-tower/bin/kubelogin
              args: [get-token, --login, workloadidentity, --server-id, 6dae42f8-4368-4678-94ff-3960e28e3630]
      contexts: [{name: aks-prod, context: {cluster: aks-prod, user: kube-tower}}]
      current-context: aks-prod
```

The plugin gets the environment of the kube-tower pod (`extraEnv` adds variables, e.g.
`AWS_REGION`) and runs at each scan when the clusters are discovered; kube-tower asks it again
for a token when the one it gave expires.
