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

Alternatively, put a full kubeconfig under a `kubeconfig` key (token or client certificate
auth only, exec plugins are not supported).

The Secrets can be created by the chart (`clusters:` value) but generating them with
ExternalSecrets keeps tokens out of git.

## Reusing ArgoCD cluster Secrets

If ArgoCD already knows your clusters, set `config.clusters.useArgocdSecrets: true`: the chart
grants kube-tower read access to Secrets in the ArgoCD namespace and every ArgoCD cluster is
scanned too. The ArgoCD credentials must allow listing pods, nodes, workloads and Applications.

The Clusters tab shows each cluster and whether it is reachable.
