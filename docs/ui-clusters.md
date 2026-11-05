# Clusters page

The nodes of every cluster, grouped by role and node group, with their versions and what differs
between them. How to connect a cluster is in [clusters](clusters.md); their registration and
connectivity are in the Clusters tab of the [Administration](ui-administration.md#clusters). How
detail panels work in general is in [usage](usage.md).

![Clusters](images/clusters-page.png)

## One card per cluster

Each card shows the Kubernetes version of the API server, the number of nodes (and how many are not
ready), and a badge with the worst finding of the cluster: **healthy**, **info**, **warning**,
**error**, or **unreachable** with the error of the last scan.

Under it:

- **Kubelet**, **Runtime** and **OS**: the versions run by the nodes, the most common first, with the
  number of nodes when there is more than one. A version that only some nodes run is highlighted.
- **Findings**: what to look at, for the whole cluster and per node (open by default when one is a
  warning or an error).
- **The nodes**, one tile each, grouped by role, then by node group. A tile shows the name, the kubelet
  version, the container runtime, the architecture and how full the node is in pods. Its colour is its
  worst finding; hovering it lists them.

The **Cluster** filter of the top bar applies. *Running only* does not, because nodes are not images.
A role [limited to some clusters](rbac.md#clusters-of-a-role) only sees those.

## Roles and node groups

| Group | Taken from |
| --- | --- |
| Role | `control-plane` for the `node-role.kubernetes.io/control-plane` (or `master`) label, else the name of another `node-role.kubernetes.io/<role>` label (`ingress`, `gpu`…), else `worker` |
| Node group | The first label of `clusters.nodePoolLabels` found on the node: EKS node group, GKE node pool, AKS agent pool, Karpenter node pool, `node.kubernetes.io/pool` |

Managed control planes (EKS, GKE, AKS) have no node: only their API server version shows.

## Findings

| Level | Finding |
| --- | --- |
| error | The node is not ready |
| error | Its kubelet (or kube-proxy) is newer than the API server, or more than 3 minor versions behind it: outside the [version skew policy](https://kubernetes.io/releases/version-skew-policy/) of Kubernetes |
| warning | Its kubelet is 1 to 3 minor versions behind the API server: supported, but to upgrade before the API server moves on |
| warning | The node is cordoned (no new pod is scheduled on it), or has a condition such as `MemoryPressure`, `DiskPressure`, `PIDPressure` |
| warning | The nodes of the cluster run different kubelet versions (often an upgrade left half done) |
| info | The nodes run different OS images, container runtimes or kernels |

Distribution suffixes are ignored to compare versions: `v1.30.4-eks-a737599`, `v1.31.2+k3s1`,
`v1.29.8-gke.1211000`.

## Detail panel

Click a node for its findings, role and node group, kubelet and kube-proxy versions (next to the API
server's), container runtime, OS and kernel, CPU and memory capacity, pods running out of the maximum,
instance type, zone and creation date.

![A node](images/clusters-node.png)

## Where the data comes from

kube-tower reads the nodes (`list nodes`, already needed for the images they cache) at each scan, even
with `images.enabled: false`. Nothing else is asked from the clusters: no new permission.

The same data is exported as the `kube_tower_nodes` metric (see [metrics](metrics.md)).
