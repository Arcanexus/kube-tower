# Clusters page

The nodes of every cluster, grouped by role and node group, with their versions and what differs
between them. How to connect a cluster is in [clusters](clusters.md); their registration and
connectivity are in the Clusters tab of the [Administration](ui-administration.md#clusters). How
detail panels work in general is in [usage](usage.md).

![Clusters](images/clusters-page.png)

## One card per cluster

Each card reads from top to bottom:

1. **Its state**: a badge, *healthy* (green), *to check* (orange), *problem* (red) or *unreachable* with
   the error of the last scan, and the Kubernetes version of the API server.
2. **What to look at**, in one line per kind of problem with the number of nodes: *1 node behind the API
   server*, *1 node cordoned*, *1 node not ready*… When there is nothing: *All 11 nodes ready, on the
   version of the API server*.
3. **The kubelet versions**: a bar split by version, as wide as the share of nodes running it, green
   when it is the version of the API server, orange when behind, red when unsupported.
4. **The nodes**, grouped by role (Control plane, Workers, `ingress`…) and node group. Each node is a
   chip with a coloured dot (its worst finding); its version only shows when it differs from the most
   common one. Hover a chip to read its findings, click it for its details.
5. **Details** (folded): the container runtimes, OS images and kernels of the nodes, and every finding
   per node.

The **Cluster** filter of the top bar applies. *Running only* does not, because nodes are not images.
A role [limited to some clusters](rbac.md#clusters-of-a-role) only sees those.

## Roles and node groups

| Group | Taken from |
| --- | --- |
| Role | `control-plane` for the `node-role.kubernetes.io/control-plane` (or `master`) label, else the name of another `node-role.kubernetes.io/<role>` label (`ingress`, `gpu`…), else `worker` |
| Node group | The first label of `clusters.nodePoolLabels` found on the node: EKS node group, GKE node pool, AKS agent pool, Karpenter node pool, `node.kubernetes.io/pool` |

Managed control planes (EKS, GKE, AKS) have no node: only their API server version shows.

## Findings

What turns a node or a cluster orange or red:

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
