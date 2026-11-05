# Clusters page

The nodes of every cluster, grouped by role and node group, with their Kubernetes versions and the
vulnerabilities of what they run. How to connect a cluster is in [clusters](clusters.md); their registration and
connectivity are in the Clusters tab of the [Administration](ui-administration.md#clusters). How
detail panels work in general is in [usage](usage.md).

![Clusters](images/clusters-page.png)

## One card per cluster

The card header gives the state of the cluster: *healthy* (green), *to check* (orange), *problem* (red)
or *unreachable* with the error of the last scan. Then, side by side:

| Block | Shows |
| --- | --- |
| **Ring** | The nodes split by kubelet version: green on the version of the API server, orange behind it, red unsupported. The number of nodes in the middle |
| **Versions** | The Kubernetes version of the API server, and each kubelet version with its number of nodes |
| **Vulnerabilities** | The critical, high and medium CVEs of the images the pods of the cluster run, each CVE counted once, with links to these images and to the outdated ones |

Under them:

- **Things to check** (open): kubelets behind or newer than the API server, nodes not ready, cordoned or
  under pressure, kubelet versions mixed across the nodes.
- **Differences between the nodes** (folded): OS images, container runtimes and kernels that are not
  the same on every node.

## One card per node

The nodes are grouped by role (Control plane, Workers, `ingress`…), then by node group. Each card shows:

- the **name**, with a warning or error icon when the node has a finding (hover the card to read them);
- the **kubelet version**, orange when behind the API server, red when unsupported;
- the **CVEs** of the images its pods run: critical, high and medium counts, *none*, *not scanned*, or
  *no pod*;
- the container runtime and the OS, and a bar of the pods it runs out of its maximum.

Its left border takes the colour of its worst finding. Click it for its details.

The **Cluster** filter of the top bar applies. *Running only* does not: the vulnerabilities are always
those of the images that pods run. A role [limited to some clusters](rbac.md#clusters-of-a-role) only
sees those.

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
instance type, zone and creation date. Below: the images its pods run, most vulnerable first, with
their status and CVEs; click one for its own details.

![A node](images/clusters-node.png)

## Where the data comes from

kube-tower reads the nodes (`list nodes`, already needed for the images they cache) at each scan, even
with `images.enabled: false`. Nothing else is asked from the clusters: no new permission.

The same data is exported as the `kube_tower_nodes` metric (see [metrics](metrics.md)).
