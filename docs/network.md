# Network and ports

What kube-tower listens on, what it connects to, and how the chart restricts both with
NetworkPolicies.

## Ports and endpoints

| Port | Served by | Paths |
| --- | --- | --- |
| `8080` (`http`) | every pod | pages, `/api/...`, `/metrics` (controller), `/healthz`, `/readyz`, `/leaderz` |
| `6379` | Valkey | Redis protocol: every pod in distributed mode, the controller only in single mode |
| `5556` | Dex (`dex.enabled`) | Dex, reached only by the pods with the `ui` role, which serve it on `/api/dex/` |

No other port: the pods never call each other. The tasks carry registry credentials (image pull
secrets) through Valkey: set a Valkey password. With `networkPolicy.enabled`, only the kube-tower pods
reach Valkey.

| Path | Use |
| --- | --- |
| `/healthz` | liveness probe |
| `/readyz` | readiness probe: 200 once the first scan has finished (a standby controller answers 503) |
| `/leaderz` | 200 on the active controller only (distributed mode) |
| `/metrics` | Prometheus metrics of the last scan (controller), see [metrics](metrics.md) |
| `/api/...` | JSON API, see [API](api.md) |

## Outbound connections

kube-tower connects, in `https://` only when credentials are involved:

- to the Kubernetes API servers of the scanned clusters (usually port `443` or `6443`);
- to the registries of the images and of the OCI Helm charts, the HTTP Helm repositories, and the git
  hosts of the charts read from git (raw files, e.g. `raw.githubusercontent.com`);
- for the vulnerability scans in standalone mode, to the Trivy database registries (`mirror.gcr.io`,
  `ghcr.io`), see [vulnerabilities](vulnerabilities.md);
- with a cloud `provider` of [registries](registries.md), to the token services of the cloud (and the GKE
  metadata server `169.254.169.254:80`);
- to the OIDC provider with single sign-on, see [authentication](authentication.md);
- from the controller, once per scan, to `endoflife.date` and `api.osv.dev` for the end of life and the
  vulnerabilities of the Kubernetes and containerd versions (`kubernetesVersions`, see the
  [Clusters page](ui-clusters.md#where-the-data-comes-from)).

The browser of the user, not kube-tower, asks GitHub for the latest release on the About page.

## Network policies

`networkPolicy.enabled: true` restricts the network of the kube-tower pod (and of the Trivy server)
with NetworkPolicies, enforced by CNIs such as Calico or Cilium:

- **Ingress**: only the `http` port of kube-tower, from `networkPolicy.ingress.from` (any pod when
  empty). The Trivy server only accepts kube-tower.
- **Egress**: DNS, the Trivy server, and `networkPolicy.egress.ports` (`443` and `6443`) towards
  `networkPolicy.egress.to` (anywhere when empty). kube-tower reaches the Kubernetes API servers, the
  registries, the Helm repositories, the git hosts and, in standalone mode, the Trivy database
  registries. Add the ports of registries or API servers that use other ones, or rules of your own
  with `networkPolicy.egress.extra`.

```yaml
networkPolicy:
  enabled: true
  ingress:
    from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: monitoring      # Prometheus scraping /metrics
  egress:
    ports:
      - port: 443
        protocol: TCP
      - port: 6443
        protocol: TCP
      - port: 5000                                       # a private registry on port 5000
        protocol: TCP
```

### Distributed mode

With `networkPolicy.enabled`, the kube-tower pods reach Valkey, which accepts the kube-tower pods only.
The tasks carry registry credentials (image pull secrets): a Valkey password is recommended
(`redis.password` or `redis.existingSecret`).
