# Scaling

By default kube-tower runs as one pod that does everything (`mode: single`). For large inventories,
or to keep the UI available while a scan uses the CPU, the chart can split it in several Deployments
that work together (`mode: distributed`). The image is the same: each pod runs some of the four
**roles**.

| Role | Does | Replicas | Kubernetes access |
| --- | --- | --- | --- |
| `ui` | Pages, JSON API; shows the state of the controller, sends it the actions of the users | any, autoscaling | none |
| `controller` | Schedules scans and rescans, holds the inventory and the task queue, serves `/metrics` | 1 active + standbys | cluster Secrets, its `Lease` |
| `worker` | Collects the clusters, checks the versions in registries and Helm repositories | any, autoscaling | read-only ClusterRole, cluster Secrets |
| `trivy` | Scans the images with Trivy, keeps the Trivy databases and results | always 1 | none needed |

See [ADR 0002](adr/0002-horizontal-scaling.md) for the design.

```
                ┌──────── ui (×N) ◄─── Ingress / Service
                │  state, actions
                ▼
          controller (1 active, standbys) ◄─── Prometheus (/metrics)
         ▲  tasks / results  ▲         └──► Redis / Valkey (optional)
         │                   │
    worker (×N)          trivy (×1)
```

## Distributed mode

```yaml
mode: distributed
distributed:
  internal:
    # Token shared by the pods (required): an existing Secret, or `token` inline
    existingSecret: kube-tower-internal     # key: token
```

```sh
kubectl -n kube-tower create secret generic kube-tower-internal --from-literal=token="$(openssl rand -hex 32)"
```

This renders four Deployments, `<release>-controller`, `-ui`, `-worker` and `-trivy`:

- the **controller** runs with 2 replicas: the active one holds a Kubernetes `Lease` and is the only
  ready one, so the Services route to it; the other waits and takes over about 15 seconds after the
  active one stopped. Its readiness probe is `/leaderz`. Its internal API (`distributed.internal.port`,
  8081) is reached through the `<release>-internal` Service, which also serves `/metrics` to the
  ServiceMonitor;
- the **ui** pods serve the pages through the usual Service and Ingress. They get no ServiceAccount
  token, no registry credential nor git token;
- the **worker** pods pull the collection and version check tasks from the controller;
- the **trivy** pod scans the images: one replica only, whatever the values, so the Trivy databases
  are downloaded once and the results cache is shared by every cluster.

Each group has its own `replicas`, `resources`, `nodeSelector`, `tolerations` and `affinity` (the
top-level ones by default), and `autoscaling` for groups without the controller or trivy roles:

```yaml
distributed:
  groups:
    ui:
      autoscaling:
        enabled: true
        minReplicas: 2
        maxReplicas: 5
        targetCPUUtilizationPercentage: 80
    worker:
      replicas: 4
      resources:
        limits:
          memory: 1Gi
```

The groups are free: a group runs the roles listed in `roles` (`all` for every one). Every role must
run in a group, `controller` and `trivy` in one group only. Set a group to `null` to remove it, e.g.
to run the UI with the controller:

```yaml
distributed:
  groups:
    controller:
      roles: [controller, ui]
    ui: null
```

A pod with `ui` and `controller` that is a standby shows no inventory: it is not ready either. To
scale the pages, run `ui` in a group of its own.

The scans are split in batches of `config.internal.batchSize` images or charts (50) shared by the
worker and trivy pods. A task that is not answered within `config.internal.taskTimeout` (30m) is given
to another pod, e.g. when a worker was stopped in the middle of it.

### Network policies

With `networkPolicy.enabled`, the kube-tower pods also accept the internal port from each other only,
and reach it and Valkey. The internal API carries registry credentials: never expose it.

## Keeping the inventory across restarts (Redis / Valkey)

The controller keeps the inventory in memory: a restarted controller, or a standby taking over,
starts with an empty one and scans first. With Redis or Valkey it keeps a copy there and shows it at
once, then waits for the rest of `refreshInterval` before the next scan. This works in both modes.

```yaml
redis:
  # A Valkey deployed by the chart (one pod, data in memory)...
  valkey:
    enabled: true
  # ...or an existing Redis / Valkey
  url: rediss://my-redis.example:6380/0
  existingSecret: kube-tower-redis   # optional password, key: password
```

Only the controller connects to it. The chart's Valkey keeps its data in memory: it survives a
controller restart, not its own. A scan in progress is never kept: a new controller starts a new one
when one is due.

## Permissions

The pods running `controller` or `worker` (and `trivy`, for the cloud identities of
[registries](registries.md)) use the ServiceAccount of the chart, with the usual
[permissions](installation.md#permissions), plus `create` on `leases` and `get` / `update` on the
`<release>-controller` Lease of the release namespace in distributed mode.
