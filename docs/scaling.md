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

See [architecture](architecture.md) for the diagrams, [ADR 0002](adr/0002-horizontal-scaling.md) and
[ADR 0003](adr/0003-valkey-bus.md) for the design.

```
       ui (×N) ◄─── Ingress / Service
          ▲  state, actions, logs
          ▼
   Valkey (required) ◄──► controller (1 active, standbys) ◄─── Prometheus (/metrics)
          ▲  tasks, results, presence, logs
   ┌──────┴────────────┐
worker (×N)        trivy (×1)
```

The pods never call each other: every exchange goes through Valkey, and only the active controller
orchestrates ([ADR 0003](adr/0003-valkey-bus.md)).

## Distributed mode

```yaml
mode: distributed
# Required: the pods talk through Valkey (or an existing Redis, see below)
redis:
  valkey:
    enabled: true
  password: <a password>    # or existingSecret: the tasks carry registry credentials
```

This renders four Deployments, `<release>-controller`, `-ui`, `-worker` and `-trivy`:

- the **controller** runs with 2 replicas: the active one holds a Kubernetes `Lease` and labels its
  pod `kube-tower.arcanexus.com/active-controller=true`; the other waits and takes over about 15
  seconds after the active one stopped. Both pods are ready (`helm --wait` and the ArgoCD health
  checks pass), the `<release>-controller` Service selects the labelled one for the ServiceMonitor
  (`/metrics`). The active controller queues the tasks in Valkey, reads their results, publishes the
  state that the ui pods show and runs their actions. Rollouts
  replace one controller pod at a time (`maxUnavailable: 1`, `maxSurge: 0`);
- the **ui** pods serve the pages through the usual Service and Ingress, from the state published in
  Valkey (read again when its revision changes). They get no ServiceAccount token, no registry
  credential nor git token;
- the **worker** pods read the collection and version check tasks from Valkey, where the controller
  queues them, and send their results back there;
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
        minReplicas: 1
        maxReplicas: 4
        targetCPUUtilizationPercentage: 80   # of the CPU request (100m by default)
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

A pod with `ui` and `controller` that is a standby shows no inventory: such pods use `/leaderz` as
readiness probe, so the UI Service skips the standby (which then stays not ready: `helm --wait` and
ArgoCD wait for it). To scale the pages, run `ui` in a group of its own.

Every pod writes every 5 seconds a key in Valkey that expires unless written again (standby
controllers too), and ships its log lines there: the **Administration** page shows the state of each
role and pod, and the **Logs** page gathers the lines of every pod, filtered by role (see
[usage](usage.md#administration)).

The scans are split in batches of `config.internal.batchSize` images or charts (50) shared by the
worker and trivy pods. A task that is not answered within `config.internal.taskTimeout` (30m) is given
to another pod, e.g. when a worker was stopped in the middle of it, three times at most.

### Network policies

With `networkPolicy.enabled`, the kube-tower pods reach Valkey, which accepts the kube-tower pods only.
The tasks carry registry credentials (image pull secrets): a Valkey password is recommended
(`redis.password` or `redis.existingSecret`).

### Sizing

Measured with an inventory of 141 images (about 400 vulnerabilities each) and 51 charts, one CPU core:

| Request | CPU per request |
| --- | --- |
| Overview | about 22 ms |
| Clusters tab, Images filtered by CVE | 14 to 18 ms |
| Images, Helm charts, Administration, detail panels | 4 to 7 ms |
| `/api/snapshot` (whole inventory as JSON, built in a thread) | about 530 ms |

A user navigating loads a page every few seconds: **one ui pod serves about 10 users** with a few
tens of millicores. An idle ui pod uses about 5m of CPU and 150Mi of memory (it reads the revision of
the state every second, the state when it changed, and decodes the inventory again when it has a new
revision); an idle worker about 3m. The defaults follow: `ui` 1 replica, 100m CPU and 192Mi requested; `worker` 2 replicas,
100m CPU and 256Mi requested.

The autoscaling target is a share of the CPU **request**: with a request far below what a pod uses
when it starts or serves a page, the HorizontalPodAutoscaler adds pods at every page load and removes
them minutes later. The default `autoscaling.behavior` damps it: one pod more per minute at most,
after 2 minutes above the target; pods removed after 5 minutes below it. Workers mostly wait for the
registries, so their CPU says little about the work queued: a fixed number of workers is usually the
better choice, autoscaling them helps with many clusters scanned often.

## Redis / Valkey

The distributed mode requires it: the pods talk through it. In both modes, the controller also keeps
a copy of the inventory there: a restarted controller, or a standby taking over, shows it at once,
then waits for the rest of `refreshInterval` before the next scan. Without it (single mode only), a
restarted controller starts with an empty inventory and scans first.

```yaml
redis:
  # A Valkey deployed by the chart (one pod, data in memory)...
  valkey:
    enabled: true
  # ...or an existing Redis / Valkey
  url: rediss://my-redis.example:6380/0
  existingSecret: kube-tower-redis   # optional password, key: password
  keyPrefix: ""                      # prefix of the keys (empty: the release name)
```

In single mode only the controller connects to it; in distributed mode every pod does. The chart's
Valkey keeps its data in memory: it survives a controller restart, not its own. A scan in progress
is never kept: a new controller empties the task queues of the previous one and starts a new scan
when one is due. Several installations can share one Redis: each uses its own `keyPrefix` (and
`config.redis.key` for the snapshot).

### From 1.0.0-rc.3

Up to rc.3 the pods talked over an internal API of the controller (port 8081) with a shared token. From
rc.4 they talk through Valkey only:

1. keep (or set) `redis.valkey.enabled: true`, or `redis.url`: the chart refuses to render without one;
2. remove `distributed.internal` from your values (ignored, the chart notes say so), then delete the
   Secret of the token (and its ExternalSecret);
3. sync: during the rollout, the pods of rc.3 lose the controller for less than a minute, the time the
   new ones replace them. The inventory kept in Valkey is shown at once.

## With ArgoCD

One pod per role and the chart's Valkey, its password in a Secret created beforehand (or synced by
ExternalSecrets like the registry credentials):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kube-tower
  namespace: argocd
spec:
  destination:
    name: in-cluster
    namespace: kube-tower
  project: default
  source:
    repoURL: ghcr.io/arcanexus/charts
    chart: kube-tower
    targetRevision: 1.0.0-rc.4
    helm:
      valuesObject:
        mode: distributed
        distributed:
          groups:
            controller:
              replicas: 1   # 2: a standby takes over in about 15 s if the active one stops
            ui:
              replicas: 1
            worker:
              replicas: 1
        redis:
          valkey:
            enabled: true
          existingSecret: kube-tower-valkey   # key: password
        config:
          clusters:
            useArgocdSecrets: true
        ingress:
          enabled: true
          hosts:
            - host: kube-tower.example.com
              paths:
                - path: /
                  pathType: Prefix
        serviceMonitor:
          enabled: true   # scrapes the active controller
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

Every pod becomes ready (standby controllers too), so ArgoCD shows the Application healthy once the
pods started. See [installation](installation.md#with-argocd) for the other values (registry
credentials, TLS, authentication middleware).

## Permissions

The pods running `controller` or `worker` (and `trivy`, for the cloud identities of
[registries](registries.md)) use the ServiceAccount of the chart, with the usual
[permissions](installation.md#permissions), plus `create` on `leases`, `get` / `update` on the
`<release>-controller` Lease and `patch` on the pods of the release namespace (the active controller
labels its own pod) in distributed mode.
