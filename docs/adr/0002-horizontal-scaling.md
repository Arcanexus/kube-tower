# ADR 0002: horizontal scaling with roles

- Status: accepted (design), implementation planned for the next major release
- Date: 2026-10-24 (updated 2026-10-26: separate `trivy` role, roles combined per pod)

## Context

kube-tower runs as one process: the UI, the API, the scheduler, the scans and the Trivy scans share
the in-memory `Snapshot` of `scanner.py`. Several replicas of that pod would each scan on their own
and show different results. The maintainer wants the same image to run as separate roles (UI, scans...)
that work together, so each part scales on its own.

## Decision

One image. Each process runs a set of roles, chosen with `roles:` in the configuration or
`KUBE_TOWER_ROLES` (comma-separated). The roles combine freely: `all` (the default) runs every role in
one pod, as today; a deployment can also put each role in its own pods and scale them independently,
or group some of them (e.g. `ui,controller` in one pod, `worker,trivy` in another).

| Role | Replicas when apart | Does | Kubernetes rights | Registry credentials |
| --- | --- | --- | --- | --- |
| `ui` | 1..N | pages, JSON API, `/metrics`; reads the snapshot from the controller, forwards actions | none | no |
| `controller` | 1 active + standby (`Lease`) | schedules scans and rescans, holds the snapshot and the task queue, merges results | cluster Secrets, `Lease` | no |
| `worker` | 1..N (HPA) | pulls tasks: collect one cluster, check a batch of images / charts | read the clusters | yes |
| `trivy` | 1..N (HPA) | pulls vulnerability tasks: scan a batch of images with the Trivy CLI | none (Trivy Operator reports are read by `worker` with the cluster) | yes |

Trivy runs in its own role: it is the heavy part (CPU, memory, a database of about 1.6 GB, minutes per
image) while version checks are many light HTTP requests. Apart, each scales and is sized on its own,
only the `trivy` pods get the Trivy binary (chart init container) and its cache, and slow scans never
hold back the version checks. Tasks carry their kind; each role pulls only its own kinds. The optional
Trivy server of the chart stays: the `trivy` pods then run as its clients and share its database.

Shared state, chosen by the maintainer:

- **Default: in the controller's memory**, served to the other roles over an internal HTTP API
  (separate port, never exposed by the Ingress, shared token, NetworkPolicies). Workers pull their
  tasks. No database: a restarted controller rebuilds the snapshot with a scan, as today.
- **Optional: Redis / Valkey**, enabled in the chart values, for a snapshot and task queue that survive
  a controller restart.
- Rejected: Kubernetes objects (ConfigMap / CRD) for the snapshot: etcd limits an object to 1 MiB and
  a snapshot with vulnerabilities outgrows it; frequent writes load the API server.

The snapshot store and the task queue are therefore an interface with two implementations (memory,
Redis). Roles in the same process talk in memory, without the internal API; roles in other pods go
through it. A pod running the controller role with several replicas has one active controller (the
`Lease` holder); the others stand by, while their other roles (e.g. `ui`) keep serving.

The chart gets `mode: single | distributed`: `single` renders today's Deployment (every role)
unchanged; `distributed` renders one Deployment per group of roles listed in the values, each with
its replicas, resources and HPA.

## Consequences

- `roles: [all]` stays the default: small installs see no change.
- The UI pods, the ones exposed to users, lose every Kubernetes right and registry credential.
- The `ui` role keeps no session state: the login and SSO planned later (#108, ArgoCD-like local
  admin + OIDC) will use signed tokens, so any `ui` replica serves any request.
- Snapshot metrics are exported by the controller only (no duplicated series).
- The Logs page shows the controller's lines; workers send the warnings and errors of each task back
  with its result.

## Steps

1. `roles` setting (only every role together accepted until the roles can run apart) and `Snapshot.from_dict`
   (JSON round trip of the snapshot, needed to send it between processes).
2. The web layer talks to a backend interface instead of the `Scanner` internals.
3. The scan split in serializable tasks (`tasks.py`: collect a cluster, check images, check charts,
   scan with Trivy), run by the `Worker` of the process (`worker.py`); `SnapshotStore` (`store.py`).
   The collect results carry the credentials of image pull secrets: the internal API sends them to
   the controller and from it to the workers, never outside (token, NetworkPolicies).
   The rescans of an image or chart and the retry of failed items are tasks too (a collect task can
   read only the images of one name, or only the Trivy Operator reports; a Trivy task can skip the cache).
4. Internal API, `ui` / `controller` / `worker` / `trivy` roles in any combination, `Lease` election, Redis option.
   Done so far: the internal API of the controller (`internal.py`, its own port, Bearer token) and the
   `QueueRunner`, which queues the tasks of the roles that run elsewhere; `worker` and `trivy`
   processes pull them (`TaskPuller`) with the credentials of image pull secrets as context. The
   version checks and Trivy scans are split in batches (`internal.batchSize`) shared by the processes;
   a Trivy process refreshes its databases at most every 10 minutes and forgets the results too old to
   be used (a batch cannot tell which images are gone). Next: a `ui` asking a remote controller, the
   administration actions and logs of the remote roles, `Lease` election.
5. Chart `mode: distributed`, documentation, release candidate.
