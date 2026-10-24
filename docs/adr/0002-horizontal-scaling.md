# ADR 0002: horizontal scaling with roles

- Status: accepted (design), implementation planned for the next major release
- Date: 2026-10-24

## Context

kube-tower runs as one process: the UI, the API, the scheduler, the scans and the Trivy scans share
the in-memory `Snapshot` of `scanner.py`. Several replicas of that pod would each scan on their own
and show different results. The maintainer wants the same image to run as separate roles (UI, scans...)
that work together, so each part scales on its own.

## Decision

One image, one role per process, chosen with `KUBE_TOWER_ROLE` or `role:` in the configuration:

| Role | Replicas | Does | Kubernetes rights | Registry credentials |
| --- | --- | --- | --- | --- |
| `all` (default) | 1 | everything, as today | yes | yes |
| `ui` | 1..N | pages, JSON API, `/metrics`; reads the snapshot from the controller, forwards actions | none | no |
| `controller` | 1 active + standby (`Lease`) | schedules scans and rescans, holds the snapshot and the task queue, merges results | cluster Secrets, `Lease` | no |
| `worker` | 1..N (HPA) | pulls tasks: collect one cluster, check a batch of images / charts, scan a batch with Trivy | read the clusters | yes |

Shared state, chosen by the maintainer:

- **Default: in the controller's memory**, served to the other roles over an internal HTTP API
  (separate port, never exposed by the Ingress, shared token, NetworkPolicies). Workers pull their
  tasks. No database: a restarted controller rebuilds the snapshot with a scan, as today.
- **Optional: Redis / Valkey**, enabled in the chart values, for a snapshot and task queue that survive
  a controller restart.
- Rejected: Kubernetes objects (ConfigMap / CRD) for the snapshot: etcd limits an object to 1 MiB and
  a snapshot with vulnerabilities outgrows it; frequent writes load the API server.

The snapshot store and the task queue are therefore an interface with two implementations (memory,
Redis). The chart gets `mode: single | distributed`; `single` renders today's Deployment unchanged.

## Consequences

- `role: all` stays the default: small installs see no change.
- The UI pods, the ones exposed to users, lose every Kubernetes right and registry credential.
- Snapshot metrics are exported by the controller only (no duplicated series).
- The Logs page shows the controller's lines; workers send the warnings and errors of each task back
  with its result.

## Steps

1. `role` setting (only `all` accepted until the other roles exist) and `Snapshot.from_dict`
   (JSON round trip of the snapshot, needed to send it between processes).
2. The web layer talks to a backend interface instead of the `Scanner` internals.
3. The scan split in serializable tasks, run locally by `all`.
4. Internal API, `ui` / `controller` / `worker` roles, `Lease` election, Redis option.
5. Chart `mode: distributed`, documentation, release candidate.
