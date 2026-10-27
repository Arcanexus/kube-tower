# ADR 0003: the processes talk through Valkey

- Status: accepted, implemented for v1.0.0-rc.4
- Date: 2026-10-27
- Replaces the transport part of [ADR 0002](0002-horizontal-scaling.md) (the internal HTTP API)

## Context

In the distributed mode of ADR 0002, every process reaches the active controller over its internal
HTTP API (port 8081, shared token): worker and trivy pods pull their tasks and send their results,
`ui` pods read the whole state every 2 seconds and send the actions of the users, and every pod
reports its presence and its log lines. Valkey only keeps the snapshot.

This has costs: every pod depends on a Service that follows the active controller, the task queue is
lost with the controller, every `ui` pod copies the whole state every 2 seconds even when nothing
changed, and the installation manages a token besides the Valkey password. Valkey is already needed
as soon as more than one pod runs.

The maintainer asked that every exchange between roles goes through Valkey, and that the controller
manages them.

## Decision

- **Valkey is required in the distributed mode.** The single mode does not change: every role runs in
  one process and talks in memory, Valkey stays optional there (it keeps the snapshot).
- **The processes only know the address of Valkey.** None of them calls the controller; the internal
  HTTP API, its port, its Service and its token go away.
- **Only the active controller orchestrates.** It writes the tasks and the state; the other processes
  only write their results, the actions of the users, their presence and their log lines.

| Keys (after `redis.keyPrefix`) | Valkey type | Written by | Read by |
| --- | --- | --- | --- |
| `tasks:worker`, `tasks:trivy` | stream + consumer group | controller | worker, trivy |
| `results` | stream + consumer group | worker, trivy | controller |
| `actions`, `reply:<id>` | stream + consumer group, list with a TTL | ui / controller | controller / ui |
| `state`, `state:snapshot`, `state:rev` | strings + counter | controller | ui |
| `pods:<name>` | string with a TTL | every process | controller |
| `logs` | capped stream | every process | ui |

- A task read by a process and never acknowledged stays pending in its group: when the key of that
  process expired, or the task is older than `internal.taskTimeout`, the controller adds it again
  (three attempts at most).
- Each task carries the epoch of the controller that queued it: a controller taking over drops the
  tasks and results of another epoch, reads the snapshot and starts a scan, as before.
- The election of the controller stays on the Kubernetes `Lease`: it is not an exchange between roles.

## Consequences

- The tasks survive a restart of a worker or trivy pod; a `ui` pod reads the state again only when its
  revision changed.
- The task context (registry credentials of image pull secrets) goes through Valkey: messages are
  deleted once acknowledged, a Valkey password is recommended, and the chart NetworkPolicy keeps
  Valkey to the kube-tower pods.
- When Valkey cannot be reached, the processes try again with growing delays and the `ui` pods show
  their last copy of the state.
- A `ui` pod reads the revision every second, the state when it changed, and the snapshot only when
  its own revision changed. The controller publishes at most every 2 seconds, and at once after an
  action so that the page shows what the action started.
- Implemented in steps: the bus (`bus.py`), the tasks, then the state, actions, presence and logs with
  the removal of the internal API (port, Service, token) from the code and the chart.
