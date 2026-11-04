# Security (Trivy Operator reports)

The **Security** page (between Helm charts and Administration) shows the reports that
[Trivy Operator](https://aquasecurity.github.io/trivy-operator/) writes in the scanned clusters besides
the `VulnerabilityReports` (those are on the [Images](vulnerabilities.md) page), for every cluster at
once:

| Type | Trivy Operator reports (`aquasecurity.github.io/v1alpha1`) | What it checks |
| --- | --- | --- |
| **Config audit** | `ConfigAuditReport`, `ClusterConfigAuditReport` | Misconfigurations of workloads and cluster resources: privileged containers, root user, writable root file system, missing limits... |
| **Exposed secrets** | `ExposedSecretReport` | Secrets left in the images (cloud keys, tokens, private keys), with the file and the line found, the secret masked by Trivy |
| **RBAC** | `RbacAssessmentReport`, `ClusterRbacAssessmentReport` | Roles and ClusterRoles granting too much: wildcards, secrets access, privilege escalation... |
| **Infrastructure** | `InfraAssessmentReport`, `ClusterInfraAssessmentReport` | Nodes and control plane components (API server, kubelet, etcd flags) |
| **Compliance** | `ClusterComplianceReport` | CIS Kubernetes Benchmark, NSA hardening guide, Pod Security Standards: passed and failed controls |

kube-tower only reads these reports: it never runs the checks itself and never changes anything.
Clusters without Trivy Operator are simply skipped (the CRDs are not found). The reports are read at
each scan, like the rest of the inventory.

The [Security page](ui-security.md) shows them: tiles per type of report and compliance framework,
the list of resources with failed checks, and the detail of each check.

## Settings

```yaml
security:
  # Read the Trivy Operator security reports (Security page)
  enabled: true
  # Exposed secrets: the lines Trivy found, the secret masked; false to leave them out
  exposedSecrets: true
```

## Permissions

kube-tower needs `get` and `list` on the report CRDs: the chart's ClusterRole has them; on a
[remote cluster](clusters.md), apply [`deploy/remote-cluster-rbac.yaml`](../deploy/remote-cluster-rbac.yaml)
again (see [permissions](permissions.md#trivy-operator-reports)). A `403` on one of them is shown in the
scan errors (status pill) with the CRD that could not be listed; the other types are still shown.

## Metrics

`kube_tower_security_findings`, `kube_tower_security_resources` and `kube_tower_compliance_controls` give
the findings, the resources checked and the compliance controls per cluster: see
[metrics](metrics.md#security-trivy-operator).

## Not covered

- History and trends: kube-tower is stateless, it shows the reports as they are now. Use the metrics
  and Prometheus for trends.
- `SbomReports`: the software bill of materials of the images is not shown.
