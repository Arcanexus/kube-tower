# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Inventory of container images from Pods, Deployments, StatefulSets, DaemonSets, CronJobs and nodes.
- Version check against the source registry (OCI distribution API), with tag shape matching and
  digest check for floating tags.
- Helm charts and subcharts deployed by ArgoCD Applications (Helm repositories, OCI, git paths).
- Multi-cluster support with ArgoCD-style cluster Secrets, optional reuse of ArgoCD cluster Secrets.
- Per registry credentials for container registries and Helm repositories.
- Web UI (Images, Helm charts, Clusters, Settings), JSON API and Prometheus metrics.
- Helm chart, multi-arch image (amd64, arm64, arm/v7), CI with coverage.
- Documentation: complete ArgoCD `Application` example (OCI chart, ingress, ArgoCD clusters, registry credentials).
- Helm chart: cluster, registry (per registry and dockerconfigjson) and git credentials can be
  created by the chart from the values or taken from existing Secrets; existing cluster Secrets
  are referenced by name (`clusters[].existingSecret`, new `clusters.secretNames` setting).
- Helm chart rendering tests.

### Changed

- License changed from GPL-3.0 to Apache-2.0.
