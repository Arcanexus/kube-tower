# Helm charts page

One line per chart deployed by an ArgoCD Application (one per Helm source of a multi-source Application),
a Flux HelmRelease or the helm command (see [where charts are found](chart-sources.md)), with the chart
and all its subcharts. How lists and detail panels work in general is in
[usage](usage.md).

![Helm charts](images/charts.png)

## The list

| Column | Meaning |
| --- | --- |
| Chart | Chart name |
| Current | Version deployed, with its release date |
| Latest minor/patch | Latest version of the same major version (`18.0.0` → `18.4.2`), with its release date. The current version when there is no newer one |
| Latest major | When a newer major version is published: the latest version (`20.1.0`), with its release date; `—` when there is none |
| Status | The chart and its subcharts as **one tree** (3 levels), each with its version (→ latest when behind) and its status |
| Repository | Where the chart comes from, and its type (`helm`, `oci`, `git`) |
| Deployed by | *ArgoCD Application*, *Flux HelmRelease* or *Helm release*, its name, cluster and destination namespace |

- **Release dates** come from `created` in the `index.yaml` of the repository, or the
  `org.opencontainers.image.created` annotation of an OCI chart (pushed with Helm 3.15 or later); off with
  `helm.fetchReleaseDates: false`. They are **colored by their age** like on the
  [Images page](ui-images.md#release-dates-and-their-age): green under 6 months, yellow under a year, orange
  under 2 years, red beyond (`images.releaseAgeDays`). An old deployed version is due for an update; an old
  latest version may mean a chart that is no longer maintained.
- The *Latest minor/patch* and *Latest major* columns **sort by release date**, oldest first, then newest
  first; the charts without a date come last.
- A chart up to date with an outdated subchart says how many subcharts are behind, and counts as
  `outdated` in the chips and the sort.
- **Search** by chart, Application, HelmRelease, release or repository (`flux`, `helm release` find them all).
- **Chips**: the version status (worst of the chart and its subcharts), and the **Update** chips:
  *minor/patch* lists the charts with a newer version in their major version (the safe update), *major*
  those with a newer major version. A chart can be in both. Only the chart itself counts, not its subcharts.
- How each kind of source is compared: [statuses and versions](statuses.md#helm-charts).

## Subcharts not deployed

A subchart that the Helm values of the release leave out is shown **not deployed**,
with the reason (e.g. `bitwarden-sdk-server.enabled is false`):

- its version is still compared, but it does not count in the status of the chart, the chips, the sort,
  the metrics or the scan errors; its own subcharts are not read;
- kube-tower evaluates the `condition` and `tags` of each dependency like Helm does, with the values
  ArgoCD renders the chart with: `values.yaml` of the chart, then the `valueFiles` of the Application
  (also from git, or a `$ref` source, read through `git.rawUrlTemplates`), then `values` /
  `valuesObject` and `parameters`;
- a value file that cannot be read (private git without `git.token`...) gives a warning, and every
  subchart then counts as deployed;
- a Flux HelmRelease uses its `spec.values` (not `valuesFrom`), a Helm release the values it was
  installed with;
- only the booleans of the inline values are kept, the other values can hold secrets.

## Detail panel

The **Check versions** [rescan](usage.md#rescan-one-image-or-chart) button sits at the top, next to the
full screen and close buttons. Then the current, latest minor/patch and latest major versions, each with
its release date colored by its age, the subchart tree with the repository of each subchart, the source
with links to the repository and Artifact Hub (for a Helm release, the repository found in
`helm.repositories` or on Artifact Hub), and the ArgoCD Application, Flux HelmRelease or Helm release.

![Chart details](images/chart-detail.png)
