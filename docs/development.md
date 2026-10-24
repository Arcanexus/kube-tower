# Development

## Run locally

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r src/requirements.txt -r tests/requirements.txt

# Scans the cluster of your current kubeconfig context
cat > dev-config.yaml <<'YAML'
refreshInterval: 1h
logs: {level: DEBUG, format: custom}
YAML
KUBE_TOWER_CONFIG=dev-config.yaml PYTHONPATH=src \
  uvicorn --factory kube_tower.main:create_app --reload --port 8080
```

Without in-cluster credentials, kube-tower falls back to `~/.kube/config`. Cluster Secrets are
read from `clusters.namespace` (or `POD_NAMESPACE`, default `default`).

## Tests and coverage

```sh
pytest                              # tests + coverage (terminal, coverage.xml, htmlcov/)
ruff check src tests                # lint
ruff format src tests               # format
```

The build fails if coverage drops below the `fail_under` threshold of `pyproject.toml` (90%).
Tests never need a cluster or network access: Kubernetes APIs are mocked and HTTP calls are
intercepted with [respx](https://lundberg.github.io/respx/).

## Project layout

```
src/kube_tower/
  main.py              FastAPI app factory, background scan loop
  config.py            settings (config.yaml + env)
  models.py            data exchanged between collectors, checkers, the snapshot and the UI
  clusters.py          cluster discovery (in-cluster, Secrets, ArgoCD Secrets)
  collectors/          inventory: images.py (workloads, nodes), helm.py (ArgoCD Applications),
                       vulnerabilities.py (Trivy Operator VulnerabilityReports)
  trivy.py             vulnerability scans with the Trivy CLI
  registry/            oci.py (OCI distribution API), helm.py (Helm repos, OCI charts, git), auth.py
                       (credentials), cloud.py (ECR / Artifact Registry / ACR tokens), transport.py
                       (HTTP client, timeouts, retries)
  checkers.py          version comparison, one lookup per repository per scan
  versions.py          tag parsing and ordering
  scanner.py           full scan, rescans and in-memory snapshot
  administration.py       Administration page actions (Trivy database, connectivity tests, unused node images)
  errors.py            explicit error messages (what failed, status, what to do)
  logger.py            log formats; logbuffer.py keeps the last lines for the Logs page
  web/                 ui.py + templates/ (Jinja2, htmx), summary.py (Synthesis figures), api.py,
                       metrics.py, static/ (Pico CSS, htmx, kube-tower.css/.js, icons)
charts/kube-tower/     Helm chart
deploy/                manifests for remote clusters
docs/                  documentation and ADRs
```

### Adding a source

- New kind of workload or inventory (e.g. Flux `HelmRelease`): add a collector in `collectors/`
  returning `ImageReport` / `ChartReport` objects, and call it from `scanner.py`.
- New kind of registry: add a client in `registry/` and use it from `checkers.py`.
- New page: add a route in `web/ui.py`, a template in `web/templates/` extending `base.html`
  (title in `{% block heading %}`, content in `{% block content %}`), a link in the sidebar of
  `base.html` and its name in the sub-path redirect script of `base.html`. Links must stay
  relative (no leading `/`), see `test_links_are_relative`. Icons come from the sprite
  `static/icons.svg` ([Lucide](https://lucide.dev) icons, add a `<symbol id="i-name">` to use
  `icon("name")`).
- List page: add `{% block layout %}list-page{% endblock %}` and wrap the table in
  `<div class="overflow-auto table-wrap">`: only the table scrolls, its header stays. Add
  `data-sort` to the sortable `<th>` (`data-sort="desc"` to sort descending first) and, when the
  text of a cell does not sort well, a `data-sort` value on the `<td>` (`kube-tower.js` sorts).

## CI

| Workflow | When | What |
| --- | --- | --- |
| `tests.yml` | push on `main`, pull requests | ruff, pytest with coverage (summary + HTML artifact), helm lint/template; commits the coverage badge data (`.github/badges/coverage.json`) to `main` when it changes |
| `docker-publish.yml` | push on `main`, tags, pull requests | runs the tests, builds the multi-arch image, pushes it to ghcr.io except for pull requests |
| `helm-publish.yml` | tags | packages the chart with the tag version and pushes it to `oci://ghcr.io/arcanexus/charts` |

## Releasing

1. Merge the changes into `main`.
2. Push a semver tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. CI publishes `ghcr.io/arcanexus/kube-tower:0.2.0` (and `0.2`, `0`) and the chart `0.2.0`
   whose `appVersion` points to that image. The version shown by the UI comes from the tag
   (build argument `VERSION`, `dev` when run from the sources).

## Conventions

Pull request titles start with `[ADD]` or `[FIX]` and are written in English. Design decisions
are recorded as ADRs in `docs/adr/`.
