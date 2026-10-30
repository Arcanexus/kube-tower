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
                       vulnerabilities.py (Trivy Operator VulnerabilityReports), security.py
                       (its config audit, exposed secrets, RBAC, infra and compliance reports)
  trivy.py             vulnerability scans with the Trivy CLI
  registry/            oci.py (OCI distribution API), helm.py (Helm repos, OCI charts, git), auth.py
                       (credentials), cloud.py (ECR / Artifact Registry / ACR tokens), transport.py
                       (HTTP client, timeouts, retries)
  checkers.py          version comparison, one lookup per repository per scan
  versions.py          tag parsing and ordering
  scanner.py           controller: schedules full scans and rescans, merges the task results into the snapshot
  tasks.py             tasks of a scan (collect a cluster, check versions, Trivy scan) and their results, JSON-ready
  worker.py            runs the tasks (worker and trivy roles), keeps registry tokens, Helm indexes, Trivy cache
  store.py             where the snapshot is kept (memory, or memory + Redis / Valkey)
  election.py          controller election with a Kubernetes Lease, active controller pod label
  processes.py         the processes (pods) known to the controller and their state (Administration page)
  bus.py               Valkey keys through which the processes of the distributed mode talk (ADR 0003)
  internal.py          exchanges of the distributed mode: task puller, publisher of the controller, reporter
  administration.py    Administration actions (Trivy database, connectivity tests, unused node images for the API)
  backend.py           Backend interface: all the web layer may use of the scans and the administration
  errors.py            explicit error messages (what failed, status, what to do)
  logger.py            log formats; logbuffer.py keeps the last lines for the Logs tab (of every pod on a controller)
  web/                 ui.py + templates/ (Jinja2, htmx), summary.py (Overview figures and To do list), api.py,
                       metrics.py, static/ (htmx, kube-tower.css/.js, icons; cached with asset())
charts/kube-tower/     Helm chart
deploy/                manifests for remote clusters
docs/                  documentation and ADRs, published to the wiki
.github/scripts/       docs_to_wiki.py (builds the wiki from docs/)
site/                  product website (plain HTML, CSS and JS), published on GitHub Pages
```

### Adding a source

- New kind of workload or inventory (e.g. Flux `HelmRelease`): add a collector in `collectors/`
  returning `ImageReport` / `ChartReport` objects, and call it from the collect task of `worker.py`.
  Tasks and results stay dataclasses of models, so they can be sent to another process as JSON
  (see `test_scan_tasks_survive_json` and `test_rescans_and_retry_are_tasks`): the scanner sends
  every task through its runner, it never calls a collector, a checker or Trivy itself.
- New kind of registry: add a client in `registry/` and use it from `checkers.py`.
- New page: add a route in `web/ui.py`, a template in `web/templates/` extending `base.html`
  (title in `{% block heading %}`, content in `{% block content %}`), a link in the sidebar of
  `base.html` and its name in the sub-path redirect script of `base.html`. Links must stay
  relative (no leading `/`), see `test_links_are_relative`. Icons come from the sprite
  `static/icons.svg` ([Lucide](https://lucide.dev) icons, add a `<symbol id="i-name">` to use
  `icon("name")`).
- Pages, API and metrics read and act through `request.app.state.backend` (`backend.py`), never
  the scanner or the administration directly (see `test_web_layer_only_talks_to_the_backend`): in the
  distributed mode of [ADR 0002](adr/0002-horizontal-scaling.md) the `ui` pods get a backend that asks
  the controller. Something new the web needs from the scans is added to the `Backend` interface.
- List page: add `{% block layout %}list-page{% endblock %}` and wrap the table in
  `<div class="overflow-auto table-wrap">`: only the table scrolls, its header stays. Add
  `data-sort` to the sortable `<th>` (`data-sort="desc"` to sort descending first) and, when the
  text of a cell does not sort well, a `data-sort` value on the `<td>` (`kube-tower.js` sorts).
- Navigation: the links of the pages are boosted by htmx (`hx-boost` on `<body>`): a click swaps the
  body instead of loading the page again, so code run at page load in `kube-tower.js` must also run on
  `htmx:afterSettle`, and an inline `<script>` of a page must not leave listeners behind (see `logs.html`).
- Static files: reference them with `asset("name")` (e.g. `{{ asset("kube-tower.css") }}`), which adds
  `?v=<hash of the static files>`: versioned URLs are cached by browsers for a year, the content hash
  changes them on every release. Responses are gzip compressed.
- Styles: one stylesheet, `kube-tower.css`, no CSS framework. Colours are tokens (`--kt-*` on `:root`),
  redefined for the dark theme in `[data-theme="dark"]` and in the `prefers-color-scheme: dark` block (keep
  both in sync); use them instead of fixed colours so both themes follow. Buttons take `.outline`,
  `.secondary` and `.small`, cards are `<article>` (with an optional `<header>`), switches are
  `<input type="checkbox" role="switch">`. Phones (`max-width: 768px`) get the bottom tab bar.
- Polling (while a scan, a rescan or an action runs): add `polling=1` to the URL and
  `[document.visibilityState=='visible']` to `every Ns` so hidden tabs do not poll. A poll swaps only when
  its response changed (`kube-tower.js`), and should target the smallest element that changes, never the
  buttons the user may be clicking.

## CI

| Workflow | When | What |
| --- | --- | --- |
| `tests.yml` | push on `main`, pull requests | ruff, pytest with coverage (summary + HTML artifact), helm lint/template; commits the coverage badge data (`.github/badges/coverage.json`) to `main` when it changes |
| `docker-publish.yml` | push on `main`, tags, pull requests | runs the tests, builds the multi-arch image, pushes it to ghcr.io except for pull requests |
| `helm-publish.yml` | tags | packages the chart with the tag version and pushes it to `oci://ghcr.io/arcanexus/charts` |
| `pages.yml` | push on `main` changing `site/`, `docs/images/` or the icons | publishes the product website on GitHub Pages: https://arcanexus.github.io/kube-tower/ |
| `wiki.yml` | push on `main` that changes `docs/` | publishes `docs/` to the [wiki](https://github.com/Arcanexus/kube-tower/wiki) |

## Documentation

The documentation is written in `docs/` (Markdown, images in `docs/images/`, ADRs in `docs/adr/`) and
changes in the same pull request as the code. After every merge to `main`, `wiki.yml` publishes it to
the [wiki](https://github.com/Arcanexus/kube-tower/wiki) with `.github/scripts/docs_to_wiki.py`:

- `docs/README.md` becomes the Home page, the other pages get the names listed in `PAGES` of the
  script, which also orders the sidebar (`_Sidebar.md`). ADRs are added on their own, named after
  their title.
- Links between pages and to images are written as usual relative links (`clusters.md#x`,
  `images/a.png`) and work both on GitHub and in the wiki. Links to other files of the repository
  (`../deploy/x.yaml`) become links to the `main` branch on GitHub.
- Each wiki page ends with a link to its source: never edit the wiki itself, the next publication
  replaces it.

A new page must be added to `PAGES`, else the tests (`tests/test_docs_to_wiki.py`) and the
publication fail. To preview the wiki locally:

```sh
python .github/scripts/docs_to_wiki.py docs /tmp/wiki && ls /tmp/wiki
```

The wiki must exist before the first publication: enable it (Settings > Features > Wikis) and save a
first page in the Wiki tab, then run the **Wiki** workflow (it also runs by hand, *Run workflow*).

## Product website

`site/` holds the website: `index.html`, `style.css` and `site.js`, no framework and no build step.
The workflow copies `docs/images/` into `images/` and the UI icon sprite into `icons.svg`, so the website
always shows the screenshots of the README: regenerate them and the website follows. To preview it:

```sh
mkdir -p /tmp/site && cp -r site/. /tmp/site/ && cp -r docs/images /tmp/site/images \
  && cp src/kube_tower/web/static/icons.svg /tmp/site/ && python -m http.server -d /tmp/site 8000
```

GitHub Pages must be enabled once with **Settings › Pages › Source: GitHub Actions**.

## Releasing

1. Merge the changes into `main`.
2. Push a semver tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. CI publishes `ghcr.io/arcanexus/kube-tower:0.2.0` (and `0.2`, `0`) and the chart `0.2.0`
   whose `appVersion` points to that image. The version shown by the UI comes from the tag
   (build argument `VERSION`, `dev` when run from the sources).

## Conventions

Pull request titles start with `[ADD]` or `[FIX]` and are written in English. Design decisions
are recorded as ADRs in `docs/adr/`.
