"""Helm values, just enough to know which subcharts a release deploys (`condition` and `tags` of Chart.yaml)."""

from __future__ import annotations

import re

import yaml

from kube_tower.models import ChartDependency

_UNESCAPED_DOT = re.compile(r"(?<!\\)\.")


def merge(base: dict, override: dict) -> dict:
    """`override` over `base`, nested maps merged like Helm does (a null in `override` removes the key)."""
    result = dict(base)
    for key, value in override.items():
        if value is None:
            result.pop(key, None)
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = value
    return result


def booleans(values: dict) -> dict:
    """The boolean leaves of `values` only, with their maps: conditions and tags read nothing else."""
    result = {}
    for key, value in values.items():
        if isinstance(value, bool):
            result[key] = value
        elif isinstance(value, dict) and (nested := booleans(value)):
            result[key] = nested
    return result


def parse_values(text: str | None) -> dict:
    """A values document (`helm.values`, a values file); anything but a map is ignored like Helm does."""
    data = yaml.safe_load(text or "")
    return data if isinstance(data, dict) else {}


def parameters_values(parameters: list[dict]) -> dict:
    """`helm.parameters` (`--set name=value`) as values. Only the booleans are kept (see `booleans`),
    list indexes (`a[0].b`) are skipped: a condition never points into a list.
    """
    result: dict = {}
    for p in parameters or []:
        name, value = str(p.get("name", "")), str(p.get("value", ""))
        if not name or "[" in name or p.get("forceString") or value.lower() not in ("true", "false"):
            continue
        *parents, leaf = [part.replace("\\.", ".") for part in _UNESCAPED_DOT.split(name)]
        node = result
        for part in parents:
            if not isinstance(node.get(part), dict):
                node[part] = {}
            node = node[part]
        node[leaf] = value.lower() == "true"
    return result


def application_values(helm: dict) -> dict:
    """The booleans of the inline values of an Application helm source, in ArgoCD's order of precedence:
    `values`, then `valuesObject` (which replaces `values` when both are set), then `parameters`.
    """
    inline = helm.get("valuesObject") if isinstance(helm.get("valuesObject"), dict) else parse_values(helm.get("values"))
    return merge(booleans(inline), parameters_values(helm.get("parameters") or []))


def _lookup(values: dict, path: str):
    node = values
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def not_deployed(dep: ChartDependency, values: dict, tags: dict) -> str | None:
    """Why Helm leaves `dep` out of a release with these `values` (of its parent chart), None if deployed.

    Same rules as Helm: the first path of `condition` that holds a boolean decides; without one, the
    `tags` of the dependency decide (left out only when one is false and none is true); else deployed.
    """
    for path in filter(None, (p.strip() for p in dep.condition.split(","))):
        value = _lookup(values, path)
        if isinstance(value, bool):
            return None if value else f"{path} is false"
    states = {tag: tags[tag] for tag in dep.tags if isinstance(tags.get(tag), bool)}
    if states and not any(states.values()):
        return f"tags.{', tags.'.join(states)} false"
    return None


def subchart_values(dep: ChartDependency, parent: dict, defaults: dict) -> dict:
    """The values a subchart gets: its own defaults, overridden by the parent's `<alias or name>:` block,
    and the parent's `global:` block.
    """
    values = merge(defaults, parent.get(dep.alias or dep.name) or {})
    if isinstance(parent.get("global"), dict):
        values["global"] = merge(values.get("global") or {}, parent["global"])
    return values
