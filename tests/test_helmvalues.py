from kube_tower.helmvalues import (
    application_values,
    booleans,
    merge,
    not_deployed,
    parameters_values,
    subchart_values,
)
from kube_tower.models import ChartDependency


def test_merge_like_helm():
    base = {"redis": {"enabled": True, "auth": {"enabled": True}}, "replicas": 1, "keep": "x"}
    assert merge(base, {"redis": {"auth": {"enabled": False}}, "replicas": 2, "keep": None}) == {
        "redis": {"enabled": True, "auth": {"enabled": False}},
        "replicas": 2,
    }
    assert base["redis"]["auth"]["enabled"] is True  # not modified


def test_booleans_only():
    assert booleans({"a": {"enabled": True, "password": "secret", "b": {"c": "x"}}, "d": False, "e": [True]}) == {
        "a": {"enabled": True},
        "d": False,
    }


def test_parameters_values():
    params = [
        {"name": "redis.enabled", "value": "false"},
        {"name": "a\\.b.enabled", "value": "True"},
        {"name": "image.tag", "value": "1.0"},  # not a boolean
        {"name": "x.enabled", "value": "true", "forceString": True},
        {"name": "list[0].enabled", "value": "true"},
        {"name": "", "value": "true"},
    ]
    assert parameters_values(params) == {"redis": {"enabled": False}, "a.b": {"enabled": True}}


def test_application_values_precedence():
    helm = {
        "values": "redis:\n  enabled: true\nignored: true\n",
        "parameters": [{"name": "redis.enabled", "value": "false"}],
    }
    assert application_values(helm) == {"redis": {"enabled": False}, "ignored": True}
    # valuesObject replaces values
    assert application_values({"values": "a: true", "valuesObject": {"b": False, "token": "s3cr3t"}}) == {"b": False}
    assert application_values({"values": "- not a map"}) == {}
    assert application_values({}) == {}


def test_not_deployed_condition_and_tags():
    dep = ChartDependency("bitwarden-sdk-server", "v0.6.0", "oci://x", condition="bitwarden-sdk-server.enabled")
    assert not_deployed(dep, {"bitwarden-sdk-server": {"enabled": False}}, {}) == "bitwarden-sdk-server.enabled is false"
    assert not_deployed(dep, {"bitwarden-sdk-server": {"enabled": True}}, {}) is None
    assert not_deployed(dep, {}, {}) is None  # no value: deployed

    # the first path holding a boolean decides, other values are skipped
    dep = ChartDependency("redis", "1.0.0", "x", condition="redis.enabled, global.redis.enabled", tags=["cache"])
    assert not_deployed(dep, {"redis": {"enabled": "yes"}, "global": {"redis": {"enabled": False}}}, {}) == (
        "global.redis.enabled is false"
    )
    assert not_deployed(dep, {"redis": {"enabled": True}}, {"cache": False}) is None  # condition before tags

    # tags: left out when one is false and none is true
    dep = ChartDependency("redis", "1.0.0", "x", tags=["cache", "db"])
    assert not_deployed(dep, {}, {"cache": False}) == "tags.cache false"
    assert not_deployed(dep, {}, {"cache": False, "db": False}) == "tags.cache, tags.db false"
    assert not_deployed(dep, {}, {"cache": False, "db": True}) is None
    assert not_deployed(dep, {}, {"cache": "no"}) is None


def test_subchart_values():
    dep = ChartDependency("redis", "1.0.0", "x", alias="cache")
    parent = {"cache": {"replica": {"enabled": False}}, "redis": {"ignored": True}, "global": {"x": True}}
    defaults = {"replica": {"enabled": True}, "sentinel": {"enabled": False}, "global": {"y": True}}
    assert subchart_values(dep, parent, defaults) == {
        "replica": {"enabled": False},
        "sentinel": {"enabled": False},
        "global": {"y": True, "x": True},
    }
    assert subchart_values(ChartDependency("redis", "1.0.0", "x"), {}, defaults) == defaults
