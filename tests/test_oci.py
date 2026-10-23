import base64
import json

import httpx
import pytest
import respx

from kube_tower.registry.oci import OCIClient, load_docker_credentials, parse_image_ref


@pytest.mark.parametrize(
    "image,expected",
    [
        ("nginx", "docker.io/library/nginx:latest"),
        ("bitnami/redis:7.2", "docker.io/bitnami/redis:7.2"),
        ("ghcr.io/org/app:v1@sha256:abc", "ghcr.io/org/app:v1@sha256:abc"),
        ("localhost:5000/app", "localhost:5000/app:latest"),
        ("index.docker.io/library/busybox:1.36", "docker.io/library/busybox:1.36"),
        ("quay.io/prometheus/node-exporter@sha256:abc", "quay.io/prometheus/node-exporter@sha256:abc"),
    ],
)
def test_parse_image_ref(image, expected):
    assert str(parse_image_ref(image)) == expected


def test_load_docker_credentials(tmp_path):
    cfg = tmp_path / "config.json"
    auth = base64.b64encode(b"user:pass").decode()
    cfg.write_text(
        json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": auth}, "ghcr.io": {"username": "u", "password": "p"}}})
    )
    assert load_docker_credentials(str(cfg)) == {"docker.io": ("user", "pass"), "ghcr.io": ("u", "p")}
    assert load_docker_credentials(str(tmp_path / "missing.json")) == {}


@respx.mock
async def test_list_tags_with_token_and_pagination():
    challenge = 'Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:app:pull"'
    tags = respx.get("https://registry.example.com/v2/app/tags/list?n=1000")
    tags.side_effect = [
        httpx.Response(401, headers={"www-authenticate": challenge}),
        httpx.Response(200, json={"tags": ["1.0"]}, headers={"link": '</v2/app/tags/list?n=1000&last=1.0>; rel="next"'}),
    ]
    respx.get("https://registry.example.com/v2/app/tags/list?n=1000&last=1.0").respond(200, json={"tags": ["1.1"]})
    token = respx.get("https://auth.example.com/token").respond(200, json={"token": "t0k"})
    async with httpx.AsyncClient() as http:
        assert await OCIClient(http).list_tags("registry.example.com", "app") == ["1.0", "1.1"]
    assert token.called
    assert tags.calls[-1].request.headers["authorization"] == "Bearer t0k"


@respx.mock
async def test_docker_hub_uses_api_host_and_digest():
    respx.head("https://registry-1.docker.io/v2/library/nginx/manifests/latest").respond(
        200, headers={"docker-content-digest": "sha256:123"}
    )
    async with httpx.AsyncClient() as http:
        assert await OCIClient(http).get_digest("docker.io", "library/nginx", "latest") == "sha256:123"
