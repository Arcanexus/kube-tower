import base64
import json

import httpx
import pytest
import respx

from kube_tower.registry.oci import OCIClient, RegistryError, load_docker_credentials, parse_image_ref


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


@respx.mock
async def test_registry_errors_and_basic_auth():
    respx.get("https://private.example.com/v2/app/tags/list?n=1000").mock(
        side_effect=[
            httpx.Response(401, headers={"www-authenticate": 'Basic realm="x"'}),
            httpx.Response(200, json={"tags": None}),
        ]
    )
    respx.get("https://denied.example.com/v2/app/tags/list?n=1000").respond(
        401, headers={"www-authenticate": 'Bearer realm="https://denied.example.com/token",service="x"'}
    )
    respx.get("https://denied.example.com/token").respond(403)
    respx.head("https://private.example.com/v2/app/manifests/missing").respond(404)
    respx.get("https://private.example.com/v2/app/blobs/sha256:x").respond(404)
    respx.get("https://private.example.com/v2/app/manifests/x").respond(404)
    async with httpx.AsyncClient() as http:
        oci = OCIClient(http, {"private.example.com": ("u", "p")}, mirrors={"docker.io": "mirror.example.com"})
        assert await oci.list_tags("private.example.com", "app") == []
        assert oci._api_host("docker.io") == "mirror.example.com"
        with pytest.raises(
            RegistryError, match="cannot get a pull token for denied.example.com: HTTP 403 Forbidden - access denied"
        ):
            await oci.list_tags("denied.example.com", "app")
        with pytest.raises(RegistryError, match="cannot read the digest of private.example.com/app:missing"):
            await oci.get_digest("private.example.com", "app", "missing")
        with pytest.raises(RegistryError, match="cannot download private.example.com/app@sha256:x"):
            await oci.get_blob("private.example.com", "app", "sha256:x")
        with pytest.raises(RegistryError, match="cannot read the manifest of private.example.com/app:x"):
            await oci.get_manifest("private.example.com", "app", "x", "application/json")


@respx.mock
async def test_registry_redirect_authenticates_against_the_target():
    # registry.k8s.io redirects to a regional Artifact Registry, which asks for its own token
    respx.get("https://registry.k8s.io/v2/sig-storage/nfsplugin/tags/list?n=1000").respond(
        307,
        headers={"Location": "https://europe-docker.pkg.dev/v2/k8s-artifacts-prod/images/sig-storage/nfsplugin/tags/list?n=1000"},
    )
    target = respx.get("https://europe-docker.pkg.dev/v2/k8s-artifacts-prod/images/sig-storage/nfsplugin/tags/list?n=1000")
    target.side_effect = [
        httpx.Response(
            401,
            headers={
                "www-authenticate": 'Bearer realm="https://europe-docker.pkg.dev/v2/token",'
                'scope="repository:k8s-artifacts-prod/images/sig-storage/nfsplugin:pull"'
            },
        ),
        httpx.Response(200, json={"tags": ["v4.11.0", "v4.13.0"]}),
    ]
    token = respx.get("https://europe-docker.pkg.dev/v2/token").respond(200, json={"token": "t"})
    async with httpx.AsyncClient() as http:
        assert await OCIClient(http).list_tags("registry.k8s.io", "sig-storage/nfsplugin") == ["v4.11.0", "v4.13.0"]
    assert token.calls[0].request.url.params["scope"] == "repository:k8s-artifacts-prod/images/sig-storage/nfsplugin:pull"
    assert target.calls[1].request.headers["authorization"] == "Bearer t"


@respx.mock
async def test_too_many_redirects():
    respx.get("https://loop.example.com/v2/app/tags/list?n=1000").respond(
        302, headers={"Location": "https://loop.example.com/v2/app/tags/list?n=1000"}
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(RegistryError, match="too many redirects"):
            await OCIClient(http).list_tags("loop.example.com", "app")


@respx.mock
async def test_ping():
    respx.get("https://open.example.com/v2/").respond(200)
    challenge = 'Bearer realm="https://auth.example.com/token",service="bearer.example.com"'
    respx.get("https://bearer.example.com/v2/").respond(401, headers={"www-authenticate": challenge})
    token = respx.get("https://auth.example.com/token").respond(200, json={"token": "t"})
    basic = respx.get("https://basic.example.com/v2/")
    basic.side_effect = lambda request: httpx.Response(
        200 if "authorization" in request.headers else 401, headers={"www-authenticate": 'Basic realm="r"'}
    )
    respx.get("https://down.example.com/v2/").respond(503)
    async with httpx.AsyncClient() as http:
        client = OCIClient(http, {"bearer.example.com": ("u", "p"), "basic.example.com": ("u", "p")})
        assert await client.ping("open.example.com") == "answers anonymously"
        assert await client.ping("bearer.example.com") == "token obtained with credentials"
        assert "scope" not in token.calls[-1].request.url.params
        assert token.calls[-1].request.headers["authorization"].startswith("Basic ")
        assert await client.ping("bearer.example.com", "org/app") == "pull token for org/app obtained with credentials"
        assert token.calls[-1].request.url.params["scope"] == "repository:org/app:pull"
        assert await client.ping("basic.example.com") == "answers with credentials"
        with pytest.raises(RegistryError, match="requires credentials and none are configured"):
            await OCIClient(http).ping("basic.example.com")
        with pytest.raises(RegistryError, match="down.example.com refused the connection test: HTTP 503"):
            await client.ping("down.example.com")
