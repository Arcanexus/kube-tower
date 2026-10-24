import base64
import datetime as dt
import json
import time

import httpx
import pytest
import respx

from kube_tower.config import RegistriesSettings, RegistryCredential
from kube_tower.registry import cloud
from kube_tower.registry.auth import Credentials, TokenCache, resolve_credentials
from kube_tower.registry.cloud import (
    ACR_USER,
    AwsCredentials,
    AwsProvider,
    AzureProvider,
    GcpProvider,
    identity_status,
    jwt_expiry,
    make_provider,
    sigv4_headers,
)
from kube_tower.registry.oci import OCIClient, RegistryError

ECR = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"
CLOUD_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_AUTHORITY_HOST",
    "GCE_METADATA_HOST",
)


@pytest.fixture(autouse=True)
def no_cloud_identity(monkeypatch):
    for name in CLOUD_ENV:
        monkeypatch.delenv(name, raising=False)


def _ecr_token(user="AWS", password="ecr-pass", expires=None):
    return {
        "authorizationData": [
            {
                "authorizationToken": base64.b64encode(f"{user}:{password}".encode()).decode(),
                "expiresAt": expires or time.time() + 12 * 3600,
                "proxyEndpoint": f"https://{ECR}",
            }
        ]
    }


def test_sigv4_matches_botocore():
    """Signatures computed once with botocore's SigV4Auth for the same request and time."""
    now = dt.datetime(2026, 10, 24, 12, 0, 0, tzinfo=dt.UTC)
    url = "https://api.ecr.eu-west-1.amazonaws.com/"
    headers = {
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken",
    }
    key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    signed = sigv4_headers(AwsCredentials("AKIDEXAMPLE", key), "POST", url, "eu-west-1", "ecr", headers, b"{}", now)
    assert signed["x-amz-date"] == "20261024T120000Z"
    assert signed["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/eu-west-1/ecr/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-date;x-amz-target, "
        "Signature=cd57d037a402b58182e3d582d3ca1e01e311e54e444e5dfb09e252d107e42ea8"
    )
    signed = sigv4_headers(AwsCredentials("AKIDEXAMPLE", key, "SESSION"), "POST", url, "eu-west-1", "ecr", headers, b"{}", now)
    assert signed["x-amz-security-token"] == "SESSION"
    assert signed["authorization"].endswith("Signature=90d7f417fce03356b931854917712edeadcfeab0ebf2c5768fe915553e4e47c4")


def test_ecr_region():
    assert AwsProvider.region_of(ECR) == ("eu-west-1", "amazonaws.com", "api.ecr")
    assert AwsProvider.region_of("123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn") == (
        "cn-north-1",
        "amazonaws.com.cn",
        "api.ecr",
    )
    assert AwsProvider.region_of("123456789012.dkr.ecr-fips.us-east-1.amazonaws.com")[2] == "ecr-fips"
    with pytest.raises(RegistryError, match="not an Amazon ECR registry"):
        AwsProvider.region_of("public.ecr.aws")


@respx.mock
async def test_aws_static_keys(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    route = respx.post("https://api.ecr.eu-west-1.amazonaws.com/").respond(json=_ecr_token(expires=2000000000))
    pair, expires = await AwsProvider().fetch(ECR)
    assert pair == ("AWS", "ecr-pass") and expires == 2000000000
    request = route.calls.last.request
    assert request.headers["x-amz-target"].endswith("GetAuthorizationToken")
    assert request.headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKID/")


@respx.mock
async def test_aws_irsa(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("projected-sa-token\n")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token))
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/kube-tower")
    sts = respx.post("https://sts.eu-west-1.amazonaws.com/").respond(
        content=b"""<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <AssumeRoleWithWebIdentityResult><Credentials>
            <AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>tempsecret</SecretAccessKey>
            <SessionToken>session</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>
          </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"""
    )
    ecr = respx.post("https://api.ecr.eu-west-1.amazonaws.com/").respond(json=_ecr_token())
    provider = AwsProvider()
    assert (await provider.fetch(ECR))[0] == ("AWS", "ecr-pass")
    form = dict(httpx.QueryParams(sts.calls.last.request.content.decode()))
    assert form["WebIdentityToken"] == "projected-sa-token" and form["RoleArn"].endswith("role/kube-tower")
    assert ecr.calls.last.request.headers["x-amz-security-token"] == "session"
    # The role credentials are reused until they expire
    await provider.fetch(ECR)
    assert sts.call_count == 1 and ecr.call_count == 2

    sts.respond(403, json={"message": "Not authorized"})
    provider = AwsProvider()
    with pytest.raises(RegistryError, match="cannot assume the IAM role .*kube-tower \\(IRSA\\)"):
        await provider.fetch(ECR)
    sts.respond(200, content=b"<Other/>")
    with pytest.raises(RegistryError, match="no Credentials"):
        await provider.fetch(ECR)


@respx.mock
async def test_aws_pod_identity(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("pod-identity-token")
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.23/v1/credentials")
    monkeypatch.setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", str(token))
    agent = respx.get("http://169.254.170.23/v1/credentials").respond(
        json={"AccessKeyId": "ASIA", "SecretAccessKey": "s", "Token": "t", "Expiration": "2099-01-01T00:00:00Z"}
    )
    ecr = respx.post("https://api.ecr.eu-west-1.amazonaws.com/").respond(json=_ecr_token())
    assert (await AwsProvider().fetch(ECR))[0] == ("AWS", "ecr-pass")
    assert agent.calls.last.request.headers["authorization"] == "pod-identity-token"

    monkeypatch.delenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
    monkeypatch.setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "inline")
    agent.respond(500)
    with pytest.raises(RegistryError, match="EKS Pod Identity"):
        await AwsProvider().fetch(ECR)
    assert agent.calls.last.request.headers["authorization"] == "inline"

    agent.respond(json={"AccessKeyId": "ASIA", "SecretAccessKey": "s"})
    ecr.respond(400, json={"__type": "AccessDeniedException"})
    with pytest.raises(RegistryError, match="cannot get an Amazon ECR token .*ecr:GetAuthorizationToken"):
        await AwsProvider().fetch(ECR)


async def test_aws_without_identity():
    with pytest.raises(RegistryError, match="no AWS identity for provider aws"):
        await AwsProvider().fetch(ECR)


@respx.mock
async def test_gcp(monkeypatch):
    route = respx.get(cloud.GCP_METADATA_TOKEN).respond(json={"access_token": "ya29.token", "expires_in": 3599})
    pair, expires = await GcpProvider().fetch("europe-west1-docker.pkg.dev")
    assert pair == ("oauth2accesstoken", "ya29.token") and expires > time.time() + 3500
    assert route.calls.last.request.headers["metadata-flavor"] == "Google"

    monkeypatch.setenv("GCE_METADATA_HOST", "127.0.0.1:8080")
    respx.get("http://127.0.0.1:8080/computeMetadata/v1/instance/service-accounts/default/token").respond(404)
    with pytest.raises(RegistryError, match="cannot get a Google access token for gcr.io"):
        await GcpProvider().fetch("gcr.io")
    respx.get("http://127.0.0.1:8080/computeMetadata/v1/instance/service-accounts/default/token").mock(
        side_effect=httpx.ConnectError("unreachable")
    )
    with pytest.raises(RegistryError, match="cannot reach the GKE metadata server .*Workload Identity"):
        await GcpProvider().fetch("gcr.io")


def _jwt(claims: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{payload}.sig"


@respx.mock
async def test_azure(monkeypatch, tmp_path):
    with pytest.raises(RegistryError, match="no Azure identity"):
        await AzureProvider().fetch("myacr.azurecr.io")
    token = tmp_path / "token"
    token.write_text("federated")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(token))
    entra = respx.post("https://login.microsoftonline.com/tenant/oauth2/v2.0/token").respond(json={"access_token": "aad"})
    refresh = _jwt({"exp": 2000000000})
    exchange = respx.post("https://myacr.azurecr.io/oauth2/exchange").respond(json={"refresh_token": refresh})
    assert await AzureProvider().fetch("myacr.azurecr.io") == ((ACR_USER, refresh), 2000000000)
    assert dict(httpx.QueryParams(entra.calls.last.request.content.decode()))["client_assertion"] == "federated"
    assert dict(httpx.QueryParams(exchange.calls.last.request.content.decode()))["access_token"] == "aad"

    exchange.respond(401)
    with pytest.raises(RegistryError, match="myacr.azurecr.io refused to exchange"):
        await AzureProvider().fetch("myacr.azurecr.io")
    entra.respond(400)
    with pytest.raises(RegistryError, match="Entra ID token"):
        await AzureProvider().fetch("myacr.azurecr.io")


def test_jwt_expiry():
    assert jwt_expiry(_jwt({"exp": 123})) == 123
    assert jwt_expiry("not-a-jwt") is None
    assert jwt_expiry(_jwt({"sub": "x"})) is None


def test_make_provider_and_identity(monkeypatch):
    assert isinstance(make_provider("gcp"), GcpProvider)
    with pytest.raises(ValueError, match="unknown provider 'ibm'"):
        make_provider("ibm")
    assert identity_status("aws")[0] is False
    monkeypatch.setenv("AWS_ROLE_ARN", "arn")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/t")
    assert identity_status("aws") == (True, "token fetched when needed, identity: IRSA")
    assert identity_status("azure")[0] is False
    assert identity_status("gcp")[0] is True


class FakeProvider:
    name = "fake"

    def __init__(self, lifetime: float | None = 3600):
        self.lifetime = lifetime
        self.calls = 0

    async def fetch(self, registry):
        self.calls += 1
        return ("user", f"token-{self.calls}"), (time.time() + self.lifetime) if self.lifetime is not None else None


async def test_token_cache_reuses_and_renews():
    cache, provider = TokenCache(), FakeProvider()
    assert await cache.get(provider, ECR) == ("user", "token-1")
    assert await cache.get(provider, ECR) == ("user", "token-1")
    provider.lifetime = 60  # expires within the renewal margin: fetched again each time
    cache.tokens.clear()
    await cache.get(provider, ECR)
    assert await cache.get(provider, ECR) == ("user", "token-3")
    never = FakeProvider(lifetime=None)
    await cache.get(never, "x")
    await cache.get(never, "x")
    assert never.calls == 1


async def test_credentials_lookup_order():
    provider = FakeProvider()
    creds = Credentials(
        {"harbor.example.com": ("robot$ci", "pw")},
        {ECR: provider},
        [("*.dkr.ecr.*.amazonaws.com", ("pattern", "x")), ("*.example.com", ("wild", "card"))],
    )
    assert await creds.get(ECR) == ("user", "token-1")  # exact host first
    assert await creds.get("999999999999.dkr.ecr.us-east-1.amazonaws.com") == ("pattern", "x")
    assert await creds.get("Harbor.Example.com") == ("robot$ci", "pw")
    assert await creds.get("nexus.example.com") == ("wild", "card")
    assert await creds.get("ghcr.io") is None and "ghcr.io" not in creds
    assert list(creds) == [ECR, "harbor.example.com"]
    assert creds.describe() == [ECR, "harbor.example.com", "*.dkr.ecr.*.amazonaws.com", "*.example.com"]
    merged = creds.with_pull_secrets({"harbor.example.com": ("other", "x"), "quay.io": ("q", "p")})
    assert await merged.get("harbor.example.com") == ("robot$ci", "pw")  # configured credentials win
    assert await merged.get("quay.io") == ("q", "p")
    assert not Credentials()


def test_resolve_providers_and_patterns(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    (tmp_path / "pass").write_text("pw")
    docker = tmp_path / "config.json"
    docker.write_text(json.dumps({"auths": {ECR: {"auth": base64.b64encode(b"AWS:stale").decode()}}}))
    settings = RegistriesSettings(
        docker_config_path=str(docker),
        credentials=[
            RegistryCredential(ECR, provider="aws"),
            RegistryCredential("*.dkr.ecr.*.amazonaws.com", provider="aws"),
            RegistryCredential("*.azurecr.io", provider="azure"),
            RegistryCredential("*.jfrog.io", username="ci", password_file=str(tmp_path / "pass")),
            RegistryCredential("bad.example.com", provider="ibm"),
        ],
    )
    creds, statuses = resolve_credentials(settings, pull_secrets={"quay.io": ("q", "p")})
    assert ECR in creds.providers and ECR not in creds.static  # the provider replaces the docker config entry
    assert [p for p, _ in creds.patterns] == ["*.dkr.ecr.*.amazonaws.com", "*.azurecr.io", "*.jfrog.io"]
    assert creds.static["quay.io"] == ("q", "p")
    by_host = {s.registry: s for s in statuses}
    assert by_host[ECR].source == "aws" and by_host[ECR].ok and "AWS_ACCESS_KEY_ID" in by_host[ECR].message
    assert not by_host["*.azurecr.io"].ok and "AKS Workload Identity" in by_host["*.azurecr.io"].message
    assert by_host["*.jfrog.io"].username == "ci"
    assert not by_host["bad.example.com"].ok and "unknown provider" in by_host["bad.example.com"].message
    assert by_host["quay.io"].source == "image-pull-secret"


@respx.mock
async def test_oci_client_with_ecr_tokens(monkeypatch):
    """ECR answers with a basic challenge: the password is the token of ecr:GetAuthorizationToken."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    token = respx.post("https://api.ecr.eu-west-1.amazonaws.com/").respond(json=_ecr_token())
    expected = "Basic " + base64.b64encode(b"AWS:ecr-pass").decode()

    def tags(request):
        if request.headers.get("authorization") != expected:
            return httpx.Response(401, headers={"www-authenticate": f'Basic realm="https://{ECR}/",service="ecr.amazonaws.com"'})
        return httpx.Response(200, json={"tags": ["1.0", "1.1"]})

    respx.get(f"https://{ECR}/v2/team/app/tags/list").mock(side_effect=tags)
    creds, _ = resolve_credentials(
        RegistriesSettings(
            docker_config_path="/none", credentials=[RegistryCredential("*.dkr.ecr.*.amazonaws.com", provider="aws")]
        )
    )
    async with httpx.AsyncClient() as http:
        client = OCIClient(http, creds)
        assert await client.list_tags(ECR, "team/app") == ["1.0", "1.1"]
        assert await client.list_tags(ECR, "team/app") == ["1.0", "1.1"]
    assert token.call_count == 1  # the token is reused

    token.respond(400, json={})
    creds.tokens.tokens.clear()
    async with httpx.AsyncClient() as http:
        with pytest.raises(RegistryError, match="cannot get an Amazon ECR token"):
            await OCIClient(http, creds).list_tags(ECR, "team/app")
