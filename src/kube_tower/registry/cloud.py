"""Short-lived registry credentials from the cloud identity of the pod.

Managed registries prefer (or only accept) tokens that live a few hours: Amazon ECR, Google
Artifact Registry / Container Registry, Azure Container Registry. Each provider here gets one
from the identity Kubernetes gives the pod (IRSA or EKS Pod Identity, GKE Workload Identity, AKS
Workload Identity), so no long-lived secret has to be stored. Tokens are cached by `Credentials`
(auth.py) and fetched again shortly before they expire.

No cloud SDK is needed: these are a few documented HTTP calls (AWS requests are signed with
Signature Version 4 below).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree

import httpx

from kube_tower.errors import http_error_message
from kube_tower.registry.oci import RegistryError

Pair = tuple[str, str]
# A client for the identity and token services, closed after each fetch (tokens are fetched a few times a day).
HttpFactory = Callable[[], httpx.AsyncClient]

PROVIDERS = ("aws", "gcp", "azure")


def default_http() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10, headers={"User-Agent": "kube-tower"})


def _expiry_of(timestamp: str | float | None) -> float | None:
    """`2026-10-24T20:00:00Z` or epoch seconds -> epoch seconds."""
    if timestamp is None:
        return None
    if isinstance(timestamp, int | float):
        return float(timestamp)
    return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


# --- AWS --------------------------------------------------------------------------------------------

ECR_HOST_RE = re.compile(r"^(\d{12})\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.(amazonaws\.com(?:\.cn)?)$")


@dataclass
class AwsCredentials:
    access_key: str
    secret_key: str
    session_token: str = ""
    expires_at: float | None = None


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_headers(
    creds: AwsCredentials,
    method: str,
    url: str,
    region: str,
    service: str,
    headers: dict[str, str],
    body: bytes,
    now: dt.datetime,
) -> dict[str, str]:
    """The headers of an AWS request signed with Signature Version 4 (a request without query string)."""
    parsed = httpx.URL(url)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    signed = {k.lower(): v.strip() for k, v in headers.items()}
    signed["host"] = parsed.netloc.decode()
    signed["x-amz-date"] = amz_date
    if creds.session_token:
        signed["x-amz-security-token"] = creds.session_token
    names = sorted(signed)
    canonical = "\n".join(
        [
            method,
            quote(parsed.path or "/", safe="/-_.~"),
            "",
            "".join(f"{name}:{signed[name]}\n" for name in names),
            ";".join(names),
            hashlib.sha256(body).hexdigest(),
        ]
    )
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{creds.secret_key}".encode(), day), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    auth = f"AWS4-HMAC-SHA256 Credential={creds.access_key}/{scope}, SignedHeaders={';'.join(names)}, Signature={signature}"
    return {**{k: v for k, v in signed.items() if k != "host"}, "authorization": auth}


def aws_identity() -> str | None:
    """Which AWS identity the pod has, in the order of the AWS SDKs, or None."""
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return "AWS_ACCESS_KEY_ID"
    if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") and os.environ.get("AWS_ROLE_ARN"):
        return "IRSA"
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        return "EKS Pod Identity"
    return None


class AwsProvider:
    """Amazon ECR: an authorization token (12 hours) from ecr:GetAuthorizationToken, used as the
    password of the `AWS` user, like `aws ecr get-login-password` does.

    The AWS credentials come from, in this order: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, IRSA
    (AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE) or EKS Pod Identity (AWS_CONTAINER_CREDENTIALS_FULL_URI).
    The IAM role needs ecr:GetAuthorizationToken, plus ecr:ListImages/DescribeImages/BatchGetImage/
    GetDownloadUrlForLayer on the repositories (AmazonEC2ContainerRegistryReadOnly).
    """

    name = "aws"

    def __init__(self, http: HttpFactory = default_http):
        self.http = http
        self._aws: AwsCredentials | None = None

    @staticmethod
    def region_of(registry: str) -> tuple[str, str, str]:
        """`123456789012.dkr.ecr.eu-west-1.amazonaws.com` -> (region, API domain, endpoint prefix)."""
        match = ECR_HOST_RE.match(registry)
        if not match:
            raise RegistryError(
                f"{registry} is not an Amazon ECR registry (<account>.dkr.ecr.<region>.amazonaws.com): "
                "provider aws only applies to ECR registries"
            )
        return match[3], match[4], "ecr-fips" if match[2] else "api.ecr"

    async def _aws_credentials(self, http: httpx.AsyncClient, region: str, domain: str) -> AwsCredentials:
        if self._aws and (self._aws.expires_at is None or self._aws.expires_at - 300 > time.time()):
            return self._aws
        env = os.environ
        identity = aws_identity()
        if identity == "AWS_ACCESS_KEY_ID":
            creds = AwsCredentials(env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"], env.get("AWS_SESSION_TOKEN", ""))
        elif identity == "IRSA":
            creds = await self._assume_role(http, region, domain)
        elif identity == "EKS Pod Identity":
            creds = await self._container_credentials(http)
        else:
            raise RegistryError(
                "no AWS identity for provider aws: give the kube-tower ServiceAccount an IAM role (IRSA annotation "
                "eks.amazonaws.com/role-arn or an EKS Pod Identity association), or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY"
            )
        self._aws = creds
        return creds

    async def _assume_role(self, http: httpx.AsyncClient, region: str, domain: str) -> AwsCredentials:
        # AssumeRoleWithWebIdentity is not signed: the projected ServiceAccount token is the proof.
        token = Path(os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"]).read_text().strip()
        resp = await http.post(
            f"https://sts.{region}.{domain}/",
            data={
                "Action": "AssumeRoleWithWebIdentity",
                "Version": "2011-06-15",
                "RoleArn": os.environ["AWS_ROLE_ARN"],
                "RoleSessionName": os.environ.get("AWS_ROLE_SESSION_NAME", "kube-tower"),
                "WebIdentityToken": token,
            },
        )
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot assume the IAM role {os.environ['AWS_ROLE_ARN']} (IRSA)", resp))
        ns = {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"}
        node = ElementTree.fromstring(resp.content).find(".//sts:Credentials", ns)
        if node is None:
            raise RegistryError("unexpected answer of AWS STS AssumeRoleWithWebIdentity: no Credentials")

        def text(tag: str) -> str:
            return node.findtext(f"sts:{tag}", "", ns)

        return AwsCredentials(text("AccessKeyId"), text("SecretAccessKey"), text("SessionToken"), _expiry_of(text("Expiration")))

    async def _container_credentials(self, http: httpx.AsyncClient) -> AwsCredentials:
        headers = {}
        if token_file := os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"):
            headers["Authorization"] = Path(token_file).read_text().strip()
        elif token := os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN"):
            headers["Authorization"] = token
        resp = await http.get(os.environ["AWS_CONTAINER_CREDENTIALS_FULL_URI"], headers=headers)
        if resp.status_code != 200:
            raise RegistryError(http_error_message("cannot get the AWS credentials of the pod (EKS Pod Identity)", resp))
        body = resp.json()
        return AwsCredentials(
            body["AccessKeyId"], body["SecretAccessKey"], body.get("Token", ""), _expiry_of(body.get("Expiration"))
        )

    async def fetch(self, registry: str) -> tuple[Pair, float | None]:
        region, domain, prefix = self.region_of(registry)
        async with self.http() as http:
            creds = await self._aws_credentials(http, region, domain)
            url = f"https://{prefix}.{region}.{domain}/"
            body = b"{}"
            headers = {
                "content-type": "application/x-amz-json-1.1",
                "x-amz-target": "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken",
            }
            signed = sigv4_headers(creds, "POST", url, region, "ecr", headers, body, dt.datetime.now(dt.UTC))
            resp = await http.post(url, content=body, headers=signed)
        if resp.status_code != 200:
            self._aws = None  # e.g. expired session: ask again next time
            raise RegistryError(
                http_error_message(f"cannot get an Amazon ECR token for {registry} (ecr:GetAuthorizationToken)", resp)
            )
        data = resp.json()["authorizationData"][0]
        user, _, password = base64.b64decode(data["authorizationToken"]).decode().partition(":")
        return (user, password), _expiry_of(data.get("expiresAt"))


# --- Google Cloud -----------------------------------------------------------------------------------

GCP_METADATA_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"


class GcpProvider:
    """Google Artifact Registry (*-docker.pkg.dev) and Container Registry (*gcr.io): the OAuth2 access
    token (1 hour) of the pod's Google service account, from the GKE metadata server (Workload Identity),
    used as the password of the `oauth2accesstoken` user. The service account needs
    roles/artifactregistry.reader.
    """

    name = "gcp"

    def __init__(self, http: HttpFactory = default_http):
        self.http = http

    async def fetch(self, registry: str) -> tuple[Pair, float | None]:
        url = os.environ.get("GCE_METADATA_HOST")
        url = f"http://{url}/computeMetadata/v1/instance/service-accounts/default/token" if url else GCP_METADATA_TOKEN
        try:
            async with self.http() as http:
                resp = await http.get(url, headers={"Metadata-Flavor": "Google"})
        except httpx.HTTPError as exc:
            raise RegistryError(
                f"cannot reach the GKE metadata server for a token for {registry} ({exc.__class__.__name__}): "
                "provider gcp needs GKE Workload Identity (or a GCE node)"
            ) from exc
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot get a Google access token for {registry}", resp))
        body = resp.json()
        return ("oauth2accesstoken", body["access_token"]), time.time() + int(body.get("expires_in", 3600))


# --- Azure ------------------------------------------------------------------------------------------

ACR_USER = "00000000-0000-0000-0000-000000000000"  # the user of ACR refresh tokens, as `az acr login` uses
AZURE_SCOPE = "https://management.azure.com/.default"


def azure_identity() -> bool:
    return all(os.environ.get(v) for v in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE"))


def jwt_expiry(token: str) -> float | None:
    """The `exp` claim of a JWT (not verified: only to know when to renew it)."""
    try:
        payload = token.split(".")[1]
        return float(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"])
    except (IndexError, ValueError, KeyError, TypeError):
        return None


class AzureProvider:
    """Azure Container Registry (*.azurecr.io): an Entra ID token of the pod's managed identity (AKS
    Workload Identity), exchanged for an ACR refresh token (3 hours), like `az acr login` does. The
    identity needs the AcrPull role (or Container Registry Repository Reader) on the registry.
    """

    name = "azure"

    def __init__(self, http: HttpFactory = default_http):
        self.http = http

    async def fetch(self, registry: str) -> tuple[Pair, float | None]:
        if not azure_identity():
            raise RegistryError(
                "no Azure identity for provider azure: enable AKS Workload Identity for the kube-tower ServiceAccount "
                '(annotation azure.workload.identity/client-id and pod label azure.workload.identity/use: "true")'
            )
        env = os.environ
        authority = env.get("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com/").rstrip("/")
        async with self.http() as http:
            resp = await http.post(
                f"{authority}/{env['AZURE_TENANT_ID']}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": env["AZURE_CLIENT_ID"],
                    "scope": AZURE_SCOPE,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": Path(env["AZURE_FEDERATED_TOKEN_FILE"]).read_text().strip(),
                },
            )
            if resp.status_code != 200:
                raise RegistryError(http_error_message("cannot get an Entra ID token (AKS Workload Identity)", resp))
            resp = await http.post(
                f"https://{registry}/oauth2/exchange",
                data={
                    "grant_type": "access_token",
                    "service": registry,
                    "tenant": env["AZURE_TENANT_ID"],
                    "access_token": resp.json()["access_token"],
                },
            )
        if resp.status_code != 200:
            raise RegistryError(
                http_error_message(f"{registry} refused to exchange the Entra ID token for a refresh token", resp)
            )
        refresh = resp.json()["refresh_token"]
        return (ACR_USER, refresh), jwt_expiry(refresh)


def make_provider(name: str, http: HttpFactory = default_http) -> AwsProvider | GcpProvider | AzureProvider:
    if name == "aws":
        return AwsProvider(http)
    if name == "gcp":
        return GcpProvider(http)
    if name == "azure":
        return AzureProvider(http)
    raise ValueError(f"unknown provider {name!r}: use static (default), {', '.join(PROVIDERS)}")


def identity_status(name: str) -> tuple[bool, str]:
    """Whether the pod has the identity a provider needs, for the Settings page (the token itself is fetched when needed)."""
    if name == "aws":
        identity = aws_identity()
        return (
            (True, f"token fetched when needed, identity: {identity}")
            if identity
            else (False, "no AWS identity (IRSA, EKS Pod Identity or AWS_ACCESS_KEY_ID)")
        )
    if name == "azure":
        return (
            (True, "token fetched when needed, identity: AKS Workload Identity")
            if azure_identity()
            else (
                False,
                "no Azure identity (AKS Workload Identity: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE)",
            )
        )
    return True, "token fetched when needed from the GKE metadata server"
