# Registries

kube-tower talks to registries with the standard OCI distribution API (`/v2/`): any registry that
Kubernetes can pull from works, public or private. The same credentials are used for the version
checks (tag lists, digests), the OCI Helm charts and the Trivy scans.

This page lists how to authenticate to each kind of registry. The options themselves are described
in [configuration](configuration.md#registry-authentication).

## Which method for which registry

| Registry | Image names | Authentication |
| --- | --- | --- |
| Docker Hub | `nginx`, `bitnami/redis`, `docker.io/...` | Anonymous works, but is rate limited: add a username and an [access token](https://docs.docker.com/security/for-developers/access-tokens/) |
| GitHub (ghcr.io), GitLab, Quay, Codeberg... | `ghcr.io/org/app` | Anonymous for public images, a token (PAT, deploy token, robot account) for private ones |
| Amazon ECR | `<account>.dkr.ecr.<region>.amazonaws.com/app` | `provider: aws`: the IAM role of the pod (IRSA or EKS Pod Identity), see [below](#amazon-ecr) |
| Amazon ECR Public | `public.ecr.aws/...` | Anonymous |
| Google Artifact Registry / Container Registry | `<region>-docker.pkg.dev/...`, `gcr.io/...` | `provider: gcp`: GKE Workload Identity, or a service account JSON key, see [below](#google-artifact-registry) |
| Azure Container Registry | `<name>.azurecr.io/app` | `provider: azure`: AKS Workload Identity, or a service principal / token, see [below](#azure-container-registry) |
| Harbor | `harbor.example.com/<project>/app` | A [robot account](https://goharbor.io/docs/main/working-with-projects/project-configuration/create-robot-accounts/) (username `robot$name`) with pull access |
| JFrog Artifactory | `<host>/<repository-key>/app` or `<repository-key>.<host>/app` | A user and an identity token (or API key); both repository path and subdomain methods work |
| Sonatype Nexus | `nexus.example.com:8443/app` | A user and its password; the port of the Docker connector is part of the host |
| Self-hosted `registry:2`, Zot, Gitea... | `registry.example.com/app` | Basic auth or token, as configured |
| Any of the above in the clusters' image pull secrets | | `registries.useImagePullSecrets: true`, see [below](#reusing-the-image-pull-secrets) |

Internal registries with a private CA or no TLS at all: see [TLS](#tls-private-cas-and-insecure-registries).

## Static credentials

A username and a password or token, from a Secret mounted by the chart (or a docker `config.json`).
`registry` is a host, or an fnmatch pattern of hosts:

```yaml
registries:
  credentials:
    - registry: harbor.example.com
      existingSecret: harbor-robot        # keys: username, password
      usernameKey: username
    - registry: "*.jfrog.io"              # every host matching the pattern
      existingSecret: artifactory-token
      usernameKey: username
```

Exact hosts are looked up first (per registry entries, then the docker `config.json`, then the
image pull secrets), then the patterns in their order.

## Cloud registries: tokens from the identity of the pod

Managed registries prefer short-lived tokens. With `provider`, kube-tower gets them from the
identity Kubernetes gives the pod, like the kubelet credential providers do: no long-lived secret
to store and rotate. Tokens are fetched when first needed, kept in memory, and fetched again 15
minutes before they expire. No cloud SDK is involved: only a few HTTPS requests.

The Settings page shows each provider and whether the pod has the identity it needs; the
connectivity test of the Maintenance page gets a real token.

### Amazon ECR

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/kube-tower   # IRSA
registries:
  credentials:
    - registry: "*.dkr.ecr.*.amazonaws.com"   # or one registry: 123456789012.dkr.ecr.eu-west-1.amazonaws.com
      provider: aws
```

- The IAM role needs the `AmazonEC2ContainerRegistryReadOnly` managed policy (or
  `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`,
  `ecr:ListImages`, `ecr:DescribeImages`). For registries of other accounts, their repository
  policy must allow the role.
- AWS credentials are looked up like the AWS SDKs do: `AWS_ACCESS_KEY_ID` /
  `AWS_SECRET_ACCESS_KEY` (`extraEnv`), then IRSA (`AWS_ROLE_ARN` +
  `AWS_WEB_IDENTITY_TOKEN_FILE`, set by EKS from the annotation above), then EKS Pod Identity
  (`AWS_CONTAINER_CREDENTIALS_FULL_URI`, set by EKS for an association of the ServiceAccount).
- The ECR token is valid 12 hours, for every registry of its region; China regions and FIPS
  endpoints (`dkr.ecr-fips`) work too.
- ECR pull through cache repositories (`<account>.dkr.ecr.<region>.amazonaws.com/docker-hub/library/nginx`)
  are regular ECR repositories: their tags are those already pulled through the cache.
- NetworkPolicy: allow `sts.<region>.amazonaws.com` and `api.ecr.<region>.amazonaws.com` (port
  443, open by default) and, for EKS Pod Identity, `169.254.170.23` port 80 (`networkPolicy.egress.extra`).

### Google Artifact Registry

```yaml
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: kube-tower@my-project.iam.gserviceaccount.com
registries:
  credentials:
    - registry: "*-docker.pkg.dev"    # Artifact Registry
      provider: gcp
    - registry: "*gcr.io"             # Container Registry (gcr.io, eu.gcr.io...)
      provider: gcp
```

- The token is the OAuth2 access token (1 hour) of the Google service account bound with GKE
  Workload Identity, read from the GKE metadata server. With direct Workload Identity Federation
  (no Google service account), grant the Kubernetes ServiceAccount itself the role instead.
- Role: `roles/artifactregistry.reader` on the repositories.
- Outside GKE, use a service account JSON key as static credentials: username `_json_key`,
  password the content of the key file.
- NetworkPolicy: allow the GKE metadata server, `169.254.169.254` port 80 (`networkPolicy.egress.extra`).

### Azure Container Registry

```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000   # managed identity
podLabels:
  azure.workload.identity/use: "true"
registries:
  credentials:
    - registry: "*.azurecr.io"
      provider: azure
```

- AKS Workload Identity injects `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and
  `AZURE_FEDERATED_TOKEN_FILE`: kube-tower exchanges the federated token for an Entra ID token,
  then for an ACR refresh token (3 hours), like `az acr login` does.
- Role: `AcrPull` on the registry (or `Container Registry Repository Reader` with ABAC).
- Without Workload Identity: static credentials with a service principal (username its client
  id, password its secret) or a [repository scoped token](https://learn.microsoft.com/azure/container-registry/container-registry-repository-scoped-permissions).
- NetworkPolicy: allow `login.microsoftonline.com` (port 443, open by default).

## Reusing the image pull secrets

The clusters can already pull every image: their image pull secrets hold the credentials of the
private registries. With `registries.useImagePullSecrets: true`, kube-tower reads the
`imagePullSecrets` of the pods, Deployments, StatefulSets, DaemonSets and CronJobs at each scan
(`kubernetes.io/dockerconfigjson` and legacy `kubernetes.io/dockercfg` Secrets) and uses them for
the registries that have no credentials of their own.

```yaml
config:
  registries:
    useImagePullSecrets: true
```

- It needs `get` on Secrets in every namespace: Kubernetes RBAC cannot restrict it to some names in
  all namespaces, so kube-tower can then read any Secret whose name it knows. The chart adds this
  rule to the ClusterRole of the local cluster; remote clusters need it in their own RBAC
  (`deploy/remote-cluster-rbac.yaml` has it commented out).
- When several Secrets hold credentials for the same registry, the first one read is used.
- Images pulled by the kubelet with node credentials (kubelet credential providers, e.g. ECR on EKS
  nodes) have no pull secret: use a `provider` above.
- The Settings page lists the registries found in pull secrets (source `image-pull-secret`).

## TLS: private CAs and insecure registries

An internal Harbor, Artifactory or Nexus often has a certificate signed by a company CA. Give the
CA certificates to the chart: they are trusted in addition to the public CAs, by kube-tower and by
Trivy (also useful behind a TLS-intercepting proxy).

```yaml
registries:
  ca:
    existingConfigMap: company-ca     # a ConfigMap with the PEM certificates...
    key: ca.crt
    # pem: |                          # ...or the certificates inline
    #   -----BEGIN CERTIFICATE-----
```

Last resort, `config.registries.insecure` lists registries (fnmatch patterns, port included) whose
certificate is not verified at all. Like Docker's `insecure-registries`, a listed registry that does
not answer in `https://` is then used in plain `http://` (e.g. an in-cluster `registry:2` on port
5000). Credentials are never sent over plain `http://`: such a registry must allow anonymous pulls.
Trivy scans of these registries run with `--insecure`.

```yaml
config:
  registries:
    insecure:
      - registry.local:5000
```

With the NetworkPolicy enabled, add the ports of such registries to `networkPolicy.egress.ports`.

## Not supported

- Docker credential helpers (`credsStore`, `credHelpers` of a `config.json`): the image has no
  helper binary. kube-tower logs a warning; use per registry credentials or a `provider`.
- Registries that only implement the old v1 API.
