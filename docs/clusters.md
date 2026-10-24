# Registering clusters

kube-tower always scans the cluster it runs in (disable with `clusters.inCluster: false`).
Other clusters are registered the way ArgoCD does it: one Secret per cluster.

## 1. Create a read-only ServiceAccount on the remote cluster

```sh
kubectl --context prod apply -f deploy/remote-cluster-rbac.yaml
TOKEN=$(kubectl --context prod -n kube-tower get secret kube-tower-reader-token -o jsonpath='{.data.token}' | base64 -d)
CA=$(kubectl --context prod -n kube-tower get secret kube-tower-reader-token -o jsonpath='{.data.ca\.crt}')
```

## 2. Create the cluster Secret where kube-tower runs

Install kube-tower in a namespace of its own: the cluster Secrets live there, and nothing else.

See [deploy/cluster-secret.example.yaml](../deploy/cluster-secret.example.yaml). kube-tower reads
the cluster Secrets **by name**: reference the Secret in the chart (`clusters[].existingSecret`,
see below) or in `config.clusters.secretNames`. The Secret contains:

| Key | Content |
| --- | --- |
| `name` | display name |
| `server` | API server URL |
| `config` | JSON, ArgoCD format: `bearerToken` (or `username`/`password`) and `tlsClientConfig` (`caData`, `certData`, `keyData`, `insecure`, `serverName`) |

Alternatively, put a full kubeconfig under a `kubeconfig` key. It must hold its credentials
itself (`token`, `client-certificate-data`, `certificate-authority-data`...): paths of local files
(`tokenFile`, `client-certificate`, `certificate-authority`...) and `auth-provider` are refused.
Exec plugins are refused too, unless their command is allowed (see
[managed clusters](#managed-clusters-eks-gke-aks-exec-plugins)).

## Registering clusters with the Helm chart

The `clusters` value either creates the Secret or references one you manage yourself:

```yaml
clusters:
  # The chart creates the Secret, ArgoCD format
  - name: prod
    server: https://prod.example.com:6443
    config:
      bearerToken: <token>
      tlsClientConfig:
        caData: <base64 PEM>
  # The chart creates the Secret from a kubeconfig
  - name: lab
    kubeconfig: |
      apiVersion: v1
      kind: Config
      ...
  # Existing Secret (ExternalSecrets, Sealed Secrets, by hand...), read by name
  - existingSecret: staging-cluster
```

An existing Secret must live in the kube-tower namespace and hold the keys above (`name`,
`server`, `config`, or `kubeconfig`). The chart adds every cluster Secret, the ones it creates and
the existing ones, to `config.clusters.secretNames`, and grants `get` on these Secrets only.

### Finding cluster Secrets by label (optional)

To register clusters without declaring each Secret, for example Secrets created by ExternalSecrets
as they come, set `config.clusters.listSecrets: true`: kube-tower then also lists the Secrets of
its namespace labelled `kube-tower.arcanexus.com/secret-type: cluster`
(`config.clusters.secretLabelSelector`).

Listing needs the `list` permission on Secrets, and Kubernetes RBAC cannot restrict it to a label:
kube-tower can then read **every** Secret of its namespace. That is why it is off by default, and
why kube-tower should have a namespace of its own.

Inline tokens end up in your values, hence in git with ArgoCD: prefer `existingSecret` with
ExternalSecrets or Sealed Secrets for anything but a lab.

## Reusing ArgoCD cluster Secrets

If ArgoCD already knows your clusters, set `config.clusters.useArgocdSecrets: true`: every
ArgoCD cluster is scanned too. The ArgoCD credentials must allow listing pods, nodes, workloads
and Applications.

> **Warning:** by default the ArgoCD cluster Secrets are listed, which gives kube-tower read access
> to **every** Secret of the ArgoCD namespace, including `argocd-secret` (the key signing ArgoCD
> sessions, the admin password hash) and the credentials of the git and Helm repositories.

Prefer naming the ArgoCD cluster Secrets: kube-tower then only gets `get` on these ones.

```sh
kubectl -n argocd get secret -l argocd.argoproj.io/secret-type=cluster -o name
```

```yaml
config:
  clusters:
    useArgocdSecrets: true
    argocdSecretNames:
      - cluster-prod.example.com-1234567890
      - cluster-lab.example.com-0987654321
```

A cluster added to ArgoCD later is then only scanned once its Secret is added to the list. For
production, a dedicated read-only ServiceAccount token per cluster (above) remains the safest
choice.

The Clusters tab shows each cluster and whether it is reachable.

## Managed clusters (EKS, GKE, AKS): exec plugins

The simplest way to scan a managed cluster is a ServiceAccount token, as above: it works on EKS,
GKE and AKS alike, with no plugin.

To use the cloud identity instead (IRSA or EKS Pod Identity, GKE Workload Identity, Azure Workload
Identity), use a kubeconfig whose user runs an exec plugin. kube-tower runs an exec command only
when it is listed in `config.clusters.execCommands`, written exactly as in the kubeconfig: anyone
able to create a cluster Secret could otherwise run any command in the kube-tower pod.

The plugin is not in the kube-tower image: copy it with an init container, the way the chart
copies Trivy. The kube-tower image is Alpine (musl): the plugin must be a static binary (Go plugins
built with `CGO_ENABLED=0`) or built for musl. It runs non-interactively (no browser, no device
code), with the environment of the kube-tower pod: `extraEnv` adds variables. It runs when the
clusters are discovered (each scan, each connectivity test), and again when its token expires.

The values common to the three examples below (replace `<plugin>` and the image):

```yaml
config:
  clusters:
    execCommands:
      - /opt/kube-tower/bin/<plugin>
extraInitContainers:
  - name: exec-plugin
    image: <an image holding the plugin binary>
    command: ["cp", "/path/in/the/image/<plugin>", "/opt/kube-tower/bin/<plugin>"]
    volumeMounts:
      - name: exec-plugins
        mountPath: /opt/kube-tower/bin
extraVolumes:
  - name: exec-plugins
    emptyDir: {}
extraVolumeMounts:
  - name: exec-plugins
    mountPath: /opt/kube-tower/bin
    readOnly: true
extraEnv:
  # The root filesystem is read-only: plugins that cache their tokens under $HOME write to /tmp
  - name: HOME
    value: /tmp
```

The identity must also be allowed to read the remote cluster: give it the read-only access of
[deploy/remote-cluster-rbac.yaml](../deploy/remote-cluster-rbac.yaml) (EKS access entry or
`aws-auth` mapping, GKE IAM or RBAC binding, AKS Azure RBAC or Kubernetes RBAC binding).

### EKS: aws-iam-authenticator

[aws-iam-authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator) is a static Go
binary that reads the AWS credentials of the pod (IRSA or EKS Pod Identity). `aws eks get-token`
needs the AWS CLI, which does not run in the kube-tower image.

```yaml
config:
  clusters:
    execCommands:
      - /opt/kube-tower/bin/aws-iam-authenticator
extraEnv:
  - name: HOME
    value: /tmp
  - name: AWS_REGION
    value: eu-west-1
# IRSA: the IAM role of the kube-tower pod (not needed with EKS Pod Identity)
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/kube-tower
clusters:
  - name: eks-prod
    kubeconfig: |
      apiVersion: v1
      kind: Config
      clusters: [{name: eks-prod, cluster: {server: "https://<id>.gr7.eu-west-1.eks.amazonaws.com", certificate-authority-data: "<base64 CA>"}}]
      users:
        - name: kube-tower
          user:
            exec:
              apiVersion: client.authentication.k8s.io/v1beta1
              command: /opt/kube-tower/bin/aws-iam-authenticator
              args: [token, -i, eks-prod]
      contexts: [{name: eks-prod, context: {cluster: eks-prod, user: kube-tower}}]
      current-context: eks-prod
```

### GKE: gke-gcloud-auth-plugin

`gke-gcloud-auth-plugin` reads the Google application default credentials: the metadata server
with GKE Workload Identity, or a credential configuration file set in
`GOOGLE_APPLICATION_CREDENTIALS` (Workload Identity Federation, from outside Google Cloud). Check
that the binary you copy runs on Alpine (`kubectl exec` into the pod and run it).

```yaml
config:
  clusters:
    execCommands:
      - /opt/kube-tower/bin/gke-gcloud-auth-plugin
# GKE Workload Identity: the Google service account of the kube-tower pod
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: kube-tower@my-project.iam.gserviceaccount.com
clusters:
  - name: gke-prod
    kubeconfig: |
      apiVersion: v1
      kind: Config
      clusters: [{name: gke-prod, cluster: {server: "https://<endpoint>", certificate-authority-data: "<base64 CA>"}}]
      users:
        - name: kube-tower
          user:
            exec:
              apiVersion: client.authentication.k8s.io/v1beta1
              command: /opt/kube-tower/bin/gke-gcloud-auth-plugin
              provideClusterInfo: true
      contexts: [{name: gke-prod, context: {cluster: gke-prod, user: kube-tower}}]
      current-context: gke-prod
```

### AKS: kubelogin

[kubelogin](https://github.com/Azure/kubelogin) with the `workloadidentity` login reads the Azure
Workload Identity variables that the Azure webhook injects in pods labelled
`azure.workload.identity/use: "true"`.

```yaml
config:
  clusters:
    execCommands:
      - /opt/kube-tower/bin/kubelogin
podLabels:
  azure.workload.identity/use: "true"
serviceAccount:
  annotations:
    azure.workload.identity/client-id: <client id>
clusters:
  - name: aks-prod
    kubeconfig: |
      apiVersion: v1
      kind: Config
      clusters: [{name: aks-prod, cluster: {server: "https://<fqdn>:443", certificate-authority-data: "<base64 CA>"}}]
      users:
        - name: kube-tower
          user:
            exec:
              apiVersion: client.authentication.k8s.io/v1beta1
              command: /opt/kube-tower/bin/kubelogin
              # 6dae42f8-... is the server application ID of AKS (the same for every cluster)
              args: [get-token, --login, workloadidentity, --server-id, 6dae42f8-4368-4678-94ff-3960e28e3630]
      contexts: [{name: aks-prod, context: {cluster: aks-prod, user: kube-tower}}]
      current-context: aks-prod
```

## Supported authentication methods

| Method | Supported | Notes |
| --- | --- | --- |
| ServiceAccount token (`bearerToken` / `token`) | ✅ | Recommended: works on every cluster, managed or not |
| Client certificate (`certData`/`keyData`, `client-certificate-data`/`client-key-data`) | ✅ | |
| Basic auth (`username`/`password`) | ✅ | Disabled on most clusters nowadays |
| Exec plugin allowed in `clusters.execCommands` | ✅ | Static or musl binary, non-interactive (see above) |
| CA and TLS options (`caData`, `certificate-authority-data`, `insecure`, `serverName`, `tls-server-name`) | ✅ | |
| `proxy-url` in a kubeconfig | ✅ | |
| Exec plugin not listed in `clusters.execCommands` | ❌ | Refused: add its command to the list |
| Interactive exec login (browser, device code: `kubelogin --login devicecode`, `kubectl oidc-login`) | ❌ | No terminal nor browser in the pod |
| `aws eks get-token` (AWS CLI) | ❌ | The AWS CLI does not run in the Alpine image: use aws-iam-authenticator |
| ArgoCD format `execProviderConfig` / `awsAuthConfig` | ❌ | Use a `kubeconfig` key with an exec plugin instead |
| `auth-provider` in a kubeconfig (gcp, azure, oidc) | ❌ | Removed from kubectl too: use the exec plugin of the cloud |
| Paths of local files (`tokenFile`, `client-certificate`, `client-key`, `certificate-authority`) | ❌ | Put the content inline (`token`, `*-data` keys) |
