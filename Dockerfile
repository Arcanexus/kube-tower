# Trivy CLI, used to scan images for vulnerabilities (see docs/vulnerabilities.md).
# Built from source (checked against the Go checksum database) for every platform of the image
# (linux/amd64, linux/arm64, linux/arm/v7).
FROM --platform=$BUILDPLATFORM golang:1.25 AS trivy
ARG TRIVY_VERSION=0.75.0
ARG TARGETOS TARGETARCH TARGETVARIANT
# Trivy needs a newer Go than the base image: let go download the toolchain it asks for
ENV GOTOOLCHAIN=auto CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} go install -trimpath \
      -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" \
      github.com/aquasecurity/trivy/cmd/trivy@v${TRIVY_VERSION} \
    && find "$(go env GOPATH)/bin" -name trivy -type f -exec cp {} /usr/local/bin/trivy \;

FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src

# uvicorn trusts X-Forwarded-Proto/For from the ingress controller (TLS terminated upstream)
ENV FORWARDED_ALLOW_IPS=*

WORKDIR /app

COPY src/requirements.txt src/requirements.txt
RUN pip install -r src/requirements.txt

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY src/ src/

# Version shown by the UI and the metrics, given by the CI from the image tag
ARG VERSION=dev
ENV KUBE_TOWER_VERSION=${VERSION}

# Unprivileged user, matches runAsUser in the Helm chart
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin kube-tower
USER 10001

EXPOSE 8080
CMD ["uvicorn", "--factory", "kube_tower.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
