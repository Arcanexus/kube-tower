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

COPY src/ src/

# Version shown by the UI and the metrics, given by the CI from the image tag
ARG VERSION=dev
ENV KUBE_TOWER_VERSION=${VERSION}

# Unprivileged user, matches runAsUser in the Helm chart
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin kube-tower
USER 10001

EXPOSE 8080
CMD ["uvicorn", "--factory", "kube_tower.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
