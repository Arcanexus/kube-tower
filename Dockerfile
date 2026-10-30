# Dependencies are installed on the build machine (no QEMU emulation) for the target
# architecture: pip only takes wheels built for it (musllinux), and the .pyc files do not depend on
# the CPU. A dependency without such a wheel fails the build instead of being compiled under QEMU.
# Keep both stages on the same Python version (.pyc files are per Python minor version).
FROM --platform=$BUILDPLATFORM python:3.13-alpine AS deps

ARG TARGETARCH
ARG TARGETVARIANT

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY src/requirements.txt /tmp/requirements.txt

RUN set -eu; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
        amd64) arch=x86_64 ;; \
        arm64) arch=aarch64 ;; \
        armv7) arch=armv7l ;; \
        *) echo "unsupported platform ${TARGETARCH}${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    # PyYAML has no arm/v7 wheel: build its pure Python version (no C extension, works on any CPU)
    PYYAML_FORCE_LIBYAML=0 pip wheel --no-deps --no-binary pyyaml --wheel-dir /tmp/wheels \
        "$(grep -i '^pyyaml==' /tmp/requirements.txt)"; \
    pip install --target /deps --only-binary=:all: --find-links /tmp/wheels \
        --python-version 3.13 --implementation cp --abi cp313 \
        --platform "musllinux_1_2_${arch}" --platform "musllinux_1_1_${arch}" \
        -r /tmp/requirements.txt; \
    # kubernetes ships an asyncio client kube-tower does not use (~65 MB with the aiohttp stack)
    rm -rf /deps/kubernetes/aio /deps/bin; \
    for pkg in aiohttp aiohttp_retry aiohappyeyeballs aiosignal attr attrs frozenlist multidict propcache yarl; do \
        rm -rf "/deps/${pkg}" /deps/${pkg}-*.dist-info; \
    done; \
    find /deps/kubernetes -depth \( -name test -o -name '*_test.py' \) -exec rm -rf {} +


FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# uvicorn trusts X-Forwarded-Proto/For from the ingress controller (TLS terminated upstream)
ENV FORWARDED_ALLOW_IPS=*

# Unprivileged user, matches runAsUser in the Helm chart. pip is not used at run time: removed with
# the packages it vendors (setuptools, msgpack, urllib3...), which image scanners report with their CVEs.
RUN adduser -D -H -u 10001 -s /sbin/nologin kube-tower \
    && rm -rf /usr/local/bin/pip* /usr/local/lib/python3.13/site-packages/pip \
        /usr/local/lib/python3.13/site-packages/pip-*.dist-info /usr/local/lib/python3.13/ensurepip/_bundled

COPY --from=deps /deps /usr/local/lib/python3.13/site-packages
COPY src/ /app/src/

# Version shown by the UI and the metrics, given by the CI from the image tag
ARG VERSION=dev
ENV KUBE_TOWER_VERSION=${VERSION}

WORKDIR /app
USER 10001

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "--factory", "kube_tower.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
