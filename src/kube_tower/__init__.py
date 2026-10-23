import os

# Set at image build time from the git tag (see Dockerfile and docker-publish.yml): `1.2.3` for a
# release, the branch name (`main`) otherwise; `dev` when running from the sources.
__version__ = os.environ.get("KUBE_TOWER_VERSION") or "dev"
