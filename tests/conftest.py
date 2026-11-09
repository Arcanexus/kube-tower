import pytest

from kube_tower import worker
from kube_tower.collectors.security import SecurityFindings


@pytest.fixture(autouse=True)
def no_security_reports(monkeypatch):
    """The fake clusters of the tests have no Trivy Operator: no security report (test_security.py reads them)."""
    monkeypatch.setattr(worker, "collect_security_reports", lambda cluster: SecurityFindings())


@pytest.fixture(autouse=True)
def no_deprecated_apis(monkeypatch):
    """The fake clusters of the tests have no API server metrics (test_deprecated_apis.py reads them)."""
    monkeypatch.setattr(worker, "collect_deprecated_apis", lambda cluster: ([], []))


@pytest.fixture(autouse=True)
def no_platform_lookup(monkeypatch):
    """No call to endoflife.date or OSV from the tests (test_lifecycle.py tests the lookup itself)."""
    from kube_tower import scanner

    async def lookup(settings, versions, http=None):
        return []

    monkeypatch.setattr(scanner, "lookup", lookup)


@pytest.fixture(autouse=True)
def no_known_release_dates():
    """The release dates read by a test are not kept for the next ones."""
    from kube_tower.checkers import RELEASE_DATES

    RELEASE_DATES._dates.clear()
