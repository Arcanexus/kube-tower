import pytest

from kube_tower import worker
from kube_tower.collectors.security import SecurityFindings


@pytest.fixture(autouse=True)
def no_security_reports(monkeypatch):
    """The fake clusters of the tests have no Trivy Operator: no security report (test_security.py reads them)."""
    monkeypatch.setattr(worker, "collect_security_reports", lambda cluster: SecurityFindings())
