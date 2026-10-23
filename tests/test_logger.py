import json
import logging

import pytest

from kube_tower.logger import get_logger


@pytest.mark.parametrize("fmt", ["json", "logfmt", "custom"])
def test_formats(fmt, capsys):
    logger = get_logger(f"kt-test-{fmt}", level=logging.DEBUG, format_type=fmt)
    for level in ("debug", "info", "warning", "error", "critical"):
        getattr(logger, level)(f"{level} UP DOWN message")
    out, err = capsys.readouterr()
    assert "info UP" in out or "info" in out
    assert "critical" in err and "warning" in out
    if fmt == "json":
        assert json.loads(out.splitlines()[-1])["level"] == "WARNING"
    if fmt == "logfmt":
        assert "level=INFO" in out
