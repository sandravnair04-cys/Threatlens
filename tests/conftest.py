import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "1000")
    import app as app_module
    app_module._hits.clear()
    app_module.db.init_db()
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()
