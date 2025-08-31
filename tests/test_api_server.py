
import pytest
from httpx import AsyncClient
from api_server import app

@pytest.mark.asyncio
async def test_status_endpoint_returns_expected_keys():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert set(["is_running", "processed_count", "pending_count"]).issubset(data.keys())

@pytest.mark.asyncio
async def test_config_update_changes_poll_seconds():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.post("/api/config", json={
            "poll_seconds": 15,
            "dry_run": True,
            "max_emails_per_cycle": 3,
            "require_review_high_importance": True,
            "require_review_external": False,
            "company_domain": "example.com",
            "thread_context_limit": 5
        })
        assert resp.status_code == 200
        assert "Configuration updated successfully" in resp.text
