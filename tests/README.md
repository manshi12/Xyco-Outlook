# 📬 Tests for Enhanced Email Agent

This folder contains **unit tests** and **integration tests** for the
Enhanced Email Agent (`mvp_agent.py`) and its FastAPI API
(`api_server.py`).\
The tests ensure that the agent's core email-processing logic, thread
handling, AI integration, and API endpoints work reliably.

------------------------------------------------------------------------

## 📂 Structure

    tests/
    ├── __init__.py
    ├── conftest.py              # Shared pytest fixtures (sample emails, mocks)
    ├── test_email_utils.py      # Unit tests for helper functions (headers, parsing, importance)
    ├── test_threading.py        # Thread detection & header handling tests
    ├── test_ai_processing.py    # Tests for Groq AI JSON response handling
    ├── test_smtp.py             # SMTP sending (mocked) and header checks
    ├── test_agent_flow.py       # End-to-end message processing (with mocks)
    ├── test_api_server.py       # FastAPI endpoint tests (async)
    └── README.md                # This file

------------------------------------------------------------------------

## ✅ What's Tested

-   **Email Utilities**
    -   MIME header decoding (`decode_mime_header`)
    -   Body extraction (`extract_text_from_message`)
    -   No-reply detection (`is_no_reply`)
    -   Importance classification (`get_email_importance`)
-   **Threading Logic**
    -   Detecting replies (`is_thread_reply`)
    -   Consistent thread IDs (`get_thread_id`)
    -   Proper `In-Reply-To` / `References` headers
        (`threading_headers`)
-   **AI Processing**
    -   Groq API responses are always valid JSON
    -   Required fields (`reply_needed`, `summary`, `proposed_body`) are
        present
    -   AI decision parsing under different scenarios
-   **SMTP**
    -   Messages include correct headers
    -   Body/subject are preserved during sending
-   **Agent Flow**
    -   `process_one_message` handles:
        -   New vs thread replies
        -   Manual review triggers (low confidence, external sender,
            VIP, etc.)
        -   Dry-run mode (does not actually send)
-   **FastAPI Server**
    -   `/api/status` reports agent state
    -   `/api/config` updates settings
    -   `/api/agent/start` and `/api/agent/stop` control lifecycle
    -   `/api/emails/pending` returns review queue

------------------------------------------------------------------------

## 🛠️ Running Tests

### 1. Install Dependencies

Make sure you have the requirements installed:

``` bash
pip install -r requirements.txt
pip install pytest pytest-asyncio httpx
```

### 2. Run All Tests

``` bash
pytest -v
```

### 3. Run a Specific Test File

``` bash
pytest tests/test_agent_flow.py -v
```

### 4. Run a Single Test Function

``` bash
pytest -k "test_status_endpoint_returns_expected_keys" -v
```

------------------------------------------------------------------------

## 🧪 Notes for Developers

-   **Mocks**:\
    External services (SMTP, IMAP, Groq API) are **mocked** to ensure
    tests are deterministic and do not send real emails or API
    requests.\
    See `unittest.mock.patch` usage in test files.

-   **Fixtures**:\
    Common test objects (like a plain sample email or a thread reply
    email) are defined in `conftest.py` so they can be reused across
    multiple tests.

-   **Async API Tests**:\
    API endpoints are tested with `httpx.AsyncClient` and
    `pytest-asyncio`.

-   **Dry Run Safety**:\
    The agent defaults to **dry-run mode** (`DRY_RUN=1`) during tests,
    so even if mocks fail, no emails are ever sent.

------------------------------------------------------------------------

## 🎯 Goals

These tests aim to guarantee that: 1. Core **email processing** works
even with edge cases (HTML-only emails, missing headers, no-reply
senders).\
2. **Thread handling** is consistent and does not break email chains.\
3. The **AI integration** produces valid, safe JSON output.\
4. The **FastAPI dashboard** endpoints are reliable and async-safe.\
5. Developers can confidently extend the agent without breaking existing
functionality.
