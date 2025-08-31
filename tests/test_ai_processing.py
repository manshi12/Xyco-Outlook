import json
from unittest.mock import patch
from mvp_agent import groq_chat_complete_with_thread

def test_ai_returns_well_formed_json():
    fake_json = {
        "reply_needed": True,
        "urgency_score": 0.5,
        "category": "business",
        "sentiment": "neutral",
        "requires_action": False,
        "summary": "This is a test summary",
        "key_points": ["a", "b"],
        "proposed_subject": "Re: test",
        "proposed_body": "Hello",
        "confidence": 0.9,
        "thread_context_used": False,
        "is_thread_continuation": False
    }
    fake_response = {
        "choices": [{
            "message": type("obj", (object,), {"content": json.dumps(fake_json)})
        }]
    }

    with patch("mvp_agent.groq_client.chat.completions.create", return_value=fake_response):
        result = groq_chat_complete_with_thread("prompt")
        assert result["reply_needed"] is True
        assert result["category"] == "business"
        assert "summary" in result
