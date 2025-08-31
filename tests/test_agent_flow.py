import email
from unittest.mock import patch
from mvp_agent import process_one_message

def make_msg(subject="Hello", from_addr="test@example.com", body="Hi there"):
    msg = email.message.EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg.set_content(body)
    return msg

@patch("mvp_agent.groq_chat_complete_with_thread")
def test_process_message_adds_to_review(mock_ai):
    """Ensure process_one_message triggers review flow when AI decision has low confidence."""
    mock_ai.return_value = {
        "reply_needed": True,
        "confidence": 0.5,  # low confidence → should require manual review
        "proposed_subject": "Re: Hello",
        "proposed_body": "Hi back",
        "thread_context_used": False,
        "is_thread_continuation": False
    }
    msg = make_msg()
    process_one_message(msg)  # No return, but should log + append to PENDING_REVIEW
