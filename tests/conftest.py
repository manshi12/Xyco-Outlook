import pytest
import email

@pytest.fixture
def sample_plain_msg():
    """A basic plain text email for testing utils."""
    msg = email.message.EmailMessage()
    msg["Subject"] = "Test Email"
    msg["From"] = "user@example.com"
    msg.set_content("Hello, this is a test body.")
    return msg

@pytest.fixture
def sample_thread_msg():
    """An email that looks like part of a thread."""
    msg = email.message.EmailMessage()
    msg["Subject"] = "Re: Project Update"
    msg["From"] = "colleague@example.com"
    msg["In-Reply-To"] = "<msg123@company.com>"
    msg.set_content("Following up on the project update.")
    return msg
