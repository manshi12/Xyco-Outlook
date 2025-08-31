from unittest.mock import patch
from mvp_agent import smtp_send

@patch("smtplib.SMTP")
def test_smtp_send_sets_subject_and_body(mock_smtp):
    instance = mock_smtp.return_value.__enter__.return_value
    smtp_send("to@example.com", "Subject Line", "Body content")

    sent_msg = instance.send_message.call_args[0][0]
    assert sent_msg["Subject"] == "Subject Line"
    assert "Body content" in sent_msg.get_content()
