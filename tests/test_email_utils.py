import email
from mvp_agent import decode_mime_header, extract_text_from_message, is_no_reply, get_email_importance

def test_decode_mime_header_handles_encoded_subject():
    raw = "=?utf-8?q?Hello_=E2=9C=8C?="  # "Hello ✌"
    decoded = decode_mime_header(raw)
    assert "Hello" in decoded
    assert "✌" in decoded

def test_extract_text_from_plain(sample_plain_msg):
    body = extract_text_from_message(sample_plain_msg)
    assert "Hello, this is a test body." in body

def test_extract_text_from_html():
    msg = email.message.EmailMessage()
    msg.add_alternative("<html><body><p>Hello<br>World</p></body></html>", subtype="html")
    text = extract_text_from_message(msg)
    assert "Hello" in text
    assert "World" in text

def test_is_no_reply_variants():
    assert is_no_reply("noreply@x.com")
    assert is_no_reply("DoNotReply@x.com")
    assert not is_no_reply("support@x.com")

def test_get_email_importance_levels():
    msg = email.message.EmailMessage()
    msg["Importance"] = "high"
    assert get_email_importance(msg) == "high"

    msg = email.message.EmailMessage()
    msg["X-Priority"] = "5"
    assert get_email_importance(msg) == "low"
