from mvp_agent import is_thread_reply, get_thread_id, threading_headers

def test_is_thread_reply_detects_by_subject(sample_thread_msg):
    assert is_thread_reply(sample_thread_msg)

def test_get_thread_id_stable_for_same_subject():
    from email.message import EmailMessage
    msg1 = EmailMessage(); msg1["Subject"] = "Hello"; msg1["From"] = "a@x.com"
    msg2 = EmailMessage(); msg2["Subject"] = "Hello"; msg2["From"] = "a@x.com"
    assert get_thread_id(msg1) == get_thread_id(msg2)

def test_threading_headers_include_inreply(sample_thread_msg):
    headers = threading_headers(sample_thread_msg)
    assert "In-Reply-To" in headers
    assert headers["In-Reply-To"] == "<msg123@company.com>"
