# mvp_agent_corporate.py - Enhanced for Corporate Outlook and SocGen AI API
# Corporate Email Agent with Outlook Integration and SocGen AI Support

import os
import re
import ssl
import time
import json
import imaplib
import smtplib
import logging
import email
import requests
from typing import List, Tuple, Optional, Dict
from email.header import decode_header, make_header
from email.utils import parseaddr
from email.message import EmailMessage
from datetime import datetime, timedelta
import platform
import subprocess
import base64
import socket





# Optional .env loading
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# -----------------------
# Corporate Configuration
# -----------------------
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "")
EMAIL_USER = os.getenv("EMAIL_USER", EMAIL_ADDRESS)
EMAIL_PASS = os.getenv("EMAIL_PASS", "")

# Corporate Outlook Settings
IMAP_HOST = os.getenv("IMAP_HOST", "outlook.office365.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "1") == "1"

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "60"))
MAX_EMAILS_PER_CYCLE = int(os.getenv("MAX_EMAILS_PER_CYCLE", "10"))
DRY_RUN = os.getenv("DRY_RUN", "1") == "1"

REQUIRE_REVIEW_HIGH_IMPORTANCE = os.getenv("REQUIRE_REVIEW_HIGH_IMPORTANCE", "1") == "1"
REQUIRE_REVIEW_EXTERNAL = os.getenv("REQUIRE_REVIEW_EXTERNAL", "1") == "1"
COMPANY_DOMAIN = os.getenv("COMPANY_DOMAIN", "").lower()
VIP_SENDERS_FILE = os.getenv("VIP_SENDERS_FILE", "vip_senders.json")
AUTO_REPLY_CATEGORIES = os.getenv("AUTO_REPLY_CATEGORIES", "newsletter,notification,automated").split(",")

# SocGen AI API Configuration
SOCGEN_API_BASE = os.getenv("SOCGEN_API_BASE", "https://sogpt-hom.world.socgen:446/api/v2")
SOCGEN_TOKEN_URL = os.getenv("SOCGEN_TOKEN_URL", "https://sgconnect-hom.fr.world.socgen/sgconnect/oauth2/access_token")
SOCGEN_CLIENT_ID = os.getenv("SOCGEN_CLIENT_ID", "aa558c6b-adca-4cdd-b49d-125d9678c164")
SOCGEN_CLIENT_SECRET = os.getenv("SOCGEN_CLIENT_SECRET", "k0lcckl4b7cj7ca8650cdl2naaj9")
SOCGEN_MODEL = os.getenv("SOCGEN_MODEL", "azure-openai-gpt-4o-mini-2024-07-18")

STATE_FILE = ".processed_ids.json"
PENDING_REVIEW_FILE = ".pending_review.json"
TOKEN_FILE = ".socgen_token.json"

assert EMAIL_ADDRESS and EMAIL_USER and EMAIL_PASS, "Email credentials missing"
assert IMAP_HOST and SMTP_HOST, "IMAP/SMTP host configuration missing"
assert SOCGEN_CLIENT_ID and SOCGEN_CLIENT_SECRET, "SocGen API credentials missing"



def detect_exchange_server(email_domain: str) -> Optional[str]:
    """Auto-detect Exchange server settings using DNS SRV records"""
    try:
        # Try to resolve SRV records for Exchange autodiscovery
        srv_queries = [
            f"_imaps._tcp.{email_domain}",
            f"_imap._tcp.{email_domain}",
            f"_autodiscover._tcp.{email_domain}"
        ]
        
        import dns.resolver
        for query in srv_queries:
            try:
                answers = dns.resolver.resolve(query, 'SRV')
                for answer in answers:
                    return str(answer.target).rstrip('.')
            except:
                continue
    except ImportError:
        logging.debug("dnspython not available for SRV lookup")
    except Exception as e:
        logging.debug(f"SRV lookup failed: {e}")
    
    return None

def get_exchange_autodiscover_url(email_address: str) -> Optional[str]:
    """Try Exchange autodiscovery to find server settings"""
    domain = email_address.split('@')[1] if '@' in email_address else None
    if not domain:
        return None
    
    autodiscover_urls = [
        f"https://autodiscover.{domain}/autodiscover/autodiscover.xml",
        f"https://{domain}/autodiscover/autodiscover.xml",
        f"http://autodiscover.{domain}/autodiscover/autodiscover.xml"
    ]
    
    autodiscover_xml = f"""<?xml version="1.0" encoding="utf-8"?>
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
            <EMailAddress>{email_address}</EMailAddress>
            <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>"""
    
    for url in autodiscover_urls:
        try:
            import requests
            response = requests.post(
                url, 
                data=autodiscover_xml,
                headers={'Content-Type': 'text/xml; charset=utf-8'},
                timeout=10,
                verify=False  # Corporate environments often use self-signed certs
            )
            
            if response.status_code == 200:
                # Parse the XML response to extract IMAP server
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)
                
                # Look for IMAP protocol settings
                for protocol in root.iter():
                    if protocol.tag and 'Protocol' in protocol.tag:
                        type_elem = protocol.find('.//{*}Type')
                        server_elem = protocol.find('.//{*}Server')
                        port_elem = protocol.find('.//{*}Port')
                        
                        if (type_elem is not None and type_elem.text == 'IMAP' and 
                            server_elem is not None):
                            return server_elem.text
                            
        except Exception as e:
            logging.debug(f"Autodiscover attempt failed for {url}: {e}")
            continue
    
    return None

def discover_corporate_settings(email_address: str) -> dict:
    """Discover corporate Exchange server settings"""
    domain = email_address.split('@')[1] if '@' in email_address else ""
    
    # Try common corporate Exchange patterns
    common_patterns = [
        f"mail.{domain}",
        f"exchange.{domain}",
        f"imap.{domain}",
        f"outlook.{domain}",
        f"mx.{domain}",
        f"webmail.{domain}"
    ]
    
    # Try SRV record discovery
    srv_server = detect_exchange_server(domain)
    if srv_server:
        common_patterns.insert(0, srv_server)
    
    # Try autodiscovery
    autodiscover_server = get_exchange_autodiscover_url(email_address)
    if autodiscover_server:
        common_patterns.insert(0, autodiscover_server)
    
    settings = {
        'imap_host': None,
        'imap_port': 993,
        'smtp_host': None,
        'smtp_port': 587
    }
    
    # Test each pattern
    for pattern in common_patterns:
        if test_imap_connection(pattern, 993, EMAIL_USER, EMAIL_PASS):
            settings['imap_host'] = pattern
            break
    
    # Test SMTP with same pattern
    if settings['imap_host']:
        smtp_pattern = settings['imap_host'].replace('imap', 'smtp').replace('mail', 'smtp')
        if test_smtp_connection(smtp_pattern, 587, EMAIL_USER, EMAIL_PASS):
            settings['smtp_host'] = smtp_pattern
        elif test_smtp_connection(settings['imap_host'], 587, EMAIL_USER, EMAIL_PASS):
            settings['smtp_host'] = settings['imap_host']
    
    return settings

def test_imap_connection(host: str, port: int, username: str, password: str, timeout: int = 10) -> bool:
    """Test IMAP connection with enhanced error handling for corporate environments"""
    try:
        # Create SSL context for corporate environments
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For self-signed corporate certs
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Set socket timeout
        socket.setdefaulttimeout(timeout)
        
        # Try IMAP SSL connection
        imap = imaplib.IMAP4_SSL(host, port, ssl_context=context)
        imap.login(username, password)
        imap.select("INBOX")
        imap.close()
        imap.logout()
        
        logging.info(f"IMAP connection successful: {host}:{port}")
        return True
        
    except socket.gaierror as e:
        logging.debug(f"DNS resolution failed for {host}: {e}")
        return False
    except socket.timeout:
        logging.debug(f"Connection timeout for {host}:{port}")
        return False
    except imaplib.IMAP4.error as e:
        logging.debug(f"IMAP authentication failed for {host}: {e}")
        return False
    except Exception as e:
        logging.debug(f"IMAP connection failed for {host}: {e}")
        return False
    finally:
        socket.setdefaulttimeout(None)

def test_smtp_connection(host: str, port: int, username: str, password: str, timeout: int = 10) -> bool:
    """Test SMTP connection with enhanced error handling"""
    try:
        socket.setdefaulttimeout(timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with smtplib.SMTP(host, port, timeout=timeout) as s:
            s.starttls(context=context)
            s.login(username, password)
        
        logging.info(f"SMTP connection successful: {host}:{port}")
        return True
        
    except socket.gaierror as e:
        logging.debug(f"DNS resolution failed for {host}: {e}")
        return False
    except Exception as e:
        logging.debug(f"SMTP connection failed for {host}: {e}")
        return False
    finally:
        socket.setdefaulttimeout(None)



# -----------------------
# SocGen AI API Client
# -----------------------
class SocGenAIClient:
    def __init__(self):
        self.token = None
        self.token_expires = None
        self.load_cached_token()
    
    def load_cached_token(self):
        """Load cached token from file"""
        try:
            with open(TOKEN_FILE, 'r') as f:
                token_data = json.load(f)
                self.token = token_data.get('access_token')
                expires_str = token_data.get('expires_at')
                if expires_str:
                    self.token_expires = datetime.fromisoformat(expires_str)
        except Exception as e:
            logging.debug(f"No cached token found: {e}")
    
    def save_token(self, token_data):
        """Save token to file with expiration"""
        try:
            # Calculate expiration time (assuming 1 hour)
            expires_at = datetime.now() + timedelta(seconds=token_data.get('expires_in', 3600))
            
            cache_data = {
                'access_token': token_data['access_token'],
                'expires_at': expires_at.isoformat(),
                'token_type': token_data.get('token_type', 'Bearer')
            }
            
            with open(TOKEN_FILE, 'w') as f:
                json.dump(cache_data, f, indent=2)
                
            self.token = token_data['access_token']
            self.token_expires = expires_at
            
        except Exception as e:
            logging.error(f"Failed to save token: {e}")
    
    def is_token_valid(self):
        """Check if current token is valid"""
        if not self.token or not self.token_expires:
            return False
        return datetime.now() < self.token_expires - timedelta(minutes=5)  # 5 min buffer
    
    def get_access_token(self):
        """Get or refresh access token"""
        if self.is_token_valid():
            return self.token
        
        logging.info("Refreshing SocGen AI access token...")
        
        headers = {
            'X-Application': 'YI_HACKATHON_TEST',
            'X-Key-Name': 'key_2025',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': SOCGEN_CLIENT_ID,
            'client_secret': SOCGEN_CLIENT_SECRET
        }
        
        try:
            response = requests.post(SOCGEN_TOKEN_URL, headers=headers, data=data, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            self.save_token(token_data)
            
            logging.info("SocGen AI token refreshed successfully")
            return self.token
            
        except Exception as e:
            logging.error(f"Failed to get SocGen AI token: {e}")
            raise
    
    def chat_completion(self, messages, temperature=0.3, max_tokens=1200):
        """Make chat completion request to SocGen AI API"""
        token = self.get_access_token()
        
        headers = {
            'Accept': 'application/json',
            'X-Application': 'YI_HACKATHON_TEST',
            'X-Key-Name': 'key_2025',
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "max_new_tokens": max_tokens,
            "messages": messages,
            "model": SOCGEN_MODEL,
            "parallel_tool_calls": False,
            "reasoning_effort": "medium",
            "sampling": True,
            "streaming": False,
            "temperature": temperature,
            "token_probs": False,
            "tool_choice": "auto",
            "tools": []
        }
        
        try:
            response = requests.post(
                f"{SOCGEN_API_BASE}/messages/completions",
                headers=headers,
                json=payload,
                timeout=60,
                verify=False  # For corporate environments with self-signed certs
            )
            response.raise_for_status()
            
            result = response.json()
            
            # Extract content from SocGen API response format
            if 'choices' in result and len(result['choices']) > 0:
                content = result['choices'][0].get('message', {}).get('content', '')
            elif 'content' in result:
                content = result['content']
            else:
                logging.error(f"Unexpected API response format: {result}")
                raise ValueError("Invalid API response format")
            
            return content
            
        except requests.exceptions.RequestException as e:
            logging.error(f"SocGen AI API request failed: {e}")
            raise
        except Exception as e:
            logging.error(f"SocGen AI API error: {e}")
            raise

# Initialize SocGen AI client
socgen_client = SocGenAIClient()

# -----------------------
# Logging and State (Enhanced for Corporate)
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("email_agent_corporate.log")
    ]
)

try:
    PROCESSED = set(json.load(open(STATE_FILE)))
except Exception:
    PROCESSED = set()

try:
    PENDING_REVIEW = json.load(open(PENDING_REVIEW_FILE))
except Exception:
    PENDING_REVIEW = []

try:
    VIP_SENDERS = set(json.load(open(VIP_SENDERS_FILE)))
except Exception:
    VIP_SENDERS = set()
    try:
        json.dump([], open(VIP_SENDERS_FILE, 'w'))
    except Exception:
        pass

# -----------------------
# Corporate Email Provider Utilities
# -----------------------
NO_REPLY_PATTERNS = [
    r"no-?reply",
    r"donotreply", 
    r"do-?not-?reply",
    r"noreply",
    r"automated",
    r"system",
]

def save_state():
    """Save all state to files"""
    try:
        json.dump(sorted(PROCESSED), open(STATE_FILE, "w"))
        json.dump(PENDING_REVIEW, open(PENDING_REVIEW_FILE, "w"), indent=2)
    except Exception as e:
        logging.error(f"Failed to save state: {e}")

# -----------------------
# Helper Functions (Corporate Enhanced)
# -----------------------
def decode_mime_header(value: Optional[str]) -> str:
    """Decode MIME-encoded headers (enhanced for Outlook)"""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value

def extract_text_from_message(msg: email.message.Message) -> str:
    """Extract text content from email message (Outlook optimized)"""
    def strip_html(html: str) -> str:
        # Enhanced HTML stripping for Outlook's complex HTML
        html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
        html = re.sub(r"(?is)<br\s*/?>", "\n", html)
        html = re.sub(r"(?is)</p>", "\n\n", html)
        html = re.sub(r"(?is)</div>", "\n", html)
        html = re.sub(r"(?is)<tr.*?>", "\n", html)
        html = re.sub(r"(?is)<td.*?>", " ", html)
        text = re.sub(r"(?s)<.*?>", "", html)
        # Clean up Outlook-specific artifacts
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        return text.strip()

    if msg.is_multipart():
        # Prioritize text/plain for corporate emails
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() == "text/plain":
                raw = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                try:
                    return raw.decode(charset, "replace")
                except:
                    return raw.decode("utf-8", "replace")
        
        # Fallback to HTML if no plain text
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                raw = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                try:
                    html = raw.decode(charset, "replace")
                except:
                    html = raw.decode("utf-8", "replace")
                return strip_html(html)
        return ""
    else:
        ctype = msg.get_content_type()
        raw = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        try:
            text = raw.decode(charset, "replace")
        except:
            text = raw.decode("utf-8", "replace")
        return strip_html(text) if ctype == "text/html" else text

def parseaddr_safe(value: str) -> Tuple[str, str]:
    """Safely parse email address (corporate email compatible)"""
    name, addr = parseaddr(value or "")
    return name, addr.lower()  # Normalize to lowercase for corporate

def is_thread_reply(msg: email.message.Message) -> bool:
    """Check if email is part of an existing thread (Outlook optimized)"""
    in_reply_to = msg.get("In-Reply-To")
    references = msg.get("References")
    conversation_id = msg.get("Thread-Index")  # Outlook-specific
    subject = decode_mime_header(msg.get("Subject", "")).strip()
    has_re_pattern = bool(re.match(r"^(re|fw|fwd|aw):\s*", subject, re.IGNORECASE))
    
    return bool(in_reply_to or references or conversation_id or has_re_pattern)

def extract_original_subject(subject: str) -> str:
    """Extract original subject from Re:/Fw: patterns (corporate enhanced)"""
    if not subject:
        return ""
    
    # Handle multiple Re:/Fw: patterns common in corporate emails
    clean_subject = re.sub(r"^(re|fw|fwd|aw):\s*", "", subject, flags=re.IGNORECASE)
    clean_subject = re.sub(r"^\[.*?\]\s*", "", clean_subject)  # Remove [EXTERNAL] tags
    clean_subject = re.sub(r"^(re|fw|fwd|aw):\s*", "", clean_subject, flags=re.IGNORECASE)  # Second pass
    
    return clean_subject.strip()

def get_thread_id(msg: email.message.Message) -> str:
    """Generate consistent thread ID for grouping (Outlook enhanced)"""
    # Prefer Outlook's Thread-Index if available
    thread_index = msg.get("Thread-Index")
    if thread_index:
        return f"outlook-thread-{thread_index}"
    
    in_reply_to = msg.get("In-Reply-To", "").strip()
    if in_reply_to:
        return in_reply_to
    
    references = msg.get("References", "").strip()
    if references:
        first_ref = references.split()[0] if references else ""
        if first_ref:
            return first_ref
    
    subject = extract_original_subject(decode_mime_header(msg.get("Subject", "")))
    sender = parseaddr_safe(msg.get("From", ""))[1]
    
    thread_key = f"{subject.lower()}:{sender.lower()}"
    return f"thread-{hash(thread_key)}"

def threading_headers(original: email.message.Message) -> Dict[str, str]:
    """Generate proper threading headers for replies (Outlook enhanced)"""
    headers = {}
    
    # Get the Message-ID from original email
    original_msg_id = original.get("Message-ID", "").strip()
    if original_msg_id:
        headers["In-Reply-To"] = original_msg_id
    
    # Build References chain properly
    existing_refs = original.get("References", "").strip()
    if existing_refs and original_msg_id:
        headers["References"] = f"{existing_refs} {original_msg_id}"
    elif original_msg_id:
        headers["References"] = original_msg_id
    elif existing_refs:
        headers["References"] = existing_refs
    
    # Add Outlook-specific headers for better threading
    thread_index = original.get("Thread-Index")
    if thread_index:
        # Generate a new Thread-Index for the reply (simplified approach)
        headers["Thread-Index"] = thread_index
    
    return headers

def clean_header(value: str) -> str:
    """Clean header value by removing invalid characters"""
    return re.sub(r'[\r\n]', ' ', value.strip())

def is_no_reply(addr: str) -> bool:
    """Check if address is a no-reply address (corporate enhanced)"""
    local = (addr or "").split("@")[0].lower()
    return any(re.search(p, local) for p in NO_REPLY_PATTERNS)

def get_email_importance(msg: email.message.Message) -> str:
    """Extract importance level (Outlook enhanced)"""
    importance = msg.get("Importance", "").lower()
    priority = msg.get("X-Priority", "")
    x_msmail_priority = msg.get("X-MSMail-Priority", "").lower()
    
    if importance == "high" or priority == "1" or x_msmail_priority == "high":
        return "high"
    elif importance == "low" or priority == "5" or x_msmail_priority == "low":
        return "low"
    return "normal"

def is_external_sender(sender_addr: str) -> bool:
    """Check if sender is external to company"""
    if not COMPANY_DOMAIN or not sender_addr:
        return False
    return not sender_addr.lower().endswith(f"@{COMPANY_DOMAIN}")

def is_vip_sender(sender_addr: str) -> bool:
    """Check if sender is in VIP list"""
    return sender_addr.lower() in VIP_SENDERS

def detect_email_category(msg: email.message.Message) -> str:
    """Detect email category (corporate enhanced)"""
    subject = decode_mime_header(msg.get("Subject", "")).lower()
    sender = msg.get("From", "").lower()
    body = extract_text_from_message(msg).lower()
    
    # Corporate-specific patterns
    if any(keyword in subject for keyword in 
           ["newsletter", "unsubscribe", "marketing", "promotion", "announcement"]):
        return "newsletter"
    
    if any(keyword in sender for keyword in 
           ["noreply", "no-reply", "donotreply", "automated", "system", "notification"]):
        return "automated"
    
    if any(keyword in subject for keyword in 
           ["meeting", "calendar", "appointment", "schedule", "invite", "teams"]):
        return "meeting"
    
    if any(keyword in subject or keyword in body[:500] for keyword in 
           ["urgent", "asap", "emergency", "critical", "immediate"]):
        return "urgent"
    
    if any(keyword in subject for keyword in 
           ["project", "task", "deadline", "deliverable", "milestone"]):
        return "project"
    
    return "business"

# -----------------------
# Desktop Notification (Corporate)
# -----------------------
def desktop_notify(title: str, message: str):
    """Send cross-platform desktop notification for corporate environment"""
    plat = platform.system()
    try:
        if plat == 'Darwin':
            cmd = ['osascript', '-e', f'display notification "{message}" with title "{title}"']
            subprocess.call(cmd)
            logging.info("Sent macOS notification")
        elif plat == 'Windows':
            # Enhanced Windows notification for corporate
            try:
                import win10toast
                toaster = win10toast.ToastNotifier()
                toaster.show_toast(title, message, duration=10)
            except ImportError:
                # Fallback to message box
                from ctypes import windll
                windll.user32.MessageBoxW(0, message, title, 0x00001000)
            logging.info("Displayed Windows notification")
        elif plat == 'Linux':
            subprocess.call(['notify-send', title, message])
            logging.info("Sent Linux notification")
        else:
            logging.warning("Desktop notifications not supported on this platform")
    except Exception as e:
        logging.error(f"Failed to send desktop notification: {e}")

def fetch_thread_context(msg: email.message.Message, limit: int = 5) -> List[Dict]:
    """Fetch thread context (Corporate Outlook optimized)"""
    thread_context = []
    
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        imap.login(EMAIL_USER, EMAIL_PASS)
        imap.select("INBOX")
        
        references = []
        in_reply_to = msg.get("In-Reply-To", "").strip()
        existing_refs = msg.get("References", "").strip()
        thread_index = msg.get("Thread-Index", "").strip()  # Outlook-specific
        
        if in_reply_to:
            references.append(in_reply_to)
        
        if existing_refs:
            refs = [ref.strip() for ref in existing_refs.split() if ref.strip()]
            references.extend(refs[-limit:])
        
        original_subject = extract_original_subject(decode_mime_header(msg.get("Subject", "")))
        sender_addr = parseaddr_safe(msg.get("From", ""))[1]
        
        seen_message_ids = set()
        
        # Search by Message-ID references first
        for ref_id in references:
            if ref_id in seen_message_ids:
                continue
                
            try:
                search_query = f'HEADER Message-ID "{ref_id}"'
                _, data = imap.search(None, search_query)
                
                if data and data[0]:
                    msg_nums = data[0].split()
                    for msg_num in msg_nums[:1]:
                        _, fetch_data = imap.fetch(msg_num, "(RFC822)")
                        if fetch_data and fetch_data[0] and len(fetch_data[0]) > 1:
                            raw_msg = fetch_data[0][1]
                            parsed_msg = email.message_from_bytes(raw_msg)
                            
                            thread_context.append({
                                'date': parsed_msg.get("Date", ""),
                                'from': decode_mime_header(parsed_msg.get("From", "")),
                                'subject': decode_mime_header(parsed_msg.get("Subject", "")),
                                'body': extract_text_from_message(parsed_msg)[:1000],
                                'message_id': parsed_msg.get("Message-ID", ""),
                                'thread_index': parsed_msg.get("Thread-Index", "")
                            })
                            seen_message_ids.add(ref_id)
                            
            except Exception as e:
                logging.debug(f"Failed to fetch reference {ref_id}: {e}")
                continue
        
        # Outlook Thread-Index search
        if len(thread_context) < 2 and thread_index:
            try:
                search_query = f'HEADER Thread-Index "{thread_index[:20]}"'  # Partial match
                _, data = imap.search(None, search_query)
                
                if data and data[0]:
                    msg_nums = data[0].split()[-3:]  # Last 3 messages
                    for msg_num in msg_nums:
                        try:
                            _, fetch_data = imap.fetch(msg_num, "(RFC822)")
                            if fetch_data and fetch_data[0] and len(fetch_data[0]) > 1:
                                raw_msg = fetch_data[0][1]
                                parsed_msg = email.message_from_bytes(raw_msg)
                                
                                msg_id = parsed_msg.get("Message-ID", "")
                                if msg_id not in seen_message_ids:
                                    thread_context.append({
                                        'date': parsed_msg.get("Date", ""),
                                        'from': decode_mime_header(parsed_msg.get("From", "")),
                                        'subject': decode_mime_header(parsed_msg.get("Subject", "")),
                                        'body': extract_text_from_message(parsed_msg)[:1000],
                                        'message_id': msg_id,
                                        'thread_index': parsed_msg.get("Thread-Index", "")
                                    })
                                    seen_message_ids.add(msg_id)
                                    
                        except Exception as e:
                            logging.debug(f"Failed to fetch thread message {msg_num}: {e}")
                            
            except Exception as e:
                logging.debug(f"Thread-Index search failed: {e}")
        
        # Subject-based search fallback
        if len(thread_context) < 2 and original_subject:
            try:
                search_query = f'FROM "{sender_addr}" SUBJECT "{original_subject}"'
                _, data = imap.search(None, search_query)
                
                if data and data[0]:
                    msg_nums = data[0].split()[-5:]
                    for msg_num in msg_nums:
                        try:
                            _, fetch_data = imap.fetch(msg_num, "(RFC822)")
                            if fetch_data and fetch_data[0] and len(fetch_data[0]) > 1:
                                raw_msg = fetch_data[0][1]
                                parsed_msg = email.message_from_bytes(raw_msg)
                                
                                msg_id = parsed_msg.get("Message-ID", "")
                                if msg_id not in seen_message_ids:
                                    thread_context.append({
                                        'date': parsed_msg.get("Date", ""),
                                        'from': decode_mime_header(parsed_msg.get("From", "")),
                                        'subject': decode_mime_header(parsed_msg.get("Subject", "")),
                                        'body': extract_text_from_message(parsed_msg)[:1000],
                                        'message_id': msg_id,
                                        'thread_index': parsed_msg.get("Thread-Index", "")
                                    })
                                    seen_message_ids.add(msg_id)
                                    
                        except Exception as e:
                            logging.debug(f"Failed to fetch thread message {msg_num}: {e}")
                            
            except Exception as e:
                logging.debug(f"Subject-based thread search failed: {e}")
        
        imap.close()
        imap.logout()
        
        thread_context.sort(key=lambda x: x.get('date', ''))
        return thread_context[-limit:]
        
    except Exception as e:
        logging.error(f"Thread context fetch failed: {e}")
        return []

def summarize_thread(thread_context: List[Dict]) -> str:
    """Generate AI summary of thread context using SocGen AI"""
    if not thread_context:
        return ""
    
    thread_text = ""
    for ctx in thread_context:
        thread_text += f"[{ctx['date']}] From: {ctx['from']}\nSubject: {ctx['subject']}\n{ctx['body']}\n\n"
    
    if len(thread_text) > 4000:
        thread_text = thread_text[-4000:]
    
    summary_prompt = (
        "You are a corporate email thread summary assistant. Summarize this email conversation history in 2-4 sentences. "
        "Focus on: 1) What the business conversation is about, 2) Key decisions or requests made, "
        "3) Current status/next steps, 4) Any action items or deadlines mentioned. "
        "Be concise but capture the essential business context. Output only the summary text."
    )

    try:
        messages = [
            {"role": "system", "content": summary_prompt},
            {"role": "user", "content": thread_text},
        ]
        
        summary = socgen_client.chat_completion(messages, temperature=0.3, max_tokens=200)
        logging.info(f"Generated thread summary using SocGen AI: {summary[:100]}...")
        return summary.strip()
        
    except Exception as e:
        logging.error(f"Thread summary failed: {e}")
        return f"Corporate thread conversation with {len(thread_context)} previous messages. Unable to generate detailed summary."

def build_thread_aware_prompt(msg: email.message.Message, thread_context: List[Dict]) -> str:
    """Build AI prompt with full thread context (corporate optimized)"""
    subject = decode_mime_header(msg.get("Subject", "")) or "(no subject)"
    sender = decode_mime_header(msg.get("From", "")) or "(unknown sender)"
    sender_addr = parseaddr_safe(msg.get("From", ""))[1]
    
    importance = get_email_importance(msg)
    is_external = is_external_sender(sender_addr)
    is_vip = is_vip_sender(sender_addr)
    category = detect_email_category(msg)
    is_reply = is_thread_reply(msg)
    
    current_body = extract_text_from_message(msg)
    
    # Generate thread summary using SocGen AI
    thread_summary = summarize_thread(thread_context)
    
    # Build context section
    context_section = ""
    if thread_context:
        context_section = f"\n=== THREAD HISTORY SUMMARY ===\n{thread_summary}\n"
        context_section += "\n=== RECENT THREAD MESSAGES ===\n"
        for i, ctx in enumerate(thread_context[-3:], 1):
            context_section += f"\n{i}. [{ctx['date']}] From: {ctx['from']}\n"
            context_section += f"   Subject: {ctx['subject']}\n"
            context_section += f"   Body: {ctx['body'][:300]}...\n"
        context_section += "\n=== END THREAD HISTORY ===\n"
    
    metadata = f"""Corporate Email Analysis Request:

CURRENT EMAIL:
- Subject: {subject}
- From: {sender}
- Importance: {importance}
- External sender: {is_external}
- VIP sender: {is_vip}
- Category: {category}
- Is thread reply: {is_reply}
- Company domain: {COMPANY_DOMAIN or 'not set'}

{context_section}

CURRENT EMAIL BODY:
\"\"\"{current_body[:4000]}\"\"\"

INSTRUCTIONS:
This is a corporate email {'in an ongoing thread' if is_reply else 'starting a new conversation'}. 
{'Consider the full thread context and summary when generating your response.' if thread_context else 'Generate an appropriate response based on this email.'}

Maintain professional corporate communication standards. Be concise, clear, and actionable.

Provide a JSON response with corporate thread-aware analysis and reply generation.
"""
    
    return metadata

# -----------------------
# Enhanced AI Processing with SocGen API
# -----------------------
def socgen_chat_complete_with_thread(user_prompt: str, is_thread_reply: bool = False) -> dict:
    """Enhanced SocGen AI completion with thread awareness"""
    thread_context = "corporate thread continuation" if is_thread_reply else "new corporate conversation"
    
    system_prompt = f"""You are an advanced corporate email assistant specializing in {thread_context}.

CORPORATE EMAIL GUIDELINES:
- Maintain professional tone appropriate for business environment
- Be clear, concise, and actionable
- Respect corporate hierarchy and protocols
- Use appropriate salutations and closings
- Include relevant project/meeting references when applicable

When processing thread replies:
- Consider the full conversation history and business context
- Maintain consistency with previous communications
- Reference earlier decisions, commitments, or action items
- Provide continuity in business relationships
- Address specific questions or requests from the thread
- Avoid repeating information already covered

When processing new conversations:
- Focus on the current email content
- Provide comprehensive initial responses
- Set appropriate professional tone
- Establish clear next steps or expectations

Return ONLY a strict JSON object with keys:
{{
  "reply_needed": true|false,
  "urgency_score": 0.0-1.0,
  "category": "urgent|meeting|project|business|customer|internal|automated|newsletter",
  "sentiment": "positive|negative|neutral|professional", 
  "requires_action": true|false,
  "summary": "string",
  "key_points": ["point1", "point2"],
  "proposed_subject": "string",
  "proposed_body": "string",
  "confidence": 0.0-1.0,
  "thread_context_used": true|false,
  "is_thread_continuation": {str(is_thread_reply).lower()},
  "business_priority": "high|medium|low",
  "action_items": ["item1", "item2"]
}}

Be professional, contextually aware, and ensure replies maintain corporate thread continuity.
"""

    try:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        
        content = socgen_client.chat_completion(messages, temperature=0.3, max_tokens=1200)
        
        try:
            return json.loads(content)
        except Exception:
            m = re.search(r"\{[\s\S]*\}", content)
            if not m:
                raise ValueError("SocGen AI did not return valid JSON.")
            return json.loads(m.group(0))
            
    except Exception as e:
        logging.error(f"SocGen AI API error: {e}")
        return {
            "reply_needed": False,
            "urgency_score": 0.5,
            "category": "business",
            "sentiment": "professional",
            "requires_action": False,
            "summary": "AI analysis failed",
            "key_points": [],
            "proposed_subject": "",
            "proposed_body": "",
            "confidence": 0.0,
            "thread_context_used": False,
            "is_thread_continuation": is_thread_reply,
            "business_priority": "medium",
            "action_items": []
        }

# -----------------------
# Enhanced SMTP with Corporate Outlook Support
# -----------------------
# def smtp_send(to_addr: str, subject: str, body: str, headers: dict = None):
#     """Send email via SMTP with proper headers (Corporate Outlook optimized)"""
#     msg = EmailMessage()
#     msg["From"] = EMAIL_ADDRESS
#     msg["To"] = to_addr
#     msg["Subject"] = subject
#     msg["Date"] = email.utils.formatdate(localtime=True)
    
#     # Add custom Message-ID for better tracking
#     msg["Message-ID"] = email.utils.make_msgid(domain=EMAIL_ADDRESS.split('@')[1])
    
#     # Add threading headers with cleaning
#     for k, v in (headers or {}).items():
#         if v:
#             clean_value = clean_header(str(v))
#             msg[k] = clean_value
#             logging.info(f"Added header {k}: {clean_value[:50]}...")
    
#     # Add corporate-specific headers
#     msg["X-Mailer"] = "Corporate Email Agent v2.0"
#     msg["X-Priority"] = "3"  # Normal priority
    
#     msg.set_content(body)

#     context = ssl.create_default_context()
#     with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
#         if SMTP_STARTTLS:
#             s.starttls(context=context)
#         s.login(EMAIL_USER, EMAIL_PASS)
#         s.send_message(msg)


def smtp_send(to_addr: str, subject: str, body: str, headers: dict = None):
    """Enhanced SMTP send with corporate Exchange support"""
    msg = EmailMessage()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    
    # Add custom Message-ID for better tracking
    msg["Message-ID"] = email.utils.make_msgid(domain=EMAIL_ADDRESS.split('@')[1])
    
    # Add threading headers with cleaning
    for k, v in (headers or {}).items():
        if v:
            clean_value = clean_header(str(v))
            msg[k] = clean_value
            logging.info(f"Added header {k}: {clean_value[:50]}...")
    
    # Add corporate-specific headers
    msg["X-Mailer"] = "Corporate Email Agent v2.0"
    msg["X-Priority"] = "3"  # Normal priority
    
    msg.set_content(body)

    # Enhanced SSL context for corporate Exchange
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except:
        pass

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            if SMTP_STARTTLS:
                s.starttls(context=context)
            s.login(EMAIL_USER, EMAIL_PASS)
            s.send_message(msg)
    except Exception as e:
        logging.error(f"SMTP send failed: {e}")
        raise

# -----------------------
# Enhanced Message Processing (Corporate)
# -----------------------
def requires_manual_review(msg: email.message.Message, ai_decision: dict) -> Tuple[bool, str]:
    """Determine if email requires manual review (corporate rules)"""
    reasons = []
    
    if REQUIRE_REVIEW_HIGH_IMPORTANCE and get_email_importance(msg) == "high":
        reasons.append("High importance email")
    
    from_addr = parseaddr_safe(msg.get("From", ""))[1]
    if REQUIRE_REVIEW_EXTERNAL and is_external_sender(from_addr):
        reasons.append("External sender")
    
    if is_vip_sender(from_addr):
        reasons.append("VIP sender")
    
    if ai_decision.get("urgency_score", 0) > 0.8:
        reasons.append("High urgency detected")
    
    if ai_decision.get("confidence", 1.0) < 0.7:
        reasons.append("Low AI confidence")
    
    if ai_decision.get("is_thread_continuation") and ai_decision.get("confidence", 1.0) < 0.8:
        reasons.append("Complex thread continuation")
    
    # Corporate-specific review triggers
    if ai_decision.get("business_priority") == "high":
        reasons.append("High business priority")
    
    if len(ai_decision.get("action_items", [])) > 0:
        reasons.append("Contains action items")
    
    # Check for sensitive corporate keywords
    body = extract_text_from_message(msg).lower()
    sensitive_keywords = ["contract", "legal", "compliance", "confidential", "budget", "merger", "acquisition"]
    if any(keyword in body for keyword in sensitive_keywords):
        reasons.append("Contains sensitive corporate content")
    
    return len(reasons) > 0, "; ".join(reasons)

def add_to_pending_review(msg: email.message.Message, decision: dict, reason: str, thread_summary: str = "", thread_context: List[Dict] = None):
    """Add email to pending review queue with complete thread information (corporate enhanced)"""
    
    # Store complete original message for proper threading later
    original_headers = {}
    for header_name in ['Message-ID', 'In-Reply-To', 'References', 'Date', 'Thread-Index']:
        header_value = msg.get(header_name)
        if header_value:
            original_headers[header_name] = header_value
    
    pending_item = {
        "timestamp": datetime.now().isoformat(),
        "message_id": msg.get("Message-ID"),
        "from": msg.get("From"),
        "subject": decode_mime_header(msg.get("Subject", "")),
        "importance": get_email_importance(msg),
        "category": decision.get("category", "unknown"),
        "reason": reason,
        "ai_decision": decision,
        "body_preview": extract_text_from_message(msg)[:200] + "...",
        "is_thread_reply": is_thread_reply(msg),
        "thread_context_used": decision.get("thread_context_used", False),
        "thread_summary": thread_summary,
        "original_headers": original_headers,
        "thread_context": thread_context or [],
        "business_priority": decision.get("business_priority", "medium"),
        "action_items": decision.get("action_items", [])
    }
    PENDING_REVIEW.append(pending_item)
    logging.info("Added to corporate review queue: %s - %s", pending_item["from"], reason)
    
    notify_title = "Corporate Email Pending Review"
    notify_message = f"From: {pending_item['from']}\nSubject: {pending_item['subject']}\nReason: {reason}"
    desktop_notify(notify_title, notify_message)

def process_one_message(msg: email.message.Message):
    """Enhanced message processing with corporate thread awareness"""
    subject = decode_mime_header(msg.get("Subject", ""))
    from_name, from_addr = parseaddr_safe(msg.get("From", ""))
    reply_to_name, reply_to_addr = parseaddr_safe(msg.get("Reply-To") or msg.get("From", ""))
    
    importance = get_email_importance(msg)
    category = detect_email_category(msg)
    is_reply = is_thread_reply(msg)
    
    # Guards
    if not from_addr:
        logging.info("Skip: no From address")
        return
        
    if is_no_reply(from_addr) or (reply_to_addr and is_no_reply(reply_to_addr)):
        logging.info("Skip no-reply sender: %s", from_addr)
        return

    body = extract_text_from_message(msg).strip()
    if not body:
        logging.info("Skip: empty body")
        return

    logging.info("Corporate processing | from=%s | subject=%s | importance=%s | category=%s | thread_reply=%s", 
                from_addr, subject, importance, category, is_reply)

    # Fetch thread context if this is a reply
    thread_context = []
    thread_summary = ""
    if is_reply:
        thread_context = fetch_thread_context(msg, limit=5)
        thread_summary = summarize_thread(thread_context)
        logging.info("Thread context: %d previous messages found", len(thread_context))
        if thread_summary:
            logging.info("Thread summary: %s", thread_summary[:100])

    # AI analysis with thread context using SocGen AI
    try:
        prompt = build_thread_aware_prompt(msg, thread_context)
        decision = socgen_chat_complete_with_thread(prompt, is_reply)
        
        if decision.get("thread_context_used"):
            logging.info("SocGen AI used thread context for analysis")
            
    except Exception as e:
        logging.error("SocGen AI processing error: %s", e)
        return

    reply_needed = bool(decision.get("reply_needed", False))
    confidence = decision.get("confidence", 0.5)
    
    logging.info("SocGen AI analysis | reply_needed=%s | confidence=%.2f | thread_continuation=%s | business_priority=%s", 
                reply_needed, confidence, decision.get("is_thread_continuation"), decision.get("business_priority"))

    if not reply_needed:
        logging.info("Decision: no reply needed")
        return

    # Check manual review requirements
    needs_review, review_reason = requires_manual_review(msg, decision)
    
    if needs_review:
        add_to_pending_review(msg, decision, review_reason, thread_summary, thread_context)
        return

    # Prepare reply
    proposed_subject = decision.get("proposed_subject", "").strip()
    proposed_body = decision.get("proposed_body", "").strip()

    if not proposed_body:
        logging.info("Skip: SocGen AI did not generate reply body")
        return

    # Generate proper reply subject
    if is_reply:
        original_subject = extract_original_subject(subject)
        final_subject = f"Re: {original_subject}" if original_subject else f"Re: {subject}"
    else:
        final_subject = proposed_subject if proposed_subject else f"Re: {subject}"

    to_addr = reply_to_addr or from_addr
    if to_addr.lower() == EMAIL_ADDRESS.lower():
        logging.info("Skip: would reply to self")
        return

    # Generate proper threading headers
    headers = threading_headers(msg)
    
    # Clean headers before sending
    cleaned_headers = {k: clean_header(v) for k, v in headers.items()}
    
    logging.info("Corporate thread-aware reply → %s | %s | confidence=%.2f | headers=%s", 
                to_addr, final_subject, confidence, list(headers.keys()))
    logging.info("Reply body preview: %s", proposed_body[:200] + "...")

    if DRY_RUN:
        logging.info("DRY_RUN=1 (not sending). Set DRY_RUN=0 to send.")
        return

    try:
        smtp_send(to_addr, final_subject, proposed_body, cleaned_headers)
        logging.info("Sent corporate thread-aware reply to %s", to_addr)
    except Exception as e:
        logging.error("Send failed: %s", e)

# -----------------------
# IMAP Functions (Corporate Outlook Optimized)
# -----------------------
# def imap_fetch_unseen(limit=10) -> List[email.message.Message]:
#     """Fetch unread emails from corporate Outlook, prioritizing high importance"""
#     try:
#         # Enhanced SSL context for corporate environments
#         context = ssl.create_default_context()
#         context.check_hostname = False
#         context.verify_mode = ssl.CERT_NONE  # For corporate self-signed certs
        
#         imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=context)
#         imap.login(EMAIL_USER, EMAIL_PASS)
#         imap.select("INBOX")
        
#         try:
#             # Search for high importance emails first
#             _, high_data = imap.search(None, "(UNSEEN HEADER Importance high)")
#             _, normal_data = imap.search(None, "(UNSEEN NOT HEADER Importance high)")
            
#             high_ids = high_data[0].split() if high_data and high_data[0] else []
#             normal_ids = normal_data[0].split() if normal_data and normal_data[0] else []
            
#             ids = (high_ids + normal_ids)[:limit]
#         except:
#             _, data = imap.search(None, "(UNSEEN)")
#             ids = (data[0].split() if data and data[0] else [])[:limit]
        
#         messages = []
#         for num in ids:
#             try:
#                 _, msg_data = imap.fetch(num, "(RFC822)")
#                 if not msg_data:
#                     continue
#                 raw = msg_data[0][1]
#                 messages.append(email.message_from_bytes(raw))
#             except Exception as e:
#                 logging.error(f"Failed to fetch message {num}: {e}")
#                 continue
        
#         imap.close()
#         imap.logout()
#         return messages
        
#     except Exception as e:
#         logging.error(f"Corporate IMAP fetch error: {e}")
#         return []

def imap_fetch_unseen(limit=10) -> List[email.message.Message]:
    """Enhanced IMAP fetch with corporate Exchange support and auto-discovery"""
    global IMAP_HOST, IMAP_PORT, SMTP_HOST, SMTP_PORT
    
    # Auto-discover if using default Office 365 settings in corporate environment
    if IMAP_HOST == "outlook.office365.com" and EMAIL_ADDRESS:
        logging.info("Detecting corporate Exchange server settings...")
        
        discovered = discover_corporate_settings(EMAIL_ADDRESS)
        if discovered['imap_host']:
            IMAP_HOST = discovered['imap_host']
            IMAP_PORT = discovered['imap_port']
            if discovered['smtp_host']:
                SMTP_HOST = discovered['smtp_host']
                SMTP_PORT = discovered['smtp_port']
            
            logging.info(f"Discovered corporate settings - IMAP: {IMAP_HOST}:{IMAP_PORT}, SMTP: {SMTP_HOST}:{SMTP_PORT}")
        else:
            logging.error("Could not discover corporate Exchange settings. Please configure manually.")
            return []
    
    try:
        # Enhanced SSL context for corporate environments
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For corporate self-signed certs
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Add support for legacy SSL/TLS versions if needed
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1
        except:
            pass
        
        # Set connection timeout
        socket.setdefaulttimeout(30)
        
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=context)
        
        # Enhanced login with better error handling
        try:
            imap.login(EMAIL_USER, EMAIL_PASS)
        except imaplib.IMAP4.error as e:
            if "authentication failed" in str(e).lower():
                logging.error("IMAP authentication failed. Check credentials or enable app passwords.")
            else:
                logging.error(f"IMAP login error: {e}")
            return []
        
        imap.select("INBOX")
        
        try:
            # Search for high importance emails first
            _, high_data = imap.search(None, "(UNSEEN HEADER Importance high)")
            _, normal_data = imap.search(None, "(UNSEEN NOT HEADER Importance high)")
            
            high_ids = high_data[0].split() if high_data and high_data[0] else []
            normal_ids = normal_data[0].split() if normal_data and normal_data[0] else []
            
            ids = (high_ids + normal_ids)[:limit]
        except:
            # Fallback for Exchange servers that don't support complex searches
            _, data = imap.search(None, "(UNSEEN)")
            ids = (data[0].split() if data and data[0] else [])[:limit]
        
        messages = []
        for num in ids:
            try:
                _, msg_data = imap.fetch(num, "(RFC822)")
                if not msg_data:
                    continue
                raw = msg_data[0][1]
                messages.append(email.message_from_bytes(raw))
            except Exception as e:
                logging.error(f"Failed to fetch message {num}: {e}")
                continue
        
        imap.close()
        imap.logout()
        return messages
        
    except socket.gaierror as e:
        logging.error(f"DNS resolution failed for {IMAP_HOST}: {e}")
        logging.error("This suggests your Exchange server hostname is incorrect.")
        logging.error("Try checking your corporate Exchange server settings or contact IT support.")
        return []
    except socket.timeout:
        logging.error(f"Connection timeout to {IMAP_HOST}:{IMAP_PORT}")
        logging.error("This might indicate firewall blocking or incorrect server settings.")
        return []
    except ConnectionRefusedError:
        logging.error(f"Connection refused by {IMAP_HOST}:{IMAP_PORT}")
        logging.error("Check if the server is running and the port is correct.")
        return []
    except Exception as e:
        logging.error(f"Corporate IMAP fetch error: {e}")
        return []
    finally:
        socket.setdefaulttimeout(None)

def run_cycle():
    """Run one processing cycle (corporate enhanced)"""
    try:
        msgs = imap_fetch_unseen(limit=MAX_EMAILS_PER_CYCLE)
        if not msgs:
            logging.info("No unread corporate emails.")
            return
        
        logging.info("Processing %d unread corporate emails", len(msgs))
        for m in msgs:
            msg_id = (m.get("Message-ID") or "").strip()
            if msg_id and msg_id in PROCESSED:
                logging.info("Skip (already processed): %s", msg_id)
                continue
            process_one_message(m)
            if msg_id:
                PROCESSED.add(msg_id)
        save_state()
        
        if PENDING_REVIEW:
            logging.info("=== %d corporate emails pending manual review ===", len(PENDING_REVIEW))
            
    except Exception as e:
        logging.error("Corporate cycle error: %s", e)

def show_pending_review():
    """Display emails pending manual review (corporate enhanced)"""
    if not PENDING_REVIEW:
        print("No corporate emails pending review.")
        return
    
    print(f"\n=== {len(PENDING_REVIEW)} Corporate Emails Pending Review ===")
    for i, item in enumerate(PENDING_REVIEW, 1):
        print(f"\n{i}. From: {item['from']}")
        print(f"   Subject: {item['subject']}")
        print(f"   Importance: {item['importance']}")
        print(f"   Business Priority: {item.get('business_priority', 'medium')}")
        print(f"   Thread Reply: {item.get('is_thread_reply', False)}")
        print(f"   Action Items: {len(item.get('action_items', []))}")
        print(f"   Reason: {item['reason']}")
        print(f"   Preview: {item['body_preview']}")
        if item.get("thread_summary"):
            print(f"   Thread Summary: {item['thread_summary'][:200]}...")

# -----------------------
# Corporate Health Check
# -----------------------
# def test_corporate_connections():
#     """Test all corporate connections before starting"""
#     print("Testing corporate connections...")
    
#     # Test SocGen AI API
#     try:
#         token = socgen_client.get_access_token()
#         test_messages = [
#             {"role": "system", "content": "You are a test assistant."},
#             {"role": "user", "content": "Say 'Corporate AI connection successful'"}
#         ]
#         response = socgen_client.chat_completion(test_messages, max_tokens=50)
#         print("✓ SocGen AI API: Connected")
#     except Exception as e:
#         print(f"✗ SocGen AI API: Failed - {e}")
#         return False
    
#     # Test Corporate Email (IMAP)
#     try:
#         context = ssl.create_default_context()
#         context.check_hostname = False
#         context.verify_mode = ssl.CERT_NONE
        
#         imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=context)
#         imap.login(EMAIL_USER, EMAIL_PASS)
#         imap.select("INBOX")
#         _, data = imap.search(None, "(ALL)")
#         imap.close()
#         imap.logout()
#         print("✓ Corporate Outlook IMAP: Connected")
#     except Exception as e:
#         print(f"✗ Corporate Outlook IMAP: Failed - {e}")
#         return False
    
#     # Test Corporate Email (SMTP)
#     try:
#         context = ssl.create_default_context()
#         with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
#             if SMTP_STARTTLS:
#                 s.starttls(context=context)
#             s.login(EMAIL_USER, EMAIL_PASS)
#         print("✓ Corporate Outlook SMTP: Connected")
#     except Exception as e:
#         print(f"✗ Corporate Outlook SMTP: Failed - {e}")
#         return False
    
#     print("All corporate connections successful!")
#     return True


def test_corporate_connections():
    """Enhanced connection testing with auto-discovery"""
    print("Testing corporate connections...")
    
    global IMAP_HOST, IMAP_PORT, SMTP_HOST, SMTP_PORT
    
    # Auto-discover if needed
    if IMAP_HOST == "outlook.office365.com" and EMAIL_ADDRESS:
        print("Attempting to discover corporate Exchange settings...")
        discovered = discover_corporate_settings(EMAIL_ADDRESS)
        if discovered['imap_host']:
            IMAP_HOST = discovered['imap_host']
            IMAP_PORT = discovered['imap_port']
            if discovered['smtp_host']:
                SMTP_HOST = discovered['smtp_host']
                SMTP_PORT = discovered['smtp_port']
            print(f"Discovered: IMAP={IMAP_HOST}:{IMAP_PORT}, SMTP={SMTP_HOST}:{SMTP_PORT}")
        else:
            print("Auto-discovery failed. Please configure server settings manually.")
            print("Common corporate patterns to try:")
            domain = EMAIL_ADDRESS.split('@')[1] if '@' in EMAIL_ADDRESS else ""
            print(f"  - mail.{domain}")
            print(f"  - exchange.{domain}")
            print(f"  - imap.{domain}")
            return False
    
    # Test SocGen AI API
    try:
        token = socgen_client.get_access_token()
        test_messages = [
            {"role": "system", "content": "You are a test assistant."},
            {"role": "user", "content": "Say 'Corporate AI connection successful'"}
        ]
        response = socgen_client.chat_completion(test_messages, max_tokens=50)
        print("✓ SocGen AI API: Connected")
    except Exception as e:
        print(f"✗ SocGen AI API: Failed - {e}")
        return False
    
    # Test Corporate IMAP
    if test_imap_connection(IMAP_HOST, IMAP_PORT, EMAIL_USER, EMAIL_PASS):
        print(f"✓ Corporate Exchange IMAP: Connected ({IMAP_HOST}:{IMAP_PORT})")
    else:
        print(f"✗ Corporate Exchange IMAP: Failed ({IMAP_HOST}:{IMAP_PORT})")
        return False
    
    # Test Corporate SMTP
    if test_smtp_connection(SMTP_HOST, SMTP_PORT, EMAIL_USER, EMAIL_PASS):
        print(f"✓ Corporate Exchange SMTP: Connected ({SMTP_HOST}:{SMTP_PORT})")
    else:
        print(f"✗ Corporate Exchange SMTP: Failed ({SMTP_HOST}:{SMTP_PORT})")
        return False
    
    print("All corporate connections successful!")
    return True

# -----------------------
# Main Execution (Corporate Enhanced)
# -----------------------
if __name__ == "__main__":
    logging.info("Corporate Email Agent starting (DRY_RUN=%s, POLL_SECONDS=%s)", int(DRY_RUN), POLL_SECONDS)
    logging.info("Provider: Corporate Outlook (%s) | Company: %s", SMTP_HOST, COMPANY_DOMAIN)
    logging.info("AI: SocGen Corporate API | Model: %s", SOCGEN_MODEL)
    logging.info("Review settings: HIGH_IMPORTANCE=%s, EXTERNAL=%s", 
                REQUIRE_REVIEW_HIGH_IMPORTANCE, REQUIRE_REVIEW_EXTERNAL)
    logging.info("Thread handling: ENABLED with corporate context fetch")
    
    # Test connections before starting
    if not test_corporate_connections():
        print("Connection tests failed. Please check your configuration.")
        exit(1)
    
    if PENDING_REVIEW:
        show_pending_review()
    
    try:
        while True:
            run_cycle()
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        logging.info("Corporate agent stopped by user")
        save_state()
    except Exception as e:
        logging.error("Corporate agent crashed: %s", e)
        save_state()
