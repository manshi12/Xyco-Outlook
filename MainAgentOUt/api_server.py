# api_server_corporate.py - Enhanced FastAPI server for Corporate Environment
# FastAPI REST API for Corporate Email Agent Dashboard with SocGen AI Integration

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
import os
import threading
import time
import email
from datetime import datetime, timedelta
import asyncio
from contextlib import asynccontextmanager
import requests
import imaplib
import smtplib
# Import your enhanced corporate agent
import mvp_agent as mvp_agent
import ssl

# Enhanced Pydantic Models for Corporate Environment
class EmailSummary(BaseModel):
    message_id: str
    from_addr: str
    subject: str
    timestamp: str
    importance: str
    category: str
    status: str
    is_thread_reply: Optional[bool] = False
    business_priority: Optional[str] = "medium"

class PendingEmail(BaseModel):
    id: str
    timestamp: str
    message_id: str
    from_addr: str
    subject: str
    importance: str
    category: str
    reason: str
    ai_decision: Dict[str, Any]
    body_preview: str
    is_thread_reply: Optional[bool] = False
    thread_context_used: Optional[bool] = False
    thread_summary: Optional[str] = None
    business_priority: Optional[str] = "medium"
    action_items: Optional[List[str]] = []

class EmailAction(BaseModel):
    action: str  # approve, reject, modify
    reply_subject: Optional[str] = None
    reply_body: Optional[str] = None
    maintain_thread: Optional[bool] = True

class AgentStatus(BaseModel):
    is_running: bool
    last_cycle: str
    processed_count: int
    pending_count: int
    error_count: int
    uptime_seconds: int
    thread_processing_enabled: bool = True
    ai_provider: str = "SocGen Corporate API"
    email_provider: str = "Corporate Outlook"

class AgentConfig(BaseModel):
    poll_seconds: int
    dry_run: bool
    max_emails_per_cycle: int
    require_review_high_importance: bool
    require_review_external: bool
    company_domain: str
    thread_context_limit: Optional[int] = 5
    socgen_model: Optional[str] = "azure-openai-gpt-40-mini-2024-07-18"

class CorporateAnalytics(BaseModel):
    processed_today: int
    sent_today: int
    errors_today: int
    thread_replies_processed: int
    thread_replies_sent: int
    by_category: Dict[str, int]
    by_hour: List[int]
    pending_count: int
    success_rate: float
    thread_success_rate: float
    thread_percentage: float
    corporate_metrics: Dict[str, Any]

class SocGenAPIStatus(BaseModel):
    connected: bool
    token_valid: bool
    token_expires: Optional[str]
    model: str
    last_request: Optional[str]

# Enhanced global state for corporate environment
agent_thread = None
agent_running = False
start_time = datetime.now()
email_stats = {
    "processed_today": 0,
    "sent_today": 0,
    "errors_today": 0,
    "thread_replies_processed": 0,
    "thread_replies_sent": 0,
    "by_category": {},
    "by_hour": [0] * 24,
    "thread_context_usage": [],
    "socgen_api_calls": 0,
    "corporate_external_emails": 0,
    "high_priority_emails": 0
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting Corporate Email Agent API with SocGen AI Integration...")
    yield
    global agent_running
    agent_running = False
    print("Corporate Email Agent API shutting down...")

app = FastAPI(
    title="Corporate Email Agent Dashboard API",
    description="REST API for Corporate Email Agent Management with SocGen AI",
    version="2.0.0-Corporate",
    lifespan=lifespan
)

# Enhanced CORS for corporate environment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for your corporate network
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Save the original functions for tracking
true_original_process_one = mvp_agent.process_one_message
true_original_smtp_send = mvp_agent.smtp_send

def run_agent_with_corporate_stats():
    """Enhanced agent runner with corporate-aware statistics tracking"""
    global agent_running, email_stats
    
    def tracked_process_one(msg):
        result = true_original_process_one(msg)
        
        current_hour = datetime.now().hour
        email_stats["processed_today"] += 1
        email_stats["by_hour"][current_hour] += 1
        
        # Corporate-specific tracking
        is_reply = mvp_agent.is_thread_reply(msg)
        if is_reply:
            email_stats["thread_replies_processed"] += 1
        
        # Track external vs internal
        sender_addr = mvp_agent.parseaddr_safe(msg.get("From", ""))[1]
        if mvp_agent.is_external_sender(sender_addr):
            email_stats["corporate_external_emails"] += 1
        
        # Track high priority
        if mvp_agent.get_email_importance(msg) == "high":
            email_stats["high_priority_emails"] += 1
        
        category = mvp_agent.detect_email_category(msg)
        email_stats["by_category"][category] = email_stats["by_category"].get(category, 0) + 1
        
        return result
    
    def tracked_smtp_send(*args, **kwargs):
        result = true_original_smtp_send(*args, **kwargs)
        email_stats["sent_today"] += 1
        email_stats["thread_replies_sent"] += 1  # Most corporate replies are thread continuations
        return result
    
    # Apply tracking wrappers
    mvp_agent.process_one_message = tracked_process_one
    mvp_agent.smtp_send = tracked_smtp_send
    
    while agent_running:
        try:
            mvp_agent.run_cycle()
        except Exception as e:
            print(f"Corporate agent error: {e}")
            email_stats["errors_today"] += 1
        
        time.sleep(mvp_agent.POLL_SECONDS)

# Enhanced Corporate API Endpoints

@app.get("/api/status", response_model=AgentStatus)
async def get_agent_status():
    """Get current agent status with corporate information"""
    uptime = (datetime.now() - start_time).total_seconds()
    
    return AgentStatus(
        is_running=agent_running,
        last_cycle=datetime.now().isoformat(),
        processed_count=email_stats["processed_today"],
        pending_count=len(mvp_agent.PENDING_REVIEW),
        error_count=email_stats["errors_today"],
        uptime_seconds=int(uptime),
        thread_processing_enabled=True,
        ai_provider="SocGen Corporate API",
        email_provider="Corporate Outlook"
    )

@app.get("/api/socgen-status", response_model=SocGenAPIStatus)
async def get_socgen_api_status():
    """Get SocGen AI API connection status"""
    try:
        client = mvp_agent.socgen_client
        token_valid = client.is_token_valid()
        
        return SocGenAPIStatus(
            connected=True,
            token_valid=token_valid,
            token_expires=client.token_expires.isoformat() if client.token_expires else None,
            model=mvp_agent.SOCGEN_MODEL,
            last_request=datetime.now().isoformat()
        )
    except Exception as e:
        return SocGenAPIStatus(
            connected=False,
            token_valid=False,
            token_expires=None,
            model=mvp_agent.SOCGEN_MODEL,
            last_request=None
        )

@app.get("/api/config", response_model=AgentConfig)
async def get_agent_config():
    """Get current agent configuration with corporate settings"""
    return AgentConfig(
        poll_seconds=mvp_agent.POLL_SECONDS,
        dry_run=mvp_agent.DRY_RUN,
        max_emails_per_cycle=mvp_agent.MAX_EMAILS_PER_CYCLE,
        require_review_high_importance=mvp_agent.REQUIRE_REVIEW_HIGH_IMPORTANCE,
        require_review_external=mvp_agent.REQUIRE_REVIEW_EXTERNAL,
        company_domain=mvp_agent.COMPANY_DOMAIN,
        thread_context_limit=5,
        socgen_model=mvp_agent.SOCGEN_MODEL
    )

@app.post("/api/config")
async def update_agent_config(config: AgentConfig):
    """Update agent configuration including corporate settings"""
    mvp_agent.POLL_SECONDS = config.poll_seconds
    mvp_agent.DRY_RUN = config.dry_run
    mvp_agent.MAX_EMAILS_PER_CYCLE = config.max_emails_per_cycle
    mvp_agent.REQUIRE_REVIEW_HIGH_IMPORTANCE = config.require_review_high_importance
    mvp_agent.REQUIRE_REVIEW_EXTERNAL = config.require_review_external
    mvp_agent.COMPANY_DOMAIN = config.company_domain
    
    return {"message": "Corporate configuration updated successfully"}

@app.post("/api/agent/start")
async def start_agent(background_tasks: BackgroundTasks):
    """Start the corporate email agent"""
    global agent_running, agent_thread
    
    if agent_running:
        raise HTTPException(status_code=400, detail="Corporate agent is already running")
    
    # Test connections before starting
    try:
        mvp_agent.test_corporate_connections()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Corporate connection test failed: {e}")
    
    agent_running = True
    agent_thread = threading.Thread(target=run_agent_with_corporate_stats, daemon=True)
    agent_thread.start()
    
    return {"message": "Corporate agent started successfully with SocGen AI integration"}

@app.post("/api/agent/stop")
async def stop_agent():
    """Stop the corporate email agent"""
    global agent_running
    
    if not agent_running:
        raise HTTPException(status_code=400, detail="Corporate agent is not running")
    
    agent_running = False
    return {"message": "Corporate agent stopped successfully"}

@app.get("/api/emails/pending", response_model=List[PendingEmail])
async def get_pending_emails():
    """Get emails pending manual review with corporate thread information"""
    pending_emails = []
    
    for i, item in enumerate(mvp_agent.PENDING_REVIEW):
        pending_emails.append(PendingEmail(
            id=str(i),
            timestamp=item["timestamp"],
            message_id=item["message_id"],
            from_addr=item["from"],
            subject=item["subject"],
            importance=item["importance"],
            category=item["category"],
            reason=item["reason"],
            ai_decision=item["ai_decision"],
            body_preview=item["body_preview"],
            is_thread_reply=item.get("is_thread_reply", False),
            thread_context_used=item.get("thread_context_used", False),
            thread_summary=item.get("thread_summary", ""),
            business_priority=item.get("business_priority", "medium"),
            action_items=item.get("action_items", [])
        ))
    
    return pending_emails

@app.post("/api/emails/pending/{email_id}/action")
async def handle_pending_email_with_threading(email_id: str, action: EmailAction):
    """Handle action on pending corporate email with PROPER thread support"""
    try:
        email_index = int(email_id)
        if email_index >= len(mvp_agent.PENDING_REVIEW):
            raise HTTPException(status_code=404, detail="Email not found")
        
        email_item = mvp_agent.PENDING_REVIEW[email_index]
        
        # Extract sender info
        sender = email_item["from"]
        if '<' in sender and '>' in sender:
            to_addr = sender.split('<')[-1].strip('>')
        else:
            to_addr = sender.strip()
        
        if action.action == "approve":
            # Send the AI-generated reply with PROPER threading
            reply_subject = email_item["ai_decision"].get("proposed_subject", f"Re: {email_item['subject']}")
            reply_body = email_item["ai_decision"].get("proposed_body", "")
            
            if not mvp_agent.DRY_RUN:
                headers = {}
                if action.maintain_thread and email_item.get("is_thread_reply"):
                    # Use stored original headers to maintain thread
                    original_headers = email_item.get("original_headers", {})
                    
                    original_msg_id = original_headers.get("Message-ID", "")
                    if original_msg_id:
                        headers["In-Reply-To"] = original_msg_id
                    
                    existing_refs = original_headers.get("References", "")
                    if existing_refs and original_msg_id:
                        headers["References"] = f"{existing_refs} {original_msg_id}"
                    elif original_msg_id:
                        headers["References"] = original_msg_id
                    elif existing_refs:
                        headers["References"] = existing_refs
                    
                    # Add Outlook Thread-Index if available
                    thread_index = original_headers.get("Thread-Index")
                    if thread_index:
                        headers["Thread-Index"] = thread_index
                
                if email_item.get("is_thread_reply"):
                    original_subject = mvp_agent.extract_original_subject(email_item["subject"])
                    reply_subject = f"Re: {original_subject}" if original_subject else f"Re: {email_item['subject']}"
                
                print(f"Sending corporate reply with threading headers: {headers}")
                mvp_agent.smtp_send(to_addr, reply_subject, reply_body, headers)
            
            mvp_agent.PENDING_REVIEW.pop(email_index)
            mvp_agent.save_state()
            
            return {"message": f"Corporate thread-aware reply {'sent' if not mvp_agent.DRY_RUN else 'approved (DRY RUN)'}"}
        
        elif action.action == "modify":
            if not action.reply_subject or not action.reply_body:
                raise HTTPException(status_code=400, detail="Modified subject and body required")
            
            if not mvp_agent.DRY_RUN:
                headers = {}
                if action.maintain_thread and email_item.get("is_thread_reply"):
                    original_headers = email_item.get("original_headers", {})
                    
                    original_msg_id = original_headers.get("Message-ID", "")
                    if original_msg_id:
                        headers["In-Reply-To"] = original_msg_id
                    
                    existing_refs = original_headers.get("References", "")
                    if existing_refs and original_msg_id:
                        headers["References"] = f"{existing_refs} {original_msg_id}"
                    elif original_msg_id:
                        headers["References"] = original_msg_id
                    elif existing_refs:
                        headers["References"] = existing_refs
                    
                    thread_index = original_headers.get("Thread-Index")
                    if thread_index:
                        headers["Thread-Index"] = thread_index
                
                print(f"Sending modified corporate reply with threading headers: {headers}")
                mvp_agent.smtp_send(to_addr, action.reply_subject, action.reply_body, headers)
            
            mvp_agent.PENDING_REVIEW.pop(email_index)
            mvp_agent.save_state()
            
            return {"message": f"Modified corporate thread reply {'sent' if not mvp_agent.DRY_RUN else 'approved (DRY RUN)'}"}
        
        elif action.action == "reject":
            mvp_agent.PENDING_REVIEW.pop(email_index)
            mvp_agent.save_state()
            
            return {"message": "Corporate email rejected (no reply sent)"}
        
        else:
            raise HTTPException(status_code=400, detail="Invalid action")
            
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid email ID")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/analytics/stats", response_model=CorporateAnalytics)
async def get_corporate_analytics_stats():
    """Get enhanced corporate email processing analytics"""
    thread_success_rate = 0
    if email_stats["thread_replies_processed"] > 0:
        thread_success_rate = (email_stats["thread_replies_sent"] / email_stats["thread_replies_processed"]) * 100
    
    corporate_metrics = {
        "external_email_percentage": (
            email_stats["corporate_external_emails"] / max(email_stats["processed_today"], 1) * 100
        ),
        "high_priority_percentage": (
            email_stats["high_priority_emails"] / max(email_stats["processed_today"], 1) * 100
        ),
        "socgen_api_calls": email_stats["socgen_api_calls"],
        "avg_response_time": "< 30s",  # Placeholder - implement actual timing
        "compliance_score": 95.0  # Placeholder - implement compliance tracking
    }
    
    return CorporateAnalytics(
        processed_today=email_stats["processed_today"],
        sent_today=email_stats["sent_today"],
        errors_today=email_stats["errors_today"],
        thread_replies_processed=email_stats["thread_replies_processed"],
        thread_replies_sent=email_stats["thread_replies_sent"],
        by_category=email_stats["by_category"],
        by_hour=email_stats["by_hour"],
        pending_count=len(mvp_agent.PENDING_REVIEW),
        success_rate=(
            email_stats["sent_today"] / max(email_stats["processed_today"], 1) * 100
        ),
        thread_success_rate=thread_success_rate,
        thread_percentage=(
            email_stats["thread_replies_processed"] / max(email_stats["processed_today"], 1) * 100
        ),
        corporate_metrics=corporate_metrics
    )

@app.get("/api/vip-senders")
async def get_vip_senders():
    """Get VIP senders list"""
    return {"vip_senders": list(mvp_agent.VIP_SENDERS)}

@app.post("/api/vip-senders")
async def update_vip_senders(vip_data: dict):
    """Update VIP senders list"""
    vip_senders = vip_data.get("vip_senders", [])
    mvp_agent.VIP_SENDERS = set(vip_senders)
    
    try:
        with open(mvp_agent.VIP_SENDERS_FILE, 'w') as f:
            json.dump(vip_senders, f, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save VIP senders: {e}")
    
    return {"message": "VIP senders updated successfully"}

@app.post("/api/agent/test-cycle")
async def run_test_cycle():
    """Run a single test cycle manually"""
    try:
        mvp_agent.run_cycle()
        return {"message": "Corporate test cycle completed successfully with thread processing"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Corporate test cycle failed: {e}")

@app.post("/api/socgen/test-connection")
async def test_socgen_connection():
    """Test SocGen AI API connection"""
    try:
        client = mvp_agent.socgen_client
        token = client.get_access_token()
        
        # Test with a simple message
        test_messages = [
            {"role": "system", "content": "You are a corporate email assistant."},
            {"role": "user", "content": "Test connection - respond with 'SocGen AI connected successfully'"}
        ]
        
        response = client.chat_completion(test_messages, max_tokens=50)
        
        return {
            "success": True,
            "message": "SocGen AI connection successful",
            "response": response,
            "token_expires": client.token_expires.isoformat() if client.token_expires else None
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"SocGen AI connection failed: {str(e)}",
            "response": None,
            "token_expires": None
        }

@app.post("/api/outlook/test-connection")
async def test_outlook_connection():
    """Test corporate Outlook/Exchange connection with enhanced discovery"""
    try:
        # Use the enhanced connection testing
        success = mvp_agent.test_corporate_connections()
        
        if success:
            # Get final server settings after discovery
            imap_host = mvp_agent.IMAP_HOST
            smtp_host = mvp_agent.SMTP_HOST
            
            # Get email count
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                imap = imaplib.IMAP4_SSL(imap_host, mvp_agent.IMAP_PORT, ssl_context=context)
                imap.login(mvp_agent.EMAIL_USER, mvp_agent.EMAIL_PASS)
                imap.select("INBOX")
                _, data = imap.search(None, "(ALL)")
                total_emails = len(data[0].split()) if data and data[0] else 0
                imap.close()
                imap.logout()
            except:
                total_emails = 0
            
            return {
                "success": True,
                "message": "Corporate Exchange connection successful",
                "total_emails": total_emails,
                "imap_host": imap_host,
                "smtp_host": smtp_host,
                "discovered": imap_host != "outlook.office365.com"  # Shows if auto-discovery worked
            }
        else:
            return {
                "success": False,
                "message": "Corporate Exchange connection failed - check server settings",
                "total_emails": 0,
                "imap_host": mvp_agent.IMAP_HOST,
                "smtp_host": mvp_agent.SMTP_HOST,
                "discovered": False
            }
            
    except Exception as e:
        return {
            "success": False,
            "message": f"Corporate Exchange connection failed: {str(e)}",
            "total_emails": 0,
            "imap_host": mvp_agent.IMAP_HOST,
            "smtp_host": mvp_agent.SMTP_HOST,
            "discovered": False
        }
    


@app.get("/api/corporate/health")
async def get_corporate_health():
    """Get overall corporate system health"""
    try:
        # Test SocGen AI
        socgen_client = mvp_agent.socgen_client
        socgen_healthy = socgen_client.is_token_valid()
        
        # Test Outlook (quick check)
        outlook_healthy = True  # Would need actual test here
        
        overall_health = socgen_healthy and outlook_healthy
        
        return {
            "overall_healthy": overall_health,
            "socgen_ai": {
                "healthy": socgen_healthy,
                "token_valid": socgen_healthy,
                "model": mvp_agent.SOCGEN_MODEL
            },
            "outlook": {
                "healthy": outlook_healthy,
                "imap_host": mvp_agent.IMAP_HOST,
                "smtp_host": mvp_agent.SMTP_HOST
            },
            "last_check": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "overall_healthy": False,
            "error": str(e),
            "last_check": datetime.now().isoformat()
        }

if __name__ == "__main__":
    import uvicorn
    print("Starting Corporate Email Agent API with SocGen AI Integration...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
