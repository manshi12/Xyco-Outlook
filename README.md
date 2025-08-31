# 📧 Enhanced Email Agent Dashboard

A sophisticated email automation system with thread-aware processing, AI-powered analysis, and a modern React-based dashboard for monitoring and managing email workflows. Built with Python, FastAPI, and React, this project supports Gmail and Outlook with advanced threading support and real-time analytics.

---

## 🚀 Project Overview

The **Enhanced Email Agent Dashboard** automates email processing with AI-driven responses, thread-aware reply handling, and a sleek user interface for managing pending emails. It integrates seamlessly with Gmail and Outlook, providing real-time monitoring, configuration management, and detailed analytics. The system is designed for scalability, security, and ease of use, making it ideal for both individual and enterprise email automation needs.

### Key Features

- **AI-Powered Email Processing**: Leverages Grok AI (via xAI) for intelligent email analysis and response generation.
- **Thread-Aware Handling**: Maintains email thread continuity with proper `In-Reply-To` and `References` headers.
- **Real-Time Dashboard**: A modern React-based UI for monitoring agent status, reviewing pending emails, and adjusting settings.
- **Analytics & Insights**: Tracks email processing metrics, including thread replies, success rates, and hourly activity.
- **Flexible Configuration**: Supports Gmail and Outlook with customizable settings for polling, dry-run mode, and review requirements.
- **Security & Control**: Includes VIP sender management, manual review for high-importance emails, and dry-run testing.


## 🛠️ Project Structure

```
email-agent-dashboard/
├── mvp_agent.py          # Core email processing logic with thread support
├── api_server.py         # FastAPI backend for dashboard integration
├── dashboard.html        # React-based dashboard frontend
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables (not tracked in git)
├── vip_senders.json      # VIP senders configuration
├── screenshots/          # Folder for dashboard screenshots
└── README.md             # This documentation
```

---

## 🔧 Setup Instructions

Follow these steps to set up and run the Email Agent Dashboard locally.

### Prerequisites

- **Python 3.8+**: Ensure Python is installed.
- **Node.js** (optional): For serving the dashboard with `npx serve`.
- **Email Account**: Gmail or Outlook account with IMAP/SMTP enabled.
- **Groq API Key**: Obtain from [xAI](https://x.ai/api) for AI processing.

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/email-agent-dashboard.git
cd email-agent-dashboard
```

### Step 2: Install Python Dependencies

Create and populate `requirements.txt`:

```txt
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-dotenv==1.0.0
groq==0.4.1
pydantic==2.5.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables

Create a `.env` file with the following settings, replacing placeholders with your actual credentials:

```env
# Email Configuration (Gmail/Outlook)
EMAIL_ADDRESS=your.email@company.com
EMAIL_USER=your.email@company.com
EMAIL_PASS=your_app_password
IMAP_HOST=imap.gmail.com  # or outlook.office365.com
IMAP_PORT=993
SMTP_HOST=smtp.gmail.com  # or smtp.office365.com
SMTP_PORT=587
SMTP_STARTTLS=1

# AI Configuration
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama3-8b-8192

# Dashboard Configuration
COMPANY_DOMAIN=yourcompany.com
REQUIRE_REVIEW_HIGH_IMPORTANCE=1
REQUIRE_REVIEW_EXTERNAL=1
AUTO_REPLY_CATEGORIES=newsletter,notification,automated
VIP_SENDERS_FILE=vip_senders.json

# Agent Behavior
POLL_SECONDS=60
DRY_RUN=1
MAX_EMAILS_PER_CYCLE=10
```

**Note**: Use an App Password for Gmail/Outlook for secure authentication. Do not commit `.env` to version control.

### Step 4: Set Up VIP Senders

Create `vip_senders.json` with important email addresses:

```json
[
  "ceo@yourcompany.com",
  "manager@yourcompany.com",
  "important.client@clientcompany.com"
]
```

### Step 5: Start the Application

#### Terminal 1: Run the API Server

```bash
python api_server.py
```

The API will be available at `http://localhost:8000`. Visit `http://localhost:8000/docs` for interactive API documentation.

#### Terminal 2: Serve the Dashboard

Choose one of the following options:

**Option A: Python HTTP Server**

```bash
python -m http.server 3000
```

**Option B: Node.js Serve**

```bash
npx serve -s . -l 3000
```

**Option C: Direct Browser Access**

Open `dashboard.html` directly in your browser (note: some features may be limited due to CORS).

The dashboard will be available at `http://localhost:3000`.

### Step 6: First-Time Setup

1. Open the dashboard at `http://localhost:3000`.
2. Configure settings in the **Agent Controls** section.
3. Enable **Dry Run Mode** (`DRY_RUN=1`) for testing without sending emails.
4. Click **Start Agent** to begin monitoring emails.
5. Use **Test Cycle** to process emails manually.
6. Review pending emails in the dashboard.
7. Disable **Dry Run Mode** (`DRY_RUN=0`) when ready for production.

---

## 📊 Dashboard Features

### Real-Time Monitoring
- **Agent Status**: Displays whether the agent is running or stopped.
- **Live Statistics**: Shows emails processed, sent, pending, and thread replies.
- **24-Hour Activity Chart**: Visualizes email processing patterns.
- **Auto-Refresh**: Updates every 5 seconds for real-time insights.

### Email Management
- **Pending Review Queue**: View and manage emails requiring manual review.
- **Thread Context**: Displays thread summaries for reply emails.
- **Action Options**: Approve, modify, or reject AI-generated replies.
- **Inline Editing**: Modify reply subject and body directly in the dashboard.

### Agent Controls
- **Start/Stop Agent**: Toggle email processing remotely.
- **Configuration**: Adjust polling intervals, max emails per cycle, and dry-run mode.
- **VIP Rules**: Manage important senders requiring manual review.
- **Test Cycles**: Run manual processing cycles for testing.

### Analytics
- **Success Rate**: Tracks successful email processing and sending.
- **Category Breakdown**: Shows email distribution by type (e.g., urgent, meeting, business).
- **Thread Metrics**: Monitors thread reply processing and success rates.
- **Hourly Patterns**: Visualizes email activity over 24 hours.

---

## ⚙️ Configuration Options

### General Settings
- `POLL_SECONDS`: Frequency of email checks (default: 60 seconds).
- `DRY_RUN`: Enables test mode without sending emails (default: 1).
- `MAX_EMAILS_PER_CYCLE`: Maximum emails processed per cycle (default: 10).

### Review Requirements
- `REQUIRE_REVIEW_HIGH_IMPORTANCE`: Forces manual review for high-importance emails (default: 1).
- `REQUIRE_REVIEW_EXTERNAL`: Requires review for emails from external domains (default: 1).
- `VIP_SENDERS`: Email addresses always requiring manual review.

---

## 🛠️ Troubleshooting

### Common Issues

1. **API Connection Failed**
   - Verify `api_server.py` is running on port 8000.
   - Check CORS settings in `api_server.py`.
   - Ensure no firewall is blocking localhost connections.

2. **Email Authentication Errors**
   - Use an App Password for Gmail/Outlook.
   - Enable "Allow less secure apps" for Gmail if needed.
   - Verify IMAP/SMTP host and port settings.

3. **Groq API Errors**
   - Confirm `GROQ_API_KEY` is valid.
   - Check API usage limits on [xAI](https://x.ai/api).
   - Ensure sufficient API credits.

4. **Dashboard Not Loading**
   - Check browser console for JavaScript errors.
   - Verify CDN resources (React, Chart.js) are loading.
   - Try refreshing the page or using a different browser.

### Debug Mode

Enable detailed logging by adding to `.env`:

```env
LOG_LEVEL=DEBUG
```

---

## 🔄 Development Workflow

### Testing New Features
1. Set `DRY_RUN=1` in `.env`.
2. Use the **Test Cycle** button to process emails.
3. Review results in the dashboard.
4. Adjust configurations as needed.
5. Set `DRY_RUN=0` for production deployment.

### Monitoring Production
1. Keep the dashboard open for real-time monitoring.
2. Regularly check pending emails.
3. Review analytics to optimize performance.
4. Adjust polling intervals based on email volume.

---

## 🔐 Security Considerations

- **Protect `.env` File**: Never commit to version control.
- **Use App Passwords**: Avoid using main email passwords.
- **Monitor VIP Senders**: Regularly update `vip_senders.json`.
- **Secure API Access**: Restrict to localhost or internal networks.
- **Audit Email Activity**: Watch for suspicious patterns.

---

## 📈 Scaling Up

### For High-Volume Environments
- Increase `MAX_EMAILS_PER_CYCLE` for faster processing.
- Reduce `POLL_SECONDS` for more frequent checks.
- Consider multiple agent instances for load balancing.
- Implement database storage for email history.
- Add archiving and retention policies.

### Future Enhancements
- User authentication and role-based access.
- Multi-tenant support for teams.
- Advanced analytics and custom reports.
- Integration with calendar and collaboration tools (Slack, Teams).
- Custom AI model training for specific use cases.

---

## 🆘 Support

For issues or questions:
1. Check console logs in both API server and browser.
2. Verify `.env` settings and credentials.
3. Test email connectivity manually.
4. Explore API documentation at `http://localhost:8000/docs`.
5. Contact support via [GitHub Issues](https://github.com/your-username/email-agent-dashboard/issues).

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙌 Acknowledgments

- **xAI**: For providing the Grok AI API used in email analysis.
- **FastAPI**: For powering the robust backend API.
- **React & Chart.js**: For enabling a modern, interactive dashboard.
- **Community**: Thanks to all contributors and testers!

---

*Built with ❤️ for efficient email automation.*
