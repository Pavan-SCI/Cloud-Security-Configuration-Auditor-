# 🛡️ AWS Cloud Security Configuration Auditor & Dashboard

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![AWS SDK](https://img.shields.io/badge/AWS-boto3-orange.svg)
![Framework](https://img.shields.io/badge/Framework-Flask-black.svg)
![Slack Integration](https://img.shields.io/badge/Alerts-Slack-4A154B.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-29%20passed-brightgreen.svg)

A comprehensive, enterprise-ready cloud compliance scanner that audits Amazon Web Services (AWS) resources against CIS-inspired benchmark regulations. Features an interactive glassmorphic web dashboard with light/dark theme toggle, real-time alerts, Slack ChatOps remediation integrations, and local mock testing.

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| 👑 **Root MFA & Password Policy** | Audits Root Profile MFA registration and evaluates Custom Password Strength compliance |
| 🪣 **Advanced S3 Assessment** | Flags public access block exclusions, unencrypted buckets, and disabled object versioning |
| 👤 **IAM User Audit** | Detects users lacking MFA devices and active access keys older than 90 days |
| ⚡ **Active Remediation (One-Click)** | Secure public S3 buckets, quarantine IAM users (inline lock policies), or deactivate keys directly from the dashboard |
| 🌓 **Dynamic Theme Switching** | Persisted Light & Dark mode theme toggle with high-contrast text and glowing compliance cards |
| 🚨 **Slack ChatOps Alerts** | Dispatches Slack Block Kit warnings complete with interactive quick-action buttons |
| 🧪 **Comprehensive Tests** | 29 fully mocked offline unit tests covering scanning, login flow, web endpoints, and remediations |
| 🐳 **Dockerized Deployment** | Pre-configured `requirements.txt` and lightweight `Dockerfile` for Render, AWS EC2, or ECS |

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────┐
│                     Web Browser UI                     │
│    http://127.0.0.1:5000 (Light / Dark Mode Switcher)   │
└───────────────────┬────────────────────────────────────┘
                    │ HTTP Requests (Fetch API / SSE)
┌───────────────────▼────────────────────────────────────┐
│                 Flask Backend (app.py)                 │
│  - GET /api/report            - POST /api/scan         │
│  - POST /api/remediate/*      - POST /api/webhook      │
└────────┬─────────────────────────┬─────────────────────┘
         │                         │
┌────────▼──────────┐     ┌────────▼─────────────────────┐
│  main.py          │     │  notifier.py                  │
│  - audit_iam()    │     │  - analyze_findings()         │
│  - audit_s3()     │     │  - format_slack_message()     │
│  - save_report()  │     │    (Active Remediation Blocks)│
└────────┬──────────┘     └────────┬─────────────────────┘
         │                         │
┌────────▼──────────┐     ┌────────▼─────────────────────┐
│  AWS APIs (boto3) │     │  Slack Incoming Webhook       │
│  - IAM / S3       │     │  hooks.slack.com              │
└───────────────────┘     └──────────────────────────────┘
```

---

## 📁 Repository Structure

```
Cloud-Security-Configuration-Auditor-/
├── app.py                  # Flask web server, OIDC session controllers, and API routes
├── main.py                 # Core AWS scanning logics, IAM & S3 CIS compliance checks
├── notifier.py             # Slack alerting formatter (Block Kit actions setup)
├── tests/                  # Directory containing unit test suites
│   ├── __init__.py         # Python package marker
│   └── test_auditor.py     # 29 mocked offline test cases
├── templates/
│   ├── index.html          # Compliance dashboard UI with active remediation handlers
│   ├── login.html          # Multi-mode AWS authentication interface
│   └── mock_cognito.html   # Mock OIDC consent verification page
├── static/
│   └── style.css           # Glassmorphic dark/light stylesheets & responsive layout
├── Dockerfile              # Container building instructions
├── requirements.txt        # Production dependency freeze
└── security_report.json    # Auto-saved scan report JSON
```

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.8+
* An AWS Account (Free Tier is sufficient)
* AWS CLI configured locally (`aws configure`)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Pavan-SCI/Cloud-Security-Configuration-Auditor-.git
cd Cloud-Security-Configuration-Auditor-
```

### Step 2: Install Python Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 💻 Running the Application

### 1. Web Dashboard (Recommended)
Start the Flask development server:
```bash
python3 app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

**Dashboard Capabilities:**
- **Launch AWS Security Audit**: Scan AWS IAM users, passwords, and S3 encryption/versioning in real-time.
- **Active Remediation Controls**:
  - `🔒 Secure Bucket`: Turn on Block Public Access for unblocked S3 buckets.
  - `🛑 Quarantine`: Lock down users lacking MFA by attaching an inline policy denying all operations except MFA configuration.
  - `🔑 Deactivate`: Disable old or leaking access keys with one click.
- **Theme Switcher**: Click `🌓 Theme` in the header to toggle between Dark mode and high-contrast Light mode (stored in LocalStorage).

### 2. Command-Line Interface (CLI)
You can also run audits directly via the CLI:
```bash
# Executing findings scan
python3 main.py

# Dispatches findings Slack Alert
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python3 notifier.py
```

---

## 🧪 Running Unit Tests

The test suite runs entirely offline without AWS credentials by mocking boto3 responses:
```bash
python3 -m unittest discover -s tests
```

To view a verbose list of all passing tests, run with the `-v` flag:
```bash
python3 -m unittest discover -s tests -v
```

Expected Output:
```text
test_audit_iam_users (tests.test_auditor.TestSecurityAuditor) ... ok
test_audit_s3_buckets (tests.test_auditor.TestSecurityAuditor) ... ok
test_remediate_s3_live_mode (tests.test_auditor.TestRemediationAPI) ... ok
...
Ran 29 tests in 0.066s

OK
```

---

## 🐳 Cloud Deployment (Production)

### Render / Railway (Managed Platforms)
This project is pre-configured with a `Dockerfile` and `requirements.txt`. Simply connect your GitHub repository and set the start command to:
```bash
gunicorn app:app
```
Since Render/Railway provides a public URL, ngrok is not needed for webhook event-listeners in production.

### AWS EC2 (Free Tier)
1. Launch a **`t2.micro`** instance (12-Month Free Tier) with an Ubuntu or Amazon Linux AMI.
2. In the Security Group, open ports **`22`** (SSH), **`80`** (HTTP), and **`5000`** (Custom TCP).
3. Connect via SSH, clone this repository, set up a virtual environment, and run:
   ```bash
   gunicorn --bind 0.0.0.0:5000 app:app
   ```

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).
