# 🛡️ AWS Cloud Security Configuration Auditor & Dashboard

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![AWS SDK](https://img.shields.io/badge/AWS-boto3-orange.svg)
![Framework](https://img.shields.io/badge/Framework-Flask-black.svg)
![Slack Integration](https://img.shields.io/badge/Alerts-Slack-4A154B.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-8%20passed-brightgreen.svg)

A comprehensive, lightweight security auditing platform that scans Amazon Web Services (AWS) configurations against compliance best practices inspired by the **CIS AWS Foundations Benchmark**. Features a real-time interactive glassmorphic web dashboard, automated Slack alert notifications, and a 100% offline-testable codebase.

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| 👤 **IAM Auditing** | Detects users with MFA disabled and Access Keys older than 90 days |
| 🪣 **S3 Auditing** | Flags buckets where Public Access Block is missing or incomplete |
| 📊 **Web Dashboard** | Dark glassmorphic single-page UI with live scan triggers and dynamic result tables |
| 🚨 **Slack Alerts** | Formats and dispatches Block Kit alert messages to configured Slack channels |
| 🧪 **Mock Test Suite** | 8 fully mocked unit tests using `unittest.mock` — no AWS credentials required |
| 📄 **JSON Reporting** | Exports all findings to `security_report.json` for logging and audit trail |

---

## 🏗️ How It Works

```
┌──────────────────────────────────────────────────────┐
│                    Web Browser UI                    │
│           http://127.0.0.1:5000 (Dashboard)          │
└────────────────────┬─────────────────────────────────┘
                     │ HTTP Requests (Fetch API)
┌────────────────────▼─────────────────────────────────┐
│                Flask Backend (app.py)                 │
│  GET /api/report   POST /api/scan   POST /api/notify  │
└────────┬───────────────────────┬──────────────────────┘
         │                       │
┌────────▼──────────┐   ┌───────▼──────────────────────┐
│  main.py          │   │  notifier.py                  │
│  - audit_iam()    │   │  - load_security_report()     │
│  - audit_s3()     │   │  - analyze_findings()         │
│  - save_report()  │   │  - format_slack_message()     │
└────────┬──────────┘   │  - send_slack_notification()  │
         │              └───────┬──────────────────────┘
┌────────▼──────────┐           │
│  AWS APIs (boto3) │   ┌───────▼──────────────────────┐
│  - IAM            │   │  Slack Incoming Webhook       │
│  - S3             │   │  hooks.slack.com              │
└───────────────────┘   └──────────────────────────────┘
```

---

## 📁 Repository Structure

```
Cloud-Security-Configuration-Auditor-/
├── app.py                  # Flask web server & REST API endpoints
├── main.py                 # Core AWS auditing logic (boto3)
├── notifier.py             # Slack alerting module & webhook dispatcher
├── test_auditor.py         # Offline mock test suite (unittest.mock)
├── security_report.json    # Generated audit report (auto-created on scan)
├── templates/
│   └── index.html          # Single-page dashboard UI
├── static/
│   └── style.css           # Glassmorphic dark-mode stylesheet
├── README.md               # This file
└── README_SINHALA.md       # Full setup guide in Sinhala language
```

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.8+
* An active AWS account (Free Tier is sufficient)
* AWS CLI installed on your machine

### Step 1: Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/Cloud-Security-Configuration-Auditor-.git
cd Cloud-Security-Configuration-Auditor-
```

### Step 2: Install AWS CLI
```bash
# macOS (using Homebrew)
brew install awscli
```

### Step 3: Configure AWS Credentials
```bash
aws configure
```
Provide your details when prompted:
```
AWS Access Key ID:     YOUR_ACCESS_KEY_ID
AWS Secret Access Key: YOUR_SECRET_ACCESS_KEY
Default region name:   us-east-1
Default output format: json
```

> **Where to get AWS credentials?**
> Go to AWS Console → IAM → Users → Your User → Security Credentials → Create Access Key.

### Step 4: Install Python Dependencies
```bash
python3 -m pip install boto3 flask
```

---

## 💻 Usage & Operations

### ▶ Mode A: Web UI Dashboard (Recommended)

Launch the Flask development server:
```bash
python3 app.py
```
Open **http://127.0.0.1:5000** in your web browser.

**Dashboard Capabilities:**
| Button | Action |
|---|---|
| 🔄 **Trigger AWS Security Audit** | Runs a live scan of your AWS account and populates the results tables |
| 🔔 **Send Slack Notification** | Sends a formatted Block Kit alert to your configured Slack channel |

**Tabs Available:**
| Tab | Shows |
|---|---|
| **IAM User Accounts** | Username, MFA status (Active/Disabled), flagged old Access Keys |
| **S3 Buckets** | Bucket name, Public Access Block status (Secure/Exposed) |

---

### ▶ Mode B: Command-Line Interface (CLI)

**1. Run the security audit:**
```bash
python3 main.py
```
Outputs a terminal dashboard and saves findings to `security_report.json`.

**2. Send Slack alerts:**
```bash
# Dry-run mode — prints the Slack payload to console (no webhook needed)
python3 notifier.py

# Live alerts — sends to your Slack channel
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python3 notifier.py
```

---

## 🔗 Configuring Slack Notifications

### How to Create a Slack Incoming Webhook

1. Go to **[api.slack.com/apps](https://api.slack.com/apps)** and click **Create New App** → **From Scratch**.
2. Give your app a name (e.g. `AWS Security Alert`) and select your Workspace.
3. In the left sidebar, click **Incoming Webhooks** and toggle **Activate Incoming Webhooks** → **On**.
4. Click **Add New Webhook to Workspace**, choose your target channel (e.g. `#security-alerts`), and click **Allow**.
5. Copy the generated Webhook URL (format: `https://hooks.slack.com/services/T.../B.../X...`).

### Use in Dashboard UI
Paste the Webhook URL into the **Slack Webhook URL** field in the dashboard settings panel and click **Send Slack Notification**.

### Use via Environment Variable
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python3 notifier.py
```

**Example Slack Alert Output:**
```
⚠️ AWS Security Configuration Audit Alert
Timestamp: 2026-06-29T14:00:00

❌ IAM MFA Gaps Detected
  • insecure-user

⚠️ Expired Access Keys Detected
  • User: insecure-user | Key: AKIAXXXXXXXX (100 days old)

❌ Public S3 Buckets Detected
  • public-bucket-demo

❗ Action Required: Please remediate these gaps immediately.
```

---

## 🔎 What Gets Audited

### IAM Security Checks
| Check | Risk Level | Condition |
|---|---|---|
| MFA Disabled | 🔴 High | No MFA device associated with user |
| Old Access Keys | 🟠 Medium | Active access key created > 90 days ago |

### S3 Security Checks
| Check | Risk Level | Condition |
|---|---|---|
| Public Access Block | 🔴 High | Any of the 4 block settings is `False` or missing |

---

## 🧪 Local Testing & Verification

A robust mock test suite runs entirely offline — no AWS credentials needed:
```bash
python3 -m unittest test_auditor.py
```

**Test coverage includes:**
- ✅ IAM MFA detection (enabled/disabled users)
- ✅ Access Key age evaluation (< 90 days and > 90 days scenarios)
- ✅ S3 Public Access Block detection (secure, misconfigured, and missing config)
- ✅ Slack payload Block Kit formatting
- ✅ Webhook POST success/failure handling
- ✅ Dry-run mode console output

**Expected output:**
```text
........
----------------------------------------------------------------------
Ran 8 tests in 0.003s

OK
```

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.8+ |
| AWS SDK | boto3 |
| Web Framework | Flask |
| Frontend | HTML5, Vanilla CSS (Glassmorphic), Vanilla JavaScript |
| Alerting | Slack Incoming Webhooks (Block Kit) |
| Testing | unittest, unittest.mock |
| Reporting | JSON |

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgements

- Inspired by the [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- Built using [AWS SDK for Python (boto3)](https://aws.amazon.com/sdk-for-python/)
- Alert formatting powered by [Slack Block Kit](https://api.slack.com/block-kit)
