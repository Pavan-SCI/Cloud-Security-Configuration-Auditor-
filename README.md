# AWS Cloud Security Configuration Auditor

A lightweight Python command-line tool that audits Amazon Web Services (AWS) configurations against standard security best practices inspired by the CIS AWS Foundations Benchmark.

## Features
- **IAM Security Audits**: 
  - Verifies if Multi-Factor Authentication (MFA) is enabled for all IAM users.
  - Identifies active AWS Access Keys older than 90 days (which require rotation).
- **S3 Bucket Audits**:
  - Scans S3 buckets to check if "Public Access Block" configurations are active to prevent accidental public data leaks.
- **Reporting**:
  - Displays a clean visual security dashboard in the terminal.
  - Outputs a detailed findings report to `security_report.json` for logging and remediation tracking.

## Prerequisites
- Python 3.x
- An AWS account (Free Tier works perfectly)
- AWS CLI installed and configured on your machine

## Installation & Setup

1. **Install dependencies**:
   ```bash
   pip install boto3
   ```

2. **Configure AWS Credentials**:
   Ensure your local machine has access to your AWS account. If you haven't configured the AWS CLI yet, run:
   ```bash
   aws configure
   ```
   Input your `AWS Access Key ID`, `AWS Secret Access Key`, default region (e.g. `us-east-1`), and output format (`json`).

## Usage

### 1. Run the Security Audit
Execute the auditing script to check for configurations and generate the security report:
```bash
python main.py
```
This generates a detailed file named `security_report.json` in the current directory and prints a dashboard summary to your console.

### 2. Send Slack Notifications (Optional)
You can parse the generated report and send alerts of high-risk security gaps (like disabled MFA or public S3 buckets) to your Slack channel.

#### Dry-run Mode (Inspect layout without Slack URL):
```bash
python notifier.py
```

#### Live Alerts:
Generate a Slack Webhook URL for your workspace, then set the environment variable and run:
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python notifier.py
```

---

## Local Mock Testing

You can run the full test suite locally without active AWS credentials or a live Slack connection. The test suite uses Python's built-in `unittest.mock` to simulate AWS resources (IAM users, S3 configurations, access key lifetimes) and Slack Webhook requests.

To run the tests:
```bash
python -m unittest test_auditor.py
```

---

## How It Works
The auditor utilizes the AWS SDK for Python (`boto3`) to query the AWS IAM and S3 APIs:
- `boto3.client('iam').list_users()` retrieves the list of active users.
- `list_mfa_devices()` checks for active MFA configurations.
- `list_access_keys()` evaluates the age of active developer credentials.
- `boto3.client('s3').get_public_access_block()` checks bucket policy restrictions.

