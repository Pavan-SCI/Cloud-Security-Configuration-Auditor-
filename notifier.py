import os
import json
import urllib.request
import urllib.error
from datetime import datetime

REPORT_FILENAME = "security_report.json"

def load_security_report(filename=REPORT_FILENAME):
    """Loads the security report JSON file."""
    if not os.path.exists(filename):
        print(f"[-] Error: Report file '{filename}' not found. Please run main.py first to generate it.")
        return None
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[-] Error parsing security report JSON: {e}")
        return None

def analyze_findings(report):
    """Analyzes the report and returns lists of high-risk findings."""
    high_risk_mfa = []
    high_risk_keys = []
    high_risk_s3 = []
    unencrypted_s3 = []
    unversioned_s3 = []
    
    # 1. Analyze IAM Audit
    iam_audit = report.get("IAM_Audit", [])
    for user in iam_audit:
        username = user.get("UserName")
        if not user.get("MFAEnabled", False):
            high_risk_mfa.append(username)
        
        old_keys = user.get("OldAccessKeys", [])
        for key in old_keys:
            high_risk_keys.append({
                "UserName": username,
                "AccessKeyId": key.get("AccessKeyId"),
                "AgeDays": key.get("AgeDays")
            })
            
    # 2. Analyze S3 Audit
    s3_audit = report.get("S3_Audit", [])
    for bucket in s3_audit:
        bname = bucket.get("BucketName")
        if bucket.get("IsPublic", False):
            high_risk_s3.append(bname)
        if not bucket.get("IsEncrypted", True):
            unencrypted_s3.append(bname)
        if not bucket.get("IsVersioned", True):
            unversioned_s3.append(bname)
            
    # 3. Analyze Account Metadata
    metadata = report.get("Account_Metadata", {})
    root_mfa_disabled = not metadata.get("RootMFAEnabled", True)
    password_policy_missing = not metadata.get("PasswordPolicyConfigured", True)
            
    return {
        "mfa_disabled": high_risk_mfa,
        "old_keys": high_risk_keys,
        "public_s3": high_risk_s3,
        "unencrypted_s3": unencrypted_s3,
        "unversioned_s3": unversioned_s3,
        "root_mfa_disabled": root_mfa_disabled,
        "password_policy_missing": password_policy_missing,
        "timestamp": report.get("Timestamp", datetime.now().isoformat())
    }

def format_slack_message(findings):
    """Formats the findings into a Slack Block Kit payload."""
    blocks = [
        {
          "type": "header",
          "text": {
            "type": "plain_text",
            "text": "⚠️ AWS Security Configuration Audit Alert",
            "emoji": True
          }
        },
        {
          "type": "context",
          "elements": [
            {
              "type": "mrkdwn",
              "text": f"*Timestamp:* {findings['timestamp']}"
            }
          ]
        },
        {
          "type": "divider"
        }
    ]
    
    has_gaps = False
    
    # Root Account Warning
    if findings.get("root_mfa_disabled", False):
        has_gaps = True
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "❌ *VULNERABILITY: Root Account MFA is Disabled!*\n• Critical risk! Root MFA should be enabled immediately to protect against root-level takeovers."
            }
        })
        
    # Password Policy Warning
    if findings.get("password_policy_missing", False):
        has_gaps = True
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "⚠️ *IAM Password Policy Gaps*\n• The account is using the default weak AWS password policy. Configure a strong custom password policy."
            }
        })
    
    # MFA Disabled Warnings
    if findings["mfa_disabled"]:
        has_gaps = True
        mfa_text = "*Users with MFA Disabled:*\n" + "\n".join([f"• `{user}`" for user in findings["mfa_disabled"]])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"❌ *IAM MFA Gaps Detected*\n{mfa_text}"
            }
        })
        
    # Old Access Keys Warnings
    if findings["old_keys"]:
        has_gaps = True
        keys_text = "*Keys requiring rotation (>90 days old):*\n" + "\n".join([
            f"• User: `{k['UserName']}` | Key: `{k['AccessKeyId']}` ({k['AgeDays']} days old)"
            for k in findings["old_keys"]
        ])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"⚠️ *Expired Access Keys Detected*\n{keys_text}"
            }
        })
        
    # Public S3 Buckets Warnings
    if findings["public_s3"]:
        has_gaps = True
        s3_text = "*Buckets with Public Access Block Disabled:*\n" + "\n".join([f"• `{bucket}`" for bucket in findings["public_s3"]])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"❌ *Public S3 Buckets Detected*\n{s3_text}"
            }
        })
        
    # S3 Extra Data Protection Warnings
    if findings.get("unencrypted_s3") or findings.get("unversioned_s3"):
        has_gaps = True
        s3_extra_text = ""
        if findings.get("unencrypted_s3"):
            s3_extra_text += "*Unencrypted S3 Buckets:*\n" + "\n".join([f"• `{b}`" for b in findings["unencrypted_s3"]]) + "\n"
        if findings.get("unversioned_s3"):
            s3_extra_text += "*Versioning Disabled S3 Buckets:*\n" + "\n".join([f"• `{b}`" for b in findings["unversioned_s3"]])
            
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"⚠️ *S3 Data Protection Warnings*\n{s3_extra_text}"
            }
        })
        
    if not has_gaps:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "✅ *Audit Complete:* No high-risk security gaps detected."
            }
        })
    else:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "❗ *Action Required:* Please remediate these gaps immediately to secure your AWS infrastructure."
                }
            ]
        })
        
    return {
        "text": "AWS Security Configuration Audit Alert",
        "blocks": blocks
    }

def send_slack_notification(payload, webhook_url):
    """Sends the formatted payload to Slack Webhook URL."""
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response:
            status_code = response.getcode()
            if status_code == 200:
                print("[+] Slack alert sent successfully!")
                return True
            else:
                print(f"[-] Failed to send Slack alert. Status code: {status_code}")
                return False
    except urllib.error.URLError as e:
        print(f"[-] Network/Webhook connection failed: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error sending notification: {e}")
        return False

def trigger_slack_notification(webhook_url=None, report_filename=REPORT_FILENAME):
    """
    Loads security report, analyzes findings, formats Slack payload,
    and sends the notification to the provided or environment-defined Slack webhook URL.
    Returns a tuple (success, message).
    """
    report = load_security_report(report_filename)
    if not report:
        return False, "Security report not found. Run main.py first."
        
    findings = analyze_findings(report)
    payload = format_slack_message(findings)
    
    if not webhook_url:
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        
    if webhook_url:
        success = send_slack_notification(payload, webhook_url)
        if success:
            return True, "Slack alert sent successfully!"
        else:
            return False, "Failed to send Slack alert."
    else:
        return False, "SLACK_WEBHOOK_URL is not set."

def main():
    print("==================================================")
    print("       Cloud Security Alert Notifier              ")
    print("==================================================")
    
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    success, message = trigger_slack_notification(webhook_url)
    
    if not success and "not set" in message:
        print("[!] Note: SLACK_WEBHOOK_URL environment variable is not set.")
        # Load and show dry-run
        report = load_security_report()
        if report:
            findings = analyze_findings(report)
            payload = format_slack_message(findings)
            print("[*] Running in DRY-RUN mode. Visualized message payload below:")
            print(json.dumps(payload, indent=2))
            print("==================================================")
            print("To send live Slack alerts, run with: ")
            print("export SLACK_WEBHOOK_URL=\"your_webhook_url\" && python notifier.py")
            print("==================================================")
    else:
        print(f"[*] Alert Status: {message}")

if __name__ == "__main__":
    main()
