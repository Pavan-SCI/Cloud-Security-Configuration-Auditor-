import os
import json
import queue
import boto3
from functools import wraps
from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
from datetime import datetime

# Import auditing & notifying functions
import main
import notifier

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'sec-auditor-key-xyz'

REPORT_FILENAME = "security_report.json"

# Thread-safe queues for connected clients
clients = []

def announce(event_type, data):
    """Broadcasts a Server-Sent Event to all connected dashboard clients."""
    payload = json.dumps({"type": event_type, "data": data})
    for q in list(clients):
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass

def login_required(f):
    """Decorator to enforce that the user has an active AWS session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('aws_creds'):
            if request.path.startswith('/api/'):
                return jsonify({"error": "Unauthorized. Please log in."}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Renders login page and authenticates using AWS Credentials/Roles."""
    if session.get('aws_creds'):
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        auth_mode = request.form.get('auth_mode') # 'keys' or 'role'
        region = request.form.get('region_name') or 'us-east-1'
        
        creds = {"region_name": region}
        
        if auth_mode == 'keys':
            creds["aws_access_key_id"] = request.form.get('aws_access_key_id', '').strip()
            creds["aws_secret_access_key"] = request.form.get('aws_secret_access_key', '').strip()
        elif auth_mode == 'role':
            creds["role_arn"] = request.form.get('role_arn', '').strip()
            # Optional keys if they want to assume a role via specific IAM credentials
            aws_id = request.form.get('aws_access_key_id', '').strip()
            aws_secret = request.form.get('aws_secret_access_key', '').strip()
            if aws_id and aws_secret:
                creds["aws_access_key_id"] = aws_id
                creds["aws_secret_access_key"] = aws_secret
                
        # Validate credentials with AWS STS
        try:
            print("[*] Validating user credentials on login...")
            sts_client = main.get_aws_client('sts', creds)
            identity = sts_client.get_caller_identity()
            account_id = identity.get('Account')
            
            # Authentication successful - store in session cookies
            session['aws_creds'] = creds
            session['aws_account_id'] = account_id
            session['region_name'] = region
            session['role_arn'] = creds.get('role_arn')
            
            print(f"[+] Login successful! Connected to AWS Account: {account_id}")
            return redirect(url_for('index'))
        except Exception as e:
            print(f"[-] Credentials validation failed: {e}")
            error = f"AWS connection failed: {str(e)}"
            
    return render_template('login.html', error=error)

@app.route('/logout', methods=['POST'])
def logout():
    """Clears AWS credentials session cookies and logs out."""
    session.pop('aws_creds', None)
    session.pop('aws_account_id', None)
    session.pop('region_name', None)
    session.pop('role_arn', None)
    return jsonify({"success": True, "message": "Successfully logged out!"})

@app.route('/')
@login_required
def index():
    """Serves the main dashboard page."""
    return render_template('index.html')

@app.route('/api/stream')
def sse_stream():
    """Server-Sent Events route to push real-time notifications to browser."""
    def event_generator():
        q = queue.Queue(maxsize=50)
        clients.append(q)
        try:
            yield f"data: {json.dumps({'type': 'connection', 'message': 'Connected to Real-time AWS Auditor Stream'})}\n\n"
            while True:
                msg = q.get()
                yield f"data: {msg}\n\n"
        except GeneratorExit:
            pass
        finally:
            if q in clients:
                clients.remove(q)
                
    return Response(event_generator(), mimetype="text/event-stream")

@app.route('/api/report', methods=['GET'])
@login_required
def get_report():
    """Retrieves the current security report findings and active connection metadata."""
    report_exists = os.path.exists(REPORT_FILENAME)
    
    report_data = None
    if report_exists:
        try:
            with open(REPORT_FILENAME, 'r') as f:
                report_data = json.load(f)
        except Exception as e:
            return jsonify({
                "error": f"Failed to read report: {str(e)}",
                "report": None
            }), 500
            
    return jsonify({
        "success": True,
        "report": report_data,
        "role_arn": session.get("role_arn"),
        "aws_account_id": session.get("aws_account_id"),
        "region_name": session.get("region_name")
    })

@app.route('/api/scan', methods=['POST'])
@login_required
def run_scan():
    """Triggers the AWS Security Audit scan dynamically using session credentials."""
    try:
        creds = session.get('aws_creds')
        report_data = main.run_audit_and_save(REPORT_FILENAME, creds)
        announce("report_updated", report_data)
        return jsonify({
            "success": True,
            "message": "AWS Security Audit completed successfully!",
            "report": report_data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Scan execution failed: {str(e)}"
        }), 500

@app.route('/api/notify', methods=['POST'])
@login_required
def send_notification():
    """Sends Slack alerts with audit findings."""
    data = request.json or {}
    webhook_url = data.get("webhook_url")
    
    success, message = notifier.trigger_slack_notification(
        webhook_url=webhook_url,
        report_filename=REPORT_FILENAME
    )
    
    return jsonify({
        "success": success,
        "message": message
    })

@app.route('/api/webhook', methods=['POST'])
def aws_webhook_receiver():
    """
    Receives EventBridge/CloudTrail security changes in real-time.
    Triggered anonymously. Uses active session credentials if configured, otherwise falls back.
    """
    try:
        event = request.json or {}
        detail = event.get("detail", {})
        event_name = detail.get("eventName", "Unknown AWS Configuration Change")
        
        request_params = detail.get("requestParameters", {})
        resource_name = "Unknown"
        resource_type = "AWS Resource"
        
        if "userName" in request_params:
            resource_name = request_params.get("userName")
            resource_type = "IAM User"
        elif "bucketName" in request_params:
            resource_name = request_params.get("bucketName")
            resource_type = "S3 Bucket"
            
        print(f"[*] Real-time Webhook Triggered: Event '{event_name}' on {resource_type} '{resource_name}'")
        
        # Pull credentials from active session if available
        creds = session.get('aws_creds')
        
        # Run a fresh AWS audit
        report_data = main.run_audit_and_save(REPORT_FILENAME, creds)
        
        # Check if the specific updated resource has a security warning
        findings = notifier.analyze_findings(report_data)
        has_warning = False
        warning_msg = ""
        
        if resource_type == "IAM User":
            if resource_name in findings.get("mfa_disabled", []):
                has_warning = True
                warning_msg = f"MFA is Disabled for newly created user '{resource_name}'!"
            elif any(k.get("UserName") == resource_name for k in findings.get("old_keys", [])):
                has_warning = True
                warning_msg = f"User '{resource_name}' has keys requiring rotation!"
        elif resource_type == "S3 Bucket":
            if resource_name in findings.get("public_s3", []):
                has_warning = True
                warning_msg = f"S3 Bucket '{resource_name}' is PUBLIC / Block Public Access is disabled!"
                
        if has_warning:
            print(f"[!] Warning detected in real-time: {warning_msg}")
            notifier.trigger_slack_notification(report_filename=REPORT_FILENAME)
            
        # Announce update to all open dashboards
        announce("aws_security_event", {
            "event_name": event_name,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "has_warning": has_warning,
            "warning_message": warning_msg,
            "report": report_data
        })
        
        return jsonify({
            "success": True,
            "message": f"Webhook processed: {event_name}",
            "has_warning": has_warning
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Webhook processing error: {str(e)}"
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
