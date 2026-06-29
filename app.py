import os
import json
from flask import Flask, render_template, jsonify, request
from datetime import datetime

# Import auditing & notifying functions
import main
import notifier

app = Flask(__name__, template_folder='templates', static_folder='static')

REPORT_FILENAME = "security_report.json"

@app.route('/')
def index():
    """Serves the main dashboard page."""
    return render_template('index.html')

@app.route('/api/report', methods=['GET'])
def get_report():
    """Retrieves the current security report findings."""
    if not os.path.exists(REPORT_FILENAME):
        return jsonify({
            "error": "No security report found. Please trigger a scan.",
            "report": None
        }), 404
        
    try:
        with open(REPORT_FILENAME, 'r') as f:
            report_data = json.load(f)
        return jsonify({
            "success": True,
            "report": report_data
        })
    except Exception as e:
        return jsonify({
            "error": f"Failed to read report: {str(e)}",
            "report": None
        }), 500

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Triggers the AWS Security Audit scan and returns findings."""
    try:
        # Run audit and save findings to file
        report_data = main.run_audit_and_save(REPORT_FILENAME)
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
def send_notification():
    """Sends Slack alerts with audit findings."""
    data = request.json or {}
    webhook_url = data.get("webhook_url")
    
    # Trigger Slack alert
    success, message = notifier.trigger_slack_notification(
        webhook_url=webhook_url,
        report_filename=REPORT_FILENAME
    )
    
    return jsonify({
        "success": success,
        "message": message
    })

if __name__ == '__main__':
    # Run server locally on port 5000
    app.run(debug=True, host='127.0.0.1', port=5000)
