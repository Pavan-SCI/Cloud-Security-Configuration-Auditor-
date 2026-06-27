import unittest
from unittest.mock import patch, MagicMock, mock_open
import datetime
from datetime import timezone
import json
import os
import io

# Import modules to test
import main
import notifier

class TestSecurityAuditor(unittest.TestCase):
    
    @patch('boto3.client')
    def test_audit_iam_users(self, mock_boto_client):
        # Create a mock IAM client
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        
        # Configure client.list_users() mock response
        mock_iam.list_users.return_value = {
            'Users': [
                {'UserName': 'secure-user'},
                {'UserName': 'insecure-user'}
            ]
        }
        
        # Configure client.list_mfa_devices() mock response
        # secure-user has MFA enabled, insecure-user does not
        def list_mfa_devices_side_effect(UserName):
            if UserName == 'secure-user':
                return {'MFADevices': [{'SerialNumber': 'arn:aws:iam::123456789012:mfa/secure-user'}]}
            return {'MFADevices': []}
        mock_iam.list_mfa_devices.side_effect = list_mfa_devices_side_effect
        
        # Configure client.list_access_keys() mock response
        # secure-user has new keys (10 days old)
        # insecure-user has old keys (100 days old)
        now_time = datetime.datetime.now(timezone.utc)
        def list_access_keys_side_effect(UserName):
            if UserName == 'secure-user':
                return {
                    'AccessKeyMetadata': [
                        {
                            'AccessKeyId': 'AKIASECURE123',
                            'CreateDate': now_time - datetime.timedelta(days=10),
                            'Status': 'Active'
                        }
                    ]
                }
            else:
                return {
                    'AccessKeyMetadata': [
                        {
                            'AccessKeyId': 'AKIAINSECURE456',
                            'CreateDate': now_time - datetime.timedelta(days=100),
                            'Status': 'Active'
                        }
                    ]
                }
        mock_iam.list_access_keys.side_effect = list_access_keys_side_effect
        
        # Run audit function
        report = main.audit_iam_users()
        
        # Assertions
        self.assertEqual(len(report), 2)
        
        secure_user_report = next(u for u in report if u['UserName'] == 'secure-user')
        self.assertTrue(secure_user_report['MFAEnabled'])
        self.assertEqual(len(secure_user_report['OldAccessKeys']), 0)
        
        insecure_user_report = next(u for u in report if u['UserName'] == 'insecure-user')
        self.assertFalse(insecure_user_report['MFAEnabled'])
        self.assertEqual(len(insecure_user_report['OldAccessKeys']), 1)
        self.assertEqual(insecure_user_report['OldAccessKeys'][0]['AccessKeyId'], 'AKIAINSECURE456')
        self.assertTrue(insecure_user_report['OldAccessKeys'][0]['AgeDays'] >= 99)

    @patch('boto3.client')
    def test_audit_s3_buckets(self, mock_boto_client):
        # Create a mock S3 client
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        
        # Configure client.list_buckets()
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'secure-bucket'},
                {'Name': 'insecure-bucket'},
                {'Name': 'missing-config-bucket'}
            ]
        }
        
        # Mock client.get_public_access_block()
        from botocore.exceptions import ClientError
        def get_public_access_block_side_effect(Bucket):
            if Bucket == 'secure-bucket':
                return {
                    'PublicAccessBlockConfiguration': {
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                }
            elif Bucket == 'insecure-bucket':
                return {
                    'PublicAccessBlockConfiguration': {
                        'BlockPublicAcls': False,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                }
            else:
                # Simulate botocore exception
                raise ClientError(
                    error_response={'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration', 'Message': 'The public access block configuration was not found'}},
                    operation_name='GetPublicAccessBlock'
                )
        mock_s3.get_public_access_block.side_effect = get_public_access_block_side_effect
        mock_s3.exceptions.ClientError = ClientError
        
        # Run audit function
        report = main.audit_s3_buckets()
        
        # Assertions
        self.assertEqual(len(report), 3)
        
        secure_bucket = next(b for b in report if b['BucketName'] == 'secure-bucket')
        self.assertFalse(secure_bucket['IsPublic'])
        
        insecure_bucket = next(b for b in report if b['BucketName'] == 'insecure-bucket')
        self.assertTrue(insecure_bucket['IsPublic'])
        
        missing_config_bucket = next(b for b in report if b['BucketName'] == 'missing-config-bucket')
        self.assertTrue(missing_config_bucket['IsPublic'])

class TestNotifier(unittest.TestCase):
    
    def setUp(self):
        self.sample_report = {
            "Timestamp": "2026-06-28T01:00:00",
            "IAM_Audit": [
                {
                    "UserName": "insecure-user",
                    "MFAEnabled": False,
                    "OldAccessKeys": [
                        {
                            "AccessKeyId": "AKIAINSECURE456",
                            "AgeDays": 100
                        }
                    ]
                },
                {
                    "UserName": "secure-user",
                    "MFAEnabled": True,
                    "OldAccessKeys": []
                }
            ],
            "S3_Audit": [
                {
                    "BucketName": "insecure-bucket",
                    "IsPublic": True
                },
                {
                    "BucketName": "secure-bucket",
                    "IsPublic": False
                }
            ]
        }
        
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists')
    def test_load_security_report(self, mock_exists, mock_file):
        mock_exists.return_value = True
        mock_file.return_value.__enter__.return_value.read.return_value = json.dumps(self.sample_report)
        
        report = notifier.load_security_report("dummy.json")
        self.assertIsNotNone(report)
        self.assertEqual(report['Timestamp'], "2026-06-28T01:00:00")
        
    def test_analyze_findings(self):
        findings = notifier.analyze_findings(self.sample_report)
        
        self.assertEqual(findings['mfa_disabled'], ['insecure-user'])
        self.assertEqual(len(findings['old_keys']), 1)
        self.assertEqual(findings['old_keys'][0]['UserName'], 'insecure-user')
        self.assertEqual(findings['old_keys'][0]['AccessKeyId'], 'AKIAINSECURE456')
        self.assertEqual(findings['public_s3'], ['insecure-bucket'])
        
    def test_format_slack_message(self):
        findings = {
            "mfa_disabled": ["insecure-user"],
            "old_keys": [{"UserName": "insecure-user", "AccessKeyId": "AKIAINSECURE456", "AgeDays": 100}],
            "public_s3": ["insecure-bucket"],
            "timestamp": "2026-06-28T01:00:00"
        }
        
        payload = notifier.format_slack_message(findings)
        
        self.assertEqual(payload['text'], "AWS Security Configuration Audit Alert")
        # Blocks check
        blocks = payload['blocks']
        self.assertTrue(any(b.get('type') == 'header' for b in blocks))
        
        # Verify content exists in blocks
        blocks_text = json.dumps(blocks)
        self.assertIn("insecure-user", blocks_text)
        self.assertIn("AKIAINSECURE456", blocks_text)
        self.assertIn("insecure-bucket", blocks_text)

    @patch('urllib.request.urlopen')
    def test_send_slack_notification_success(self, mock_urlopen):
        # Mock successful POST response (status code 200)
        mock_response = MagicMock()
        mock_response.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        result = notifier.send_slack_notification({"text": "test"}, "https://hooks.slack.com/dummy")
        self.assertTrue(result)
        
    @patch('urllib.request.urlopen')
    def test_send_slack_notification_failure(self, mock_urlopen):
        # Mock failed response (status code 400 or raises URLError)
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Bad Request")
        
        result = notifier.send_slack_notification({"text": "test"}, "https://hooks.slack.com/dummy")
        self.assertFalse(result)

    @patch('sys.stdout', new_callable=io.StringIO)
    @patch('notifier.load_security_report')
    @patch('os.environ.get')
    def test_notifier_main_dry_run(self, mock_env_get, mock_load, mock_stdout):
        # Mock report loading and Slack URL missing
        mock_load.return_value = self.sample_report
        mock_env_get.side_effect = lambda key, default=None: None if key == "SLACK_WEBHOOK_URL" else default
        
        notifier.main()
        
        output = mock_stdout.getvalue()
        self.assertIn("Running in DRY-RUN mode", output)
        self.assertIn("insecure-user", output)
        self.assertIn("insecure-bucket", output)

if __name__ == '__main__':
    unittest.main()
