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

class TestFlaskRealTimeAPI(unittest.TestCase):
    
    def setUp(self):
        from app import app
        app.config['TESTING'] = True
        self.client = app.test_client()
        # Enable aws_creds session state for API testing
        with self.client.session_transaction() as sess:
            sess['aws_creds'] = {
                "aws_access_key_id": "AKIAINSECURE123",
                "aws_secret_access_key": "mock_secret",
                "region_name": "us-east-1"
            }
            sess['aws_account_id'] = "123456789012"
        
    @patch('main.run_audit_and_save')
    @patch('notifier.trigger_slack_notification')
    def test_aws_webhook_receiver_iam(self, mock_notify, mock_audit):
        # Setup mock report
        mock_audit.return_value = {
            "Timestamp": "2026-07-07T05:59:46",
            "IAM_Audit": [
                {
                    "UserName": "Insecure-Test-User",
                    "MFAEnabled": False,
                    "OldAccessKeys": []
                }
            ],
            "S3_Audit": []
        }
        
        # Test request body mimicking EventBridge CloudTrail user creation event
        payload = {
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventName": "CreateUser",
                "requestParameters": {
                    "userName": "Insecure-Test-User"
                }
            }
        }
        
        response = self.client.post('/api/webhook', json=payload)
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertTrue(response_data['success'])
        self.assertTrue(response_data['has_warning'])
        
        # Verify that Slack alert notification was triggered because user is insecure (no MFA)
        mock_notify.assert_called_once()

    @patch('main.run_audit_and_save')
    @patch('notifier.trigger_slack_notification')
    def test_aws_webhook_receiver_s3_secure(self, mock_notify, mock_audit):
        # Setup mock report
        mock_audit.return_value = {
            "Timestamp": "2026-07-07T05:59:46",
            "IAM_Audit": [],
            "S3_Audit": [
                {
                    "BucketName": "secure-bucket-demo",
                    "IsPublic": False
                }
            ]
        }
        
        payload = {
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventName": "CreateBucket",
                "requestParameters": {
                    "bucketName": "secure-bucket-demo"
                }
            }
        }
        
        response = self.client.post('/api/webhook', json=payload)
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertTrue(response_data['success'])
        self.assertFalse(response_data['has_warning']) # No warning because bucket is secure
        
        # Verify that Slack notification was NOT triggered
        mock_notify.assert_not_called()

class TestKeylessRoleDelegation(unittest.TestCase):
    
    @patch('boto3.client')
    def test_get_aws_client_local(self, mock_boto_client):
        import main
        main.get_aws_client('iam')
        mock_boto_client.assert_called_with('iam', region_name='us-east-1')

    @patch('boto3.client')
    def test_get_aws_client_assumed_role(self, mock_boto_client):
        import main
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'ASIA_TEMP_KEY',
                'SecretAccessKey': 'TEMP_SECRET',
                'SessionToken': 'TEMP_TOKEN'
            }
        }
        
        def boto_client_side_effect(service_name, **kwargs):
            if service_name == 'sts':
                return mock_sts
            return MagicMock()
            
        mock_boto_client.side_effect = boto_client_side_effect
        
        main.get_aws_client('s3', creds={"role_arn": "arn:aws:iam::123456789012:role/TestRole"})
        
        mock_sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/TestRole",
            RoleSessionName="SaaSAuditingSession",
            ExternalId="auditor-secure-token-xyz"
        )

    @patch('boto3.client')
    def test_get_aws_client_web_identity(self, mock_boto_client):
        import main
        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.return_value = {
            'Credentials': {
                'AccessKeyId': 'ASIA_WEB_KEY',
                'SecretAccessKey': 'WEB_SECRET',
                'SessionToken': 'WEB_TOKEN'
            }
        }
        
        def boto_client_side_effect(service_name, **kwargs):
            if service_name == 'sts':
                return mock_sts
            return MagicMock()
            
        mock_boto_client.side_effect = boto_client_side_effect
        
        main.get_aws_client('s3', creds={
            "role_arn": "arn:aws:iam::123456789012:role/WebRole",
            "web_identity_token": "id-token-xyz"
        })
        
        mock_sts.assume_role_with_web_identity.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/WebRole",
            RoleSessionName="CognitoSSOAuditingSession",
            WebIdentityToken="id-token-xyz"
        )

class TestFlaskAuthentication(unittest.TestCase):
    
    def setUp(self):
        from app import app
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_login_page_renders(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enter your AWS configuration", response.data)

    def test_unauthenticated_api_redirects(self):
        response = self.client.get('/api/report')
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertEqual(data['error'], "Unauthorized. Please log in.")

    def test_unauthenticated_page_redirects(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/login'))

    @patch('main.get_aws_client')
    def test_login_success_keys(self, mock_get_client):
        # Mock STS client identity validation
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_get_client.return_value = mock_sts
        
        response = self.client.post('/login', data={
            'auth_mode': 'keys',
            'aws_access_key_id': 'AKIAINSECURE123',
            'aws_secret_access_key': 'secret_pass_123',
            'region_name': 'us-east-1'
        })
        
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/'))
        
        # Verify credentials saved in session cookie
        with self.client.session_transaction() as sess:
            self.assertEqual(sess['aws_account_id'], "123456789012")
            self.assertEqual(sess['aws_creds']['aws_access_key_id'], "AKIAINSECURE123")

    @patch('main.get_aws_client')
    def test_login_success_role(self, mock_get_client):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "987654321098"}
        mock_get_client.return_value = mock_sts
        
        response = self.client.post('/login', data={
            'auth_mode': 'role',
            'role_arn': 'arn:aws:iam::987654321098:role/TestAuditor',
            'region_name': 'us-west-2'
        })
        
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/'))
        
        with self.client.session_transaction() as sess:
            self.assertEqual(sess['aws_account_id'], "987654321098")
            self.assertEqual(sess['role_arn'], "arn:aws:iam::987654321098:role/TestAuditor")

    @patch('main.get_aws_client')
    def test_login_failure(self, mock_get_client):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = Exception("Invalid Signature")
        mock_get_client.return_value = mock_sts
        
        response = self.client.post('/login', data={
            'auth_mode': 'keys',
            'aws_access_key_id': 'AKIAWRONG',
            'aws_secret_access_key': 'wrong_secret',
            'region_name': 'us-east-1'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AWS connection failed", response.data)

    def test_logout(self):
        with self.client.session_transaction() as sess:
            sess['aws_creds'] = {"aws_access_key_id": "mock"}
            sess['aws_account_id'] = "123456789012"
            
        response = self.client.post('/logout')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        
        with self.client.session_transaction() as sess:
            self.assertNotIn('aws_creds', sess)
            self.assertNotIn('aws_account_id', sess)

    def test_login_aws_redirects_to_mock_when_no_domain(self):
        response = self.client.get('/login/aws')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/login/aws/mock'))

    def test_mock_consent_renders(self):
        response = self.client.get('/login/aws/mock')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AWS Security Configuration Auditor", response.data)
        self.assertIn(b"Approve & Log In", response.data)

    def test_mock_consent_approval_redirects(self):
        response = self.client.post('/login/aws/mock/approve')
        self.assertEqual(response.status_code, 302)
        self.assertIn('code=mock-auth-code-12345', response.headers['Location'])

    def test_callback_mock_mode_success(self):
        response = self.client.get('/callback?code=mock-auth-code-12345')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/'))
        
        with self.client.session_transaction() as sess:
            self.assertEqual(sess['aws_account_id'], "123456789012")
            self.assertEqual(sess['auth_method'], "OIDC Cognito (Mock)")
            self.assertEqual(sess['aws_creds']['web_identity_token'], "mock-identity-jwt-token-9876")

if __name__ == '__main__':
    unittest.main()
