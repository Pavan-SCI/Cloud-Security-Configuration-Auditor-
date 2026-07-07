import boto3
import json
from datetime import datetime, timezone

def get_aws_client(service_name, creds=None):
    """
    Initializes a boto3 client dynamically based on provided session credentials.
    If creds is empty/None, falls back to default local CLI credentials.
    """
    creds = creds or {}
    role_arn = creds.get("role_arn")
    region_name = creds.get("region_name") or "us-east-1"
    
    # Credentials variables
    aws_access_key_id = creds.get("aws_access_key_id")
    aws_secret_access_key = creds.get("aws_secret_access_key")
    aws_session_token = creds.get("aws_session_token")
    web_identity_token = creds.get("web_identity_token")
    aws_profile = creds.get("aws_profile")
    
    if aws_profile:
        print(f"[*] Initializing AWS Client '{service_name}' using Named CLI Profile: '{aws_profile}'...")
        session = boto3.Session(profile_name=aws_profile)
        return session.client(service_name, region_name=region_name)
        
    if role_arn and web_identity_token:
        if web_identity_token.startswith("mock-") or "mock" in role_arn.lower():
            print(f"[*] [Mock SSO Mode] Bypassing STS token exchange. Using local AWS credentials for demo...")
            return boto3.client(service_name, region_name=region_name)
            
        print(f"[*] Assuming Role via Web Identity: '{role_arn}' via STS...")
        sts_client = boto3.client('sts', region_name=region_name)
        assumed_role_object = sts_client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName="CognitoSSOAuditingSession",
            WebIdentityToken=web_identity_token
        )
        credentials = assumed_role_object['Credentials']
        return boto3.client(
            service_name,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region_name
        )
        
    if role_arn:
        if "mock" in role_arn.lower():
            print(f"[*] [Mock Role Mode] Bypassing STS AssumeRole. Using local AWS credentials for demo...")
            return boto3.client(service_name, region_name=region_name)
            
        print(f"[*] Assuming Role: '{role_arn}' via AWS STS...")
        if aws_access_key_id and aws_secret_access_key:
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                region_name=region_name
            )
        else:
            sts_client = boto3.client('sts', region_name=region_name)
            
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SaaSAuditingSession",
            ExternalId="auditor-secure-token-xyz"
        )
        credentials = assumed_role_object['Credentials']
        return boto3.client(
            service_name,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region_name
        )
        
    if aws_access_key_id and aws_secret_access_key:
        return boto3.client(
            service_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region_name
        )
        
    return boto3.client(service_name, region_name=region_name)

def audit_iam_users(creds=None):
    """
    Audits AWS IAM users for security best practices:
    1. Checks if Multi-Factor Authentication (MFA) is enabled.
    2. Checks if there are active access keys older than 90 days.
    """
    print("[*] Auditing IAM Users...")
    try:
        client = get_aws_client('iam', creds)
        users = client.list_users()['Users']
    except Exception as e:
        print(f"[-] IAM Audit failed to list users: {e}")
        raise e
        
    report = []
    
    for user in users:
        username = user['UserName']
        
        # 1. Check if MFA is enabled
        mfa_devices = client.list_mfa_devices(UserName=username)['MFADevices']
        mfa_enabled = len(mfa_devices) > 0
        
        # 2. Check Access Keys Age
        keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
        old_keys = []
        for key in keys:
            create_date = key['CreateDate']
            age_days = (datetime.now(timezone.utc) - create_date).days
            if age_days > 90 and key['Status'] == 'Active':
                old_keys.append({
                    "AccessKeyId": key['AccessKeyId'],
                    "AgeDays": age_days
                })
        
        report.append({
            "UserName": username,
            "MFAEnabled": mfa_enabled,
            "OldAccessKeys": old_keys
        })
        
    return report

def audit_s3_buckets(creds=None):
    """
    Audits S3 Buckets to check if Public Access Block is configured.
    An unconfigured or partially configured public access block represents a security gap.
    """
    print("[*] Auditing S3 Buckets...")
    try:
        client = get_aws_client('s3', creds)
        buckets = client.list_buckets()['Buckets']
    except Exception as e:
        print(f"[-] S3 Audit failed to list buckets: {e}")
        raise e
        
    report = []
    
    for bucket in buckets:
        name = bucket['Name']
        is_public = False
        try:
            # Check if Public Access Block configurations are active
            pab = client.get_public_access_block(Bucket=name)
            config = pab['PublicAccessBlockConfiguration']
            # If any block parameter is False, S3 bucket configurations have security gaps
            if not (config['BlockPublicAcls'] and config['IgnorePublicAcls'] and 
                    config['BlockPublicPolicy'] and config['RestrictPublicBuckets']):
                is_public = True
        except client.exceptions.ClientError as e:
            # If no public access block configuration exists, it is open/public by default
            is_public = True
            
        report.append({
            "BucketName": name,
            "IsPublic": is_public
        })
        
    return report

def run_audit_and_save(filename="security_report.json", creds=None):
    """
    Executes the IAM and S3 security audits, aggregates the results,
    saves them to a JSON file, and returns the aggregated report dict.
    """
    iam_report = audit_iam_users(creds)
    s3_report = audit_s3_buckets(creds)
    
    final_report = {
        "Timestamp": datetime.now().isoformat(),
        "IAM_Audit": iam_report,
        "S3_Audit": s3_report
    }
    
    with open(filename, 'w') as f:
        json.dump(final_report, f, indent=4)
        
    return final_report

def main():
    print("==================================================")
    print("    AWS Cloud Security Configuration Auditor      ")
    print("==================================================")
    
    try:
        # Run audit and save report
        final_report = run_audit_and_save()
        iam_report = final_report["IAM_Audit"]
        s3_report = final_report["S3_Audit"]
        filename = "security_report.json"
        
        print(f"\n[+] Audit complete! Detailed report saved to: {filename}")
        
        # Print Security Gap Dashboard to Console
        print("\n" + "="*20 + " SECURITY DASHBOARD " + "="*20)
        
        print("\n[!] IAM MFA & Access Key Findings:")
        for user in iam_report:
            mfa_status = "✅ MFA Enabled" if user['MFAEnabled'] else "❌ WARNING: MFA is Disabled!"
            print(f"- User: {user['UserName']}")
            print(f"  Status: {mfa_status}")
            if user['OldAccessKeys']:
                for key in user['OldAccessKeys']:
                    print(f"  ⚠️ Access Key {key['AccessKeyId']} is active for {key['AgeDays']} days (Limit: 90 days)")
            else:
                print("  ✅ All active access keys are under 90 days old.")
                
        print("\n[!] S3 Public Access Findings:")
        if not s3_report:
            print("- No S3 buckets found in this AWS account.")
        for bucket in s3_report:
            bucket_status = "❌ WARNING: Public Access is Enabled!" if bucket['IsPublic'] else "✅ Secure (Private Bucket)"
            print(f"- Bucket: {bucket['BucketName']}")
            print(f"  Status: {bucket_status}")
            
        print("\n" + "="*50)
            
    except Exception as e:
        print(f"\n[Error] Failed to execute audit: {e}")
        print("Please check your AWS CLI configurations (credentials/permissions) and try again.")

if __name__ == "__main__":
    main()
