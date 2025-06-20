#!/usr/bin/env python3
import argparse
import json
import time
import boto3
from botocore.exceptions import ClientError


module_info = {
    'name': 's3__enum_bucket_owner',
    'author': 'Cloudar by Ben Bridts (Original), Adapted for Pacu',
    'category': 'ENUM',
    'one_liner': 'Discovers AWS account IDs that own specified S3 buckets',
    'description': (
        'This module discovers the AWS account ID that owns specified S3 buckets '
        'using IAM policy conditions (s3:ResourceAccount). It works by leveraging '
        'STS assume-role with policy intersection to determine the account ID '
        'one digit at a time.\n\n'
        'Role Requirements:\n'
        '1. You must either provide an existing role ARN that you can assume\n'
        '2. Or have permissions to create a temporary role (requires IAM write access)\n'
        '3. The role (existing or created) must allow sts:AssumeRole\n\n'
        'ref: https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/'
    ),
    'services': ['S3', 'STS', 'IAM'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--buckets', '--role-arn'],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--buckets',
    required=False,
    default=None,
    help='Comma-separated list of S3 bucket names to enumerate'
)
parser.add_argument(
    '--role-arn',
    required=False,
    default=None,
    help='Role ARN to use for enumeration. If not provided, the module will attempt to create a temporary role'
)


def try_access_with_pattern(bucket_name, session, pattern, role_arn=None):
    """Try to access a bucket with a specific account ID pattern."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowResourceAccount",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringLike": {
                        "s3:ResourceAccount": [f"{pattern}*"]
                    }
                }
            }
        ]
    }

    try:
        sts = session.client('sts')
        if not role_arn:
            role_arn = session.current_role_arn

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='PacuS3EnumAccount',
            Policy=json.dumps(policy),
            DurationSeconds=900
        )

        s3 = boto3.client(
            's3',
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )

        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code in ['AccessDenied', 'InvalidClientTokenId']:
            return False
        if error_code == 'ThrottlingException':
            time.sleep(1)
            return try_access_with_pattern(bucket_name, session, pattern, role_arn)
        raise


def enumerate_bucket_account(bucket_name, session, role_arn=None):
    """Enumerate the AWS account ID that owns a bucket."""
    account_id = ''
    digits = '0123456789'

    print(f"\nStarting account ID discovery for bucket: {bucket_name}")
    print("Found digits will be marked with '*', remaining positions with 'x'")

    for position in range(12):
        found_digit = False
        for digit in digits:
            pattern = account_id + digit
            if try_access_with_pattern(bucket_name, session, pattern, role_arn):
                account_id += digit
                found_digit = True
                mask = '*' * len(account_id) + 'x' * (12 - len(account_id))
                print(f"\rCurrent progress: [{mask}]", end='', flush=True)
                break

        if not found_digit:
            if account_id:
                print(f"\nPartial account ID found: {account_id}")
            return None

    print(f"\nFound complete account ID: {account_id}")
    return account_id


def create_temp_role(session, bucket_name):
    """Create a temporary role for bucket enumeration."""
    iam = session.client('iam')
    role_name = f"PacuS3EnumRole-{int(time.time())}"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": session.current_role_arn
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        role_arn = response['Role']['Arn']

        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ]
                }
            ]
        }

        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"S3Access-{bucket_name}",
            PolicyDocument=json.dumps(bucket_policy)
        )

        print(f"Created temporary role: {role_arn}")
        return role_arn
    except ClientError as e:
        print(f"Error creating temporary role: {str(e)}")
        return None


def cleanup_temp_role(session, role_arn):
    """Clean up the temporary role."""
    if not role_arn:
        return

    try:
        iam = session.client('iam')
        role_name = role_arn.split('/')[-1]

        for policy in iam.list_role_policies(RoleName=role_name)['PolicyNames']:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy)

        iam.delete_role(RoleName=role_name)
        print(f"Cleaned up temporary role: {role_arn}")
    except ClientError as e:
        print(f"Error cleaning up role: {str(e)}")


def main(args, pacu_main):
    """Main module function."""
    session = pacu_main.get_active_session()

    if not isinstance(args, argparse.Namespace):
        args = parser.parse_args(args)

    buckets = []
    if args.buckets:
        buckets = args.buckets.split(',')
    elif session.S3:
        buckets = [bucket['Name'] for bucket in session.S3.get('Buckets', [])]

    if not buckets:
        print("No buckets specified. Use --buckets or run s3__enum_buckets first.")
        return None

    print(f"\nStarting enumeration of {len(buckets)} bucket(s)...")

    results = {
        'buckets_enumerated': len(buckets),
        'accounts_found': 0,
        'failed_buckets': 0,
        'account_ids': {}
    }

    role_arn = args.role_arn
    if not role_arn:
        role_arn = create_temp_role(session, buckets[0])

    try:
        for bucket in buckets:
            account_id = enumerate_bucket_account(bucket, session, role_arn)
            if account_id:
                results['accounts_found'] += 1
                results['account_ids'][bucket] = account_id
            else:
                results['failed_buckets'] += 1
    finally:
        if not args.role_arn:
            cleanup_temp_role(session, role_arn)

    return results


def summary(data, pacu_main):
    """Summarize the results of the module execution."""
    if not data:
        return 'No buckets were enumerated.'

    msg = (
        f'{data["accounts_found"]} account IDs found from {data["buckets_enumerated"]} buckets.\n'
        f'{data["failed_buckets"]} buckets failed enumeration.\n'
        '\nFound account IDs:'
    )

    for bucket, account_id in data['account_ids'].items():
        msg += f'\n  {bucket}: {account_id}'

    return msg
