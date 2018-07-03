#!/usr/bin/env python3
import argparse
import boto3
import botocore
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_lambda',

    # Name and any other notes about the author
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates data from AWS Lambda.',

    # Full description about what the module does and how it works
    'description': 'This module pulls data related to Lambda Functions, source code, aliases, event source mappings, versions, tags, and policies.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['Lambda'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--versions-all'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--versions-all', required=False, default=False, action='store_true', help='Grab all versions instead of just the latest')


# For when "help module_name" is called, don't modify this
def help():
    return [module_info, parser.format_help()]


# Main is the first function that is called when this module is executed
def main(args, pacu_main):
    session = pacu_main.get_active_session()
    proxy_settings = pacu_main.get_proxy_settings()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    regions = get_regions('Lambda')

    lambda_data = {}
    lambda_data['Functions'] = []
    for region in regions:
        print(f'Starting region {region}...')

        client = boto3.client(
            'lambda',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
        )

        try:
            account_settings = client.get_account_settings()
            # pop any ResponseMetaData to have cleaner account_settings response
            account_settings.pop('ResponseMetadata', None)
            for key in account_settings:
                lambda_data[key] = account_settings[key]
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Access Denied for get-account-settings')
            else:
                print(error)

        lambda_functions = []
        try:
            response = client.list_functions()
            lambda_functions = response['Functions']
            while 'NextMarker' in response:
                response = client.list_functions(Marker=response['NextMarker'])
                lambda_functions += response['Functions']
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Access Denied for list_functions')

        for func in lambda_functions:
            try:
                func['Code'] = client.get_function(FunctionName=func['FunctionArn'])['Code']
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('Access Denied for get-function')

            try:
                response = client.list_aliases(FunctionName=func['FunctionArn'])
                func['Aliases'] = response['Aliases']
                while 'NextMarker' in response:
                    response = client.list_aliases(FunctionName=func['FunctionArn'], Marker=response['NextMarker'])
                    func['Aliases'] += response['Aliases']
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('Access Denied for list-aliases')

            try:
                response = client.list_event_source_mappings(FunctionName=func['FunctionArn'])
                func['EventSourceMappings'] = response['EventSourceMappings']
                while 'NextMarker' in response:
                    response = client.list_event_source_mappings(FunctionName=func['FunctionArn'], Marker=response['NextMarker'])
                    func['EventSourceMappings'] += response['EventSourceMappings']
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('Access Denied for list-event-source-mappings')

            if args.versionsAll:
                try:
                    response = client.list_versions_by_function(FunctionName=func['FunctionArn'])
                    func['Versions'] = response['Versions']
                    while 'NextMarker' in response:
                        response = client.list_versions_by_function(FunctionName=func['FunctionArn'], Marker=response['NextMarker'])
                        func['Versions'] += response['Versions']
                except ClientError as error:
                    if error.response['Error']['Code'] == 'AccessDeniedException':
                        print('Access Denied for list-versions-by-function')

            try:
                func['Tags'] = client.list_tags(Resource=func['FunctionArn'])['Tags']
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('Access Denied for list-tags')

            try:
                func['Policy'] = client.get_policy(FunctionName=func['FunctionArn'])['Policy']
            except client.exceptions.ResourceNotFoundException:
                print('No valid Policy found for ' + func['FunctionName'])
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('Access Denied for get-policy')

        lambda_data['Functions'] += lambda_functions

    session.update(pacu_main.database, Lambda=lambda_data)

    print(f"{module_info['name']} completed.\n")
    return
