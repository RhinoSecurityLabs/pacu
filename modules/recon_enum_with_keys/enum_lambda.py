#!/usr/bin/env python3
import boto3
import argparse
import os
from botocore.exceptions import ClientError
from functools import partial

from pacu import util

# When writing a module, feel free to remove any comments, placeholders, or anything else that doesn't relate to your module

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_module',

    # Name and any other notes about the author
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates data from AWS Lambda',

    # Full description about what the module does and how it works
    'description': 'This module pulls data related to Lambda Functions, versions,',

    # A list of AWS services that the module utilizes during its execution
    'services': ['Lambda'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--versionsAll', required=False, default=False, action='store_true', help='Grab all versions instead of just the latest')


# For when "help module_name" is called, don't modify this
def help():
    return [module_info, parser.format_help()]


# Main is the first function that is called when this module is executed
def main(args, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    #input = partial(util.input, session_name=session.name, database=database)
    key_info = partial(util.key_info, database=database)
    #fetch_data = partial(util.fetch_data, database=database)
    get_regions = partial(util.get_regions, database=database)
    #install_dependencies = partial(util.install_dependencies, database=database)
    ######

    regions = get_regions('Lambda')

    lambda_data = {}
    lambda_data['Functions'] = []
    for region in regions:
        print('Starting region {}...'.format(region))
        client = boto3.client(
            'lambda',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token
        )
        try:
            account_settings = client.get_account_settings()
            # pop any ResponseMetaData to have cleaner account_settings response
            account_settings.pop('ResponseMetadata', None)
            for key in account_settings:
                lambda_data[key] = account_settings[key]
        except ClientError as err:
            if(err.response['Error']['Code'] == 'AccessDeniedException'):
                print('Access Denied for get-account-settings')
            else:
                print(err)

        lambda_functions = []
        try:
            response = client.list_functions()
            lambda_functions = response['Functions']
            while 'NextMarker' in response:
                response = client.list_functions(Marker=response['NextMarker'])
                lambda_functions += response['Functions']
        except ClientError as err:
            if(err.response['Error']['Code'] == 'AccessDeniedException'):
                print('Access Denied for list_functions')
        for func in lambda_functions:
            try:
                func['Code'] = client.get_function(FunctionName=func['FunctionArn'])['Code']
            except ClientError as err:
                if(err.response['Error']['Code'] == 'AccessDeniedException'):
                    print('Access Denied for get-function')
            try:
                response = client.list_aliases(FunctionName=func['FunctionArn'])
                func['Aliases'] = response['Aliases']
                while 'NextMarker' in response:
                    response = client.list_aliases(FunctionName=func['FunctionArn'], Marker=response['NextMarker'])
                    func['Aliases'] += response['Aliases']
            except ClientError as err:
                if(err.response['Error']['Code'] == 'AccessDeniedException'):
                    print('Access Denied for list-aliases')
            try:
                response = client.list_event_source_mappings(FunctionName=func['FunctionArn'])
                func['EventSourceMappings'] = response['EventSourceMappings']
                while 'NextMarker' in response:
                    response = client.list_event_source_mappings(FunctionName=func['FunctionArn'], Marker=response['NextMarker'])
                    func['EventSourceMappings'] += response['EventSourceMappings']
            except ClientError as err:
                if(err.response['Error']['Code'] == 'AccessDeniedException'):
                    print('Access Denied for list-event-source-mappings')
            if args.versionsAll:
                try:
                    response = client.list_versions_by_function(FunctionName=func['FunctionArn'])
                    func['Versions'] = response['Versions']
                    while 'NextMarker' in response:
                        response = client.list_versions_by_function(FunctionName=func['FunctionArn'], Marker=response['NextMarker'])
                        func['Versions'] += response['Versions']
                except ClientError as err:
                    if(err.response['Error']['Code'] == 'AccessDeniedException'):
                        print('Access Denied for list-versions-by-function')
            try:
                func['Tags'] = client.list_tags(Resource=func['FunctionArn'])['Tags']
            except ClientError as err:
                if(err.response['Error']['Code'] == 'AccessDeniedException'):
                    print('Access Denied for list-tags')
            try:
                func['Policy'] = client.get_policy(FunctionName=func['FunctionArn'])['Policy']
            except client.exceptions.ResourceNotFoundException:
                print('No valid Policy found for ' + func['FunctionName'])
            except ClientError as err:
                if(err.response['Error']['Code'] == 'AccessDeniedException'):
                    print('Access Denied for get-policy')
        lambda_data['Functions'] += lambda_functions

    session.update(database, Lambda=lambda_data)

    print('{} completed.'.format(os.path.basename(__file__)))
    return
