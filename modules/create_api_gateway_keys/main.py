#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'create_api_gateway_keys',

    # Name and any other notes about the author
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'post_exploitation',
    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Attempts to create an API gateway key for a (or all) rest APIs that are defined.',

    # Full description about what the module does and how it works
    'description': 'This module pulls data related to Lambda Functions, source code, aliases, event source mappings, versions, tags, and policies.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['apigateway'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')
parser.add_argument('--cleanup', required=False, default=None, action='store_true', help='Searches for Pacu keys previously generated and removes them.')


def cleanup(pacu_main, regions):
    for region in regions:
        client = pacu_main.get_boto3_client('apigateway', region)
        try:
            keys = client.get_api_keys()['items']
            if len(keys) < 1:
                print('  No keys were found for {}'.format(region))
            for key in keys:
                if key['name'] == 'Pacu':
                    try:
                        client.delete_api_key(apiKey=key['id'])
                        print('  Key deletion successul for: {}'.format(region))
                    except ClientError as error:
                        if error.response['Error']['Code'] == 'AccessDeniedException':
                            print('The current credentials lacks the authorization to delete API keys.')
                            return False
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('The current credentials lacks the authorization to list API keys.')
                return False
    return True


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    regions = args.regions.split(',') if args.regions else get_regions('apigateway')
    summary_data = {}

    if args.cleanup:
        if cleanup(pacu_main, regions):
            print('  Successfully cleaned up old Pacu keys.')
            summary_data['cleanup'] = True
        else:
            print('  Keys were not successfully cleaned up.')
            summary_data['cleanup'] = False
        user_input = input('  Do you want to continue key creation? (y/n)')
        if user_input != 'y':
            return summary_data

    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('apigateway', region)
        try:
            response = client.create_api_key(name='Pacu')
            print('  Successfully created API key for: {}'.format(region))
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Unable to add key due to lack of authorization')
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'cleanup' in data:
        if data['cleanup']:
            out += '  Old keys were successfully removed\n'
        else:
            out += '  Old keys were not successfully removed\n'
    return out
