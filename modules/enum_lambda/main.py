#!/usr/bin/env python3
import argparse
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
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')


def fetch_lambda_data(client, print, func, key, **kwargs):
    caller = getattr(client, func)
    try:
        #print('  Starting enumeration of {}'.format(key))
        response = caller(**kwargs)
        data = response[key]
        if isinstance(data, (dict, list)):
            return data
        while 'nextMarker' in response:
            response = caller({**kwargs, **{'NextMarker': response['nextMarker']}})
            data.extend(response[key])
        return data
    except client.exceptions.ResourceNotFoundException:
        pass
    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('    FAILURE: MISSING NEEDED PERMISSIONS')
        else:
            print(code)
    return []


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    get_regions = pacu_main.get_regions
    ######

    regions = args.regions.split(',') if args.regions else get_regions('Lambda')

    lambda_data = {'AccountUsage':{}}
    summary_data = {}
    lambda_data['Functions'] = []
    for region in regions:
        print('Starting region {}...'.format(region))

        client = pacu_main.get_boto3_client('lambda', region)
        print('  Enumerating Account Settings')
        try:
            account_settings = client.get_account_settings()
            lambda_data['AccountUsage'][region] = {}
            lambda_data['AccountUsage'][region]['AccountLimit'] = account_settings['AccountLimit']
            lambda_data['AccountUsage'][region]['AccountUsage'] = account_settings['AccountUsage']
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('    FAILURE: MISSING NEEDED PERMISSIONS')
            else:
                print(error.response['Error']['Code'])
        
        print('  Enumerating Lambda Functions')
        lambda_functions = fetch_lambda_data(
            client, print, 'list_functions', 'Functions')
        if not lambda_functions:
            print('  No functions found')
            continue
        else:
            print('  Successfully found {} functions'.format(len(lambda_functions)))
            dive_prompt = input('  Perform deeper function enumeration? (y/n) ')
            if dive_prompt.lower() == 'y':
                for func in lambda_functions:
                    print('    Enumerating data for {}'.format(func['FunctionName']))
                    func_arn = func['FunctionArn']
                    func['Code'] = fetch_lambda_data(
                        client, print, 'get_function', 'Code',
                        FunctionName=func_arn)
                    func['Aliases'] = fetch_lambda_data(
                        client, print, 'list_aliases', 'Aliases',
                        FunctionName=func_arn)
                    func['EventSourceMappings'] = fetch_lambda_data(
                        client, print, 'list_event_source_mappings',
                        'EventSourceMappings', FunctionName=func_arn)
                    func['Tags'] = fetch_lambda_data(
                        client, print, 'list_tags', 'Tags', Resource=func_arn)
                    func['Policy'] = fetch_lambda_data(
                        client, print, 'get_policy', 'Policy',
                        FunctionName=func_arn)
                    if args.versions_all:
                        func['Versions'] = fetch_lambda_data(
                            client, print, 'list_versions_by_function',
                            'Versions', FunctionName=func_arn)
            for func in lambda_functions:
                func['Region'] = region
            lambda_data['Functions'] += lambda_functions
            summary_data[region] = len(lambda_functions)
    session.update(pacu_main.database, Lambda=lambda_data)

    print('\n{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    out = ''
    for region in sorted(data):
        out += '  {} functions found in {}.\n'.format(data[region], region)
    if not out:
        out = '  No Lambda data found'
    return out
