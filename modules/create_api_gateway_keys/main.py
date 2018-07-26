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

def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    regions = args.regions.split(',') if args.regions else get_regions('apigateway')

    lambda_data = {}
    summary_data = {}
    lambda_data['Functions'] = []
    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('apigateway', region)
        print('Test')
    return summary_data


def summary(data, pacu_main):
    out = ''
    return out
