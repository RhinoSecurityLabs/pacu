#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError


# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'sms__get_secrets',

    # Name and any other notes about the author.
    'author': 'Nick Spagnola From RSL',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'enumerates and dumps secrets from AWS Secrets Manager and AWS parameter store',

    # Full description about what the module does and how it works.
    'description': 'This module will enumerate secrets in AWS Secrets Manager and AWS Systems manager parameter store.',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['SSM,secretsmanager'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab.
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('', required=False, default=None, help='')

ARG_FIELD_MAPPER = {
    'secrets': 'Secrets'
}

def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions


    if args.regions is None:
        regions = get_regions('secretsmanager')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return None
    else:
        regions = args.regions.split(',')

    all_secrets_secrets_manager = []
    all_secrets_ssm = []

    for region in regions:
        secrets = []
        secrets_ssm = []

        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('secretsmanager', region)
        
        
        response = None
        next_token = False
        while (response is None) or 'NextToken' in response):
            if next_token is False:
            try:
                response = client.list_secrets()
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'UnauthorizedOperation':
                    print('  Access denied to ListClusters.')
                else:
                    print('  ' + code)
                print('    Could not list secrets... Exiting')
                return None
                    
            else:
                response = client.list_secrets()

            for arn in response['clusterArns']:
                clusters.append(arn)
        print('  {} cluster arn(s) found.'.format(len(clusters)))
        all_clusters += clusters


    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    return data


# The summary function will be called by Pacu after running main, and will be
# passed the data returned from main. It should return a single string
# containing a curated summary of every significant thing that the module did,
# whether successful or not; or None if the module exited early and made no
# changes that warrant a summary being displayed. The data parameter can
# contain whatever data is needed in any structure desired. A length limit of
# 1000 characters is enforced on strings returned by module summary functions.
def summary(data, pacu_main):
    if 'some_relevant_key' in data.keys():
        return 'This module compromised {} instances in the SomeRelevantKey service.'.format(len(data['some_relevant_key']))
    else:
        return 'No instances of the SomeRelevantKey service were compromised.'
