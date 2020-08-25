#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'r53__enum',

    # Name and any other notes about the author.
    'author': 'Aaron Rea - Scalesec',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'Enumerates Route53 hosted zones',

    # Full description about what the module does and how it works.
    'description': 'This module enumerates Route53 hosted zones accross active regions in an accounnt',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['Route53'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab.
    'arguments_to_autocomplete': [
        '--regions'
    ],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    install_dependencies = pacu_main.install_dependencies

    data = {'HostedZones': []}

    try:
        client = pacu_main.get_boto3_client('route53')
        data['HostedZones'] = client.list_hosted_zones()['HostedZones']
    except ClientError as error:
        print('Failed to list R53 Hosted Zones')

    session.update(pacu_main.database, r53=data)

    return data


def summary(data, pacu_main):
    if 'Name' in data.keys():
        return f'Found {len(data['HostedZones'])} hosted zones'
    else:
        return 'No hosted zones found.'
