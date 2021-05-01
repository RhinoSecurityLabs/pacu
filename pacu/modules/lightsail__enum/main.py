#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError

MASTER_FIELDS = [
    'active-names',
    'blueprints',
    'bundles',
    'instances',
    'key-pairs',
    'operations',
    'static-ips',
    'disks',
    'disk-snapshots',
    'load-balancers'
]

module_info = {
    'name': 'lightsail__enum',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'ENUM',
    'one_liner': 'Captures common data associated with Lightsail',
    'description': "This module examines Lightsail data fields and automatically enumerates them for all available regions. Available fields can be passed upon execution to only look at certain types of data. By default, all Lightsail fields will be captured.",
    'services': ['Lightsail'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--' + field for field in MASTER_FIELDS],
}


def add_field(name: str) -> None:
    parser.add_argument(
        '--' + name,
        required=False,
        default=False,
        action='store_true',
        help='Enumerate Lightsail ' + name.replace('-', ' ')
    )


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
for field in MASTER_FIELDS:
    add_field(field)


def setup_storage(fields):
    out = {}
    for field in fields:
        out[field] = []
    return out


# Converts snake_case to camelcase.
def camelCase(name):
    splitted = name.split('_')
    out = splitted[0]
    for word in splitted[1:]:
        out += word[0].upper() + word[1:]
    return out


def fetch_lightsail_data(client, func, print):
    # Adding 'get_' portion to each field to build command.
    caller = getattr(client, 'get_' + func)
    try:
        response = caller()
        data = response[camelCase(func)]
        while 'nextPageToken' in response:
            response = caller(pageToken=response['nextPageToken'])
            data.extend(response[camelCase(func)])
        print('    Found {} {}'.format(len(data), func))
        if func != 'active_names':
            for resource in data:
                resource['region'] = client.meta.region_name
        return data
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print('  {}'.format(func))
            print('    FAILURE: MISSING REQUIRED AWS PERMISSIONS')
        else:
            print('Unknown Error:\n{}'.format(error))
    return []


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    fields = [arg for arg in vars(args) if getattr(args, arg)]
    if not fields:
        # Converts kebab-case to snake_case to match expected Boto3 function names.
        fields = [field.replace('-', '_') for field in MASTER_FIELDS]

    lightsail_data = setup_storage(fields)
    regions = get_regions('lightsail')

    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('lightsail', region)
        for field in fields:
            lightsail_data[field].extend(fetch_lightsail_data(client, field, print))

    summary_data = {'regions': regions}
    for field in lightsail_data:
        summary_data[field] = len(lightsail_data[field])

    session.update(pacu_main.database, Lightsail=lightsail_data)
    return summary_data


def summary(data, pacu_main):
    out = '  Regions Enumerated:\n'
    for region in data['regions']:
        out += '    {}\n'.format(region)
    del data['regions']
    for field in data:
        out += '  {} {} enumerated\n'.format(data[field], field[:-1] + '(s)')
    return out
