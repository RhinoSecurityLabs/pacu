#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError

module_info = {
    'name': 'enum_lightsail',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'recon_enum_with_keys',
    'one_liner': 'Captures common data associated with lightsail',
    'description': """
        This module takes a set of compromised keys and captures data found into the
        database. This data includes instances, states, snapshots, domains, disks, and
        operations.
        """,
    'services': ['lightsail'],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
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
    ],
}

master_fields = [
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


def add_field(name):
    parser.add_argument(
        '--' + name,
        required=False,
        default=False,
        action='store_true',
        help='Enumerate Lightsail ' + name.replace('-', ' ')
    )


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
for field in master_fields:
    add_field(field)


def help():
    return [module_info, parser.format_help()]


def setup_storage(fields):
    out = {}
    for field in fields:
        out[field] = []
    return out


def camelCase(name):
    splitted = name.split('_')
    out = splitted[0]
    for word in splitted[1:]:
        out += word[0].upper() + word[1:]
    return out


def fetch_lightsail_data(client, func):
    caller = getattr(client, 'get_' + func)
    try:
        response = caller()
        data = response[camelCase(func)]
        while 'nextPageToken' in response:
            response = caller(pageToken=response['nextPageToken'])
            data.append(response[camelCase(func)])
        return data
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print(f'AccessDenied for: {func}')
        else:
            print(f'Unknown Error:\n{error}')
    return []


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    fields = []
    for arg in vars(args):
        if getattr(args, arg):
            fields.append(arg)
    if not fields:
        fields = [field.replace('-', '_') for field in master_fields]

    lightsail_data = setup_storage(fields)
    regions = get_regions('lightsail')

    for region in regions:
        print(f'Starting region {region}...')
        client = pacu_main.get_boto3_client('lightsail', region)
        for field in fields:
            lightsail_data[field] = fetch_lightsail_data(client, field)

    session.update(pacu_main.database, Lightsail=lightsail_data)
    print(f"{module_info['name']} completed.\n")
    return
