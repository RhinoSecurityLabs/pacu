#!/usr/bin/env python3
import argparse
from copy import deepcopy

from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'transfer_family__enum',

    # Name and any other notes about the author
    'author': 'Julio Melo from appminer.io and eufuihackeado.com.br',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates AWS Transfer Family SFTP/FTP and FTPS servers',

    # Full description about what the module does and how it works
    'description': 'This module enumerates all relevant servers from AWS Transfer Family of a given region',
    # A list of AWS services that the module utilizes during its execution
    'services': ['Transfer'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [
        '--regions'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')

def fetch_transfer_servers(client, func, key, print, **kwargs):
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        data = response[key]
        while 'NextToken' in response and response['NextToken'] != '':
            print({**kwargs, **{'NextToken': response['NextToken']}})
            response = caller({**kwargs, **{'NextToken': response['NextToken']}})
            data.extend(response[key])
        for resource in data:
            resource['region'] = client.meta.region_name
        return data
    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('  {} FAILURE: MISSING NEEDED PERMISSIONS'.format(func))
        else:
            print(code)
    return []


def fetch_transfer_server_users(client, func, key, print, **kwargs):
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        data = response[key]
        while 'NextToken' in response and response['NextToken'] != '':
            print({**kwargs, **{'NextToken': response['NextToken']}})
            response = caller({**kwargs, **{'NextToken': response['NextToken']}})
            data.extend(response[key])
        for resource in data:
            resource['region'] = client.meta.region_name
        return data
    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('  {} FAILURE: MISSING NEEDED PERMISSIONS'.format(func))
        else:
            print(code)
    return []

def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    if args.regions is None:
        regions = get_regions('transfer')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    all_servers = []
    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('transfer', region)

        # Servers instances
        servers = fetch_transfer_servers(client, 'list_servers', 'Servers', print)
        print('  {} server(s) found.'.format(len(servers)))
        for server in servers:
            server_id = server['ServerId']
            server_details = client.describe_server(ServerId=server_id)
            server['Details'] = server_details
            server['Users'] = fetch_transfer_server_users(client, 'list_users', 'Users', print, ServerId=server_id)
            for user in server['Users']:
                user['Details'] = client.describe_user(ServerId=server_id, UserName=user['UserName'])
            server['Endpoint'] = f"{server_id}.server.transfer.{server['region']}.amazonaws.com"

        all_servers += servers

    summary_data = {
        'servers': len(all_servers),
    }

    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            del summary_data[var]

    transfer_data = deepcopy(session.Transfer)

    transfer_data['Servers'] = all_servers
    session.update(pacu_main.database, Transfer=transfer_data)

    return summary_data


def summary(data, pacu_main):
    out = ''
    for key in data:
        out += '  {} total {}(s) found.\n'.format(data[key], key[:-1])
    out += '\n  AWS Transfer Family resources saved in Pacu database. You can run `data Transfer` to view this info.\n'
    return out
