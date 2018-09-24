#!/usr/bin/env python3
import argparse
from copy import deepcopy

from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'glue__enum',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates Glue connections, crawlers, databases, development endpoints, and jobs.',

    # Full description about what the module does and how it works
    'description': 'This module enumerates all relevant data from AWS Glue, including connections, crawlers, databases, development endpoints, and jobs. By default, everything will be enumerated, but by passing available arguments, you can specify what data you want. For example, if any arguments are passed in, only the passed in arguments will be enumerated, but if either all or no arguments are passed in, everything will be enumerated.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['Glue'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [
        '--regions',
        '--connections',
        '--crawlers',
        '--databases',
        '--dev-endpoints',
        '--jobs'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')
parser.add_argument('--connections', required=False, default=False, action='store_true', help='Enumerate Glue connections.')
parser.add_argument('--crawlers', required=False, default=False, action='store_true', help='Enumerate Glue crawlers.')
parser.add_argument('--databases', required=False, default=False, action='store_true', help='Enumerate Glue databases.')
parser.add_argument('--dev-endpoints', required=False, default=False, action='store_true', help='Enumerate Glue development endpoints.')
parser.add_argument('--jobs', required=False, default=False, action='store_true', help='Enumerate Glue jobs.')


def fetch_glue_data(client, func, key, print, **kwargs):
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

    if args.connections is False and args.databases is False and args.crawlers is False and args.jobs is False and args.dev_endpoints is False:
        args.connections = args.databases = args.crawlers = args.jobs = args.dev_endpoints = True
    if args.regions is None:
        regions = get_regions('glue')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    all_connections = []
    all_crawlers = []
    all_databases = []
    all_dev_endpoints = []
    all_jobs = []
    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('glue', region)

        # Connections
        if args.connections:
            connections = fetch_glue_data(client, 'get_connections', 'ConnectionList', print)
            print('  {} connection(s) found.'.format(len(connections)))
            all_connections += connections

        # Crawlers
        if args.crawlers:
            crawlers = fetch_glue_data(client, 'get_crawlers', 'Crawlers', print)
            print('  {} crawler(s) found.'.format(len(crawlers)))
            all_crawlers += crawlers

        # Databases
        if args.databases:
            databases = fetch_glue_data(client, 'get_databases', 'DatabaseList', print)
            print('  {} database(s) found.'.format(len(databases)))
            all_databases += databases

        # Development Endpoints
        if args.dev_endpoints:
            dev_endpoints = fetch_glue_data(client, 'get_dev_endpoints', 'DevEndpoints', print)
            print('  {} development endpoint(s) found.'.format(len(dev_endpoints)))
            all_dev_endpoints += dev_endpoints

        # Jobs
        if args.jobs:
            jobs = fetch_glue_data(client, 'get_jobs', 'Jobs', print)
            print('  {} job(s) found.'.format(len(jobs)))
            all_jobs += jobs

    summary_data = {
        'connections': len(all_connections),
        'crawlers': len(all_crawlers),
        'databases': len(all_databases),
        'dev_endpoints': len(all_dev_endpoints),
        'jobs': len(all_jobs),
    }

    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            del summary_data[var]

    glue_data = deepcopy(session.Glue)
    glue_data['Connections'] = all_connections
    glue_data['Crawlers'] = all_crawlers
    glue_data['Databases'] = all_databases
    glue_data['DevEndpoints'] = all_dev_endpoints
    glue_data['Jobs'] = all_jobs
    session.update(pacu_main.database, Glue=glue_data)

    return summary_data


def summary(data, pacu_main):
    out = ''
    for key in data:
        out += '  {} total {}(s) found.\n'.format(data[key], key[:-1])
    out += '\n  Glue resources saved in Pacu database.\n'
    return out
