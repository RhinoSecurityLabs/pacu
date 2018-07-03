#!/usr/bin/env python3
import argparse
import boto3
import botocore
from copy import deepcopy


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_glue',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

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
parser.add_argument('--connections', required=False, default=False, help='Enumerate Glue connections.')
parser.add_argument('--crawlers', required=False, default=False, help='Enumerate Glue crawlers.')
parser.add_argument('--databases', required=False, default=False, help='Enumerate Glue databases.')
parser.add_argument('--dev-endpoints', required=False, default=False, help='Enumerate Glue development endpoints.')
parser.add_argument('--jobs', required=False, default=False, help='Enumerate Glue jobs.')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    proxy_settings = pacu_main.get_proxy_settings()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    all = False
    if args.connections is False and args.databases is False and args.crawlers is False and args.jobs is False and args.dev_endpoints is False:
        all = True

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
        connections = []
        crawlers = []
        databases = []
        dev_endpoints = []
        jobs = []

        print(f'Starting region {region}...')
        client = boto3.client(
            'glue',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
        )

        # Connections
        if args.connections is True or all is True:
            try:
                response = client.get_connections(
                    MaxResults=200
                )

                for connection in response['ConnectionList']:
                    connection['Region'] = region
                    connections.append(connection)

                while 'NextToken' in response:
                    response = client.get_connections(
                        MaxResults=200,
                        NextToken=response['NextToken']
                    )
                    for connection in response['ConnectionList']:
                        connection['Region'] = region
                        connections.append(connection)

                print(f'  {len(connections)} connection(s) found.')
                all_connections += connections

            except Exception as error:
                print(f'Error while running client.get_connections: {error}')

        # Crawlers
        if args.crawlers is True or all is True:
            try:
                response = client.get_crawlers(
                    MaxResults=200
                )

                for crawler in response['Crawlers']:
                    crawler['Region'] = region
                    crawlers.append(crawler)

                while 'NextToken' in response:
                    response = client.get_crawlers(
                        MaxResults=200,
                        NextToken=response['NextToken']
                    )

                    for crawler in response['Crawlers']:
                        crawler['Region'] = region
                        crawlers.append(crawler)

                print(f'  {len(crawlers)} crawler(s) found.')
                all_crawlers += crawlers

            except Exception as error:
                print(f'Error while running client.get_crawlers: {error}')

        # Databases
        if args.databases is True or all is True:
            try:
                response = client.get_databases(
                    MaxResults=200
                )

                for database in response['DatabaseList']:
                    database['Region'] = region
                    databases.append(database)

                while 'NextToken' in response:
                    response = client.get_databases(
                        MaxResults=200,
                        NextToken=response['NextToken']
                    )

                    for database in response['DatabaseList']:
                        database['Region'] = region
                        databases.append(database)

                print(f'  {len(databases)} database(s) found.')
                all_databases += databases

            except Exception as error:
                print(f'Error while running client.get_databases: {error}')

        # Development Endpoints
        if args.dev_endpoints is True or all is True:
            try:
                response = client.get_dev_endpoints()
                for dev_endpoint in response['DevEndpoints']:
                    dev_endpoint['Region'] = region
                    dev_endpoints.append(dev_endpoint)

                while 'NextToken' in response and not response['NextToken'] == '':
                    response = client.get_dev_endpoints(
                        NextToken=response['NextToken']
                    )

                    for dev_endpoint in response['DevEndpoints']:
                        dev_endpoint['Region'] = region
                        dev_endpoints.append(dev_endpoint)

                print(f'  {len(dev_endpoints)} development endpoint(s) found.')
                all_dev_endpoints += dev_endpoints

            except Exception as error:
                print(f'Error while running client.get_dev_endpoints: {error}')

        # Jobs
        if args.jobs is True or all is True:
            try:
                response = client.get_jobs(
                    MaxResults=200
                )

                for job in response['Jobs']:
                    job['Region'] = region
                    jobs.append(job)

                while 'NextToken' in response:
                    response = client.get_jobs(
                        MaxResults=200,
                        NextToken=response['NextToken']
                    )

                    for job in response['Jobs']:
                        job['Region'] = region
                        jobs.append(job)

                print(f'  {len(jobs)} job(s) found.')
                all_jobs += jobs

            except Exception as error:
                print(f'Error while running client.get_jobs: {error}')

    print(f'{len(all_connections)} total connection(s) found.')
    print(f'{len(all_crawlers)} total crawler(s) found.')
    print(f'{len(all_databases)} total database(s) found.')
    print(f'{len(all_dev_endpoints)} total development endpoint(s) found.')
    print(f'{len(all_jobs)} total job(s) found.')

    glue_data = deepcopy(session.Glue)
    glue_data['Connections'] = all_connections
    glue_data['Crawlers'] = all_crawlers
    glue_data['Databases'] = all_databases
    glue_data['DevEndpoints'] = all_dev_endpoints
    glue_data['Jobs'] = all_jobs
    session.update(pacu_main.database, Glue=glue_data)

    print(f"{module_info['name']} completed.\n")
    return
