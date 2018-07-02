#!/usr/bin/env python3
import argparse
import boto3, botocore
from copy import deepcopy
from functools import partial
import os
import time

from pacu import util


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_elb_logging',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Collects a list of Elastic Load Balancers without access logging.',

    # Description about what the module does and how it works
    'description': 'This module will enumerate all EC2 Elastic Load Balancers and save their data to the current session, as well as write a list of ELBs with logging disabled to ./sessions/[current_session_name]/downloads/elbs_no_logs_[timestamp].csv.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['ElasticLoadBalancing'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')


def help():
    return [module_info, parser.format_help()]


def main(args, proxy_settings, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    get_regions = partial(util.get_regions, database=database)
    ######

    regions = get_regions('ElasticLoadBalancing')

    if 'LoadBalancers' not in session.EC2.keys():
        ec2_data = deepcopy(session.EC2)
        ec2_data['LoadBalancers'] = []
        session.update(database, EC2=ec2_data)

    load_balancers = list()
    for region in regions:
        print(f'Starting region {region}...')
        client = boto3.client(
            'elbv2',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
        )

        count = 0
        response = None
        next_marker = False

        while (response is None or 'NextMarker' in response):
            if next_marker is False:
                response = client.describe_load_balancers()
            else:
                response = client.describe_load_balancers(Marker=next_marker)

            if 'NextMarker' in response:
                next_marker = response['NextMarker']
            for load_balancer in response['LoadBalancers']:
                load_balancer['Region'] = region
                load_balancers.append(load_balancer)

            count += len(response['LoadBalancers'])

        print(f'  {count} total load balancer(s) found in {region}.')

    ec2_data = deepcopy(session.EC2)
    ec2_data['LoadBalancers'] = deepcopy(load_balancers)
    session.update(database, EC2=ec2_data)

    print(f"{len(session.EC2['LoadBalancers'])} total load balancer(s) found.")

    now = time.time()
    csv_file_path = f'sessions/{session.name}/downloads/elbs_no_logs_{now}.csv'

    with open(csv_file_path, 'w+') as csv_file:
        csv_file.write('Load Balancer Name,Load Balancer ARN,Region\n')

        for load_balancer in session.EC2['LoadBalancers']:
            print(load_balancer)
            response = client.describe_load_balancer_attributes(
                LoadBalancerArn=load_balancer['LoadBalancerArn']
            )
            print(response)

            for attribute in response['Attributes']:
                if attribute['Key'] == 'access_logs.s3.enabled':
                    if attribute['Value'] is False or attribute['Value'] == 'false':
                        csv_file.write(f"{load_balancer['LoadBalancerName']},{load_balancer['LoadBalancerArn']},{load_balancer['Region']}\n")

    print(f'A list of load balancers without access logging has been saved to ./{csv_file_path}')
    print('All data has been saved to the current session.')

    print(f'{os.path.basename(__file__)} completed.')
    return
