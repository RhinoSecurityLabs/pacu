#!/usr/bin/env python3
import argparse
from copy import deepcopy
import time
from utils import convert_list_to_dict_by_key


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_elb_logging',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

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


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    regions = get_regions('elasticloadbalancing')
    summary_data = {'load_balancers': 0}
    if 'LoadBalancers' not in session.EC2.keys():
        ec2_data = deepcopy(session.EC2)
        ec2_data['LoadBalancers'] = {}
        session.update(pacu_main.database, EC2=ec2_data)

    load_balancers = list()
    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('elbv2', region)

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
                # Adding Attributes to current load balancer database
                load_balancer['Attributes'] = client.describe_load_balancer_attributes(
                    LoadBalancerArn=load_balancer['LoadBalancerArn']
                )['Attributes']
                load_balancers.append(load_balancer)

            count += len(response['LoadBalancers'])
        summary_data['load_balancers'] += count
        print('  {} total load balancer(s) found in {}.'.format(count, region))

    ec2_data = deepcopy(session.EC2)


    # CHECK BEFORE COMMITTING
    ec2_data['LoadBalancers'] = deepcopy(convert_list_to_dict_by_key(load_balancers, 'LoadBalancerName'))


    session.update(pacu_main.database, EC2=ec2_data)

    print('{} total load balancer(s) found.'.format(len(session.EC2['LoadBalancers'])))

    now = time.time()
    csv_file_path = 'sessions/{}/downloads/elbs_no_logs_{}.csv'.format(session.name, now)
    summary_data['csv_file_path'] = csv_file_path

    with open(csv_file_path, 'w+') as csv_file:
        csv_file.write('Load Balancer Name,Load Balancer ARN,Region\n')
        for name, load_balancer in session.EC2['LoadBalancers'].items():
            print(load_balancer)
            for attribute in load_balancer['Attributes']:
                if attribute['Key'] == 'access_logs.s3.enabled':
                    if attribute['Value'] is False or attribute['Value'] == 'false':
                        csv_file.write('{},{},{}\n'.format(name, load_balancer['LoadBalancerArn'], load_balancer['Region']))

    print('A list of load balancers without access logging has been saved to ./{}'.format(csv_file_path))
    print('All data has been saved to the current session.')

    print('{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    out = '  {} Load balancer(s) have been found\n'.format(data['load_balancers'])
    if data['load_balancers'] > 0:
        out += '    Load balancer information has been saved to: {}\n'.format(data['csv_file_path'])
    return out
