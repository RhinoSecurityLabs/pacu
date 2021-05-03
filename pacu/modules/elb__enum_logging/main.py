#!/usr/bin/env python3
import argparse
from copy import deepcopy
import time

from botocore.exceptions import ClientError

from pacu.core.lib import strip_lines, save
from pacu import Main

module_info = {
    'name': 'elb__enum_logging',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'EVADE',
    'one_liner': 'Collects a list of Elastic Load Balancers without access logging.',
    'description': strip_lines('''
        This module will enumerate all EC2 Elastic Load Balancers and save their data to the current session, as well as
        write a list of ELBs with logging disabled to
        ~/.local/share/pacu/sessions/[current_session_name]/downloads/elbs_no_logs_[timestamp].csv.
    '''),
    'services': ['ElasticLoadBalancing'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help=strip_lines('''
    One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.
'''))


def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print

    get_regions = pacu_main.get_regions
    if not args.regions:
        regions = get_regions('elasticloadbalancing')
    else:
        regions = args.regions.split(',')
    summary_data = {'load_balancers': 0}
    if 'LoadBalancers' not in session.EC2.keys():
        ec2_data = deepcopy(session.EC2)
        ec2_data['LoadBalancers'] = []
        session.update(pacu_main.database, EC2=ec2_data)

    load_balancers = list()
    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('elbv2', region)

        count = 0
        response = None
        next_marker = False

        while (response is None or 'NextMarker' in response):
            try:
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
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDenied':
                    print('  FAILURE: MISSING REQUIRED AWS PERMISSIONS')
                else:
                    print('  {}'.format(error.response['Error']['Code']))
                break
            if response and 'LoadBalancers' in response:
                count += len(response['LoadBalancers'])
        summary_data['load_balancers'] += count
        print('  {} load balancer(s) found '.format(count))

    ec2_data = deepcopy(session.EC2)
    ec2_data['LoadBalancers'] = deepcopy(load_balancers)
    session.update(pacu_main.database, EC2=ec2_data)

    print('\n{} total load balancer(s) found.'.format(len(session.EC2['LoadBalancers'])))

    now = time.time()
    p = 'elbs_no_logs_{}.csv'.format(now)
    summary_data['csv_file_path'] = p
    summary_data['logless'] = 0

    with save(p, 'w+') as f:
        f.write('Load Balancer Name,Load Balancer ARN,Region\n')
        for load_balancer in session.EC2['LoadBalancers']:
            for attribute in load_balancer['Attributes']:
                if attribute['Key'] == 'access_logs.s3.enabled':
                    if attribute['Value'] is False or attribute['Value'] == 'false':
                        f.write('{},{},{}\n'.format(
                            load_balancer['LoadBalancerName'], load_balancer['LoadBalancerArn'], load_balancer['Region'])
                        )
                        summary_data['logless'] += 1
    return summary_data


def summary(data, pacu_main: 'Main'):
    out = '  {} Load balancer(s) have been found\n'.format(data['load_balancers'])
    if data['logless'] > 0:
        out += '  {} Load balancer(s) found without logging\n'.format(data['logless'])
        out += '  List of Load balancers without logging saved to:\n    {}\n'.format(data['csv_file_path'])
    return out
