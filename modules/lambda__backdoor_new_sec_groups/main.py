#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError


module_info = {
    'name': 'lambda__backdoor_new_sec_groups',

    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_created_security_groups_lambda/backdoor_created_security_groups_lambda.py',

    'category': 'PERSIST',

    'one_liner': 'Creates a Lambda function and CloudWatch Events rule to backdoor new security groups.',

    'description': 'This module creates a new Lambda function and an accompanying CloudWatch Events rule that will trigger upon a new EC2 security group being created in the account. The function will automatically add a backdoor rule to that security group with your supplied IP address as the source.',

    'services': ['Lambda', 'Events', 'EC2'],

    'prerequisite_modules': [],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--regions', '--ip-range', '==port-range'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions to create the backdoor Lambda function in, in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('--ip-range', required=True, help='The IP range to allow backdoor access to. This would most likely be your own IP address in the format: 127.0.0.1/32')
parser.add_argument('--port-range', required=False, default='1-65535', help='The port range to give yourself access to in the format: starting-ending (ex: 200-800). By default, all ports are allowed (1-65535).')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ######
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    get_regions = pacu_main.get_regions
    ######

    regions = get_regions('Lambda')

    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('lambda', region)
        data = client.do_something()

    return data


def summary(data, pacu_main):
    if 'some_relevant_key' in data.keys():
        return 'This module compromised {} instances in the SomeRelevantKey service.'.format(len(data['some_relevant_key']))
    else:
        return 'No instances of the SomeRelevantKey service were compromised.'
