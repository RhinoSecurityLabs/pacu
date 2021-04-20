#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import time

from pacu.core.lib import strip_lines, save
from pacu import Main

module_info = {
    'name': 'ec2__check_termination_protection',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'ENUM',
    'one_liner': 'Collects a list of EC2 instances without termination protection.',
    'description': strip_lines('''
        This module will check to see if EC2 instance termination protection is enabled for a set of instances. By 
        default, this module will run against all instances. All instances with termination protection disabled will be 
        written to a file at ~/.local/share/pacu/sessions/[current_session_name]/downloads/termination_protection_disabled_[timestamp].csv
        in .CSV format.
    '''),
    'services': ['EC2'],
    'prerequisite_modules': ['ec2__enum'],
    'arguments_to_autocomplete': ['--instances'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instances', required=False, default=None, help=strip_lines('''
    A comma separated list of EC2 instances and their regions in the format instanceid@region. The default is to target 
    all instances.
'''))


def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print

    fetch_data = pacu_main.fetch_data
    ######
    summary_data = {'instance_count': 0}
    # fetch_data is used when there is a prerequisite module to the current module. The example below shows how to fetch
    # all EC2 security group data to use in this module.
    if fetch_data(['EC2', 'Instances'], module_info['prerequisite_modules'][0], '--instances') is False:
        print('Pre-req module not run successfully. Exiting...')
        return summary_data
    instances = session.EC2['Instances']

    now = time.time()
    p = 'termination_protection_disabled_{}.csv'.format(session.name, now)
    summary_data['csv_file_path'] = p
    with save(p, 'w+') as f:
        f.write('Instance Name,Instance ID,Region\n')
        for instance in instances:
            client = pacu_main.get_boto3_client('ec2', instance['Region'])

            try:
                instance['TerminationProtection'] = client.describe_instance_attribute(
                    Attribute='disableApiTermination',
                    InstanceId=instance['InstanceId']
                )['DisableApiTermination']['Value']
                if instance['TerminationProtection'] is False:
                    name = ''
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    f.write('{},{},{}\n'.format(name, instance['InstanceId'], instance['Region']))
                    summary_data['instance_count'] += 1
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'UnauthorizedOperation':
                    print('  Access denied to DescribeInstanceAttribute.')
                    break
                else:
                    print('  ' + code)
                print('Failed to retrieve info for instance ID {}: {}'.format(instance['InstanceId'], error))

    ec2_data = deepcopy(session.EC2)
    ec2_data['Instances'] = instances
    session.update(pacu_main.database, EC2=ec2_data)
    return summary_data


def summary(data, pacu_main):
    out = '  {} instances have termination protection disabled\n'.format(data['instance_count'])
    if data['instance_count'] > 0:
        out += '  Identified instances have been written to:\n'
        out += '     {}\n'.format(data['csv_file_path'])
    return out
