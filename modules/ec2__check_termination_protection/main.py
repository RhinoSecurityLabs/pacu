#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import time


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'ec2__check_termination_protection',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Collects a list of EC2 instances without termination protection.',

    # Description about what the module does and how it works
    'description': 'This module will check to see if EC2 instance termination protection is enabled for a set of instances. By default, this module will run against all instances. All instances with termination protection disabled will be written to a file at ./sessions/[current_session_name]/downloads/termination_protection_disabled_[timestamp].csv in .CSV format.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['ec2__enum'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--instances'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instances', required=False, default=None, help='A comma separated list of EC2 instances and their regions in the format instanceid@region. The default is to target all instances.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######
    summary_data = {'instance_count': 0}
    # fetch_data is used when there is a prerequisite module to the current module. The example below shows how to fetch all EC2 security group data to use in this module.
    if fetch_data(['EC2', 'Instances'], module_info['prerequisite_modules'][0], '--instances') is False:
        print('Pre-req module not run successfully. Exiting...')
        return summary_data
    instances = session.EC2['Instances']

    now = time.time()
    csv_file_path = 'sessions/{}/downloads/termination_protection_disabled_{}.csv'.format(session.name, now)
    summary_data['csv_file_path'] = csv_file_path
    with open(csv_file_path, 'w+') as csv_file:
        csv_file.write('Instance Name,Instance ID,Region\n')
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
                    csv_file.write('{},{},{}\n'.format(name, instance['InstanceId'], instance['Region']))
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
