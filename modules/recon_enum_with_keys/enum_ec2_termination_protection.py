#!/usr/bin/env python3
import argparse
import boto3, botocore
from botocore.exceptions import ClientError
from copy import deepcopy
from functools import partial
import os
import time

from pacu import util


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_ec2_termination_protection',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Collects a list of EC2 instances without termination protection.',

    # Description about what the module does and how it works
    'description': 'This module will check to see if EC2 instance termination protection is enabled for a set of instances. By default, this module will run against all instances. All instances with termination protection disabled will be written to a file at ./sessions/[current_session_name]/downloads/termination_protection_disabled_[timestamp].csv in .CSV format.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_ec2_instances'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--instances'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instances', required=False, default=None, help='A comma separated list of EC2 instances and their regions in the format instanceid@region. The default is to target all instances.')


def help():
    return [module_info, parser.format_help()]


def main(args, proxy_settings, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    fetch_data = partial(util.fetch_data, database=database)
    ######

    # fetch_data is used when there is a prerequisite module to the current module. The example below shows how to fetch all EC2 security group data to use in this module.
    if fetch_data(['EC2', 'Instances'], 'enum_ec2_instances', '') is False:
        print('Pre-req module not run successfully. Exiting...')
        return
    instances = session.EC2['Instances']

    try:
        client = boto3.client(
            'ec2',
            region_name=instances[0]['Region'],
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
        )
        dryrun = client.describe_instance_attribute(
            DryRun=True,
            Attribute='disableApiTermination',
            InstanceId=instances[0]['InstanceId']
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_instance_attribute".\nExiting module.')
            return

    now = time.time()
    csv_file_path = f'sessions/{session.name}/downloads/termination_protection_disabled_{now}.csv'

    with open(csv_file_path, 'w+') as csv_file:
        csv_file.write('Instance Name,Instance ID,Region\n')
        for instance in instances:
            client = boto3.client(
                'ec2',
                region_name=instance['Region'],
                aws_access_key_id=session.access_key_id,
                aws_secret_access_key=session.secret_access_key,
                aws_session_token=session.session_token,
                config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
            )

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
                    csv_file.write(f"{name},{instance['InstanceId']},{instance['Region']}\n")
            except Exception as error:
                print(f"Failed to retrieve info for instance ID {instance['InstanceId']}: {error}")

    ec2_data = deepcopy(session.EC2)
    ec2_data['Instances'] = instances
    session.update(database, EC2=ec2_data)

    print(f'Instances with Termination Protection disabled have been written to ./{csv_file_path}')
    print(f'{os.path.basename(__file__)} completed.')
    return
