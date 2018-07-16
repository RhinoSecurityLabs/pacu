#!/usr/bin/env python3
import argparse
import base64
from botocore.exceptions import ClientError
import os


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'download_ec2_userdata',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Downloads user data from EC2 instances.',

    # Description about what the module does and how it works
    'description': 'This module will take a list of EC2 instance IDs and request then download the User Data associated with each instance. All of the data will be saved to ./sessions/[session_name]/downloads/user_data.txt.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_ec2_instances'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--instance-ids'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instance-ids', required=False, default=None, help='One or more (comma separated) EC2 instance IDs with their regions in the format instance_id@region. Defaults to all EC2 instances.')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    instances = []

    # Check permissions before doing anything
    try:
        client = pacu_main.get_boto3_client('ec2', 'us-east-1')
        client.describe_instance_attribute(
            Attribute='userData',
            DryRun=True,
            InstanceId='1'
        )
    except ClientError as e:
        if not str(e).find('UnauthorizedOperation') == -1:
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_instance_attribute".\nExiting module.')
            return

    if args.instance_ids is not None:
        for instance in args.instance_ids.split(','):
            instances.append({
                'InstanceId': instance.split('@')[0],
                'Region': instance.split('@')[1]
            })
    else:
        if fetch_data(['EC2', 'Instances'], 'enum_ec2', '--instances') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        instances = session.EC2['Instances']

    if not os.path.exists('sessions/{}/downloads/'.format(session.name)):
        os.makedirs('sessions/{}/downloads/'.format(session.name))

    for instance in instances:
        client = pacu_main.get_boto3_client('ec2', instance['Region'])

        user_data = client.describe_instance_attribute(
            InstanceId=instance['InstanceId'],
            Attribute='userData'
        )['UserData']

        if 'Value' in user_data.keys():
            formatted_user_data = '{}@{}:\n{}\n'.format(
                instance['InstanceId'],
                instance['Region'],
                base64.b64decode(user_data['Value'])
            )

            print(formatted_user_data)

            with open('sessions/{}/downloads/user_data.txt'.format(session.name), 'a+') as data_file:
                data_file.write(formatted_user_data)

        else:
            print('{}@{}: No user data'.format(instance['InstanceId'], instance['Region']))

    print('{} completed.\n'.format(module_info['name']))
    return
