#!/usr/bin/env python3
import argparse
import base64
import os
import gzip

from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'ec2__download_userdata',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Downloads User Data from EC2 instances.',

    # Description about what the module does and how it works
    'description': 'This module will take a list of EC2 instance IDs and request then download the User Data associated with each instance. All of the data will be saved to ./sessions/[session_name]/downloads/user_data.txt.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['ec2__enum'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--instance-ids'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instance-ids', required=False, default=None, help='One or more (comma separated) EC2 instance IDs with their regions in the format instance_id@region. Defaults to all EC2 instances.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    instances = []
    summary_data = {'userdata_downloads': 0}
    # Check permissions before doing anything
    try:
        client = pacu_main.get_boto3_client('ec2', pacu_main.get_regions('ec2')[0])
        client.describe_instance_attribute(
            Attribute='userData',
            DryRun=True,
            InstanceId='1'
        )
    except ClientError as error:
        code = error.response['Error']['Code']
        if code != 'DryRunOperation':
            print('FAILURE: ')
            if code == 'AccessDenied':
                print('  MISSING NEEDED PERMISSIONS')
            else:
                print('  ' + code)

    if args.instance_ids is not None:
        for instance in args.instance_ids.split(','):
            instances.append({
                'InstanceId': instance.split('@')[0],
                'Region': instance.split('@')[1]
            })
    else:
        if fetch_data(['EC2', 'Instances'], module_info['prerequisite_modules'][0], '--instances') is False:
            print('Pre-req module not run successfully. Exiting...')
            return None
        instances = session.EC2['Instances']

    if not os.path.exists('sessions/{}/downloads/ec2_user_data/'.format(session.name)):
        os.makedirs('sessions/{}/downloads/ec2_user_data/'.format(session.name))

    print('Targeting {} instance(s)...'.format(len(instances)))
    for instance in instances:
        instance_id = instance['InstanceId']
        region = instance['Region']
        client = pacu_main.get_boto3_client('ec2', region)

        user_data = client.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute='userData'
        )['UserData']

        if 'Value' in user_data.keys():
            try:
                formatted_user_data = '{}@{}:\n{}\n\n'.format(
                    instance_id,
                    region,
                    base64.b64decode(user_data['Value']).decode('utf-8')
                )
                print('  {}@{}: User Data found'.format(instance_id, region))
            except UnicodeDecodeError as error:
                if 'codec can\'t decode byte 0x8b' in str(error):
                    decoded = base64.b64decode(user_data['Value'])
                    decompressed = gzip.decompress(decoded)
                    formatted_user_data = '{}@{}:\n{}\n\n'.format(
                        instance_id,
                        region,
                        decompressed.decode('utf-8')
                    )
                    print('  {}@{}: User Data found'.format(instance_id, region))

            # Write to the "all" file
            with open('sessions/{}/downloads/ec2_user_data/all_user_data.txt'.format(session.name), 'a+') as data_file:
                data_file.write(formatted_user_data)
            # Write to the individual file
            with open('sessions/{}/downloads/ec2_user_data/{}.txt'.format(session.name, instance_id), 'w+') as data_file:
                data_file.write(formatted_user_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
            summary_data['userdata_downloads'] += 1

        else:
            print('  {}@{}: No User Data found'.format(instance_id, region))

    return summary_data


def summary(data, pacu_main):
    session = pacu_main.get_active_session()
    out = '  Downloaded EC2 User Data for {} instance(s) to ./sessions/{}/downloads/ec2_user_data/.\n'.format(data['userdata_downloads'], session.name)
    return out
