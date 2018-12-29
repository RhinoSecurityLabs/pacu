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
    'one_liner': 'Downloads User Data from EC2 instances/launch templates.',

    # Description about what the module does and how it works
    'description': 'This module will take a list of EC2 instance IDs and/or EC2 launch template IDs and request then download the User Data associated with each instance/template. All of the data will be saved to ./sessions/[session_name]/downloads/ec2_user_data/.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['ec2__enum'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--instance-ids', '--template-ids'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instance-ids', required=False, default=None, help='One or more (comma separated) EC2 instance IDs with their regions in the format instance_id@region. Defaults to all EC2 instances in the database.')
parser.add_argument('--template-ids', required=False, default=None, help='One or more (comma separated) EC2 launch template IDs with their regions in the format template_id@region. Defaults to all EC2 launch templates in the database.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    instances = []
    templates = []
    summary_data = {'instance_downloads': 0, 'template_downloads': 0}

    if args.instance_ids is not None:
        for instance in args.instance_ids.split(','):
            instance_id, region = instance.split('@')
            instances.append({
                'InstanceId': instance_id,
                'Region': region
            })
    elif args.template_ids is None:
        # If args.instance_ids was not passed in,
        # only fetch instances if args.template_ids
        # is also None
        if fetch_data(['EC2', 'Instances'], module_info['prerequisite_modules'][0], '--instances') is False:
            print('Pre-req module not run successfully. Exiting...')
            return None
        instances = session.EC2['Instances']

    if args.template_ids is not None:
        for template in args.template_ids.split(','):
            template_id, region = template.split('@')
            templates.append({
                'LaunchTemplateId': template_id,
                'Region': region
            })
    elif args.instance_ids is None:
        # If args.template_ids was not passed in,
        # only fetch templates if args.instance_ids
        # is also None
        if fetch_data(['EC2', 'LaunchTemplates'], module_info['prerequisite_modules'][0], '--launch-templates') is False:
            print('Pre-req module not run successfully. Exiting...')
            templates = []
        else:
            templates = session.EC2['LaunchTemplates']

    if not os.path.exists('sessions/{}/downloads/ec2_user_data/'.format(session.name)):
        os.makedirs('sessions/{}/downloads/ec2_user_data/'.format(session.name))

    if instances:
        print('Targeting {} instance(s)...'.format(len(instances)))
        for instance in instances:
            instance_id = instance['InstanceId']
            region = instance['Region']
            client = pacu_main.get_boto3_client('ec2', region)

            try:
                user_data = client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )['UserData']
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'AccessDenied':
                    print('  Access denied to DescribeInstanceAttribute.')
                    print('Skipping the rest of the instances...')
                    break
                else:
                    print('  ' + code)

            if 'Value' in user_data.keys():
                decoded = base64.b64decode(user_data['Value'])

                if decoded[0] == 139:  # Byte \x8b (139) indicates gzip compressed content
                    decompressed = gzip.decompress(decoded)
                    formatted_user_data = '{}@{}:\n{}\n\n'.format(
                        instance_id,
                        region,
                        decompressed.decode('utf-8', 'backslashreplace')
                    )
                else:
                    formatted_user_data = '{}@{}:\n{}\n\n'.format(
                        instance_id,
                        region,
                        decoded.decode('utf-8', 'backslashreplace')
                    )

                print('  {}@{}: User Data found'.format(instance_id, region))

                # Write to the "all" file
                with open('sessions/{}/downloads/ec2_user_data/all_user_data.txt'.format(session.name), 'a+') as data_file:
                    data_file.write(formatted_user_data)
                # Write to the individual file
                with open('sessions/{}/downloads/ec2_user_data/{}.txt'.format(session.name, instance_id), 'w+') as data_file:
                    data_file.write(formatted_user_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
                summary_data['instance_downloads'] += 1
            else:
                print('  {}@{}: No User Data found'.format(instance_id, region))
        print()
    else:
        print('No instances to target.\n')

    if templates:
        print('Targeting {} launch template(s)...'.format(len(templates)))
        for template in templates:
            template_id = template['LaunchTemplateId']
            region = template['Region']
            client = pacu_main.get_boto3_client('ec2', region)

            all_versions = []

            try:
                response = client.describe_launch_template_versions(
                    LaunchTemplateId=template_id
                )
                all_versions.extend(response['LaunchTemplateVersions'])
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'AccessDenied':
                    print('  Access denied to DescribeLaunchTemplateVersions.')
                    print('Skipping the rest of the launch templates...\n')
                    break
                else:
                    print('  ' + code)

            while response.get('NextToken'):
                response = client.describe_launch_template_versions(
                    LaunchTemplateId=template_id,
                    NextToken=response['NextToken']
                )
                all_versions.extend(response['LaunchTemplateVersions'])

            for version in all_versions:
                if version['LaunchTemplateData'].get('UserData'):
                    try:
                        was_unzipped = False
                        user_data = version['LaunchTemplateData']['UserData']
                        formatted_user_data = '{}-version-{}@{}:\n{}\n\n'.format(
                            template_id,
                            version['VersionNumber'],
                            region,
                            base64.b64decode(user_data).decode('utf-8')
                        )
                    except UnicodeDecodeError as error:
                        if 'codec can\'t decode byte 0x8b' in str(error):
                            decoded = base64.b64decode(user_data['Value'])
                            decompressed = gzip.decompress(decoded)
                            formatted_user_data = '{}@{}:\n{}\n\n'.format(
                                instance_id,
                                region,
                                decompressed.decode('utf-8')
                            )
                            was_unzipped = True
                    print('  {}-version-{}@{}: User Data found'.format(template_id, version['VersionNumber'], region))
                    if was_unzipped:
                        print('    Gzip decoded the User Data')

                    # Write to the "all" file
                    with open('sessions/{}/downloads/ec2_user_data/all_user_data.txt'.format(session.name), 'a+') as data_file:
                        data_file.write(formatted_user_data)
                    # Write to the individual file
                    with open('sessions/{}/downloads/ec2_user_data/{}-version-{}.txt'.format(session.name, template_id, version['VersionNumber']), 'w+') as data_file:
                        data_file.write(formatted_user_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
                    summary_data['template_downloads'] += 1
                else:
                    print('  {}-version-{}@{}: No User Data found'.format(template_id, version['VersionNumber'], region))
        print()
    else:
        print('No launch templates to target.\n')

    return summary_data


def summary(data, pacu_main):
    session = pacu_main.get_active_session()
    out = '  Downloaded EC2 User Data for {} instance(s) and {} launch template(s) to ./sessions/{}/downloads/ec2_user_data/.\n'.format(data['instance_downloads'], data['template_downloads'], session.name)
    return out
