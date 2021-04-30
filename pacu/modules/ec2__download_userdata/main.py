#!/usr/bin/env python3
import argparse
import base64
import os
import gzip

from botocore.exceptions import ClientError

from pacu.core.lib import strip_lines, save, downloads_dir
from pacu.core.secretfinder.utils import regex_checker, Color
from pacu import Main

module_info = {
    'name': 'ec2__download_userdata',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'ENUM',
    'one_liner': 'Downloads User Data from EC2 instances/launch templates.',
    'description': strip_lines('''
        This module will take a list of EC2 instance IDs and/or EC2 launch template IDs and request then download the
        User Data associated with each instance/template. All of the data will be saved to
        ~/.local/share/pacu/sessions/[session_name]/downloads/ec2_user_data/.
    '''),
    'services': ['EC2'],
    'prerequisite_modules': ['ec2__enum'],
    'arguments_to_autocomplete': ['--instance-ids', '--template-ids', '--filter'],
}

parser = argparse.ArgumentParser(add_help=True, description=module_info['description'])

parser.add_argument('--instance-ids', required=False, default=None, help=strip_lines('''
    One or more (comma separated) EC2 instance IDs with their regions in the format instance_id@region. Defaults to all
    EC2 instances in the database.
'''))
parser.add_argument('--template-ids', required=False, default=None, help=strip_lines('''
    One or more (comma separated) EC2 launch template IDs with their regions in the format template_id@region. Defaults
    to all EC2 launch templates in the database.
'''))
parser.add_argument('--filter', required=False, default=False, help=strip_lines('''
    Specify tags, values or tag:value pairs to match before downloading user data. Using format tag_name_only:,
    :value_only, tag:value_pair
'''))

def main(args, pacu_main: 'Main'):
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
        if fetch_data(['EC2', 'Subnets'], module_info['prerequisite_modules'][0], '--instances') is False:
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

    if instances:
        print('Targeting {} instance(s)...'.format(len(instances)))
        for instance in instances: 

            # if the filter is actived check the tags. If tags do not match skip instance
            if args.filter and not has_tags(args.filter.split(','), instance):
                continue

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

                try:
                    decompressed = gzip.decompress(decoded)
                    formatted_user_data = '{}@{}:\n{}\n\n'.format(
                        instance_id,
                        region,
                        decompressed.decode('utf-8', 'backslashreplace')
                    )
                except:
                    formatted_user_data = '{}@{}:\n{}\n\n'.format(
                        instance_id,
                        region,
                        decoded.decode('utf-8', 'backslashreplace')
                    )

                print('  {}@{}: User Data found'.format(instance_id, region))

                # Check for secrets
                find_secrets(formatted_user_data)

                # Write to the "all" file
                with save('ec2_user_data/all_user_data.txt', 'a+') as f:
                    f.write(formatted_user_data)
                # Write to the individual file
                with save('ec2_user_data/{}.txt'.format(instance_id)) as f:
                    f.write(formatted_user_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
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
                        try:
                            decoded = base64.b64decode(user_data)
                            decompressed = gzip.decompress(decoded)
                            formatted_user_data = '{}@{}:\n{}\n\n'.format(
                                instance_id,
                                region,
                                decompressed.decode('utf-8')
                            )
                            was_unzipped = True
                        except:
                            print('ERROR: GZIP decrompressing template data')
                    print('  {}-version-{}@{}: User Data found'.format(template_id, version['VersionNumber'], region))
                    if was_unzipped:
                        print('    Gzip decoded the User Data')

                    # Write to the "all" file
                    with save('ec2_user_data/all_user_data.txt', 'a+') as f:
                        f.write(formatted_user_data)
                    # Write to the individual file
                    with save('ec2_user_data/{}-version-{}.txt'.format(template_id, version['VersionNumber'])) as f:
                        f.write(formatted_user_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
                    summary_data['template_downloads'] += 1
                else:
                    print('  {}-version-{}@{}: No User Data found'.format(template_id, version['VersionNumber'], region))
        print()
    else:
        print('No launch templates to target.\n')

    return summary_data


def find_secrets(userdata):
    detections = regex_checker(userdata)
    [Color.print(Color.GREEN, '\tDetected {}: {}'.format(itemkey, detections[itemkey])) for itemkey in detections]


def has_tags(filters, userdata):
    try:
        tags = userdata['Tags']
    # Instance has no Key
    except KeyError:
        return False
    
    # If there is only one tag it will be a dict. Convert it to a list
    if isinstance(tags, dict):
        tags = list(tags)

    for tag in tags:
        for item in filters:
            # This splits items at :
            item_list = item.split(':')
            
            # Item is a key value pair
            if len(item_list[0]) and len(item_list[1]) > 0:
                if '{}:{}'.format(item_list[0], item_list[1]) == "{}:{}".format(tag['Key'], tag['Value']):
                    return True
            # Key only 
            elif len(item_list[0]) > 0:
                if item_list[0] == tag['Key']:
                    return True
            # Value only
            else:
                if item_list[1] in tag['Value']:
                    return True
    # No matches were found 
    return False


def summary(data, pacu_main: 'Main'):
    session = pacu_main.get_active_session()
    out = '  Downloaded EC2 User Data for {} instance(s) and {} launch template(s) to {}/ec2_user_data/.\n'.format(
        downloads_dir(), data['instance_downloads'], data['template_downloads'], session.name
    )
    return out
