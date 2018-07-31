#!/usr/bin/env python3
import os
import csv
import argparse
from botocore.exceptions import ClientError
module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'generate_lightsail_ssh_keys',

    # Name and any other notes about the author
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'post_exploitation',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Creates SSH keys for available regions in AWS Lightsail.',

    # Full description about what the module does and how it works
    'description': 'This module creates SSH keys that can be used to connect to Lightsail instances. New keys can be created, or a public key file can be passed to import a pre-existing key.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['Lightsail'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--key-name', '--import-key-file', '--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--key-name', default='Pacu', required=False, help='Alias for imported/created key pair. Defaults to Pacu.')
parser.add_argument('--import-key-file', required=False, help='Import a key if specified, otherwise, create one.')
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    args = parser.parse_args(args)
    created_keys = {}
    name = args.key_name
    regions = args.regions.split(',') if args.regions else get_regions('lightsail')

    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('lightsail', region)
        try:
            if args.import_key_file is None:
                print('  Creating new key...')
                response = client.create_key_pair(keyPairName=name)
                created_keys[region] = {
                    'name': name,
                    'private': response['privateKeyBase64'],
                    'public': response['publicKeyBase64']
                }
            else:
                print('  Importing key...')
                try:
                    with open(args.import_key_file, 'r') as key_file:
                        key = key_file.read()
                except IOError:
                    print('Error opening key file.')
                    break
                response = client.import_key_pair(keyPairName=name, publicKeyBase64=key)
                created_keys[region] = {
                    'name': name,
                    'private': 'IMPORTED',
                    'public': key
                }
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('Unauthorized to add key pair to Lightsail.')
            elif 'already in use' in str(error):
                print('Key name already in use.')
                continue
            break
        except client.exceptions.InvalidInputException as error:
            print('Invalid key format provided.')
            break

    ssh_key_dir = os.path.join(os.getcwd(), 'sessions', session.name, 'downloads', 'ssh')
    if not os.path.exists(ssh_key_dir):
        os.makedirs(ssh_key_dir)
    file_name = os.path.join(ssh_key_dir, 'keys.csv')

    with open(file_name, 'w') as csvfile:
        writer = csv.writer(csvfile)
        for region in created_keys:
            key = created_keys[region]
            writer.writerow([region, key['name'], key['public'], key['private']])
    print('{} completed.\n'.format(module_info['name']))

    summary_data = {'keys': len(created_keys.keys())}
    return summary_data


def summary(data, pacu_main):
    out = '  {} keys created'.format(data['keys'])
    return out
