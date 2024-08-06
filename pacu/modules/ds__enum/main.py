#!/usr/bin/env python3
import argparse
from copy import deepcopy
from random import choice

from pacu.core.lib import save
from botocore.exceptions import ClientError
from pacu.core.secretfinder.utils import regex_checker, Color

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'ds__enum',

    # Name and any other notes about the author
    'author': '@_chebuya of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates a AWS Directory Service offerings.',

    # Description about what the module does and how it works
    'description': 'The module is used to enumerate AWS Directory Service offerings including AWS Managed Microsoft AD, AD Connector, and Simple AD',

    # A list of AWS services that the module utilizes during its execution
    'services': ['DS'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [
        '--regions',
        '--managed-ad',
        '--directories',
        '--domain-controllers',
        '--trusts',
        '--settings',
        '--shared-directories'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions')
parser.add_argument('--directories', required=False, default=False, action='store_true', help='Enumerate Directories')
parser.add_argument('--domain-controllers', required=False, default=False, action='store_true', help='Enumerate Domain Controllers')
parser.add_argument('--trusts', required=False, default=False, action='store_true', help='Enumerate Domain Trusts')
parser.add_argument('--settings', required=False, default=False, action='store_true', help='Enumerate Directory Settings')
parser.add_argument('--shared-directories', required=False, default=False, action='store_true', help='Enumerate Shared Directories')

ARG_FIELD_MAPPER = {
    'managed_ad': 'ManagedAD',
    'directories': 'Directories',
    'domain_controllers': 'DomainControllers',
    'trusts': 'Trusts',
    'settings': 'Settings',
    'shared_directories': 'SharedDirectories'
}

def get_directories(client, do_print=True):
    directories = {}

    paginator = client.get_paginator("describe_directories")
    for resource_records in paginator.paginate():
        directories.update({directory["DirectoryId"]:directory for directory in resource_records['DirectoryDescriptions']})

    if not do_print:
        return directories

    for directory_id,directory in directories.items():
        directory_type = directory['Type']

        print(f"DirectoryId: {directory_id}")
        print(f"  DNSName: {directory['Name']}")
        print(f"  NetBIOSName: {directory['ShortName']}")
        print(f"  DirectoryType: {directory_type}")
        if "Description" in directory:
            print(f"  Description: {directory['Description']}")
        if "Edition" in directory:
            print(f"  Edition: {directory['Edition']}")
        if "Size" in directory:
            print(f"  Size: {directory['Size']}")
        print(f"  CreatedAt: {str(directory['LaunchTime'])}")

    return directories    


def get_domain_controllers(client, directories):
    directory_domain_controllers = {}

    
    directory_ids = list(directories)

    for directory_id in directory_ids:
        
        paginator = client.get_paginator("describe_domain_controllers")
        for resource_records in paginator.paginate(DirectoryId=directory_id):

            directory_domain_controllers[directory_id] = [domain_controller for domain_controller in resource_records['DomainControllers']]

    
    for directory_id,domain_controllers in directory_domain_controllers.items():

        print(f"Domain controllers for {directory_id}/{directories[directory_id]['Name']}")

        for domain_controller in domain_controllers:

            domain_controller_id = domain_controller['DomainControllerId']
            print(f"  DomainControllerId: {domain_controller_id}")
            print(f"    Status: {domain_controller['Status']}")
            print(f"    OsVersion: {directories[directory_id]['OsVersion']}")
            print(f"    IpAddress: {domain_controller['DnsIpAddr']}")
            print(f"    VpcId: {domain_controller['VpcId']}")
            print(f"    SecurityGroupId: {directories[directory_id]['VpcSettings']['SecurityGroupId']}")
            print(f"    SubnetId: {domain_controller['SubnetId']}")
            print(f"    AvailabilityZone: {domain_controller['AvailabilityZone']}")

    return directory_domain_controllers


def get_trusts(client, directories):
    trusts = {}

    paginator = client.get_paginator("describe_trusts")
    for resource_records in paginator.paginate():
        for trust in resource_records["Trusts"]:
            directory_id = trust["DirectoryId"]
            if directory_id not in trusts:
                trusts[directory_id] = {}

            trusts[directory_id].update({trust["TrustId"]: trust})


    for directory_id,directory_trusts in trusts.items():
        domain_name = directories[directory_id]['Name']
        print(f"Trusts for {directory_id}/{domain_name}")
        for trust_id,trust in directory_trusts.items():
            remote_domain_name = trust['RemoteDomainName']
            trust_direction = trust['TrustDirection']
            if trust_direction == 'One-Way: Outgoing':
                print(f"{remote_domain_name} trusts {domain_name}")
            elif trust_direction == 'One-Way: Incoming':
                print(f"{remote_domain_name} trusts {domain_name}")
            elif trust_direction == 'Two-Way':
                print(f"{remote_domain_name} and {domain_name} trust each other")

            print(f"  TrustId: {trust_id}")
            print(f"  TrustState: {trust['TrustState']}")
            print(f"  TrustType: {trust['TrustType']}")

    return trusts

def get_settings(client, directories):
    settings = {}

    for directory_id,directory in directories.items():
        print(f"Settings for {directory_id}/{directory['Name']}")

        directory_settings = client.describe_settings(DirectoryId=directory_id)["SettingEntries"]
        settings[directory_id] = directory_settings
        for settings in directory_settings:
            print(f"  {settings['Name']}: {settings['AppliedValue'].replace('able', 'abled')}")

    return settings


def get_shared_directories(client, directories):
    shared_directories = {}

    if directories == None:
        directories = get_directories(client, do_print=False)
    directory_ids = list(directories)

    for directory_id in directory_ids:
        paginator = client.get_paginator("describe_shared_directories")
        for resource_records in paginator.paginate(OwnerDirectoryId=directory_id):
            shared_directories[directory_id] = resource_records['SharedDirectories']

    for directory_id,share_settings in shared_directories.items():
        print(f"Share settings for {directory_id}/{directories[directory_id]['Name']}")
        for setting in share_settings:
            print(f"  {setting['OwnerDirectoryId']} is shared with {setting['SharedAccountId']}")
            print(f"    ShareMethod: {setting['ShareMethod']}")
            print(f"    ShareNotes: {setting['ShareNotes']}")
    
    return shared_directories
    

def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    if args.directories is False and args.domain_controllers is False and args.trusts is False and args.settings is False and args.shared_directories is False:
        args.directories = args.domain_controllers = args.trusts = args.settings = args.shared_directories = True

    if args.regions is None:
        regions = get_regions('ds')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    client = pacu_main.get_boto3_client('ds', choice(regions))

    all_directories = []
    all_domain_controllers = []
    all_trusts = []
    all_settings = []
    all_shared_directories = []
    for region in regions:

        if any([args.directories]):
            print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('ds', region)

        directories = None    
        if args.directories:
            try:
                directories = get_directories(client)
                all_directories.append(directories)
            except ClientError as error:
                print(f"Failed to list directories: {error}")

        if args.domain_controllers:
            try:
                if directories == None:
                    directories = get_directories(client, do_print=False)
                domain_controllers = get_domain_controllers(client, directories)
                all_domain_controllers.append(domain_controllers)
            except ClientError as error:
                print(f"Failed to list domain controllers: {error}")

        if args.trusts:
            try:
                if directories == None:
                    directories = get_directories(client, do_print=False)
                trusts = get_trusts(client, directories)
                all_trusts.append(trusts)
            except ClientError as error:
                print(f"Failed to list trusts: {error}")

        if args.settings:
            try:
                if directories == None:
                    directories = get_directories(client, do_print=False)
                settings = get_settings(client, directories)
                all_settings.append(settings)
            except ClientError as error:
                print(f"Failed to list settings: {error}")

        if args.shared_directories:
             try:
                if directories == None:
                    directories = get_directories(client, do_print=False)
                shared_directories = get_shared_directories(client, directories)
                all_shared_directories.append(shared_directories)
             except ClientError as error:
                print(f"Failed to list settings: {error}")


    gathered_data = {
        'Directories': all_directories,
        'DomainControllers': all_domain_controllers,
        'Trusts': all_trusts,
        'Settings': all_settings,
        'SharedDirectories': all_shared_directories
    }

    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            del gathered_data[ARG_FIELD_MAPPER[var]]

    ds_data = deepcopy(session.DS)
    for key, value in gathered_data.items():
        ds_data[key] = value
    session.update(pacu_main.database, DS=ds_data)

    gathered_data['regions'] = regions

    if any([args.directories, args.domain_controllers, args.trusts, args.settings, args.shared_directories]):
        return gathered_data
    else:
        print('No data successfully enumerated.\n')
        return None 



def summary(data, pacu_main):
    results = []

    results.append('  Regions:')
    for region in data['regions']:
        results.append('     {}'.format(region))

    results.append('')

    if 'Directories' in data:
        results.append('    {} total directorie(s) found.'.format(len(data['Directories'])))

    if 'DomainControllers' in data:
        results.append('    {} total domain controller(s) found.'.format(len(data['DomainControllers'][0])))

    if 'Trusts' in data:
        results.append('    {} total trust(s) found.'.format(len(data['Trusts'][0])))

    if 'Settings' in data:
        results.append('    {} total setting(s) found.'.format(len(data['Settings'][0])))

    if 'SharedDirectories' in data:
        if len(list(data['SharedDirectories'][0])) != 0:
            directory_id = list(data['SharedDirectories'][0])[0]
            results.append('    {} total shared directorie(s) found.'.format(len(data['SharedDirectories'][0][directory_id])))

    return '\n'.join(results)