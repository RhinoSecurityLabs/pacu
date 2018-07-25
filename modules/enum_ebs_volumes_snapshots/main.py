#!/usr/bin/env python3
import argparse
from copy import deepcopy
import time
import random
import os

from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_ebs_volumes_snapshots',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates EBS volumes and snapshots and logs any without encryption.',

    # Description about what the module does and how it works
    'description': 'This module will enumerate all of the Elastic Block Store volumes, snapshots, and snapshot permissions in the account and save the data to the current session. It will also note whether or not each volume/snapshot is encrypted, then write a list of the unencrypted volumes to ./sessions/[current_session_name]/downloads/unencrypted_ebs_volumes_[timestamp].csv and unencrypted snapshots to ./sessions/[current_session_name]/downloads/unencrypted_ebs_snapshots_[timestamp].csv in .CSV format.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions', '--vols', '--snaps', '--account-ids', '--snapshot-permissions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument(
    '--regions',
    required=False,
    default=None,
    help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.'
)
parser.add_argument(
    '--vols',
    required=False,
    default=False,
    action='store_true',
    help='If this argument is passed without --snaps, this module will only enumerate volumes. If neither are passed, both volumes and snapshots will be enumerated.'
)
parser.add_argument(
    '--snaps',
    required=False,
    default=False,
    action='store_true',
    help='If this argument is passed without --vols, this module will only enumerate snapshots. If neither are passed, both volumes and snapshots will be enumerated.'
)
parser.add_argument(
    '--snapshot-permissions',
    required=False,
    default=False,
    action='store_true',
    help='Capture permissions for each found snapshot. Found permissions will be captured in the database and written to the sessions downloads directory as snapshot_permissions.txt'
)
parser.add_argument(
    '--account-ids',
    required=False,
    default=None,
    help='One or more (comma separated) AWS account IDs. If snapshot enumeration is enabled, then this module will fetch all snapshots owned by each account in this list of AWS account IDs. Defaults to the current user accounts AWS account ID.'
)


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    get_regions = pacu_main.get_regions
    ######

    if args.snaps is False and args.vols is False:
        args.snaps = args.vols = True

    ec2_data = deepcopy(session.EC2)
    if 'Volumes' not in ec2_data.keys():
        ec2_data['Volumes'] = []
    if 'Snapshots' not in ec2_data.keys():
        ec2_data['Snapshots'] = []
    session.update(pacu_main.database, EC2=ec2_data)

    if args.regions is None:
        regions = get_regions('ec2')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    print('Targeting regions {}.'.format(regions))

    current_account = None
    account_ids = []

    if args.account_ids is None and args.snaps is True:
        user = key_info()

        if 'AccountId' in user:
            account_ids = [user['AccountId']]

        if current_account is None or current_account is False:
            current_account = input('No account IDs were passed in as arguments and the account ID for the current user has not been stored in this session yet. An account ID is required to get valid results from the snapshot enumeration portion of this module. If you know the current users account ID then enter it now, otherwise, enter y to try and fetch it, or enter n to skip EBS snapshot enumeration. ([account_id]/y/n) ')

            if current_account is None or current_account == '' or current_account.lower() == 'n':
                account_ids = []

            elif current_account == 'y':
                try:
                    client = pacu_main.get_boto3_client('iam')

                    user = client.get_user()['User']

                    # Might as well fill current key data while it is here
                    current_account = user['Arn'].split('rn:aws:iam::')[1].split(':user/')[0]
                    account_ids = [current_account]

                    session_aws_key = session.get_active_aws_key(pacu_main.database)
                    session_aws_key.update(
                        pacu_main.database,
                        account_id=current_account,
                        user_name=user['UserName'],
                        user_arn=user['Arn'],
                        user_id=user['UserId'],
                    )

                except Exception as error:
                    print('Error running get_user. It is possible that the account ID has been returned in this error: {}'.format(error))
                    current_account = input('If the AWS account ID was returned in the previous error, enter it now to continue, or enter n to skip EBS snapshot enumeration. ([account_id]/n) ')
                    if current_account == 'n':
                        account_ids = []
                    else:
                        account_ids = [current_account]

            else:
                account_ids = [current_account]

    elif args.snaps is True:
        if ',' in args.account_ids:
            account_ids = args.account_ids.split(',')
        else:
            account_ids = [args.account_ids]

    else:
        pass  # Ignore args.account_ids if args.snaps is False

    client = pacu_main.get_boto3_client('ec2', random.choice(regions))

    # Check permissions before hammering through each region
    if args.vols is True:
        try:
            client.describe_volumes(
                DryRun=True
            )
        except ClientError as error:
            if str(error).find('UnauthorizedOperation') != -1:
                print('The current AWS credentials do not have the necessary permissions to run "describe_volumes".\nExiting module.')
                return

    if args.snaps is True and not account_ids == []:
        try:
            client.describe_snapshots(
                OwnerIds=account_ids,
                DryRun=True
            )
        except ClientError as error:
            if str(error).find('UnauthorizedOperation') != -1:
                print('The current AWS credentials do not have the necessary permissions to run "describe_snapshots".\nExiting module.')
                return

    now = time.time()

    all_vols = []
    all_snaps = []
    volumes_csv_data = []
    snapshots_csv_data = []
    snapshot_permissions = {
        'Public': [],
        'Shared': {},
        'Private': []
    }
    for region in regions:
        print('Starting region {} (this may take a while if there are thousands of EBS volumes/snapshots)...'.format(region))
        client = pacu_main.get_boto3_client('ec2', region)

        if args.vols is True:
            # Start EBS Volumes in this region
            count = 0
            response = None
            next_token = False

            while (response is None or 'NextToken' in response):
                if next_token is False:
                    response = client.describe_volumes(
                        MaxResults=500  # Using this as AWS can timeout the connection if there are too many volumes to return in one
                    )
                else:
                    response = client.describe_volumes(
                        MaxResults=500,
                        NextToken=next_token
                    )

                if 'NextToken' in response:
                    next_token = response['NextToken']

                for volume in response['Volumes']:
                    volume['Region'] = region
                    all_vols.append(volume)
                    if volume['Encrypted'] is False:
                        name = ''
                        if 'Tags' in volume:
                            for tag in volume['Tags']:
                                if tag['Key'] == 'Name':
                                    name = tag['Value']
                                    break
                        volumes_csv_data.append('{},{},{}\n'.format(name, volume['VolumeId'], region))

                count += len(response['Volumes'])

            print('  {} total volume(s) found in {}.'.format(count, region))

        if args.snaps is True and not account_ids == []:
            # Start EBS Snapshots in this region
            count = 0
            response = None
            next_token = False

            while (response is None or 'NextToken' in response):
                if next_token is False:
                    response = client.describe_snapshots(
                        OwnerIds=account_ids,
                        MaxResults=1000  # Using this as AWS can timeout the connection if there are too many snapshots to return in one
                    )
                else:
                    response = client.describe_snapshots(
                        OwnerIds=account_ids,
                        NextToken=next_token,
                        MaxResults=1000
                    )

                if 'NextToken' in response:
                    next_token = response['NextToken']

                for snapshot in response['Snapshots']:
                    snapshot['Region'] = region

                    if args.snapshot_permissions:
                        print('    Starting enumeration for Snapshot Permissions...')
                        snapshot['CreateVolumePermissions'] = client.describe_snapshot_attribute(
                            Attribute='createVolumePermission',
                            SnapshotId=snapshot['SnapshotId']
                        )['CreateVolumePermissions']

                        if not snapshot['CreateVolumePermissions']:
                            snapshot_permissions['Private'].append(snapshot['SnapshotId'])
                        elif 'UserId' in snapshot['CreateVolumePermissions'][0]:
                            snapshot_permissions['Shared'][snapshot['SnapshotId']] = [entry['UserId'] for entry in snapshot['CreateVolumePermissions']]
                        elif 'Group' in snapshot['CreateVolumePermissions'][0]:
                            snapshot_permissions['Public'].append(snapshot['SnapshotId'])

                    all_snaps.append(snapshot)
                    if snapshot['Encrypted'] is False:
                        name = ''
                        if 'Tags' in snapshot:
                            for tag in snapshot['Tags']:
                                if tag['Key'] == 'Name':
                                    name = tag['Value']
                                    break
                        snapshots_csv_data.append('{},{},{}\n'.format(name, snapshot['SnapshotId'], region))

                count += len(response['Snapshots'])

            print('  {} total snapshot(s) found in {}.'.format(count, region))

    summary_data = {'snapshot_permissions': args.snapshot_permissions}
    if args.vols is True:
        ec2_data['Volumes'] = all_vols
        unencrypted_volumes_csv_path = 'sessions/{}/downloads/unencrypted_ebs_volumes_{}.csv'.format(session.name, now)
        with open(unencrypted_volumes_csv_path, 'w+') as unencrypted_volumes_csv:
            unencrypted_volumes_csv.write('Volume Name,Volume ID,Region\n')
            print('Writing data for {} volumes...'.format(len(volumes_csv_data)))
            for line in volumes_csv_data:
                unencrypted_volumes_csv.write(line)
        summary_data['volumes'] = len(ec2_data['Volumes'])
        summary_data['volumes_csv_path'] = unencrypted_volumes_csv_path

    if args.snaps is True:
        ec2_data['Snapshots'] = all_snaps
        unencrypted_snapshots_csv_path = 'sessions/{}/downloads/unencrypted_ebs_snapshots_{}.csv'.format(session.name, now)
        with open(unencrypted_snapshots_csv_path, 'w+') as unencrypted_snapshots_csv:
            unencrypted_snapshots_csv.write('Snapshot Name,Snapshot ID,Region\n')
            print('Writing data for {} snapshots...'.format(len(snapshots_csv_data)))
            for line in snapshots_csv_data:
                unencrypted_snapshots_csv.write(line)
        summary_data['snapshots'] = len(ec2_data['Snapshots'])
        summary_data['snapshots_csv_path'] = unencrypted_snapshots_csv_path

    if args.snapshot_permissions:
        permission_data = {
            'Public': len(snapshot_permissions['Public']),
            'Shared': len(snapshot_permissions['Shared']),
            'Private': len(snapshot_permissions['Private']),
        }
        temp = permission_data.copy()
        summary_data.update(temp)
        path = os.path.join(os.getcwd(), 'sessions', session.name, 'downloads', 'snapshot_permissions_' + str(now) + '.txt')
        with open(path, 'w') as out_file:
            out_file.write('Public:\n')
            for public in snapshot_permissions['Public']:
                out_file.write('    {}'.format(public))
            out_file.write('Shared:\n')
            for snap in snapshot_permissions['Shared']:
                out_file.write('    {}\n'.format(snap))
                for aws_id in snapshot_permissions['Shared'][snap]:
                    out_file.write('        {}\n'.format(aws_id))
            out_file.write('Private:\n')
            for private in snapshot_permissions['Private']:
                out_file.write('    {}\n'.format(private))
            summary_data['snapshot-permissions-path'] = path
    session.update(pacu_main.database, EC2=ec2_data)
    print('All data has been saved to the current session.')

    print('{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'volumes' in data:
        out += '  {} Volumes found\n'.format(data['volumes'])
    if 'volumes_csv_path' in data:
        out += '    Unencrypted volume information written to: {}\n'.format(data['volumes_csv_path'])
    if 'snapshots' in data:
        out += '  {} Snapshots found\n'.format(data['snapshots'])
    if 'snapshots_csv_path' in data:
        out += '    Unencrypted snapshot information written to: {}\n'.format(data['snapshots_csv_path'])
    if data['snapshot_permissions']:
        out += '  Snapshot Permissions: \n'
        out += '    {} Public snapshots found\n'.format(data['Public'])
        out += '    {} Private snapshots found\n'.format(data['Private'])
        out += '    {} Shared snapshots found\n'.format(data['Shared'])
        out += '      Snapshot permissions information written to: {}\n'.format(data['snapshot-permissions-path'])
    return out
