#!/usr/bin/env python3
import argparse
from copy import deepcopy
import time
import os

from botocore.exceptions import ClientError

from pacu.core.lib import downloads_dir

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'rds__enum_snapshots',

    # Name and any other notes about the author
    'author': 'Ng Song Guan (GovTech-CSG)',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates RDS snapshots and logs any without encryption.',

    # Description about what the module does and how it works
    'description': 'This module will enumerate all the RDS snapshots (including cluster snapshots) of the account and also snapshots that have been shared by other accounts to this account. It can also enumerate the snapshot permissions in the account and save the data to the current session. It will also note whether or not each snapshot is encrypted, then write a list of the unencrypted snapshots to ./sessions/[current_session_name]/downloads/unencrypted_rds_snapshots_[timestamp].csv in .CSV format. For written files, DB cluster snapshots will have a "(cluster)" added beside its identifier.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['RDS'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions', '--snapshot-permissions', '--no-include-shared'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument(
    '--regions',
    required=False,
    default=None,
    help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.'
)
parser.add_argument(
    '--snapshot-permissions',
    required=False,
    default=False,
    action='store_true',
    help='Capture permissions for each found snapshot that belongs to this account. Permissions for snapshots shared to this account are not included. Found permissions will be captured in the database and written to the sessions downloads directory as rds_snapshot_permissions.txt'
)

parser.add_argument(
    '--no-include-shared',
    required=False,
    default=False,
    action='store_true',
    help='Do not include snapshots shared to this account by other accounts.'
)


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    rds_data = deepcopy(session.RDS)
    if 'Snapshots' not in rds_data.keys():
        rds_data['Snapshots'] = []
    session.update(pacu_main.database, RDS=rds_data)

    if args.regions is None:
        regions = get_regions('rds')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    now = time.time()
    all_snaps = []
    snapshots_csv_data = []
    shared_by_other_account_snapshots = []
    snapshot_permissions = {
        'Public': [],
        'Shared': {},
        'Private': [],
    }

    def fetch_rds_data(client, func, key, print, **kwargs):
        caller = getattr(client, func)
        try:
            response = caller(**kwargs)
            data = response[key]
            if isinstance(data, (dict, str)):
                return data
            while 'Marker' in response:
                response = caller({**kwargs, **{'Marker': response['Marker']}})
                data.extend(response[key])
            return data

        except ClientError as error:
            print('  FAILURE:')
            code = error.response['Error']['Code']
            if code == 'AccessDenied':
                print('    MISSING NEEDED PERMISSIONS for ' + func)
            else:
                print(code)
            print('    Skipping ' + func)
        return []

    # Create rds directory
    directory = str(downloads_dir()/'rds')
    if not os.path.exists(directory):
        os.makedirs(directory)

    for region in regions:
        print('Starting region {} (this may take a while if there are thousands of RDS snapshots)...'.format(region))
        # Start RDS Snapshots in this region
        count = 0

        rdsClient = pacu_main.get_boto3_client('rds', region)

        # Enumerate normal snapshots
        rdsSnapshotData = fetch_rds_data(rdsClient, 'describe_db_snapshots', 'DBSnapshots',
                                print, IncludeShared=not args.no_include_shared, MaxRecords=100)

        # Enumerate cluster snapshots
        rdsClusterSnapshotData = fetch_rds_data(rdsClient, 'describe_db_cluster_snapshots', 'DBClusterSnapshots',
                                print, IncludeShared=not args.no_include_shared, MaxRecords=100)

        # Check basic info for normal snapshots
        for snapshot in rdsSnapshotData:
            all_snaps.append(snapshot)
            snapshot['Region'] = region

            if snapshot['Encrypted'] is False:
                snapshots_csv_data.append('{},{}\n'.format(snapshot['DBSnapshotIdentifier'], region))

            if snapshot['SnapshotType'] == 'shared':
                    shared_by_other_account_snapshots.append(snapshot['DBSnapshotIdentifier'])

        # Check basic info for cluster snapshots
        for clusterSnapshot in rdsClusterSnapshotData:
            all_snaps.append(clusterSnapshot)
            clusterSnapshot['Region'] = region

            if clusterSnapshot['StorageEncrypted'] is False:
                snapshots_csv_data.append('{},{}\n'.format(clusterSnapshot['DBClusterSnapshotIdentifier'] + " (cluster)", region))

            if clusterSnapshot['SnapshotType'] == 'shared':
                    shared_by_other_account_snapshots.append(clusterSnapshot['DBClusterSnapshotIdentifier'] + " (cluster)")

        # Handle permissions check for both types of snapshots
        if args.snapshot_permissions and (rdsSnapshotData or rdsClusterSnapshotData):
            print('  Starting enumeration for own account\'s Snapshot Permissions...')

            for snapshot in rdsSnapshotData:
                if snapshot['SnapshotType'] == 'shared':
                    continue  # Ignore permission check for snapshots shared by other account so move on to next snapshot

                # Automated snapshots are always private
                if snapshot['SnapshotType'] == 'automated':
                    snapshot_permissions['Private'].append(snapshot['DBSnapshotIdentifier'])

                # Only manual snapshots will be updated with RestoreAttributeValues
                else:
                    attributes = fetch_rds_data(rdsClient, "describe_db_snapshot_attributes", 'DBSnapshotAttributesResult',
                                        print, DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])

                    # If user does not have permission to DescribeDBSnapshotAttributes, skip this loop
                    if attributes == []:
                        break

                    for attr in attributes['DBSnapshotAttributes']:
                        if attr['AttributeName'] == 'restore':
                            snapshot['RestoreAttributeValues'] = attr['AttributeValues']
                            break

                    if not snapshot['RestoreAttributeValues']:
                        snapshot_permissions['Private'].append(snapshot['DBSnapshotIdentifier'])
                    elif snapshot['RestoreAttributeValues'][0] == 'all':
                        snapshot_permissions['Public'].append(snapshot['DBSnapshotIdentifier'])
                    else:
                        snapshot_permissions['Shared'][snapshot['DBSnapshotIdentifier']] = snapshot['RestoreAttributeValues']

            for clusterSnapshot in rdsClusterSnapshotData:
                if clusterSnapshot['SnapshotType'] == 'shared':
                    continue  # Ignore permission check for snapshots shared by other account so move on to next snapshot

                # Automated snapshots are always private
                if clusterSnapshot['SnapshotType'] == 'automated':
                    snapshot_permissions['Private'].append(clusterSnapshot['DBClusterSnapshotIdentifier'] + " (cluster)")

                # Only manual snapshots will be updated with RestoreAttributeValues
                else:
                    attributes = fetch_rds_data(rdsClient, "describe_db_cluster_snapshot_attributes", 'DBClusterSnapshotAttributesResult',
                                        print, DBClusterSnapshotIdentifier=clusterSnapshot['DBClusterSnapshotIdentifier'])

                    # If user does not have permission to DescribeDBClusterSnapshotAttributes, skip this loop
                    if attributes == []:
                        break

                    for attr in attributes['DBClusterSnapshotAttributes']:
                        if attr['AttributeName'] == 'restore':
                            clusterSnapshot['RestoreAttributeValues'] = attr['AttributeValues']
                            break

                    if not clusterSnapshot['RestoreAttributeValues']:
                        snapshot_permissions['Private'].append(clusterSnapshot['DBClusterSnapshotIdentifier'] + " (cluster)")
                    elif clusterSnapshot['RestoreAttributeValues'][0] == 'all':
                        snapshot_permissions['Public'].append(clusterSnapshot['DBClusterSnapshotIdentifier'] + " (cluster)")
                    else:
                        snapshot_permissions['Shared'][clusterSnapshot['DBClusterSnapshotIdentifier'] + " (cluster)"] = clusterSnapshot['RestoreAttributeValues']

        count += len(rdsSnapshotData)
        count += len(rdsClusterSnapshotData)

        print('    {} snapshot(s) found'.format(count))

    summary_data = {'snapshot_permissions': args.snapshot_permissions}

    rds_data['Snapshots'] = all_snaps
    summary_data['snapshots'] = len(rds_data['Snapshots'])
    unencrypted_snapshots_csv_path = '{}/unencrypted_rds_snapshots_{}.csv'.format(directory, now)
    
    if (snapshots_csv_data):
        with open(unencrypted_snapshots_csv_path, 'w+') as unencrypted_snapshots_csv:
            unencrypted_snapshots_csv.write('Snapshot Identifier ,Region\n')
            print('  Writing data for {} unencrypted snapshots...'.format(len(snapshots_csv_data)))
            for line in snapshots_csv_data:
                unencrypted_snapshots_csv.write(line)
        summary_data['snapshots_csv_path'] = unencrypted_snapshots_csv_path

    if not args.no_include_shared:
        summary_data['Shared by other account'] = len(shared_by_other_account_snapshots)
    else:
        summary_data['Shared by other account'] = False

    if args.snapshot_permissions:
        permission_data = {
            'Public': len(snapshot_permissions['Public']),
            'Shared': len(snapshot_permissions['Shared']),
            'Private': len(snapshot_permissions['Private']),
        }
        temp = permission_data.copy()
        summary_data.update(temp)

        path = str(downloads_dir()/f"rds_snapshot_permissions_{now}.txt")
        with open(path, 'w') as out_file:
            out_file.write('Public:\n')
            for public in snapshot_permissions['Public']:
                out_file.write('    {}\n'.format(public))
            out_file.write('Shared:\n')
            for snap in snapshot_permissions['Shared']:
                out_file.write('    {}\n'.format(snap))
                for aws_id in snapshot_permissions['Shared'][snap]:
                    out_file.write('        {}\n'.format(aws_id))
            out_file.write('Private:\n')
            for private in snapshot_permissions['Private']:
                out_file.write('    {}\n'.format(private))
            if not args.no_include_shared:
                out_file.write('Shared by other account:\n')
                for sharedWithAccount in shared_by_other_account_snapshots:
                    out_file.write('    {}\n'.format(sharedWithAccount))
            summary_data['snapshot-permissions-path'] = path
    session.update(pacu_main.database, RDS=rds_data)

    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'snapshots' in data:
        out += '  {} RDS Snapshots found\n'.format(data['snapshots'])
        if data['Shared by other account']:
            out += '    {} of these snapshots are shared by other accounts to this account\n'.format(data['Shared by other account'])

    if 'snapshots_csv_path' in data:
        out += '  Unencrypted snapshot information written to:\n    {}\n'.format(data['snapshots_csv_path'])
    if data['snapshot_permissions']:
        out += '  Snapshot Permissions: \n'
        out += '    {} Public snapshots found\n'.format(data['Public'])
        out += '    {} Private snapshots found\n'.format(data['Private'])
        out += '    {} Shared snapshots found\n'.format(data['Shared'])
        out += '      Snapshot permissions information written to: {}\n'.format(data['snapshot-permissions-path'])
    return out
