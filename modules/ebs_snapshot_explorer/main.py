#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""
from copy import deepcopy
import json
from pathlib import Path

from botocore.exceptions import ClientError

from . import parser
from . import module_info


def input_helper(input):
    """Helper function that loops until a successful response is given"""
    prompt = '    Load next set of volumes? (y/n) '
    while True:
        response = input(prompt)
        if response.lower() == 'y':
            return True
        elif response.lower() == 'n':
            return False

def load_volumes(client, print, input, instance_id, volume_ids):
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
    set_count = 10

    while set_index < len(volume_ids):
        current_volume_set = volume_ids[set_index:set_index + set_count]
        waiter = client.get_waiter('volume_available')
        waiter.wait(VolumeIds=current_volume_set)
        attached = modify_volume_set(
            client, print, 'attach_volume', instance_id, current_volume_set)
        if not attached:
            print(' Volume attachment failed')
            print(' Exiting...')
            return False
        running = input_helper(input)
        detached = modify_volume_set(
            client, print, 'detach_volume', instance_id, current_volume_set)
        if not detached:
            print(' Volume detachment failed')
            print(' Exiting...')
            return False
        waiter.wait(VolumeIds=current_volume_set)
        set_index += set_count
        if not running:
            break
    cleanup(client)
    return True


def modify_volume_set(client, print, func, instance_id, volume_id_set):
    """Helper function to load volumes on an instance to not overload the
    instance.

    Args:
        client (boto3.client): client to interact with AWS
        print (func): Overwritten built-in print function
        func (str): Function sname to modify_volume_set
        instance_id (str): instance_id to attach volumes to
        volume_ids (list): list of volume_ids to (de)attach to the instance.
    Returns:
        bool: True if the volumes were successfully attached.
    """
    for volume_id in volume_id_set:
        try:
            kwargs = {
                'InstanceId':instance_id,
                'VolumeId':volume_id
            }
            if func == 'attach_volume':
                kwargs['Device'] = get_valid_device(client, instance_id)
            caller = getattr(client, func)
            caller(**kwargs)
        except ClientError as error:
            code = error.response['Error']['Code']
            if  code == 'UnauthorizedOperation':
                print('  FAILURE MISSING AWS PERMISSIONS')
            else:
                print(error)
            return False
    return True

def get_valid_device(client, instance):
    """Returns the next device mapping available

    Args:
        client (boto3.client): Client that gets the current block device mappings
        instance (str): InstanceId to get curretn block device mappings
    Returns:
        str: Returns next mapping in form of /dev/xvd[base], otherwise /dev/xvdzz

    """
    response = client.describe_instances(InstanceIds=[instance])
    mappings = response['Reservations'][0]['Instances'][0]['BlockDeviceMappings']
    current_mappings = [device['DeviceName'] for device in mappings]
    base_mappings = [char for char in 'bcdefghijklmnoqrstuvwxyz']
    for base in base_mappings:
        if '/dev/xvd' + base not in current_mappings:
            return '/dev/xvd' + base
    return '/dev/xvdzz'


def get_snapshots(pacu, session, region):
    """Returns snapshots given an AWS region
    Args:
        pacu (Main): Reference to Pacu
        session (PacuSession): Reference to the Pacu session database
        regions (list): Regions to check for snapshots
    Returns:
        dict: Mapping regions to corresponding list of snapshot_ids.
    """
    ec2_data = deepcopy(session.EC2)
    if 'Snapshots' not in ec2_data:
        fields = ['EC2', 'Snapshots']
        module = 'enum_ebs_volumes_snapshots'
        fetched_ec2_instances = pacu.fetch_data(fields, module)
        if fetched_ec2_instances is False:
            return None
    snapshot_ids = []
    for snapshot in ec2_data['Snapshots']:
        if snapshot['Region'] == region:
            snapshot_ids.append(snapshot['SnapshotId'])
    return snapshot_ids


def get_volumes(pacu, session, region):
    """Returns volumes given an AWS region
    Args:
        pacu (Main): Reference to Pacu
        session (PacuSession): Reference to the Pacu session database
        regions (list): Regions to check for volumes
    Returns:
        dict: Mapping regions to corresponding list of volume_ids.
    """
    ec2_data = deepcopy(session.EC2)
    if 'Volumes' not in ec2_data:
        fields = ['EC2', 'Volumes']
        module = 'enum_ebs_volumes_snapshots'
        fetched_ec2_instances = pacu.fetch_data(fields, module)
        if fetched_ec2_instances is False:
            return None
    volume_ids = []
    for volume in ec2_data['Volumes']:
        if volume['Region'] == region:
            volume_ids.append(volume['VolumeId'])
    return volume_ids


def generate_volumes_from_snapshots(client, snapshots, zone):
    """Returns a list of generated volumes"""
    volume_ids = []
    waiter = client.get_waiter('snapshot_completed')
    waiter.wait(SnapshotIds=snapshots)
    for snapshot in snapshots:
        response = client.create_volume(
            SnapshotId=snapshot, AvailabilityZone=zone)
        volume_ids.append(response['VolumeId'])
    store_temp_data({'volumes':volume_ids})
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
    temp_file = Path(__file__).parent / 'temp.json'
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
    temp_file = Path(__file__).parent / 'temp.json'
    if temp_file.exists():
        with temp_file.open('r') as json_file:
            existing_data = json.load(json_file)
            data.update(existing_data)
    with temp_file.open('w+') as json_file:
        json.dump(data, json_file)


def main(args, pacu):
    """Main module function, called from Pacu"""
    args = parser.parse_args(args)
    session = pacu.get_active_session()
    print = pacu.print

    instance = args.instance
    region = args.region
    zone = region + args.zone
    client = pacu.get_boto3_client('ec2', region)

    if not cleanup(client):
        print('  Cleanup failed')
        return summary_data

    snapshots = get_snapshots(pacu, session, region)
    volumes = get_volumes(pacu, session, region)
    summary_data = {'snapshots': len(snapshots), 'volumes': len(volumes)}

    print('  Attaching volumes...')
    temp_snaps = generate_snapshots_from_volumes(client, volumes)
    temp_volumes = generate_volumes_from_snapshots(client, temp_snaps, zone)
    load_volumes(client, pacu.print, pacu.input, instance, temp_volumes)
    print('  Finished attaching volumes')

    print('  Attaching volumes from existing snapshots')
    temp_volumes = generate_volumes_from_snapshots(client, snapshots, zone)
    load_volumes(client, pacu.print, pacu.input, instance, temp_volumes)
    print('  Finished attaching existing snapshot volumes ')

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
