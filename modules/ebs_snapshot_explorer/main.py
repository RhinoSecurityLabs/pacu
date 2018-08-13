#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""
from copy import deepcopy
from botocore.exceptions import ClientError
from . import parser
from . import module_info


def get_interactive_instance(pacu, session, region):
    """Returns an instance given an AWS region
    Args:
        region (str): Region to get EC2 instance.
    Returns:
        str: The instance ID for the given region.
    """
    ec2_data = deepcopy(session.EC2)
    if 'Snapshots' not in ec2_data:
        fields = ['EC2', 'Snapshots']
        module = 'enum_ebs_volumes_snapshots'
        fetched_ec2_instances = pacu.fetch_data(fields, module)
        if fetched_ec2_instances is False:
            return None
    for instance in ec2_data['Instances']:
        if instance['Region'] == region:
            instance_id = instance['InstanceId']
            availability_zone = instance['Placement']['AvailabilityZone']
            return instance_id, availability_zone
    return None


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
    SET_COUNT = 10

    while set_index < len(volume_ids):
        attached = modify_volume_set(
            client, print, 'attach_volume', instance_id, 
            volume_ids[set_index:set_index + 40])
        if not attached:
            print(' Volume attachment failed')
            print(' Exiting...')
            return False
        input('Press any key to load next set of volumes...')
        detached = modify_volume_set(
            client, print, 'detach_volume', instance_id,
            volume_ids[set_index:set_index + 40])
        if not detached:
            print(' Volume detachment failed')
            print(' Exiting...')
            return False
        set_index += SET_COUNT
    return True


def modify_volume_set(client, print, func, instance_id, volume_id_set):
    """Helper function to load volumes on an instance to not overload the
    instance.

    Args:
        client (boto3.client): client to interact with AWS
        print (func): Overwritten built-in print function
        func (str): Function name to modify_volume_set
        instance_id (str): instance_id to attach volumes to
        volume_ids (list): list of volume_ids to attach to the instance.
    Returns:
        bool: True if the volumes were successfully attached.
    """

    BASE_DEVICE = 'xvd'
    device_offset = 'f'
    for volume_id in volume_id_set:
        try:
            kwargs = {
                'Device':BASE_DEVICE+device_offset,
                'InstanceId':instance_id,
                'VolumeId':volume_id
            }
            caller = getattr(client, func)
            caller(**kwargs)
            device_offset = chr(ord(device_offset) + 1)
        except ClientError as error:
            if error.response['Error']['Code'] == 'UnauthorizedOperation':
                print('  Unauthorized Operation')
            elif error.response['Error']['Code'] == 'VolumeInUse':
                print('  Volume in Use')
                print('    Skipping...')
            else:
                print(error)
            return False
    return True


def get_snapshots(pacu, session, regions):
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
    snapshot_ids = {}
    for region in regions:
        snapshot_ids[region] = []
    for snapshot in ec2_data['Snapshots']:
        if snapshot['Region'] in regions:
            snapshot_ids[snapshot['Region']].append(snapshot['SnapshotId'])
    return snapshot_ids


def get_volumes(pacu, session, regions):
    """Returns volumes given an AWS region
    Args:
        pacu (Main): Reference to Pacu
        session (PacuSession): Reference to the Pacu session database
        regions (list): Regions to check for volumes
    Returns:
        dict: Mapping regions to corresponding list of snapshot_ids.
    """
    ec2_data = deepcopy(session.EC2)
    if 'Snapshots' not in ec2_data:
        fields = ['EC2', 'Volumes']
        module = 'enum_ebs_volumes_snapshots'
        fetched_ec2_instances = pacu.fetch_data(fields, module)
        if fetched_ec2_instances is False:
            return None
    volume_ids = {}
    for region in regions:
        volume_ids[region] = []
    for volume in ec2_data['Volumes']:
        if volume['Region'] in regions:
            volume_ids[volume['Region']].append(volume['VolumeId'])
    return volume_ids


def main(args, pacu):
    """Main module function, called from Pacu"""
    args = parser.parse_args(args)
    session = pacu.get_active_session()
    print = pacu.print
    input = pacu.input
    key_info = pacu.key_info
    regions = pacu.get_regions('ec2')
    region = regions[0]
    print(get_snapshots(pacu, session, regions))
    print(get_volumes(pacu, session, regions))
    print(get_interactive_instance(pacu, session, region))

    #client = pacu.get_boto3_client('ec2', region)


    #volumes = [
    #    'vol-0687a3892ffce7f1c',
    #    'vol-05d1644b7587c3e95',
    #    'vol-0faddc520225b5b97',
    #]
    #instance_id = 'i-0ffc126ebc52e0103'
    #success = load_volumes(client, print, input, instance_id, volumes)
    #print(success)

    #for region in regions:
    #    client = pacu.get_boto3_client('ec2', region)
    #    instance_id, availability_zone = get_interactive_instance(
    #        pacu, session, region
    #    )
    #    if not instance_id:
    #        pacu.print("No valid instance found")
    #        continue
    #    # Set the target instance to load
    #    pacu.print(instance_id, availability_zone)

    summary_data = {}
    return summary_data


def summary(data, pacu):
    """Returns a formatted string based on passed data."""
    return str(data)
