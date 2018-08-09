#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""

from botocore.exceptions import ClientError
from . import parser
from . import module_info


def get_interactive_instance(pacu_main, session, region):
    """Returns an instance given an AWS region
    Args:
        region (str): Region to get EC2 instance.
    Returns:
        str: The instance ID for the given region.
    """
    fields = ["EC2", "Instances"]
    module = "enum_ec2"
    args = "--instances --region ap-northeast-2"
    fetched_ec2_instances = pacu_main.fetch_data(fields, module, args)
    if fetched_ec2_instances is False:
        return None
    for instance in session.EC2["Instances"]:
        if instance["Region"] == region:
            instance_id = instance["InstanceId"]
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
        load_volume_set(
            client, print, instance_id,
            volume_ids[set_index:set_index + 40])
        index += SET_COUNT
        input('Press enter to load next set of volumes...')

    return instance_id, volume_ids


def load_volume_set(client, print, instance_id, volume_id_set):
    """Helper function to load volumes on an instance to not overload the
    instance.

    Args:
        instance_id (str): instance_id to attach volumes to
        volume_id_set (list): list of volume_ids to attach to the instance.
    Returns:
        bool: True if the volumes were successfully attached.
    """

    BASE_DEVICE = 'xvd'
    device_offset = 'f'
    for volume_id in volume_id_set:
        try:
            client.attach_volume(
                Device=BASE_DEVICE+device_offset,
                InstanceId=instance_id,
                VolumeId=volume_id)
            device_offset = chr(ord(device_offset) + 1)
        except ClientError as error:
            if error.response['Error']['Code'] == 'UnauthorizedOperation':
                print('  Unauthorized Operation')
            else:
                print(' Unknown Error')
            return False
    return True


def main(args, pacu_main):
    """Main module function, called from Pacu"""
    args = parser.parse_args(args)
    session = pacu_main.get_active_session()
    # input = pacu_main.input
    # key_info = pacu_main.key_info
    # get_regions = pacu_main.get_regions

    regions = ["ap-northeast-2"]
    for region in regions:
        instance_id, availability_zone = get_interactive_instance(
            pacu_main, session, region
        )
        if not instance_id:
            pacu_main.print("No valid instance found")
            continue
        # Set the target instance to load
        pacu_main.print(instance_id, availability_zone)

    summary_data = {}
    return summary_data


def summary(data, pacu_main):
    """Returns a formatted string based on passed data."""
    return str(data)
