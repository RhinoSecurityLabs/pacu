#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""

#from botocore.exceptions import ClientError
from . import parser
from . import module_info


def get_interactive_instance(pacu_main, session, region):
    """Returns an instance given an AWS region
    Args:
        region (str): Region to get EC2 instance.
    Returns:
        str: The instance ID for the given region.
    """
    if pacu_main.fetch_data(['EC2', 'Instances'], 'enum_ec2', '--instances --region ap-northeast-2', True) is False:
        return None
    for instance in session.EC2['Instances']:
        if instance['Region'] == region:
            return instance['InstanceId']
    return None

def main(args, pacu_main):
    """Main module function, called from Pacu"""

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    session = pacu_main.get_active_session()
    #input = pacu_main.input
    #key_info = pacu_main.key_info
    #get_regions = pacu_main.get_regions
    ######
    regions = ['ap-northeast-2']
    for region in regions:
        instanceId = get_interactive_instance(
            pacu_main, session, region
        )
        if not instanceId:
            pacu_main.print('Failed to get a valid instanceId')
            continue
        pacu_main.print(instanceId)
    summary_data = {}
    return summary_data


def summary(data, pacu_main):
    """Returns a formatted string based on passed data."""
    return str(data)
