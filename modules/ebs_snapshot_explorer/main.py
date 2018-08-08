#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""

#from botocore.exceptions import ClientError
from . import parser


def get_interactive_instance(region):
    """Returns an instance given an AWS region
    Args:
        region (str): Region to get EC2 instance.
    Returns:
        str: The instance ID for the given region.
    """
    return region

def main(args, pacu_main):
    """Main module function, called from Pacu"""

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    #session = pacu_main.get_active_session()
    #input = pacu_main.input
    #key_info = pacu_main.key_info
    #get_regions = pacu_main.get_regions
    ######
    regions = ['ap-northeast-1']
    for region in regions:
        pacu_main.print(get_interactive_instance(region))

    summary_data = {}
    return summary_data


def summary(data, pacu_main):
    """Returns a formatted string based on passed data."""
    return str(data)
