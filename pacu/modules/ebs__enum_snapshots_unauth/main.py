#!/usr/bin/env python3
import argparse
import os
import time
from pacu.core.lib import strip_lines
from botocore.exceptions import ClientError
from pacu.core.lib import downloads_dir
from pacu import Main
from copy import deepcopy

module_info = {
    'name': 'ebs__enum_snapshots_unauth',
    'author': 'Yan Sandman (y4nush)',
    'category': 'RECON_UNAUTH',
    'one_liner': 'Enumerates EBS snapshots using a keyword, account ID, or wordlists.',
    'description': strip_lines('''This module will enumerate all the EBS snapshots across all regions, looking for
     snapshots that contain a specific keyword in their description, associated with a specific account ID, or match
     keywords/account IDs from wordlists. The results will be saved in the session's directory and printed to
     the console in the summary if there are 25 or fewer results.'''),
    'services': ['EC2'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--keyword', '--account-id', '--keyword-wordlist', '--account-id-wordlist'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


parser.add_argument(
    '--keyword',
    help='Keyword to search for in EBS snapshot descriptions.'
)
parser.add_argument(
    '--account-id',
    help='AWS account ID to search for associated EBS snapshots.'
)
parser.add_argument(
    '--keyword-wordlist',
    help='File path to a wordlist of keywords to search for in EBS snapshot descriptions.'
)
parser.add_argument(
    '--account-id-wordlist',
    help='File path to a wordlist of AWS account IDs to search for associated EBS snapshots.'
)


def load_wordlist(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    except Exception as e:
        return str(e)


def search_snapshots(ec2_client, filters):
    try:
        return ec2_client.describe_snapshots(Filters=filters).get('Snapshots', [])
    except ClientError as error:
        print('    FAILURE:')
        print('    ' + error.response['Error']['Code'])
        return []


def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    ec2_data = deepcopy(session.EC2) if hasattr(session, 'EC2') else {}
    if 'Volumes' not in ec2_data.keys():
        ec2_data['Volumes'] = []
    if 'Snapshots' not in ec2_data.keys():
        ec2_data['Snapshots'] = []

    existing_snapshots_ids = {snapshot['SnapshotId'] for snapshot in ec2_data['Snapshots']}
    snapshots_found = []  # Store all the snapshots found during the current execution

    keyword_list = [args.keyword] if args.keyword else load_wordlist(
        args.keyword_wordlist) if args.keyword_wordlist else []
    account_id_list = [args.account_id] if args.account_id else load_wordlist(
        args.account_id_wordlist) if args.account_id_wordlist else []

    if not keyword_list and not account_id_list:
        print("Please specify a keyword, account ID, keyword wordlist, or account ID wordlist.")
        return

    regions = get_regions('ec2')
    if not regions:
        print("No regions found. Exiting...")
        return

    session_name = session.name
    directory = str(downloads_dir() / session_name / 'ebs')
    if not os.path.exists(directory):
        os.makedirs(directory)

    for region in regions:
        print('Starting region {}...'.format(region))
        ec2Client = pacu_main.get_boto3_client('ec2', region)

        for keyword in keyword_list:
            filters = [{'Name': 'status', 'Values': ['completed']}, {'Name': 'description', 'Values': [f'*{keyword}*']}]
            snapshots = search_snapshots(ec2Client, filters)
            for snapshot in snapshots:
                snapshot['Region'] = region
                snapshot['Keyword'] = keyword
                snapshot.setdefault('AccountId', '')
                snapshot.setdefault('Description', '')
                print('Snapshot found: {}'.format(snapshot['SnapshotId']))
                snapshots_found.append(snapshot)
                if snapshot['SnapshotId'] not in existing_snapshots_ids:
                    ec2_data['Snapshots'].append(snapshot)
                    existing_snapshots_ids.add(snapshot['SnapshotId'])

        for account_id in account_id_list:
            filters = [{'Name': 'status', 'Values': ['completed']}, {'Name': 'owner-id', 'Values': [account_id]}]
            snapshots = search_snapshots(ec2Client, filters)
            for snapshot in snapshots:
                snapshot['Region'] = region
                snapshot['AccountId'] = account_id
                snapshot.setdefault('Keyword', '')
                snapshot.setdefault('Description', '')
                print('[+] Snapshot found: {}'.format(snapshot['SnapshotId']))
                snapshots_found.append(snapshot)
                if snapshot['SnapshotId'] not in existing_snapshots_ids:
                    ec2_data['Snapshots'].append(snapshot)
                    existing_snapshots_ids.add(snapshot['SnapshotId'])

    snapshot_file_path = '{}/ebs_snapshots_{}.txt'.format(directory, time.time())
    with open(snapshot_file_path, 'w+') as snapshot_file:
        for snapshot in snapshots_found:
            snapshot_file.write(
                'Keyword/AccountId: {}, SnapshotId: {}, Region: {}, Description: {}, OwnerId: {}, Encrypted: {}\n'.format(
                    snapshot.get('Keyword') or snapshot.get('AccountId'), snapshot['SnapshotId'], snapshot['Region'],
                    snapshot['Description'], snapshot['OwnerId'], snapshot['Encrypted']
                ))

    # Update the session data with the modified ec2_data
    session.update(pacu_main.database, EC2=ec2_data)

    summary_data = {
        'snapshots': snapshots_found,
        'snapshot_file_path': snapshot_file_path
    }
    return summary_data


def summary(data, pacu_main):
    out = '  {} EBS Snapshots found\n'.format(len(data['snapshots']))
    if len(data['snapshots']) <= 25:
        for snapshot in data['snapshots']:
            out += '    Keyword/AccountId: {}, SnapshotId: {}, Region: {}, Description: {}, OwnerId: {}, Encrypted: {}\n'.format(
                snapshot.get('Keyword') or snapshot.get('AccountId'), snapshot['SnapshotId'], snapshot['Region'],
                snapshot['Description'], snapshot['OwnerId'], snapshot['Encrypted']
            )
    else:
        out += '  More than 25 results found. Snapshot information is written to:\n    {}\n'.format(data['snapshot_file_path'])
    return out
