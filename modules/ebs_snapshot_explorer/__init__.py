import argparse

module_info = {
    'name': 'ebs_snapshot_explorer',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylab.com',
    'category': 'post_exploitation',
    'one_liner': 'Loads EBS snapshots and volumes so they are easily accessible.',
    'description': 'This module will use an EC2 instance to load Elastic Block Store volumes and snapshots in the account and allow the user to access the data.',
    'services': ['EC2'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions', '--vols', '--snaps', '--account-ids'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--regions',
    required=False,
    default=None,
    help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.'
)
parser.add_argument(
    '--vols',
    required=False,
    default=False,
    action='store_true',
    help='If this argument is passed without --snaps, this module will only enumerate volumes. If neither are passed, both volumes and snapshots will be enumerated.'
)
parser.add_argument(
    '--snaps',
    required=False,
    default=False,
    action='store_true',
    help='If this argument is passed without --vols, this module will only enumerate snapshots. If neither are passed, both volumes and snapshots will be enumerated.'
)
parser.add_argument(
    '--account-ids',
    required=False,
    default=None,
    help='One or more (comma separated) AWS account IDs. If snapshot enumeration is enabled, then this module will fetch all snapshots owned by each account in this list of AWS account IDs. Defaults to the current user accounts AWS account ID.'
)


