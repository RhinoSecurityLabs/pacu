import argparse

module_info = {
    'name': 'ebs_snapshot_explorer',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylab.com',
    'category': 'post_exploitation',
    'one_liner': 'Loads EBS snapshots and volumes so they are easily accessible.',
    'description': 'This module will use an EC2 instance to load Elastic Block Store volumes and snapshots in the account and allow the user to access the data.',
    'services': ['EC2'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--instance', '--region', '--zone'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--instance',
    required=True,
    default=None,
    help='InstanceId of instance to target'
)
parser.add_argument(
    '--region',
    required=True,
    default=None,
    help='Region of instance to target'
)
parser.add_argument(
    '--zone',
    required=True,
    default=None,
    help='Availability zone of instance to target'
)


