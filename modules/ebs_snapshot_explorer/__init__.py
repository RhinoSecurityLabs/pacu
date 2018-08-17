import argparse

module_info = {
    'name': 'ebs_snapshot_explorer',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylab.com',
    'category': 'post_exploitation',
    'one_liner': 'Loads EBS snapshots and volumes so they are easily accessible.',
    'description': 'This module will use an EC2 instance to load Elastic Block Store volumes and snapshots in the account and allow the user to access the data.',
    'services': ['EC2'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions', '--instance'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--regions',
    required=False,
    default=None,
    help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.'
)
parser.add_argument(
    '--instance',
    required=False,
    default=None,
    help='Instance to load volumes to in format instance@region(availabilityzone)'
)


