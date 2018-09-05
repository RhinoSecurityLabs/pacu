#!/usr/bin/env python3
import argparse

module_info = {
    'name': 'rds_snapshot_explorer',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'post-exploitation',
    'one_liner': 'Snapshot databases, change the master password, exfiltrate data.',
    'description': 'Snapshot all databases, restore new databases from those snapshots, then ModifyDBInstance to change the master password, then maybe mysqldump/psqldump/etc to exfil it, then cleanup all the resources that were created.',
    'services': ['RDS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

def main(args, pacu):
    """Main module function, called from Pacu"""
    # parser.parse_args(args)
    regions = pacu.get_regions('rds')
    for region in regions:
        pacu.print('Region: {}'.format(region))
        all_dbs = []
        client = pacu.get_boto3_client('rds', region)
        paginator = client.get_paginator('describe_db_instances')
        instances = paginator.paginate()
        for instance in instances:
            all_dbs.extend(instance['DBInstances'])
        print(all_dbs)
    return {}


def summary(data, pacu_main):
    out = ''
    return out
