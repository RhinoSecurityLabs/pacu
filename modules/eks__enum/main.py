#!/usr/bin/env python3
import argparse
import docker
from botocore.exceptions import ClientError
import base64
import subprocess32 as subprocess

module_info = {
    'name': 'eks_enum',
    'author': 'David Fentz',
    'category': 'ENUM',
    'one_liner': 'Does this thing.',
    'description': 'This module does this thing by using xyz and outputs info to abc. Here is a note also.',
    'services': ['ECS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

def main(args, pacu_main):
    pacu_main.update_regions() # apparently we can't trust pacu to run this on boot, seems odd. 
    args = parser.parse_args(args)
    print = pacu_main.print
    session = pacu_main.get_active_session()
    get_regions = pacu_main.get_regions
    data = {
        "clusters": []
    }

    if args.regions is None:
        regions = get_regions('eks')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')
    
    for region in regions:
        eks_client = pacu_main.get_boto3_client('eks', region)
        clusters = eks_client.list_clusters()["clusters"]
        print(f"clusters in {region}: {clusters}")
        if len(clusters) > 0:
            data['clusters'].append(clusters)
        
    session.update(pacu_main.database, EKS=data) 
    return "All good brother!"


def summary(data, pacu_main):
    return str(data)
