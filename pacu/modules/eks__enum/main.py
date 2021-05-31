#!/usr/bin/env python3
import argparse
from copy import deepcopy

from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'EKS_enum',

    # Name and any other notes about the author
    'author': 'Julio Melo of appminer.io and eufuihackeado.com.br',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates EKS clusters',

    # Full description about what the module does and how it works
    'description': 'This module enumerates all relevant data from AWS EKS (mandaged Kubernetes cluster) of a given region',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EKS'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [
        '--regions'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')

def fetch_eks_clusters(client, func, key, print, **kwargs):
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        data = response[key]
        while 'nextToken' in response and response['nextToken'] != '':
            print({**kwargs, **{'nextToken': response['nextToken']}})
            response = caller({**kwargs, **{'nextToken': response['nextToken']}})
            data.extend(response[key])
        return data
    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('  {} FAILURE: MISSING NEEDED PERMISSIONS'.format(func))
        else:
            print(code)
    return []


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    if args.regions is None:
        regions = get_regions('eks')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    all_eks_clusters = []
    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('eks', region)
        # EKS clusters
        eks_clusters_instances = fetch_eks_clusters(client, 'list_clusters', 'clusters', print)
        print('  {} cluster(s) found.'.format(len(eks_clusters_instances)))
        for cluster in eks_clusters_instances:
            print(f'Retrieving details about cluster: {cluster}')
            cluster_dict = {'name': cluster}
            cluster_dict['details'] = client.describe_cluster(name=cluster)
            all_eks_clusters.append(cluster_dict)
    
        all_eks_clusters += eks_clusters_instances


    summary_data = {
        'eks_clusters': len(all_eks_clusters),
    }

    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            del summary_data[var]

    EKS_data = deepcopy(session.EKS)

    EKS_data['eks_clusters'] = all_eks_clusters
    session.update(pacu_main.database, EKS=EKS_data)

    return summary_data


def summary(data, pacu_main):
    out = ''
    for key in data:
        out += '  {} total {}(s) found.\n'.format(data[key], key[:-1])
    out += '\n  EKS clusters saved in Pacu database. You can run `data EKS` to view this info.\n'
    out += '\n  TIP: You can use kube-hunter and hunt for security weaknesses in Kubernetes clusters.\n'
    return out
