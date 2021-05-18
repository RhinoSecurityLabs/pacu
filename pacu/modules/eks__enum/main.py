#!/usr/bin/env python3
import argparse

module_info = {
    'name': 'eks_enum',
    'author': 'David Fentz',
    'category': 'ENUM',
    'one_liner': 'This module enumerates over EKS resources.',
    'description': 'This module enumerates over EKS resources.',
    'services': ['EKS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
        '--regions',
        '--no_addons',
        '--no_identity_provider_configs',
        '--no_fargate_profiles',
    ],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('--no_addons', required=False, action='store_true', default=False, help='Exclude EKS addons')
parser.add_argument('--no_identity_provider_configs', required=False, action='store_true', default=False, help='Exclude EKS identity provider configs')
parser.add_argument('--no_fargate_profiles', required=False, action='store_true', default=False, help='Exclude EKS fargate profiles')

def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print
    session = pacu_main.get_active_session()
    get_regions = pacu_main.get_regions
    data = {}
    cluster_count = 0

    if args.regions is None:
        regions = get_regions('eks')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    for region in regions:
        eks_client = pacu_main.get_boto3_client('eks', region)
        cluster_paginator = eks_client.get_paginator("list_clusters")
        cluster_page_iterator = cluster_paginator.paginate(PaginationConfig={'PageSize': 50})
        data[region] = { # use this to count clusters
            "clusters": {}
        }
        for page in cluster_page_iterator:
            clusters = page["clusters"]
            for cluster in clusters:
                nodegroups = []
                addons = []
                fargate_profiles = []
                ip_configs = []

                nodegroup_paginator = eks_client.get_paginator("list_nodegroups")
                nodegroup_page_iterator = nodegroup_paginator.paginate(clusterName=cluster, PaginationConfig={'PageSize': 50})
                addon_paginator = eks_client.get_paginator("list_addons")
                addon_page_iterator = addon_paginator.paginate(clusterName=cluster, PaginationConfig={'PageSize': 50})
                fargate_paginator = eks_client.get_paginator("list_fargate_profiles")
                fargate_page_iterator = fargate_paginator.paginate(clusterName=cluster, PaginationConfig={'PageSize': 50})
                ip_config_paginator = eks_client.get_paginator("list_identity_provider_configs")
                ip_config_page_iterator = ip_config_paginator.paginate(clusterName=cluster, maxResults=1, PaginationConfig={'PageSize': 1})

                for page in nodegroup_page_iterator:
                    nodegroups.append(page["nodegroups"])
                for page in addon_page_iterator:
                    addons.append(page["addons"])
                for page in fargate_page_iterator:
                    fargate_profiles.append(page["fargateProfileNames"])
                for page in ip_config_page_iterator:
                    ip_configs.append(page["identityProviderConfigs"])

                data[region]['clusters'][cluster] = {
                    "cluster_description": eks_client.describe_cluster(name=cluster)["cluster"],
                    "nodegroups": nodegroups
                }
                if not args.no_addons:
                    data[region]['clusters'][cluster]["addons"] = addons
                if not args.no_fargate_profiles:
                    data[region]['clusters'][cluster]["fargate_profiles"] = fargate_profiles
                # if not args.no_identity_provider_configs:
                    # data[region]['clusters'][cluster]["identity_provider_configs"] = ip_configs

        region_clusters = [cluster for cluster in data[region]["clusters"]]
        print(f"clusters in {region}: {region_clusters}")
        cluster_count += len(data[region]["clusters"])
    session.update(pacu_main.database, EKS=data) 
    return cluster_count
    

def summary(cluster_count, pacu_main):
    return f"Found {cluster_count} clusters in total.\nTo see EKS data, run \"data EKS\","
