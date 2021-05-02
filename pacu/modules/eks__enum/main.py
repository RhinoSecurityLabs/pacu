#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import base64
import kubernetes as kube

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
parser.add_argument('--verbose', required=False, action='store_true', default=False, help='Enable verbose output')

# fips endpoints cause duplicates in the data that we pull back, and I see no reason atm to include them
def remove_fips(original_regions):
    non_fips_regions = []
    for region in original_regions:
        if "fips" not in region:
            non_fips_regions.append(region)
    return non_fips_regions

def build_summary_message():
    return "All good buddy!"

def main(args, pacu_main):
    pacu_main.update_regions() # apparently we can't trust pacu to run this on boot, seems odd. 
    args = parser.parse_args(args)
    print = pacu_main.print
    session = pacu_main.get_active_session()
    get_regions = pacu_main.get_regions
    data = {}

    if args.regions is None:
        regions = get_regions('eks')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    regions = remove_fips(regions)
    for region in regions:
        eks_client = pacu_main.get_boto3_client('eks', region)
        clusters = eks_client.list_clusters()["clusters"]
        print(f"clusters in {region}: {clusters}")
        if len(clusters) > 0:
            data[region] = {
            "clusters": []
            }
            for cluster in clusters:
                if args.verbose:
                    data[region]['clusters'].append({
                        "cluster": eks_client.describe_cluster(name=cluster)["cluster"],
                        "nodegroups": eks_client.list_nodegroups(clusterName=cluster)["nodegroups"],
                        "addons": eks_client.list_addons(clusterName=cluster)["addons"],
                        "fargate_profiles": eks_client.list_fargate_profiles(clusterName=cluster)["fargateProfileNames"],
                        "identity_provider_configs": eks_client.list_identity_provider_configs(clusterName=cluster)["identityProviderConfigs"]
                        })
                else:
                    data[region]['clusters'].append({
                        "cluster": cluster,
                        "nodegroups": eks_client.list_nodegroups(clusterName=cluster)['nodegroups']
                        })
        
    session.update(pacu_main.database, EKS=data) 
    return build_summary_message()


def summary(data, pacu_main):
    return str(data)
