#!/usr/bin/env python3
import argparse
import json
from copy import deepcopy
from botocore.exceptions import ClientError


module_info = {
    'name': 'ecr__enum',
    'author': 'Manas Bellani',
    'category': 'ENUM',
    'one_liner': 'Enumerates repostories and relevant images/tags ',
    'description': 'This module enumerates information about all ECR images and repositories within Elastic Container Registry (ECR)',
    'services': ['ECR'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    regions = args.regions.split(',') if args.regions else get_regions('all')

    num_repos_found = 0
    summary_data = {}

    # Initialize ECR
    summary_data['ecr'] = {}
    summary_data['ecr']['regions'] = {}
    summary_data['ecr']['repo_names'] = []
    summary_data['ecr']['repo_images'] = []

    for region in regions:

        region_repositories = []
        region_images = []

        print('Checking region {} for ECR Repositories...'.format(region))
        client = pacu_main.get_boto3_client('ecr', region)

        # Begin enumeration

        # Get the repositories
        response = {}
        try:
            response = client.describe_repositories()
            region_repositories.extend(response['repositories'])

            while 'nextToken' in response:
                response = client.describe_repositories(
                    nextToken=response['nextToken']
                )
                region_repositories.extend(response['repositories'])

            if region_repositories:

                # Count the number of repositories found
                num_repos_found += len(region_repositories)

                # Extract the repository name for this region's repository
                repo_names = [repo_info['repositoryName'] for repo_info in region_repositories]
                for repo_name in repo_names:
                    summary_data['ecr']['repo_names'].append(repo_name)
            
                # Extract each image for the repository by repo name
                for repo_name in repo_names:
                    response = client.describe_images(
                        repositoryName=repo_name
                    )
                    region_images.extend(
                        response['imageDetails']
                    )
                    while 'nextToken' in response:
                        response = client.describe_images(
                            repositoryName=repo_name,
                            nextToken=response['nextToken']
                        )
                        region_images.extend(
                            response['imageDetails']
                        )
                
                print("Number of repos found for region, {}: {}".format(
                        len(region_repositories), 
                        region
                    )
                )

                print("Displaying repos for region, {}:".format(region))
                print(
                    json.dumps(region_repositories, indent=4, default=str)
                )

                if region_images:
                    print("Displaying ALL images for each repo in region, {}:".format(repo_name, region))
                    print(
                        json.dumps(region_images, indent=4, default=str)
                    )
                    

                # Adding repositories to region for extraction ater on
                summary_data['ecr']['regions'][region] = {}
                summary_data['ecr']['regions'][region]['repositories'] = region_repositories
                summary_data['ecr']['regions'][region]['repo_images'] = region_images
                

        except Exception as err:
            print('No ECR repositories retrieved for region: {}'.format(region))
            print('Error class: {}, Error message: {}'.format(err.__class__, str(err)))
    
    summary_data['ecr']['num_repos_found'] = num_repos_found

    return summary_data

def summary(data, pacu_main):
    out = ''
    for region in sorted(data):
        out += 'Num of ECR repos found: {}'.format(data['ecr']['num_repos_found'])
    return out
