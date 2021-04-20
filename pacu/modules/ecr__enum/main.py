#!/usr/bin/env python3
import argparse
import json
from copy import deepcopy
from botocore.exceptions import ClientError
import time

from pacu.core.lib import downloads_dir

module_info = {
    'name': 'ecr__enum',
    'author': 'Manas Bellani',
    'category': 'ENUM',
    'one_liner': 'Enumerates repostories and relevant images/tags ',
    'description': 'This module enumerates information about all ECR images and repositories within Elastic Container Registry (ECR). It writes the JSON results found to "Downloads" folder within sessions folder',
    'services': ['API.ECR'],
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

    # Get a list of all regions from which to get ECR data
    regions = args.regions.split(',') if args.regions else get_regions('all')

    summary_data = {}

    # Initialize data
    summary_data['ecr'] = {}
    summary_data['ecr']['regions'] = {}

    # Prepare output file to store ECR data
    now = time.time()
    outfile_path = str(downloads_dir()/f"ecr_enum_{now}.json")

    # Loop through each region to get ECR data one-by-one
    for region in regions:

        #  Keep count of ECR repos
        num_repos_found = 0

        # Maintain a regional count of ECR repositories and images
        region_repositories = []
        region_images = []

        print('Checking region {} for ECR Repositories...'.format(region))
        client = pacu_main.get_boto3_client('ecr', region)

        # Get all the ECR repositories for the region
        response = {}
        try:
            response = client.describe_repositories()
            region_repositories.extend(response['repositories'])
            while 'nextToken' in response:
                response = client.describe_repositories(
                    nextToken=response['nextToken']
                )
                region_repositories.extend(response['repositories'])

            # Assuming we get any ECR repositories for the region
            if region_repositories:

                # Count the number of repositories found
                num_repos_found += len(region_repositories)

                # Extract the repository name for this region's repository
                repo_names = [repo_info['repositoryName'] for repo_info in region_repositories]

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

                # Let the user know how many repos we have found
                print("Number of repos found for region, {}: {}".format(
                        region,
                        len(region_repositories)
                    )
                )

                # Count number of images discovered for this region
                if region_images:
                    print("Number of images found for ALL repos in region, {}: {}".format(
                            region,
                            len(region_images)
                        )
                    )

                # Adding repositories to region for extraction ater on
                summary_data['ecr']['regions'][region] = {}
                summary_data['ecr']['regions'][region]['num_repos_found'] = num_repos_found
                summary_data['ecr']['regions'][region]['repositories'] = region_repositories
                summary_data['ecr']['regions'][region]['repo_images'] = region_images

        except Exception as err:
            print('No ECR repositories retrieved for region: {}'.format(region))
            print('Error class: {}, Error message: {}'.format(err.__class__, str(err)))

    # Write all the data to the output file
    print("Writing all ECR results to file: {}".format(outfile_path))
    with open(outfile_path, "w+") as f:
        f.write(
            json.dumps(summary_data, indent=4, default=str)
        )

    return summary_data

def summary(data, pacu_main):
    out = ''
    for region, region_info in data['ecr']['regions'].items():
        out += 'Num of ECR repos found: {} in region: {} \n'.format(
            region_info['num_repos_found'],
            region
        )
    return out
