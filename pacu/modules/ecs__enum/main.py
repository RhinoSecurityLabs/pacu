#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
from random import choice

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'ecs__enum',

    # Name and any other notes about the author.
    'author': 'Nicholas Spagnola from Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'This module enumerates information from ECS',

    # Full description about what the module does and how it works.
    'description': 'This module enumerates available information from ECS',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['ECS'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab.
    'arguments_to_autocomplete': [
        '--clusters',
        '--attributes',
        '--services',
        '--taskdef',
        '--regions'
    ],
}

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--clusters', required=False, action='store_true', default=False, help='Enumerate ECS Clusters')
parser.add_argument('--containers', required=False, action='store_true', default=False, help='Enumerate ECS Containers')
parser.add_argument('--services', required=False, action='store_true', default=False, help='Enumerate ECS Services')
parser.add_argument('--taskdef', required=False, action='store_true', default=False, help='Enumerate ECS Task Defintions')
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

ARG_FIELD_MAPPER = {
    'clusters': 'Clusters',
    'containers': 'Containers',
    'services': 'Services',
    'taskdef': 'TaskDefinitions'
}

def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print
    session = pacu_main.get_active_session()
    get_regions = pacu_main.get_regions

    if args.regions is None:
        regions = get_regions('ecs')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')
    
    all_clusters = []
    all_containers = []
    all_services = []
    all_task_defs = []

    if args.clusters is False and args.containers is False and args.services is False and args.taskdef is False:
        args.taskdef = args.services = args.containers = args.clusters = True

    for region in regions:
        clusters = []
        containers = []
        services = []
        task_defs = []

        
        if any([args.clusters, args.containers, args.services, args.taskdef]):
            print('Starting region {}...'.format(region))
        
        client = pacu_main.get_boto3_client('ecs', region)

        if args.clusters:
            response = None
            #next_token = False
            while (response is None):# or 'NextToken' in response):
                #if next_token is False:
                try:
                    response = client.list_clusters()
                except ClientError as error:
                    code = error.response['Error']['Code']
                    print('FAILURE: ')
                    if code == 'UnauthorizedOperation':
                        print('  Access denied to ListClusters.')
                    else:
                        print('  ' + code)
                    print('    Skipping cluster enumeration...')
                        
                else:
                    response = client.list_clusters()

                for arn in response['clusterArns']:
                    clusters.append(arn)
            print('  {} cluster arn(s) found.'.format(len(clusters)))
            all_clusters += clusters

        if args.containers:
            for cluster_arn in clusters:
                response = None
                next_token = False
                while (response is None or 'NextToken' in response):
                    if next_token is False:
                        try:
                            response = client.list_container_instances(
                                cluster=cluster_arn,
                                maxResults=100  # To prevent timeouts if there are too many instances
                            )
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('FAILURE: ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to ListContainerInstances.')
                            else:
                                print('  ' + code)
                            print('  Skipping container enumeration...')
                            args.containers = False
                            break
                    else:
                        response = client.list_container_instances(
                            cluster=cluster_arn,
                            maxResults=100,
                            nextToken=next_token
                        )
                    if 'NextToken' in response:
                        next_token = response['NextToken']
                
                    for container in response['containerInstanceArns']:
                        containers.append(container)
            
            print('  {} container(s) found.'.format(len(containers)))
            all_containers += containers

        if args.services:
            for cluster_arn in clusters:
                response = None
                next_token = False
                while (response is None or 'NextToken' in response):
                    if next_token is False:
                        try:
                            response = client.list_services(
                                cluster=cluster_arn,
                                maxResults=100  # To prevent timeouts if there are too many instances
                            )
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('FAILURE: ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to ListServices.')
                            else:
                                print('  ' + code)
                            print('  Skipping instance enumeration...')
                            args.services = False
                            break
                    else:
                        response = client.list_services(
                            cluster=cluster_arn,
                            maxResults=100,
                            nextToken=next_token
                        )
                    if 'nextToken' in response:
                        next_token = response['nextToken']
                    for service_arns in response['serviceArns']:
                        services.append(service_arns)

            print('  {} service(s) found.'.format(len(services)))
            all_services += services

        if args.taskdef:
            response = None
            next_token = False
            while (response is None or 'nextToken' in response):
                if next_token is False:
                    try:
                        response = client.list_task_definitions(
                            maxResults=100  # To prevent timeouts if there are too many instances
                        )
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        print('FAILURE: ')
                        if code == 'UnauthorizedOperation':
                            print('  Access denied to ListTaskDefinitions.')
                        else:
                            print('  ' + code)
                        print('  Skipping instance enumeration...')
                        args.taskdef = False
                        break
                else:
                    response = client.list_task_definitions(
                        maxResults=100,
                        nextToken=next_token
                    )
                if 'nextToken' in response:
                    next_token = response['nextToken']
                for task_def in response['taskDefinitionArns']:
                    task_defs.append(task_def)

            print('  {} task definition(s) found.'.format(len(task_defs)))
            all_task_defs += task_defs

    gathered_data = {
        'Clusters': all_clusters,
        'Containers': all_containers,
        'Services': all_services,
        'TaskDefinitions': all_task_defs
    }

    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            del gathered_data[ARG_FIELD_MAPPER[var]]

    ecs_data = deepcopy(session.ECS)
    for key, value in gathered_data.items():
        ecs_data[key] = value
    session.update(pacu_main.database, ECS=ecs_data)    


    gathered_data['regions'] = regions

    if any([args.clusters,args.containers,args.services,args.taskdef]):
        return gathered_data
    else:
        print('No data successfully enumerated.\n')
        return None


def summary(data, pacu_main):
    results = []

    results.append('  Regions:')
    for region in data['regions']:
        results.append('     {}'.format(region))

    results.append('')

    if 'Clusters' in data:
        results.append('    {} total cluster(s) found.'.format(len(data['Clusters'])))

    if 'Containers' in data:
        results.append('    {} total container(s) found.'.format(len(data['Containers'])))

    if 'Services' in data:
        results.append('    {} total service(s) found.'.format(len(data['Services'])))

    if 'TaskDefinitions' in data:
        results.append('    {} total task definition(s) found.'.format(len(data['TaskDefinitions'])))

    return '\n'.join(results)



    
