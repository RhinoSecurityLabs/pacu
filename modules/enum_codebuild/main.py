#!/usr/bin/env python3
import argparse


module_info = {
    'name': 'enum_codebuild',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'recon_enum_with_keys',
    'one_liner': 'Enumerates CodeBuild builds and projects while looking for sensitive data',
    'description': 'This module enumerates all CodeBuild builds and projects, with the goal of finding sensitive information in the environment variables associated with each one, like passwords, secrets, or API keys.',
    'services': ['CodeBuild'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions', '--builds', '--projects'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('--builds', required=False, default=False, action='store_true', help='Enumerate builds. If this is passed in without --projects, then only builds will be enumerated. By default, both are enumerated.')
parser.add_argument('--projects', required=False, default=False, action='store_true', help='Enumerate projects. If this is passed in without --builds, then only projects will be enumerated. By default, both are enumerated.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    all = args.builds == args.projects == False
    regions = args.regions.split(',') if args.regions else get_regions('CodeBuild') 

    all_projects = []
    all_builds = []
    environment_variables = []
    for region in regions:
        region_projects = []
        region_builds = []

        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('codebuild', region)

        # Begin enumeration

        # Projects
        if all is True or args.projects is True:
            project_names = []
            response = client.list_projects()
            project_names.extend(response['projects'])
            while 'nextToken' in response:
                response = client.list_projects(
                    nextToken=response['nextToken']
                )
                project_names.extend(response['projects'])

            if len(project_names) > 0:
                region_projects = client.batch_get_projects(
                    names=project_names
                )['projects']
                print('  Found {} projects.'.format(len(region_projects)))
                all_projects.extend(region_projects)

        # Builds
        if all is True or args.builds is True:
            build_ids = []
            response = client.list_builds()
            build_ids.extend(response['ids'])
            while 'nextToken' in response:
                response = client.list_builds(
                    nextToken=response['nextToken']
                )
                build_ids.extend(response['ids'])

            if len(build_ids) > 0:
                region_builds = client.batch_get_builds(
                    ids=build_ids
                )['builds']
                print('  Found {} builds.\n'.format(len(region_builds)))
                all_builds.extend(region_builds)

    # Begin environment variable dump

    # Projects
    for project in all_projects:
        if 'environment' in project and 'environmentVariables' in project['environment']:
            environment_variables.extend(project['environment']['environmentVariables'])

    # Builds
    for build in all_builds:
        if 'environment' in build and 'environmentVariables' in build['environment']:
            environment_variables.extend(build['environment']['environmentVariables'])

    # Kill duplicates
    environment_variables = list(set(environment_variables))

    # Store in session
    session.CodeBuild['EnvironmentVariables'] = environment_variables
    
    summary_data = {'EnvironmentVariables': environment_variables}

    if len(all_projects) > 0:
        session.CodeBuild['Projects'] = all_projects
        summary_data['Projects'] = all_projects

    if len(all_builds) > 0:
        session.CodeBuild['Builds'] = all_builds
        summary_data['Builds'] = all_builds

    print('All environment variables found (duplicates removed):\n')

    print('{} completed.\n'.format(module_info['name']))
    summary_data = {
        'EnvironmentVariables': [
            {'name': 'a', 'value': 5, 'type': 'PLAINTEXT'},
            {'name': 'b', 'value': 7},
            {'name': 'c', 'value': 8, 'type': 'PARAMETER_STORE'}
        ],
        'Builds': [1, 2, 3, 4, 5],
        'Projects': [1, 2, 3, 4]
    }
    return summary_data


def summary(data, pacu_main):
    out = ''
    for item in data:
        out += '    {} total {} found.\n'.format(len(data[item]), item)
    return out
