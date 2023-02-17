#!/usr/bin/env python3
import argparse
from copy import deepcopy
from botocore.exceptions import ClientError


module_info = {
    'name': 'codebuild__enum',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'ENUM',
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

    if args.builds is False and args.projects is False:
        enum_all = True
    else:
        enum_all = False
    regions = args.regions.split(',') if args.regions else get_regions('CodeBuild')

    all_projects = []
    all_builds = []
    environment_variables = []
    summary_data = {}
    for region in regions:
        region_projects = []
        region_builds = []
        summary_data[region] = {}

        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('codebuild', region)

        # Begin enumeration

        # Projects
        if enum_all is True or args.projects is True:
            project_names = []
            response = {}
            try:
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
                    print('Found {} projects'.format(len(region_projects)))
                    summary_data[region]['Projects'] = len(region_projects)
                    all_projects.extend(region_projects)
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('No projects got for region: {} - AccessDeniedException'.format(region))
                    print('ClientError getting projects: {}'.format(error))


        # Builds
        if enum_all is True or args.builds is True:
            build_ids = []
            response = {}
            try:
                response = client.list_builds()
                build_ids.extend(response['ids'])
            except ClientError as error:
               if error.response['Error']['Code'] == 'AccessDeniedException':
                   print('No code-builds builds got for region: {} - AccessDeniedException'.format(region))
                   print('ClientError getting builds: {}'.format(error))

               
            while 'nextToken' in response:
                try:
                    response = client.list_builds(
                        nextToken=response['nextToken']
                    )
                    build_ids.extend(response['ids'])
                except ClientError as error:
                    if error.response['Error']['Code'] == 'AccessDeniedException':
                        print('No further code-builds builds for region: {} - AccessDeniedException'.format(region))
                        print('ClientError getting further builds: {}'.format(error))

            if len(build_ids) > 0:
                region_builds = {}
                try:
                    region_builds = client.batch_get_builds(
                        ids=build_ids
                    )['builds']
                    print('  Found {} builds'.format(len(region_builds)))
                    summary_data[region]['Builds'] = len(region_builds)
                    all_builds.extend(region_builds)
                except ClientError as error:
                    if error.response['Error']['Code'] == 'AccessDeniedException':
                        print('No info retrieved about code-builds for region: {} - AccessDeniedException'.format(region))
                        print('ClientError getting info about builds: {}'.format(error))

        if not summary_data[region]:
            del summary_data[region]

    # Begin environment variable dump

    # Projects
    for project in all_projects:
        if 'environment' in project and 'environmentVariables' in project['environment']:
            environment_variables.extend(project['environment']['environmentVariables'])

    # Builds
    for build in all_builds:
        if 'environment' in build and 'environmentVariables' in build['environment']:
            environment_variables.extend(build['environment']['environmentVariables'])

    # Store in session
    codebuild_data = deepcopy(session.CodeBuild)
    codebuild_data['EnvironmentVariables'] = environment_variables
    summary_data['All'] = {'EnvironmentVariables': len(environment_variables)}

    if len(all_projects) > 0:
        codebuild_data['Projects'] = all_projects
        summary_data['All']['Projects'] = len(all_projects)

    if len(all_builds) > 0:
        codebuild_data['Builds'] = all_builds
        summary_data['All']['Builds'] = len(all_builds)

    session.update(pacu_main.database, CodeBuild=codebuild_data)

    return summary_data

def summary(data, pacu_main):
    out = ''
    for region in sorted(data):
        out += '    {}\n'.format(region)
        for val in data[region]:
            out += '        {} {} found.\n'.format(data[region][val], val[:-1] + '(' + val[-1] + ')')
    return out
