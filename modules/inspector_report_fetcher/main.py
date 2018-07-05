#!/usr/bin/env python3
import argparse
import boto3
from botocore.exceptions import ClientError
from functools import partial
import os
import sys
import urllib.request
import shutil
import json

from pacu import util


# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'Inspector Report Fetcher',

    # Name and any other notes about the author.
    'author': 'Alexander Morgenstern',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'Does this thing.',

    # Full description about what the module does and how it works.
    'description': 'This module does this thing by using xyz and outputs info to abc. Here is a note also.',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['Inspector'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab.
    'arguments_to_autocomplete': [
        '--downloadReports'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--downloadReports', required=False, default=False, action='store_true', help='Optional argument to download HTML reports for each run')


# For when "help module_name" is called. Don't modify this, and make sure it's
# included in your module.
def help():
    return [module_info, parser.format_help()]


# Main is the first function that is called when this module is executed.
def main(args, database):
    session = util.get_active_session(database)

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    #input = partial(util.input, session_name=session.name, database=database)
    #key_info = partial(util.key_info, database=database)
    #fetch_data = partial(util.fetch_data, database=database)
    get_regions = partial(util.get_regions, database=database)
    #install_dependencies = partial(util.install_dependencies, database=database)
    ######

    #regions = get_regions('EC2')
    #regions = get_regions('Inspector')
    regions = ['us-east-1']
    for region in regions:
        print('Starting region {}...'.format(region))
        client = boto3.client(
            'inspector',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            # Even if the session doesn't have a session token, this will work
            # because the value will be None and will be ignored.
            aws_session_token=session.session_token
        )

        if args.downloadReports:
            assessment_runs = []
            response = client.list_assessment_runs()
            assessment_runs += response['assessmentRunArns']
            while 'nextToken' in response:
                response = client.list_findings(nextToken=response['nextToken'])
                assessment_runs += response['assessmentRunArns']

            for run in assessment_runs:
                response = client.get_assessment_report(
                    assessmentRunArn=run,
                    reportFileFormat='HTML',
                    reportType='FULL'
                )
                if not os.path.exists(f'sessions/{session.name}/downloads/inspector_assessments/'):
                    os.makedirs(f'sessions/{session.name}/downloads/inspector_assessments/')
                file_name = f'sessions/{session.name}/downloads/inspector_assessments/' + str(run)[-10:] + '.html'
                print(file_name)
                with urllib.request.urlopen(response['url']) as response, open(file_name, 'a') as out_file:
                    out_file.write(str(response.read()))
    
        findings = []
        response = client.list_findings()
        findings = response['findingArns']
        while 'nextToken' in response:
            response = client.list_findings(nextToken=response['nextToken'])
            findings += response['findingArns']

       
        descriptions = client.describe_findings(findingArns=findings)['findings']
        #for description in descriptions:
        #    description.pop('description', None)
        #    description.pop('recommendation', None)
        #    description.pop('createdAt', None)
        #    description.pop('updatedAt', None)
            
        print(json.dumps(descriptions, indent=4, sort_keys=True, default=str))
        print(f"{module_info['name']} completed.\n")
        return

def download_report(url, destination):
    return True
