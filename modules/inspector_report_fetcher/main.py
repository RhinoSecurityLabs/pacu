#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import os
import urllib.request

module_info = {
    'name': 'inspector_report_fetcher',
    'author': 'Alexander Morgenstern',
    'category': 'recon_enum_with_keys',
    'one_liner': 'Captures vulnerabilties found when running a preconfigured inspector report',
    'description':
        """
        This module captures findings for reports in regions that support AWS Inspector.
        The optional argument --download-reports will automatically download any reports found
        into the session downloads directory under a folder named after the run id of the
        inspector report.""",
    'services': ['Inspector'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
        '--download-reports'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--download-reports', required=False, default=False, action='store_true', help='Optional argument to download HTML reports for each run')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    regions = get_regions('Inspector')
    complete_data = {}
    for region in regions:
        print('Starting region {}...'.format(region))

        client = pacu_main.get_boto3_client('inspector', region)

        if args.download_reports:
            assessment_runs = []
            response = ''
            try:
                response = client.list_assessment_runs()
                assessment_runs += response['assessmentRunArns']
                while 'nextToken' in response:
                    response = client.list_findings(nextToken=response['nextToken'])
                    assessment_runs += response['assessmentRunArns']
            except ClientError as error:
                    if error.response['Error']['Code'] == 'AccessDeniedException':
                        print('Access Denied for list-assessment-runs')
            for run in assessment_runs:
                response = client.get_assessment_report(
                    assessmentRunArn=run,
                    reportFileFormat='HTML',
                    reportType='FULL'
                )
                if not os.path.exists(f'sessions/{session.name}/downloads/inspector_assessments/'):
                    os.makedirs(f'sessions/{session.name}/downloads/inspector_assessments/')
                file_name = f'sessions/{session.name}/downloads/inspector_assessments/' + str(run)[-10:] + '.html'
                print('Report saved to: ' + file_name)
                with urllib.request.urlopen(response['url']) as response, open(file_name, 'a') as out_file:
                    out_file.write(str(response.read()))
        findings = []
        try:
            response = client.list_findings()
            findings = response['findingArns']
            while 'nextToken' in response:
                response = client.list_findings(nextToken=response['nextToken'])
                findings += response['findingArns']
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Access Denied for list-findings')
                continue
        try:
            if len(findings) < 1:
                continue
            descriptions = client.describe_findings(findingArns=findings)['findings']
            complete_data[region] = descriptions
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Access Denied for describe-findings')
    session.update(pacu_main.database, Inspector=complete_data)
    print(f"{module_info['name']} completed.\n")
    return
