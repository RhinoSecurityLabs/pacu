#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import os
import time

from pacu.core.lib import strip_lines, save
from pacu import Main

module_info = {
    'name': 'iam__get_credential_report',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'ENUM',
    'one_liner': 'Generates and downloads an IAM credential report.',
    'description': strip_lines('''
        This module tries to download a credential report for the AWS account, giving a lot of authentication
        history/info for users in the account. If it does not find a report, it will prompt you to generate one. The
        report is saved in ~/.local/share/sessions/[current_session_name]/downloads/get_credential_report_[current_time].csv
    '''),
    'services': ['IAM'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    ######

    client = pacu_main.get_boto3_client('iam')
    report = None
    generated = False
    summary_data = {'generated': False}
    while True:
        try:
            report = client.get_credential_report()
            break
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'ReportNotPresent' or code == 'ReportInProgress':
                if generated or code == 'ReportInProgress':
                    generated = True
                    print('waiting...')
                    time.sleep(20)
                else:
                    generate = input('Report not found. Generate? (y/n) ')
                    if generate == 'y':
                        try:
                            client.generate_credential_report()
                            print('  Starting. Checking completion every 20 seconds...')
                            generated = True
                            summary_data['generated'] = True
                        except ClientError as error:
                            if error.response['Error']['Code'] == 'AccessDenied':
                                print('Unauthorized to generate_credential_report')
                                report = None
                                break
                    else:
                        report = None
                        break
            elif code == 'AccessDenied':
                print('  FAILURE:')
                print('    MISSING NEEDED PERMISSIONS')
                report = None
                break
            else:
                print('Unrecognized ClientError: {} ({})'.format(str(error), error.response['Error']['Code']))
                break

    if report and 'Content' in report:
        filename = 'downloads/get_credential_report_{}.csv'.format(session.name, time.time())
        save(report['Content'].decode(), filename)
        summary_data['report_location'] = filename
        print('Credential report saved to {}'.format(filename))

    else:
        print('\n  Unable to generate report.')

    return summary_data


def summary(data, pacu_main):
    out = ''
    if data['generated']:
        out += '  Report was generated\n'
    else:
        out += '  Report was not generated\n'
    if 'report_location' in data:
        out += '    Report saved to: {}\n'.format(data['report_location'])
    return out
