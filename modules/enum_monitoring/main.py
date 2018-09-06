#!/usr/bin/env python3
import argparse
from copy import deepcopy
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_monitoring',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'logging_monitoring',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Detects monitoring and logging capabilities.',

    # Description about what the module does and how it works
    'description': 'This module will enumerate the different logging and monitoring capabilities that have been implemented in the current AWS account. By default the module will enumerate all services that it supports, but by specifying the individual arguments, it is possible to target specific services. The supported services include CloudTrail, CloudWatch, Config, Shield, VPC, and GuardDuty.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['GuardDuty', 'CloudTrail', 'Shield', 'monitoring', 'Config', 'EC2'],  # CloudWatch needs to be "monitoring" and VPC needs to be "EC2" here for "ls" to work

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--vpc', '--config', '--cloud-trail', '--cloud-watch', '--shield', '--guard-duty'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--cloud-trail', required=False, default=False, action='store_true', help='Enumerate CloudTrail logging implementations.')
parser.add_argument('--cloud-watch', required=False, default=False, action='store_true', help='Enumerate CloudWatch alarms.')
parser.add_argument('--shield', required=False, default=False, action='store_true', help='Enumerate the Shield DDoS plan.')
parser.add_argument('--guard-duty', required=False, default=False, action='store_true', help='Enumerate GuardDuty security implementations.')
parser.add_argument('--config', required=False, default=False, action='store_true', help='Enumerate Config configurations and resources.')
parser.add_argument('--vpc', required=False, default=False, action='store_true', help='Enumerate VPC flow logs.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    enum_all = False
    if not any([args.cloud_trail, args.cloud_watch, args.shield, args.guard_duty, args.config, args.vpc]):
        enum_all = True

    summary_data = {}
    if enum_all is True or args.shield is True:
        print('Starting Shield...')

        try:
            client = pacu_main.get_boto3_client('shield', 'us-east-1')

            subscription = client.get_subscription_state()

            if subscription == 'ACTIVE':
                time_period = client.describe_subscription()
                shield_data = deepcopy(session.Shield)
                shield_data['AdvancedProtection'] = True
                shield_data['StartTime'] = time_period['Subscription']['StartTime']
                shield_data['TimeCommitmentInDays'] = time_period['Subscription']['TimeCommitmentInSeconds'] / 60 / 60 / 24
                session.update(pacu_main.database, Shield=shield_data)
                print('    Advanced (paid) DDoS protection enabled through AWS Shield.')
                print('      Subscription Started: {}\nSubscription Commitment: {} days'.format(session.Shield['StartTime'], session.Shield['TimeCommitmentInDays']))
                summary_data['ShieldSubscription'] = 'Active'
                summary_data['ShieldSubscriptionStart'] = session.Shield['StarTime']
                summary_data['ShieldSubscriptionLength'] = session.Shield['TimeCommitmentInDays']
            else:
                shield_data = deepcopy(session.Shield)
                shield_data['AdvancedProtection'] = False
                session.update(pacu_main.database, Shield=shield_data)
                print('    Standard (default/free) DDoS protection enabled through AWS Shield.')
                summary_data['ShieldSubscription'] = 'Inactive'

        except ClientError as error:
            print('Error {} getting Shield Info'.format(error))

    if enum_all is True or args.cloud_trail is True:
        print('CloudTrail Enumeration...')
        cloudtrail_regions = get_regions('cloudtrail')
        all_trails = []

        for region in cloudtrail_regions:
            print('  {}:'.format(region))

            client = pacu_main.get_boto3_client('cloudtrail', region)

            trails = client.describe_trails(
                includeShadowTrails=False
            )
            print('    {} trails'.format(len(trails['trailList'])))

            for trail in trails['trailList']:
                trail['Region'] = region
                all_trails.append(trail)

        cloudtrail_data = deepcopy(session.CloudTrail)
        cloudtrail_data['Trails'] = all_trails
        session.update(pacu_main.database, CloudTrail=cloudtrail_data)
        print('  {} total CloudTrail trails'.format(len(session.CloudTrail['Trails'])))
        summary_data['CloudTrails'] = len(session.CloudTrail['Trails'])

    if enum_all is True or args.guard_duty is True:
        print('GuardDuty Enumeration...')
        master_count = 0
        guard_duty_regions = get_regions('guardduty')
        all_detectors = []

        for region in guard_duty_regions:
            detectors = []
            print('  {}...'.format(region))

            client = pacu_main.get_boto3_client('guardduty', region)

            response = client.list_detectors()

            for detector in response['DetectorIds']:
                status, master = get_detector_master(detector, client)
                detectors.append({
                    'Id': detector,
                    'Region': region,
                    'MasterStatus': status,
                    'MasterAccountId': master
                })
                if not master:
                    master_count += 1

            while 'NextToken' in response:
                response = client.list_detectors(
                    NextToken=response['NextToken']
                )

                for detector in response['DetectorIds']:
                    status, master = get_detector_master(detector, client)
                    detectors.append({
                        'Id': detector,
                        'Region': region,
                        'MasterStatus': status,
                        'MasterAccountId': master
                    })
                    if not master:
                        master_count += 1

            print('    {} GuardDuty Detectors'.format(len(detectors)))
            all_detectors.extend(detectors)

        summary_data['MasterDetectors'] = master_count
        guardduty_data = deepcopy(session.GuardDuty)
        guardduty_data['Detectors'] = all_detectors
        session.update(pacu_main.database, GuardDuty=guardduty_data)
        print('  {} total GuardDuty Detectors'.format(len(session.GuardDuty['Detectors'])))
        summary_data['Detectors'] = len(session.GuardDuty['Detectors'])

    if enum_all is True or args.config is True:
        print('AWS Config Enumeration...')
        config_regions = get_regions('config')
        all_rules = []
        all_delivery_channels = []
        all_configuration_recorders = []
        all_configuration_aggregators = []

        for region in config_regions:
            print('  {}...'.format(region))

            client = pacu_main.get_boto3_client('config', region)

            response = client.describe_config_rules()
            rules = response['ConfigRules']
            while 'NextToken' in response:
                response = client.describe_config_rules(
                    NextToken=response['NextToken']
                )
                rules.extend(response['ConfigRules'])
            print('    {} rules found.'.format(len(rules)))
            for rule in rules:
                rule['Region'] = region
            all_rules.extend(rules)

            delivery_channels = client.describe_delivery_channels()['DeliveryChannels']
            delivery_channels_status = client.describe_delivery_channel_status()['DeliveryChannelsStatus']
            for channel in delivery_channels:
                channel['Region'] = region
                for status in delivery_channels_status:
                    if channel['name'] == status['name']:
                        channel.update(status)  # Merge the channel "status" fields into the actual channel for the DB
                        break
            print('    {} delivery channels'.format(len(delivery_channels)))
            all_delivery_channels.extend(delivery_channels)

            configuration_recorders = client.describe_configuration_recorders()['ConfigurationRecorders']
            configuration_recorders_status = client.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
            for recorder in configuration_recorders:
                recorder['Region'] = region
                for status in configuration_recorders_status:
                    if recorder['name'] == status['name']:
                        recorder.update(status)  # Merge the recorder "status" fields into the actual recorder for the DB
                        break
            print('    {} configuration recorders'.format(len(configuration_recorders)))
            all_configuration_recorders.extend(configuration_recorders)

            # The following regions lack support for configuration aggregators.
            BAD_AGGREGATION_REGIONS = ['eu-west-2', 'ca-central-1', 'eu-west-3', 'sa-east-1', 'ap-south-1', 'ap-northeast-2']
            if region in BAD_AGGREGATION_REGIONS:
                continue
            response = client.describe_configuration_aggregators()
            configuration_aggregators = response['ConfigurationAggregators']
            while 'NextToken' in response:
                response = client.describe_configuration_aggregators(
                    NextToken=response['NextToken']
                )
                configuration_aggregators.extend(response['ConfigurationAggregators'])
            for aggregator in configuration_aggregators:
                aggregator['Region'] = region
            print('    {} configuration aggregators'.format(len(configuration_aggregators)))
            all_configuration_aggregators.extend(configuration_aggregators)

        config_data = deepcopy(session.Config)
        config_data['Rules'] = all_rules
        config_data['Recorders'] = all_configuration_recorders
        config_data['DeliveryChannels'] = all_delivery_channels
        config_data['Aggregators'] = all_configuration_aggregators
        session.update(pacu_main.database, Config=config_data)
        print('  {} total Config rules'.format(len(session.Config['Rules'])))
        summary_data.update({
            'config': {
                'rules': len(all_rules),
                'recorders': len(all_configuration_recorders),
                'delivery_channels': len(all_delivery_channels),
                'aggregators': len(all_configuration_aggregators),
            }
        })

    if enum_all is True or args.cloud_watch is True:
        print('CloudWatch Enumeration...')
        cw_regions = get_regions('monitoring')
        all_alarms = []

        for region in cw_regions:
            print('  {}...'.format(region))

            client = pacu_main.get_boto3_client('cloudwatch', region)

            response = client.describe_alarms()
            alarms = response['MetricAlarms']
            while 'NextToken' in response:
                response = client.describe_alarms(
                    NextToken=response['NextToken']
                )
                alarms.extend(response['MetricAlarms'])
            print('    {} alarms'.format(len(alarms)))

            for alarm in alarms:
                alarm['Region'] = region

            all_alarms.extend(alarms)

        cw_data = deepcopy(session.CloudWatch)
        cw_data['Alarms'] = all_alarms
        session.update(pacu_main.database, CloudWatch=cw_data)
        print('  {} total CloudWatch alarms'.format(len(session.CloudWatch['Alarms'])))
        summary_data['alarms'] = len(all_alarms)

    if enum_all is True or args.vpc is True:
        print('VPC Enumeration...')
        vpc_regions = get_regions('ec2')
        all_flow_logs = []

        for region in vpc_regions:
            print('  Starting region {}...'.format(region))

            client = pacu_main.get_boto3_client('ec2', region)

            response = client.describe_flow_logs(
                MaxResults=1000
            )
            flow_logs = response['FlowLogs']
            while 'NextToken' in response:
                response = client.describe_flow_logs(
                    MaxResults=1000,
                    NextToken=response['NextToken']
                )
                flow_logs.extend(response['FlowLogs'])
            print('    {} flow logs'.format(len(flow_logs)))

            for flow_log in flow_logs:
                flow_log['Region'] = region

            all_flow_logs.extend(flow_logs)

        vpc_data = deepcopy(session.VPC)
        vpc_data['FlowLogs'] = all_flow_logs
        session.update(pacu_main.database, VPC=vpc_data)
        print('  {} total VPC flow logs'.format(len(session.VPC['FlowLogs'])))
        summary_data['flowlogs'] = len(all_flow_logs)

    print('\n{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'ShieldSubscription' in data:
        out += 'Shield Subscription Status: {}\n'.format(data['ShieldSubscription'])
        if data['ShieldSubscription'] == 'Active':
            out += '  Shield Subscription Start: {}\n'.format(data['ShieldSubscriptionStart'])
            out += '  Shield Subscription Length: {} day(s(\n'.format(data['ShieldSubscriptionLength'])
    if 'CloudTrails' in data:
        out += '  {} CloudTrail Trail(s) found.\n'.format(data['CloudTrails'])
    if 'Detectors' in data:
        out += '  {} GuardDuty Detector(s) found.\n'.format(data['Detectors'])
    if 'MasterDetectors' in data:
        out += '  {} Master GuardDuty Detector(s) found.\n'.format(data['MasterDetectors'])
    if 'config' in data:
        out += '  AWS Config Data:\n'
        out += '    {} Rules found.\n'.format(data['config']['rules'])
        out += '    {} Recorders found.\n'.format(data['config']['recorders'])
        out += '    {} Delivery Channels found.\n'.format(data['config']['delivery_channels'])
        out += '    {} Aggregators found.\n'.format(data['config']['aggregators'])
    if 'alarms' in data:
        out += '  {} CloudWatch Alarm(s) found.\n'.format(data['alarms'])
    if 'flowlogs' in data:
        out += '  {} VPC flow logs found.\n'.format(data['flowlogs'])
    return out


def get_detector_master(detector_id, client):
    response = client.get_master_account(
        DetectorId=detector_id
    )
    if 'Master' not in response:
        return(None, None)

    status = None
    master = None

    if 'RelationshipStatus' in response['Master']:
        status = response['Master']['RelationshipStatus']

    if 'AccountId' in response['Master']:
        master = response['Master']['AccountId']

    return(status, master)
