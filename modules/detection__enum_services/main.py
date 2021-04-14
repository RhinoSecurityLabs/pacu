#!/usr/bin/env python3
import argparse
from copy import deepcopy
from botocore.exceptions import ClientError, EndpointConnectionError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'detection__enum_services',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'EVADE',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Detects monitoring and logging capabilities.',

    # Description about what the module does and how it works
    'description': 'This module will enumerate the different logging and monitoring capabilities that have been implemented in the current AWS account. By default the module will enumerate all services that it supports, but by specifying the individual arguments, it is possible to target specific services. The supported services include CloudTrail, CloudWatch, Config, Shield, VPC, and GuardDuty. Not all regions contain support for AWS Config aggregators, so no attempts are made to obtain aggregators in unsupported regions. When a permission issue is detected for an action, future attempts to call that action will be skipped. If permissions to enumerate a service have all been invalidated, the enumeration of that service will stop for all subsequen regions and the module will continue execution.',

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
    arguments = [args.cloud_trail, args.cloud_watch, args.shield, args.guard_duty, args.config, args.vpc]
    enum_all = not any(arguments)

    summary_data = {}

    if args.shield or enum_all:
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
            code = error.response['Error']['Code']
            print('  Error getting Shield info: {}\n'.format(code))
    if args.cloud_trail or enum_all:
        print('Starting CloudTrail...')
        cloudtrail_regions = get_regions('cloudtrail')
        all_trails = []
        cloudtrail_permission = True
        for region in cloudtrail_regions:
            if not cloudtrail_permission:
                print('  No Valid Permissions Found')
                print('    Skipping subsequent enumerations for remaining regions...')
                break
            print('  Starting region {}...'.format(region))

            client = pacu_main.get_boto3_client('cloudtrail', region)
            try:
                trails = client.describe_trails(includeShadowTrails=False)
                for trail in trails['trailList']:
                    trail['Region'] = region
                    all_trails.append(trail)
                print('    {} trail(s) found.'.format(len(trails['trailList'])))
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('    ACCESS DENIED: DescribeTrails')
                    print('       Skipping subsequent enumerations...')
                    cloudtrail_permission = False
                else:
                    print('    {}'.format(code))

        cloudtrail_data = deepcopy(session.CloudTrail)
        cloudtrail_data['Trails'] = all_trails
        session.update(pacu_main.database, CloudTrail=cloudtrail_data)
        print('  {} total CloudTrail trail(s) found.'.format(len(session.CloudTrail['Trails'])))
        summary_data['CloudTrails'] = len(session.CloudTrail['Trails'])
    if args.guard_duty or enum_all:
        print('Starting GuardDuty...')
        guard_duty_regions = get_regions('guardduty')
        all_detectors = []
        guard_duty_permission = True
        master_count = 0

        for region in guard_duty_regions:
            if not guard_duty_permission:
                print('  No Valid Permissions Found')
                print('    Skipping subsequent enumerations for remaining regions...')
                break
            detectors = []
            print('  Starting region {}...'.format(region))
            client = pacu_main.get_boto3_client('guardduty', region)
            paginator = client.get_paginator('list_detectors')
            page_iterator = paginator.paginate()
            try:
                for page in page_iterator:
                    for detector in page['DetectorIds']:
                        status, master = get_detector_master(detector, client)
                        detectors.append({
                            'Id': detector,
                            'Region': region,
                            'MasterStatus': status,
                            'MasterAccountId': master
                        })
                        if not master:
                            master_count += 1
                print('    {} GuardDuty Detector(s) found.'.format(len(detectors)))
                all_detectors.extend(detectors)
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('    ACCESS DENIED: ListDetectors')
                    print('       Skipping subsequent enumerations...')
                    guard_duty_permission = False
                else:
                    print('    {}'.format(code))
            except EndpointConnectionError as error: 
                print('    Error connecting to Guardduty Endpoint for region: {}'.format(region))
                print('        Error: {}, {}'.format(error.__class__, str(error)))
            except Exception as error: 
                print('    Generic Error when enumerating Guardduty detectors for region: {}'.format(region))
                print('        Error: {}, {}'.format(error.__class__, str(error)))

        summary_data['MasterDetectors'] = master_count
        guardduty_data = deepcopy(session.GuardDuty)
        guardduty_data['Detectors'] = all_detectors
        session.update(pacu_main.database, GuardDuty=guardduty_data)
        print('  {} total GuardDuty Detector(s) found.\n'.format(len(session.GuardDuty['Detectors'])))
        summary_data['Detectors'] = len(session.GuardDuty['Detectors'])

    if args.config or enum_all:
        print('Starting Config...')
        config_regions = get_regions('config')
        all_rules = []
        all_delivery_channels = []
        all_configuration_recorders = []
        all_configuration_aggregators = []
        permissions = {
            'rules': True,
            'delivery_channels': True,
            'recorders': True,
            'aggregators': True,
        }
        for region in config_regions:
            if not any([permissions[action] for action in permissions]):
                print('  No Valid Permissions Found')
                print('    Skipping subsequent enumerations for remaining regions...')
                break
            print('  Starting region {}...'.format(region))

            client = pacu_main.get_boto3_client('config', region)
            if permissions['rules']:
                paginator = client.get_paginator('describe_config_rules')
                rules_pages = paginator.paginate()

                rules = []
                try:
                    for page in rules_pages:
                        rules.extend(page['ConfigRules'])
                    for rule in rules:
                        rule['Region'] = region
                    print('    {} rule(s) found.'.format(len(rules)))
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('    ACCESS DENIED: DescribeConfigRules')
                        print('      Skipping subsequent enumerations...')
                        permissions['rules'] = False
                    else:
                        print('    {}'.format(code))

                all_rules.extend(rules)

            if permissions['delivery_channels']:
                delivery_channels = []
                try:
                    delivery_channels = client.describe_delivery_channels()['DeliveryChannels']
                    try:
                        delivery_channels_status = client.describe_delivery_channel_status()['DeliveryChannelsStatus']
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        if code == 'AccessDeniedException':
                            print('    ACCESS DENIED: DescribeDeliveryChannelStatus')
                        else:
                            print('    {}'.format(code))
                    for channel in delivery_channels:
                        channel['Region'] = region
                        for status in delivery_channels_status:
                            if channel['name'] == status['name']:
                                channel.update(status)  # Merge the channel "status" fields into the actual channel for the DB
                                break
                    print('    {} delivery channel(s) found.'.format(len(delivery_channels)))
                    all_delivery_channels.extend(delivery_channels)
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('    ACCESS DENIED: DescribeDeliveryChannels')
                        print('      Skipping subsequent enumerations...')
                        permissions['delivery_channels'] = False
                    else:
                        print('    {}'.format(code))

            if permissions['recorders']:
                configuration_recorders = []
                try:
                    configuration_recorders = client.describe_configuration_recorders()['ConfigurationRecorders']
                    try:
                        configuration_recorders_status = client.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        if code == 'AccessDeniedException':
                            print('    ACCESS DENIED: DescribeConfigurationRecorderStatus')
                        else:
                            print('    {}'.format(code))
                    for recorder in configuration_recorders:
                        recorder['Region'] = region
                        for status in configuration_recorders_status:
                            if recorder['name'] == status['name']:
                                recorder.update(status)  # Merge the recorder "status" fields into the actual recorder for the DB
                                break
                    print('    {} configuration recorder(s) found.'.format(len(configuration_recorders)))
                    all_configuration_recorders.extend(configuration_recorders)
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('    ACCESS DENIED: DescribeConfigurationRecorders')
                        print('      Skipping subsequent enumerations...')
                        permissions['recorders'] = False
                    else:
                        print('    {}'.format(code))

            # The following regions lack support for configuration aggregators.
            BAD_AGGREGATION_REGIONS = ['eu-west-2', 'ca-central-1', 'eu-west-3', 'sa-east-1', 'ap-south-1', 'ap-northeast-2']
            if region in BAD_AGGREGATION_REGIONS:
                print('    Skipping unsupported aggregator region...')
                continue

            if permissions['aggregators']:
                configuration_aggregators = []
                kwargs = {}
                while True:
                    try:
                        response = client.describe_configuration_aggregators(**kwargs)
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        if code == 'AccessDeniedException':
                            print('    ACCESS DENIED: DescribeConfigurationAggregators')
                            print('      Skipping subsequent enumerations...')
                            permissions['aggregators'] = False
                        else:
                            print('    {}'.format(code))
                        break
                    configuration_aggregators = response['ConfigurationAggregators']
                    if 'NextToken' in response:
                        kwargs['NextToken'] = response['NextToken']
                    else:
                        for aggregator in configuration_aggregators:
                            aggregator['Region'] = region
                        print('    {} configuration aggregator(s) found.'.format(len(configuration_aggregators)))
                        all_configuration_aggregators.extend(configuration_aggregators)
                        break

        config_data = deepcopy(session.Config)
        config_data['Rules'] = all_rules
        config_data['Recorders'] = all_configuration_recorders
        config_data['DeliveryChannels'] = all_delivery_channels
        config_data['Aggregators'] = all_configuration_aggregators
        session.update(pacu_main.database, Config=config_data)

        print('  {} total Config rule(s) found.'.format(len(session.Config['Rules'])))
        print('  {} total Config recorder(s) found.'.format(len(session.Config['Recorders'])))
        print('  {} total Config delivery channel(s) found.'.format(len(session.Config['DeliveryChannels'])))
        print('  {} total Config aggregator(s) found.\n'.format(len(session.Config['Aggregators'])))
        summary_data.update({
            'config': {
                'rules': len(all_rules),
                'recorders': len(all_configuration_recorders),
                'delivery_channels': len(all_delivery_channels),
                'aggregators': len(all_configuration_aggregators),
            }
        })

    if args.cloud_watch or enum_all:
        print('Starting CloudWatch...')
        cw_regions = get_regions('monitoring')
        all_alarms = []
        cloudwatch_permission = True
        for region in cw_regions:
            if not cloudwatch_permission:
                print('  No Valid Permissions Found')
                print('    Skipping subsequent enumerations for remaining regions...')
                break

            print('  Starting region {}...'.format(region))
            client = pacu_main.get_boto3_client('cloudwatch', region)
            paginator = client.get_paginator('describe_alarms')
            page_iterator = paginator.paginate()
            alarms = []
            try:
                for page in page_iterator:
                    alarms.extend(page['MetricAlarms'])
                print('    {} alarms found.'.format(len(alarms)))
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDenied':
                    print('    ACCESS DENIED: DescribeAlarms')
                    print('      Skipping subsequent enumerations...')
                    cloudwatch_permission = False
                else:
                    print('    {}'.format(code))
            for alarm in alarms:
                alarm['Region'] = region
            all_alarms.extend(alarms)

        cw_data = deepcopy(session.CloudWatch)
        cw_data['Alarms'] = all_alarms
        session.update(pacu_main.database, CloudWatch=cw_data)
        print('  {} total CloudWatch alarm(s) found.'.format(len(session.CloudWatch['Alarms'])))
        summary_data['alarms'] = len(all_alarms)
    if args.vpc or enum_all:
        print('Starting VPC...')
        vpc_regions = get_regions('ec2')
        all_flow_logs = []
        flow_log_permission = True

        for region in vpc_regions:
            if not flow_log_permission:
                print('  No Valid Permissions Found')
                print('    Skipping subsequent enumerations for remaining regions...')
                break
            print('  Starting region {}...'.format(region))

            client = pacu_main.get_boto3_client('ec2', region)
            kwargs = {'MaxResults': 1000}
            flow_logs = []
            while True:
                try:
                    response = client.describe_flow_logs(**kwargs)
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'UnauthorizedOperation':
                        print('    ACCESS DENIED: DescribeFlowLogs')
                        print('      Skipping subsequent enumerations...')
                        flow_log_permission = False
                    else:
                        print('    {}'.format(code))
                    break
                flow_logs.extend(response['FlowLogs'])
                if 'NextToken' in response:
                    kwargs['NextToken'] = response['NextToken']
                else:
                    print('    {} flow log(s) found.'.format(len(flow_logs)))
                    break
            for flow_log in flow_logs:
                flow_log['Region'] = region

            all_flow_logs.extend(flow_logs)

        vpc_data = deepcopy(session.VPC)
        vpc_data['FlowLogs'] = all_flow_logs
        session.update(pacu_main.database, VPC=vpc_data)
        print('  {} total VPC flow log(s) found.'.format(len(session.VPC['FlowLogs'])))
        summary_data['flowlogs'] = len(all_flow_logs)

    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'ShieldSubscription' in data:
        out += '  Shield Subscription Status: {}\n'.format(data['ShieldSubscription'])
        if data['ShieldSubscription'] == 'Active':
            out += '    Shield Subscription Start: {}\n'.format(data['ShieldSubscriptionStart'])
            out += '    Shield Subscription Length: {} day(s(\n'.format(data['ShieldSubscriptionLength'])
    if 'CloudTrails' in data:
        out += '  {} CloudTrail Trail(s) found.\n'.format(data['CloudTrails'])
    if 'Detectors' in data:
        out += '  {} GuardDuty Detector(s) found.\n'.format(data['Detectors'])
    if 'MasterDetectors' in data:
        out += '  {} Master GuardDuty Detector(s) found.\n'.format(data['MasterDetectors'])
    if 'config' in data:
        out += '  AWS Config Data:\n'
        out += '    {} Rule(s) found.\n'.format(data['config']['rules'])
        out += '    {} Recorder(s) found.\n'.format(data['config']['recorders'])
        out += '    {} Delivery Channel(s) found.\n'.format(data['config']['delivery_channels'])
        out += '    {} Aggregator(s) found.\n'.format(data['config']['aggregators'])
    if 'alarms' in data:
        out += '  {} CloudWatch Alarm(s) found.\n'.format(data['alarms'])
    if 'flowlogs' in data:
        out += '  {} VPC flow log(s) found.\n'.format(data['flowlogs'])

    if not out:
        return '  No data could be found'
    return out


def get_detector_master(detector_id, client):
    try:
        response = client.get_master_account(
            DetectorId=detector_id
        )
    except ClientError:
        raise
    if 'Master' not in response:
        return(None, None)

    status = None
    master = None

    if 'RelationshipStatus' in response['Master']:
        status = response['Master']['RelationshipStatus']

    if 'AccountId' in response['Master']:
        master = response['Master']['AccountId']

    return(status, master)
