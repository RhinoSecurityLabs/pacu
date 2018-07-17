#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import os
import datetime
import pytz
import csv


module_info = {
    'name': 'dl_cloudwatch_logs',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'logging_monitoring',
    'one_liner': 'Captures Cloudwatch logs and downloads them to the session downloads folder',
    'description': """
        This module examines all logs for all regions and saves them as CSV files. By default,
        only events that were logged in the past 24 hours will be captured. Otherwise, they will
        be captured based on the passed time arguments. The files will be downloaded in a similar
        format to pacu/sessions/{session}/downloads/cloud_watch_logs/{timestamp}, with session
        being the active session, and timestamp being the start of this module's execution.
        """,
    'services': ['logs'],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
        '--from-time',
        '--to-time'
    ],
}
DEFAULT_FROM_TIME = pytz.utc.localize(datetime.datetime.today() - datetime.timedelta(days=1))

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--from-time',
    required=False,
    default=DEFAULT_FROM_TIME,
    help='Download logs from time format "yyyy[-mm[-dd-[hh-mm-ss]]]". Unfilled fields will assume earliest possible time'
)
parser.add_argument(
    '--to-time',
    required=False,
    default=None,
    help='Download logs up to and not including time format "yyyy[-mm[-dd-[hh-mm-ss]]]". Unfilled fields will assume earliest possible time'
)


def parse_time(time):
    time_fields = [int(field) for field in time.split('-')]
    # Fill missing month and day.
    if len(time_fields) == 1:
        time_fields.append(1)
        time_fields.append(1)
    # Fill missing day.
    elif len(time_fields) == 2:
        time_fields.append(1)
    return pytz.utc.localize(datetime.datetime(*time_fields))


def write_stream_file(session_name, scan_time, group_name, stream_name, events):
    if not events:
        return True
    stream_group_path = os.path.join(os.getcwd(), 'sessions', session_name, 'downloads', 'cloud_watch_logs', str(scan_time), group_name[1:])
    if not os.path.exists(stream_group_path):
        os.makedirs(stream_group_path)
    file_name = os.path.join(stream_group_path, stream_name.replace('/', '_') + '.txt')
    flag = 'a' if os.path.isfile(file_name) else 'w'

    with open(file_name, flag, newline='') as out_file:
        event_writer = csv.writer(
            out_file,
            delimiter=',',
        )
        if flag == 'w':
            event_writer.writerow(['timestamp', 'message'])
        for event in events:
            event_writer.writerow([event['timestamp'], event['message']])
    return True


def collect_all(client, func, key, **kwargs):
    """Collects data given a Boto3 client, function, and a key to look for responses. Returns a list."""
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        out = response[key]
        while 'nextToken' in response:
            response = caller({'nextToken': response['nextToken'], **kwargs})
            out += response[key]
        return out
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print('AccessDenied for: {}'.format(func))
    return []


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    if type(args.from_time) == str:
        from_time = parse_time(args.from_time)
    else:
        from_time = DEFAULT_FROM_TIME

    if type(args.to_time) == str:
        to_time = parse_time(args.to_time)

    scan_time = int(datetime.datetime.now().timestamp())
    regions = get_regions('logs')
    log_groups = {}
    for region in regions:
        print('Collecting logs for region {}...'.format(region))
        client = pacu_main.get_boto3_client('logs', region)
        groups = collect_all(client, 'describe_log_groups', 'logGroups')
        group_names = [group['logGroupName'] for group in groups]
        for group in group_names:
            log_groups[group] = {}

        for log_group in log_groups.keys():
            streams = collect_all(client, 'describe_log_streams', 'logStreams', **{'logGroupName': log_group})
            log_groups[log_group] = [stream['logStreamName'] for stream in streams]

        some_events_found = False
        for group in log_groups.keys():
            for stream in log_groups[group]:
                start_time = int(from_time.timestamp() * 1000 + from_time.microsecond / 1000)
                end_time = int(to_time.timestamp() * 1000 + to_time.microsecond / 1000) if args.to_time else None
                kwargs = {
                    'logGroupName': group,
                    'logStreamName': stream,
                    'startTime': start_time,
                }
                if end_time:
                    kwargs['endTime'] = end_time
                response = client.get_log_events(**kwargs)
                if not response['events']:
                    continue
                some_events_found = True
                write_stream_file(session.name, scan_time, group, stream, response['events'])
                while 'nextBackwardToken' in response:
                    old_Token = response['nextBackwardToken']
                    response = client.get_log_events(
                        **{'nextToken': response['nextBackwardToken']},
                        **kwargs
                    )
                    write_stream_file(session.name, scan_time, group, stream, response['events'])
                    if old_Token == response['nextBackwardToken']:
                        print('Captured Events for {}'.format(stream))
                        break

        if not some_events_found:
            print('  No events found.')

    print('\nLogs downloaded to pacu/sessions/{}/downloads/cloud_watch_logs/{}'.format(session.name, scan_time))
    print("{} completed.\n".format(module_info['name']))
    return
