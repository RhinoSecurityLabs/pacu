#!/usr/bin/env python3
import argparse
import csv
import datetime
import os

from botocore.exceptions import ClientError

from pacu.core.lib import save, strip_lines, downloads_dir
from pacu import Main

module_info = {
    'name': 'cloudwatch__download_logs',
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',
    'category': 'EVADE',
    'one_liner': 'Captures CloudWatch logs and downloads them to the session downloads folder',
    'description': strip_lines('''
        This module examines all logs for all regions and saves them as CSV files. By default, only events that were
        logged in the past 24 hours will be captured. Otherwise, they will be captured based on the passed time
        arguments. The files will be downloaded in a similar format to
        ~/.local/share/pacu/sessions/{session}/downloads/cloud_watch_logs/{timestamp}, with session being the active session, and
        timestamp being the start of this module's execution.
    '''),
    'services': ['logs'],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
        '--from-time',
        '--to-time',
        '--regions'
    ],
}
DEFAULT_FROM_TIME = datetime.datetime.today().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(days=1)

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
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')


def parse_time(time):
    time_fields = [int(field) for field in time.split('-')]
    # Fill missing month and day.
    if len(time_fields) == 1:
        time_fields.append(1)
        time_fields.append(1)
    # Fill missing day.
    elif len(time_fields) == 2:
        time_fields.append(1)
    return datetime.datetime(*time_fields).replace(tzinfo=datetime.timezone.utc)


def write_stream_file(session_name, scan_time, group_name, stream_name, events):
    if not events:
        return True
    stream_group_path = os.path.join('cloud_watch_logs', str(scan_time), group_name[1:])
    file_name = os.path.join(stream_group_path, stream_name.replace('/', '_') + '.csv')

    with save(file_name, 'a', newline='') as f:
        event_writer = csv.writer(f, delimiter=',')
        for event in events:
            event_writer.writerow([event['timestamp'], event['message']])
    return True


def collect_all(client, func, key, **kwargs):
    """Collects data and stores it in a list."""
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        out = response[key]
        while 'nextToken' in response:
            response = caller(**{'nextToken': response['nextToken'], **kwargs})
            out += response[key]
        return out
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print('AccessDenied for: {}'.format(func))
    return []


def millisecond(time_stamp):
    """Returns millisecond from timestamp"""
    return int(time_stamp.timestamp() * 1000 + time_stamp.microsecond / 1000)


def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    summary_data = {}


    if args.regions is None:
        regions = get_regions('logs')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    if isinstance(args.from_time, str):
        from_time = parse_time(args.from_time)
    else:
        from_time = DEFAULT_FROM_TIME
    if isinstance(args.to_time, str):
        to_time = parse_time(args.to_time)

    scan_time = int(datetime.datetime.now().timestamp())
    log_groups = {}
    for region in regions:
        print('Enumerating {}...'.format(region))
        client = pacu_main.get_boto3_client('logs', region)
        groups = collect_all(client, 'describe_log_groups', 'logGroups')
        if not groups:
            print('  No Log Groups found')
            continue
        else:
            print('  {} Log Groups found'.format(len(groups)))
        group_names = [group['logGroupName'] for group in groups]
        for group in group_names:
            log_groups[group] = {}

        for log_group in log_groups:
            streams = collect_all(
                client, 'describe_log_streams', 'logStreams',
                **{'logGroupName': log_group})
            log_groups[log_group] = [stream['logStreamName'] for stream in streams]
        if not streams:
            print(' No Streams found')
            continue
        else:
            stream_count = sum([len(log_groups[key]) for key in log_groups])
            print('  {} Streams found'.format(stream_count))
        event_count = 0
        for group in log_groups:
            for stream in log_groups[group]:
                start_time = millisecond(from_time)
                end_time = millisecond(to_time) if args.to_time else None
                kwargs = {
                    'logGroupName': group,
                    'logStreamNames': [stream],
                    'startTime': start_time,
                }
                if end_time:
                    kwargs['endTime'] = end_time

                paginator = client.get_paginator('filter_log_events')
                page_iterator = paginator.paginate(**kwargs)
                for response in page_iterator:
                    event_count += len(response['events'])
                    write_stream_file(
                        session.name, scan_time, group, stream,
                        response['events'])
                print('    Captured Events for {}'.format(stream))
        summary_data[region] = {
            'groups': len(log_groups),
            'streams': sum([len(log_groups[key]) for key in log_groups]),
            'events': event_count,
        }
    dl_root = str(downloads_dir()) + '/cloud_watch_logs/'
    summary_data['log_download_path'] = '{}{}'.format(dl_root, scan_time)
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'log_download_path' in data:
        out += 'Logs downloaded to: {}\n'.format(data['log_download_path'])
        del data['log_download_path']
    for region in data:
        out += '  {}:\n'.format(region)
        for key in data[region]:
            out += '    {}:{}\n'.format(key, data[region][key])
    return out
