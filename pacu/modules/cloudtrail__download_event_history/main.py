#!/usr/bin/env python3
import argparse
import json
import time

from pacu.core.lib import strip_lines, save, downloads_dir
from pacu import Main

module_info = {
    'name': 'cloudtrail__download_event_history',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'EVADE',
    'one_liner': 'Downloads CloudTrail event history to JSON files.',
    'description': strip_lines('''
        This module will download the CloudTrail event history for each specified region in both JSON format to 
        ~/.local/share/pacu/sessions/[current_session_name]/downloads/cloudtrail_[region]_event_history_[timestamp].json.
        Warning: This module can take a very long time to complete because the maximum events per API call is 50, when 
        there could be tens or hundreds of thousands or more total events to download. A rough estimate is about 10000
        events retrieved per five minutes.
    '''),
    'services': ['CloudTrail'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')


def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print

    get_regions = pacu_main.get_regions
    ######
    summary_data = {}
    if args.regions is None:
        regions = get_regions('cloudtrail')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    for region in regions:
        events = []
        print('Downloading logs from {}:'.format(region))
        print(' This may take a while...')
        client = pacu_main.get_boto3_client('cloudtrail', region)

        event_history = client.lookup_events(
            MaxResults=50,
        )
        events += event_history['Events']

        while 'NextToken' in event_history:
            print('  Processing additional results...')
            event_history = client.lookup_events(
                MaxResults=50,
                NextToken=event_history['NextToken']
            )
            events += event_history['Events']

        summary_data[region] = len(events)
        print('Finished enumerating {}'.format(region))

        now = time.time()
        filename = 'cloudtrail_{}_event_history_{}.json'.format(region, now)
        with save(filename) as f:
            json.dump(events, f, indent=2, default=str)
        print('  Events written to {}/cloudtrail_{}_event_history_{}.json'.format(downloads_dir(), region, now))

    return summary_data


def summary(data, pacu_main):
    out = ''
    for region in data:
        out += '  {} Event(s) found for {}.\n'.format(data[region], region)
    return out
