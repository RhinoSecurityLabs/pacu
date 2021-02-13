#!/usr/bin/env python3
import argparse
import json
import time


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'cloudtrail__download_event_history',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'EVADE',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Downloads CloudTrail event history to JSON files.',

    # Description about what the module does and how it works
    'description': 'This module will download the CloudTrail event history for each specified region in both JSON format to ./sessions/[current_session_name]/downloads/cloudtrail_[region]_event_history_[timestamp].json. Warning: This module can take a very long time to complete because the maximum events per API call is 50, when there could be tens or hundreds of thousands or more total events to download. A rough estimate is about 10000 events retrieved per five minutes.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['CloudTrail'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')


def main(args, pacu_main):
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
        with open('sessions/{}/downloads/cloudtrail_{}_event_history_{}.json'.format(session.name, region, now), 'w+') as json_file:
            json.dump(events, json_file, indent=2, default=str)
        print('  Events written to ./sessions/{}/downloads/cloudtrail_{}_event_history_{}.json'.format(session.name, region, now))

    return summary_data


def summary(data, pacu_main):
    out = ''
    for region in data:
        out += '  {} Event(s) found for {}.\n'.format(data[region], region)
    return out
