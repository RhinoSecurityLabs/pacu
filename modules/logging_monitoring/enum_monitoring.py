#!/usr/bin/env python3
import argparse
import boto3
from copy import deepcopy
from functools import partial
import os

from pacu import util


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_logging_monitoring',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Detects monitoring and logging capabilities.',

    # Description about what the module does and how it works
    'description': 'This module will enumerate the different logging and monitoring capabilities that have been implemented in the current AWS account. By default the module will enumerate all services that it supports, but by specifying the individual parameters, it is possible to target specific services. The supported services include CloudTrail, Shield, and GuardDuty.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['GuardDuty', 'CloudTrail', 'Shield'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--vpc', '--config', '--cloud-trail', '--cloud-watch', '--waf', '--shield', '--guard-duty'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--cloud-trail', required=False, default=False, action='store_true', help='Enumerate CloudTrail logging implementations.')
parser.add_argument('--shield', required=False, default=False, action='store_true', help='Enumerate Shield DDoS rules.')
parser.add_argument('--guard-duty', required=False, default=False, action='store_true', help='Enumerate GuardDuty security implementations.')


def help():
    return [module_info, parser.format_help()]


def main(args, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    get_regions = partial(util.get_regions, database=database)
    ######

    all = False
    if args.cloud_trail is False and args.shield is False and args.guard_duty is False:
        all = True

    if all is True or args.shield is True:
        print('Starting Shield...')
        client = boto3.client(
            'shield',
            region_name='us-east-1',
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token
        )

        subscription = client.get_subscription_state()

        if subscription == 'ACTIVE':
            time_period = client.describe_subscription()
            shield_data = deepcopy(session.Shield)
            shield_data['AdvancedProtection'] = True
            shield_data['StartTime'] = time_period['Subscription']['StartTime']
            shield_data['TimeCommitmentInDays'] = time_period['Subscription']['TimeCommitmentInSeconds'] / 60 / 60 / 24
            session.update(database, Shield=shield_data)
            print(f"    Advanced (paid) DDoS protection enabled through AWS Shield.\n      Subscription Started: {session.Shield['StartTime']}\nSubscription Commitment: {session.Shield['TimeCommitmentInDays']} days")

        else:
            shield_data = deepcopy(session.Shield)
            shield_data['AdvancedProtection'] = False
            session.update(database, Shield=shield_data)
            print('    Standard (default/free) DDoS protection enabled through AWS Shield.')

    if all is True or args.cloud_trail is True:
        print('Starting CloudTrail...')
        cloudtrail_regions = get_regions('cloudtrail')
        all_trails = []

        for region in cloudtrail_regions:
            print(f'  Starting region {region}...')

            client = boto3.client(
                'cloudtrail',
                region_name=region,
                aws_access_key_id=session.access_key_id,
                aws_secret_access_key=session.secret_access_key,
                aws_session_token=session.session_token
            )

            trails = client.describe_trails(
                includeShadowTrails=False
            )
            print(f"    {len(trails['trailList'])} trails found.")

            for trail in trails['trailList']:
                trail['Region'] = region
                all_trails.append(trail)

        cloudtrail_data = deepcopy(session.CloudTrail)
        cloudtrail_data['Trails'] = all_trails
        session.update(database, CloudTrail=cloudtrail_data)
        print(f"  {len(session.CloudTrail['Trails'])} total CloudTrail trails found.\n")

    if all is True or args.guard_duty is True:
        print('Starting GuardDuty...')
        guard_duty_regions = get_regions('guardduty')
        all_detectors = []

        for region in guard_duty_regions:
            detectors = []
            print(f'  Starting region {region}...')

            client = boto3.client(
                'guardduty',
                region_name=region,
                aws_access_key_id=session.access_key_id,
                aws_secret_access_key=session.secret_access_key,
                aws_session_token=session.session_token
            )

            response = client.list_detectors()

            for detector in response['DetectorIds']:
                detectors.append({
                    'Id': detector,
                    'Region': region
                })

            while 'NextToken' in response:
                response = client.list_detectors(
                    NextToken=response['NextToken']
                )

                for detector in response['DetectorIds']:
                    detectors.append({
                        'Id': detector,
                        'Region': region
                    })

            print(f'    {len(detectors)} GuardDuty Detectors found.')
            all_detectors.extend(detectors)

        guardduty_data = deepcopy(session.GuardDuty)
        guardduty_data['Detectors'] = all_detectors
        session.update(database, GuardDuty=guardduty_data)
        print(f"  {len(session.GuardDuty['Detectors'])} total GuardDuty Detectors found.\n")

    print(f'{os.path.basename(__file__)} completed.')
    return
