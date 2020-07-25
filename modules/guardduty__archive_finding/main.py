#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import copy
import string
import random
import json
import math

module_info = {
    'name': 'guardduty__archive_finding',
    'author': 'Manas Bellani',
    'category': 'EVADE',
    'one_liner': 'Archive GuardDuty finding on a specified Guard-duty detector',
    'description': 'This module will archive a specific guard-duty finding by ID which should by default hide the finding from AWS console.',
    'services': ['GuardDuty'],
    'prerequisite_modules': ['detection__enum_services'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--detector', '--finding-id']
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--detector', required=True, 
    help='The detector ID from which the finding should be deleted')
parser.add_argument('--finding-ids', required=False, default=None, 
    help='Comma-separated list of GuardDuty finding IDs to archive')


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions

    # split comma-sep list to list
    finding_ids = args.finding_ids.split(",")

    # Prepare data to write info out to user
    data = {'detector': args.detector, 'finding_ids': finding_ids, 
            'success': False, 'detector_region': ''}
    
    # Get the detector info previously collected by the enum_services module
    regions = get_regions('GuardDuty')
    if fetch_data(['GuardDuty', 'Detectors'], module_info['prerequisite_modules'][0], '--guard-duty') is False:
        print('Pre-req module failed.')
        return
    detectors = copy.deepcopy(session.GuardDuty['Detectors'])

    # Get the region related to the detector
    detector_region = ""
    if detectors:
        for detector_info in detectors:
            if args.detector == detector_info["Id"]:
                detector_region = detector_info["Region"]
                data['detector_region'] = detector_region

    # Check if we have thee region for the detector
    if not detector_region:
        print("Detector: {} not found. Exiting.".format(detector_info))
        return data
    else:

        try:
            # Get the guard duty client for the detector's region
            client = pacu_main.get_boto3_client('guardduty', detector_region)

            # since we can only work with limited nummber of findings, we divide
            # findings into parts to archive
            num_findings_in_set = 50
            num_iters = math.ceil(
                len(finding_ids)/num_findings_in_set
            )
            
            for i in range(0, num_iters):
                lbound = i * num_findings_in_set
                ubound = (i+1) * num_findings_in_set

                # Attempt to archive the finding now
                response = client.archive_findings(
                    DetectorId=args.detector,
                    FindingIds=finding_ids[lbound:ubound]
                )

                data['success'] = True

        except Exception as error: 
            print('    Generic Error when archiving Guardduty finding on region: {}, detector: {}'.format(detector_region, args.detector))
            print('        Error: {}, {}'.format(error.__class__, str(error)))

    return data


def summary(data, pacu_main):
    if data['success']:
        msg = 'Attempts to archive following findings for detector: {detector}, region: {detector_region} successful!\n'.format(**data)
        # Print the list of findings processed 
        for finding_id in data['finding_ids']:
            msg += " "*4 + finding_id + "\n"
    else:
        msg = 'Attempts to archive findings for detector: {detector}, region: {detector_region} unsuccessful!\n'.format(**data)

    return msg
