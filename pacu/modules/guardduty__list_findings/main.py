#!/usr/bin/env python3
import argparse
from pathlib import Path

from botocore.exceptions import ClientError
import copy
import string
import random
import json
import math
import time

module_info = {
    'name': 'guardduty__list_findings',
    'author': 'Manas Bellani',
    'category': 'ENUM',
    'one_liner': 'Gets the guard-duty statistics and finding details from all Guard-duty detectors.',
    'description': (
        'This module lists all the GuardDuty Findings available from the AWS console for each identified detector. It '
        'requires that pre-req module has been run first to ensure that all detectors for which findings need to be pulled '
        'have been populated. The results are written to ~/.local/share/pacu/sessions/<session>/guardduty/.'
    ),
    'services': ['GuardDuty'],
    'prerequisite_modules': ['detection__enum_services'],
    'external_dependencies': [],
    'arguments_to_autocomplete': []
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions

    # Prepare output file to write guardduty findings results
    now = time.time()
    out_file = Path('sessions/{}/downloads/guardduty/list_findings_{}.json'.format(session.name, now))

    # Store all the data in this
    data = {
        'detectors': {},
        'findings': {},
        'finding_details': {},
        'severity_count_map': {}
    }

    # Get all the regions that GuardDuty runs in
    regions = get_regions('GuardDuty')

    # Get the list of all detectors
    if fetch_data(['GuardDuty', 'Detectors'], module_info['prerequisite_modules'][0], '--guard-duty') is False:
        print('Pre-req module failed.')
        return
    detectors = copy.deepcopy(session.GuardDuty['Detectors'])

    # Loop through each region for guardduty detectors
    for region in regions:
        client = pacu_main.get_boto3_client('guardduty', region)

        # Get the detectors for each region
        for detector in detectors:
            if detector['Region'] == region:
                detector_id = detector['Id']
                print(' ({}) Detector {}:'.format(region, detector_id))
                data['detectors'][detector_id] = region

                try:
                    # Get the statistics of number of findings
                    response = client.get_findings_statistics(
                        DetectorId=detector_id,
                        FindingStatisticTypes=['COUNT_BY_SEVERITY']
                    )

                    # Get the raw severity to count map
                    if 'FindingStatistics' in response and 'CountBySeverity' in response['FindingStatistics']:
                        severity_count_map = json.dumps(response['FindingStatistics']['CountBySeverity'])

                        # Print the severity map properly formatted
                        data['severity_count_map'][detector_id] = severity_count_map
                        print('    Obtained Guardduty severity to count map for detector id, {}:\n{}'.format(detector_id, severity_count_map))
                        print('        Guardduty values range between 0.1-8.9. Typically, 0.1-3.9 are LOW, 4.0-6.9 are MED, 7.0-8.9 are HIGH')
                        print('        Refer for more info: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity')
                    else:
                        data['severity_count_map'] = ''
                        print('    Something went wrong getting Guardduty stats for region: {}, detector: {}'.format(region, detector_id))
                        print('        Raw response: {}'.format(str(data)))

                    # Collect the finding IDs via multiple iterations
                    data['findings'][detector_id] = []
                    next_token = ''
                    i = 0
                    while i == 0 or next_token:
                        response = client.list_findings(
                            DetectorId=detector_id,
                            NextToken=next_token
                        )

                        # Parse finding IDs
                        if 'FindingIds' in response:
                            finding_ids = response['FindingIds']
                            data['findings'][detector_id].extend(finding_ids)

                        # Get the next token if available
                        if 'NextToken' in response:
                            next_token = response['NextToken']

                        # Next iteration
                        i += 1

                    # Display the user number of finding IDs collected
                    num_findings = len(data['findings'][detector_id])
                    if num_findings > 0:
                        print('Number of findings for detector_id, {}: {}'.format(detector_id, num_findings))
                        print('Getting more details about each finding')

                    # Determining number of iterations to use to get information
                    findings_set_len = 10
                    num_iters = math.ceil(num_findings/findings_set_len)
                    print('Number of iterations for detector_id, {} to get all findings: {}'.format(detector_id, num_iters))

                    # Get brief information on each of the findings obtained in
                    # bunch of 'findings_set_len' findings
                    data['finding_details'][detector_id] = []
                    for i in range(0, num_iters):
                        print('Iterating {}th time to get findings info for detector_id: {}'.format(
                                i+1,
                                detector_id
                            )
                        )

                        # Split findings to get into a group
                        lbound = i * findings_set_len
                        ubound = (i+1) * findings_set_len
                        findings_to_get = data['findings'][detector_id][lbound:ubound]

                        # Get more info about all the findings
                        response = client.get_findings(
                            DetectorId=detector_id,
                            FindingIds=findings_to_get
                        )

                        # Parse all the findings
                        if 'Findings' in response:
                            for finding_detail in response['Findings']:
                                if finding_detail:
                                    finding_id = finding_detail['Id'],
                                    data['finding_details'][detector_id].append(
                                        {
                                            'id': finding_id[0],
                                            'type': finding_detail['Type'],
                                            'title': finding_detail['Title'],
                                            'sev': finding_detail['Severity'],
                                            'count': finding_detail['Service']['Count'],
                                            'detector': detector_id,
                                            'region': region
                                        }
                                    )

                except Exception as error:
                    print('    Generic Error collecting GuardDuty stats for region: {}, detector: {}'.format(region, detector_id))
                    print('        Error: {}, {}'.format(error.__class__, str(error)))

    print("Writing ALL findings to JSON output file: {}".format(str(out_file)))
    out_file.parent.mkdir(exist_ok=True, parents=True)
    out_file.write_text(json.dumps(data, indent=4, default=str))

    return data


def summary(data, pacu_main):
    msg = 'Stats presented for {} GuardDuty Detector(s).\n'.format(len(data['detectors']))
    for detector_id, finding_ids in data['findings'].items():
        num_findings = len(finding_ids)
        detector_region = data['detectors'][detector_id]
        msg += 'Number of findings presented for detector, {}, in region, {}, is: {}\n'.format(
            detector_id,
            detector_region,
            num_findings
        )

    return msg

