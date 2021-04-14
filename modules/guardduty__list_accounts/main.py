#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import copy
import string
import random
import json

module_info = {
    'name': 'guardduty__list_accounts',
    'author': 'Manas Bellani',
    'category': 'ENUM',
    'one_liner': (
        'List GuardDuty master account, and other accounts that are linked to GuardDuty which can provide us more lateral '
        'movement scope'
    ),
    'description': (
        'This module list accounts that are linked to the current GuardDuty account which provides list of more accounts that '
        'we can laterally move into. The module also determines the master account that acts as the administration account '
        'for GuardDuty, and also any other accounts within the organization'
    ),
    'services': ['GuardDuty'],
    'prerequisite_modules': ['detection__enum_services'],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='The set of regions to enumerate GuardDuty in (defaults '
                                                                    'to all session regions).')


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions

    data = {'detectors': [], 'accounts': []}

    
    regions = args.regions or get_regions('GuardDuty')
    if fetch_data(['GuardDuty', 'Detectors'], module_info['prerequisite_modules'][0], '--guard-duty') is False:
        print('Pre-req module failed.')
        return
    detectors = copy.deepcopy(session.GuardDuty['Detectors'])

    # To get to each
    next_token = None

    for detector in detectors:
        region = detector['Region']
        detector_id = detector['Id']

        if region not in regions:
            print(f"Skipping {detector_id} in ignored region (to change this use set_regions or pass --region to this module)")
            continue

        # Get the guardduty client for the region
        client = pacu_main.get_boto3_client('guardduty', region)

        print(' ({}) Detector {}:'.format(region, detector_id))
        data['detectors'].append(detector_id)
        try:

            # Enumerate accounts in each region
            finished_getting_accounts = False
            while not finished_getting_accounts:

                # Make the request to get the member accounts
                if next_token:
                    response = client.list_members(
                        DetectorId=detector_id,
                        MaxResults=50,
                        NextToken=next_token,
                        OnlyAssociated="false"
                    )
                else:
                    response = client.list_members(DetectorId=detector_id, MaxResults=50, OnlyAssociated="false")

                # Get the next set of member accounts
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    finished_getting_accounts = True

                if 'Members' in response and len(response['Members']) > 0:
                    print(f"    Found member accounts for {detector_id}:")
                for member in response.get('Members', []):
                    print(f"    MemberAccount: {member['AccountId']}, MasterAccount: {member['MasterId']}")
                    data['accounts'].extend([member['AccountId'], member['MasterId']])

        except Exception as err:
            if 'not owned by the current account' not in err.args[0]:
                print("Exception listing GuardDuty member accounts for region: {}, detector: {}".format(region, detector_id))
                print("    Error: {}, {}".format(err.__class__, str(err)))


        # Listing the guardduty organizational admin accounts
        try:
            finished_getting_accounts = False
            next_token = None
            while not finished_getting_accounts:
                if next_token:
                    response = client.list_organization_admin_accounts(NextToken=next_token, MaxResults=50)
                else:
                    response = client.list_organization_admin_accounts(MaxResults=50)

                if 'AdminAccounts' in response:
                    print(f"    Found GuardDuty Admin Account {response['AdminAccounts']}")
                    data['accounts'].append(response['AdminAccounts'])
                else:
                    print("   No AdminAccounts account found for region: {}, detector: {}".format(region, detector_id))

                # check if we need to get the next token for more accounts
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    finished_getting_accounts = True

        except Exception as err:
            # Can only be run from the master account.
            if 'because you are not the master account' not in err.args[0]:
                print("Exception determining GuardDuty Organizational AdminAccounts for region: {}, detector: {}".format(region, detector_id))
                print("    Error: {}, {}".format(err.__class__, str(err)))


        # List the guardduty master account
        try:
            response = client.get_master_account(DetectorId=detector_id)

            if 'Master' in response:
                print(f"    Found GuardDuty Master account: {response['Master']['AccountId']}")
                data['accounts'].append(response['Master']['AccountId'])
        except Exception as err:
            if 'not owned by the current account' not in err.args[0]:
                print("Exception determining GuardDuty master account for region: {}, detector: {}".format(region, detector_id))
                print("    Error: {}, {}".format(err.__class__, str(err)))

    return data


def summary(data, pacu_main):
    if not data['accounts']:
        return "No account ID's found"
    msg = ''
    msg += 'Accounts found:\n'
    for account in set(data['accounts']):
        msg += f"    {account}\n"
    return msg
