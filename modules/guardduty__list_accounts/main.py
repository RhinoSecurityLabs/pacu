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
    'one_liner': 'List GuardDuty master account, and other accounts that are linked to Guardduty which can provide us more lateral movement scope',
    'description': 'This module list accounts that are linked to the current GuardDuty account which provides list of more accounts that we can laterally move into. The module also determines the master account that acts as the administration account for guardduty, and also any other accounts within the organization',
    'services': ['GuardDuty'],
    'prerequisite_modules': ['detection__enum_services'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='The set of regions to enumerate GuardDuty in (defaults to all session regions).')


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions

    data = {'detectors': [], 'guardduty_accounts_info': {}}

    
    regions = get_regions('GuardDuty')
    if fetch_data(['GuardDuty', 'Detectors'], module_info['prerequisite_modules'][0], '--guard-duty') is False:
        print('Pre-req module failed.')
        return
    detectors = copy.deepcopy(session.GuardDuty['Detectors'])

    # To get to each
    next_token = None

    for region in regions:

        # Get the guardduty client for the region
        client = pacu_main.get_boto3_client('guardduty', region)
        for detector in detectors:


             # Get the detector and region for each detector
            if detector['Region'] == region:
                detector_id = detector['Id']

                print(' ({}) Detector {}:'.format(region, detector_id))
                data['detectors'].append(detector_id)
                try:

                    # Enumerate accounts in each region
                    print("List member accounts for region: {}, detector: {}".format(region, detector_id))
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
                            response = client.list_members(
                                DetectorId=detector_id,
                                MaxResults=50,
                                OnlyAssociated="false"
                            )
                        
                        # Get the next set of member accounts
                        if 'NextToken' in response:
                            next_token = response['NextToken']
                        else:
                            finished_getting_accounts = True

                        if 'Members' in response:
                            if len(response['Members']) > 0:
                                print(json.dumps(response['Members'], indent=4))
                            else:
                                print("    No Member accounts found for region: {}, detector: {}".format(region, detector_id))
                        else:
                            print("    No Member accounts found for region: {}, detector: {}".format(region, detector_id))
                        #data['guardduty_accounts_info'][detector] = response 

                except Exception as err:
                    print("Exception listing GuardDuty member accounts for region: {}, detector: {}".format(region, detector_id)) 
                    print("    Error: {}, {}".format(err.__class__, str(err)))
                

                # Listing the guardduty organizational admin accounts
                try:
                    finished_getting_accounts = False
                    next_token = None
                    while not finished_getting_accounts:
                        print("Determine the organizational AdminAccounts for region: {}, detector ID: {}".format(region, detector_id))
                        if next_token:
                            response = client.list_organization_admin_accounts(
                                NextToken=next_token,
                                MaxResults=50
                            )
                        else:
                            response = client.list_organization_admin_accounts(
                                MaxResults=50
                            )

                        if 'AdminAccounts' in response:
                            print("    AdminAccounts Account for region: {}, detector: {}".format(region, detector_id))
                            print(json.dumps(response['AdminAccounts'], indent=4))
                        else:
                            print("   No AdminAccounts account found for region: {}, detector: {}".format(region, detector_id))

                        # check if we need to get the next token for more accounts 
                        if 'NextToken' in response: 
                            next_token = response['NextToken']
                        else:
                            finished_getting_accounts = True

                except Exception as err:
                    print("Exception determining GuardDuty Organizational AdminAccounts for region: {}, detector: {}".format(region, detector_id)) 
                    print("    Error: {}, {}".format(err.__class__, str(err)))


                # List the guardduty master account
                try:
                    print("Determine the master account for region: {}, detector ID: {}".format(region, detector_id))
                    response = client.get_master_account(
                        DetectorId=detector_id
                    )

                    if 'Master' in response:
                        print(json.dumps(response['Master'], indent=4))
                    else:
                        print("   No Master account found for region: {}, detector: {}".format(region, detector_id))

                except Exception as err:
                    print("Exception determining GuardDuty master account for region: {}, detector: {}".format(region, detector_id)) 
                    print("    Error: {}, {}".format(err.__class__, str(err)))    

                
                # List any guardduty invitations that contain details of other accounts
                try:
                    finished_getting_invites = False
                    next_token = None
                    while not finished_getting_invites:
                        print("Determine the invitations for region: {}, detector ID: {}".format(region, detector_id))
                        if next_token:
                            response = client.list_invitations(
                                NextToken=next_token,
                                MaxResults=50
                            )
                        else:
                            response = client.list_invitations(
                                MaxResults=50
                            )

                        if 'Invitations' in response:
                            print("    GuardDuty Invitations for region: {}, detector: {}".format(region, detector_id))
                            print(json.dumps(response['Invitations'], indent=4))
                        else:
                            print("    No GuardDuty invitations for region: {}, detector: {}".format(region, detector_id))

                        # check if we need to get the next token for more accounts 
                        if 'NextToken' in response: 
                            next_token = response['NextToken']
                        else:
                            finished_getting_invites = True

                except Exception as err:
                    print("Exception determining GuardDuty Organizational AdminAccounts for region: {}, detector: {}".format(region, detector_id)) 
                    print("    Error: {}, {}".format(err.__class__, str(err)))


    return data


def summary(data, pacu_main):
    return 'Guardduty member account for each region: {}'.format(data['guardduty_accounts_info'])
