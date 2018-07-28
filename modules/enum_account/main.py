#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import datetime
from dateutil import tz

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_account',

    # Name and any other notes about the author
    'author': 'Chris Farris <chris@room17.com>',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates data About the account itself',

    # Full description about what the module does and how it works
    'description': 'Determines information about the AWS account itself',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--versions-all'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--versions-all', required=False, default=False, action='store_true', help='Grab all versions instead of just the latest')


# For when "help module_name" is called, don't modify this
def help():
    return [module_info, parser.format_help()]


# Main is the first function that is called when this module is executed
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######


    sts_client = pacu_main.get_boto3_client('sts')
    response = sts_client.get_caller_identity()
    key_arn = response['Arn']
    account_id = response['Account']

    iam_client = pacu_main.get_boto3_client('iam')
    response = iam_client.list_account_aliases()
    account_iam_alias = response['AccountAliases'][0]

    cwm_client = pacu_main.get_boto3_client('cloudwatch')
    try:
        response = cwm_client.get_metric_statistics(
            Namespace='AWS/Billing',
            MetricName='EstimatedCharges',
            Dimensions=[
                {
                    'Name': 'Currency',
                    'Value': 'USD'
                },
            ],
            StartTime=datetime.datetime.now() - datetime.timedelta(hours = 6),
            EndTime=datetime.datetime.now(),
            Period=21600, # 6 hours
            Statistics=['Maximum'],
            Unit='None'
        )
        if len(response['Datapoints']) == 0:
            account_spend = "unavailable"
        elif 'Maximum' not in response['Datapoints'][0]:
            account_spend = "unavailable"
        else:
            account_spend = response['Datapoints'][0]['Maximum']
    except ClientError as e:
        print("ClientError getting spend: {}".format(e))
        account_spend = "unavailable"

    org_client = pacu_main.get_boto3_client('organizations')
    org_response = org_client.describe_organization()
    org_data = org_response['Organization']


    print("Account Information:")
    print("\tAccount ID: {}".format(account_id))
    print("\tAccount IAM Alias: {}".format(account_iam_alias))
    print("\tKey Arn: {}".format(key_arn))
    print("\tAccount Spend: {} (USD)".format(account_spend))
    if org_data is not None:
        print("\tParent Account:")
        for k in org_data.keys():
            print("\t\t{}: {}".format(k, org_data[k]))

    account_data = {
        'account_id': account_id,
        'account_iam_alias': account_iam_alias,
        'account_total_spend': account_spend,
        'org_data': org_data
    }

    session.update(pacu_main.database, Account=account_data)

    print(f"{module_info['name']} completed.\n")
    return
