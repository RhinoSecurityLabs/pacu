#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import datetime


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'aws__enum_account',

    # Name and any other notes about the author
    'author': 'Chris Farris <chris@room17.com>',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates data About the account itself.',

    # Full description about what the module does and how it works
    'description': 'Determines information about the AWS account itself.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


# Main is the first function that is called when this module is executed
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    ######

    sts_client = pacu_main.get_boto3_client('sts')
    response = sts_client.get_caller_identity()
    key_arn = response['Arn']
    account_id = response['Account']

    iam_client = pacu_main.get_boto3_client('iam')
    try:
        response = iam_client.list_account_aliases()
        account_iam_alias = response['AccountAliases'][0]
    except (KeyError, IndexError):
        account_iam_alias = "<No IAM Alias defined>"
    except ClientError as e:
        print("ClientError has occurred when getting AccountAliases: {}".format(e))
        account_iam_alias = "<NotFound>"

    print('Enumerating Account: {}'.format(account_iam_alias))
    # All the billing seems to be in us-east-1. YMMV
    cwm_client = pacu_main.get_boto3_client('cloudwatch', "us-east-1")
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
            StartTime=datetime.datetime.now() - datetime.timedelta(hours=6),
            EndTime=datetime.datetime.now(),
            Period=21600,  # 6 hours
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
        if e.response['Error']['Code'] == "AccessDenied":
            account_spend = "<unauthorized>"
        else:
            print("Unable to get Spend Data: {}".format(e))
            account_spend = "<ClientError>"

    try:
        org_client = pacu_main.get_boto3_client('organizations')
        org_response = org_client.describe_organization()
        org_data = org_response['Organization']
    except ClientError as e:
        org_data = {}
        if e.response['Error']['Code'] == "AccessDeniedException":
            org_data['error'] = "Not Authorized to get Organization Data"
        else:
            print("Unable to get Organization Data: {}".format(e))
            org_data['error'] = "Error Getting Organization Data"

    account_data = {
        'account_id': account_id,
        'account_iam_alias': account_iam_alias,
        'account_total_spend': account_spend,
        'org_data': org_data
    }

    session.update(pacu_main.database, Account=account_data)

    summary_data = {
        'key_arn': key_arn,
        **account_data
    }
    return summary_data


def summary(data, pacu_main):
    out = "Account Information:\n"
    out += "    Account ID: {}\n".format(data['account_id'])
    out += "    Account IAM Alias: {}\n".format(data['account_iam_alias'])
    out += "    Key Arn: {}\n".format(data['key_arn'])
    out += "    Account Spend: {} (USD)\n".format(data['account_total_spend'])
    if data.get('org_data', None) is not None:
        out += "    Parent Account:\n"
        for key in data['org_data'].keys():
            out += "        {}: {}\n".format(key, data['org_data'][key])
    return out
