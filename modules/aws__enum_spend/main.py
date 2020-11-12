#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import datetime


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'aws__enum_spend',

    # Name and any other notes about the author
    'author': 'Chris Farris <chris@room17.com>',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates account spend by service.',

    # Full description about what the module does and how it works
    'description': 'Display what services the account uses and how much is spent. Data is pulled from CloudWatch metrics and the AWS/Billing Namespace.',

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

    # All the billing seems to be in us-east-1. YMMV
    cwm_client = pacu_main.get_boto3_client('cloudwatch', "us-east-1")

    services = []
    service_spend = {}

    try:
        response = cwm_client.list_metrics(
            Namespace='AWS/Billing',
            MetricName='EstimatedCharges'
        )
        metrics = response['Metrics']
        for m in metrics:
            for d in m['Dimensions']:
                if d['Name'] == "ServiceName":
                    services.append(d['Value'])
        if len(services) == 0:
            print('\nNo services found. Unable to determine account spend.\n')
            return
    except ClientError as e:
        print("ClientError getting spend: {}".format(e))
        return({"error": "<unauthorized>"})

    for s in services:
        try:
            print("Retrieving metrics for service {}...".format(s))
            response = cwm_client.get_metric_statistics(
                Namespace='AWS/Billing',
                MetricName='EstimatedCharges',
                Dimensions=[
                    {
                        'Name': 'ServiceName',
                        'Value': s
                    },
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
                service_spend[s] = 0
            else:
                service_spend[s] = response['Datapoints'][0]['Maximum']
        except KeyError as e:
            print("KeyError getting spend: {} -- Response: {}".format(e, response))
        except IndexError as e:
            print("IndexError getting spend: {} -- Response: {}".format(e, response))
        except ClientError as e:
            print("ClientError getting spend: {}".format(e))

    session.update(pacu_main.database, AccountSpend=service_spend)

    return service_spend


def summary(data, pacu_main):
    out = "Account Spend:\n"
    for key in sorted(data.keys(), key=lambda x: data[x], reverse=True):
        out += "        {:<30}: {:>10.2f} (USD)\n".format(key, data[key])
    return out
