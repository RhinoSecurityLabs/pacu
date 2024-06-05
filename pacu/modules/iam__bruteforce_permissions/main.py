#!/usr/bin/env python3
import argparse
import os
import sys
from copy import deepcopy
from pacu.core.enumerate_iam.main import enumerate_iam

module_info = {
    'name': 'iam__bruteforce_permissions',
    'author': 'Rhino Security Labs',
    'category': 'ENUM',
    'one_liner': 'Enumerates permissions using brute force',
    'description': "This module will automatically run through all possible API calls of supported services in order to enumerate permissions. This uses the 'enumerate-iam' library by Andres Riancho.",
    'services': ['all'],
    'prerequisite_modules': [],
    'external_dependencies': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print

    aws_key = session.get_active_aws_key(pacu_main.database)

    access_key = aws_key.access_key_id
    secret_key = aws_key.secret_access_key
    session_token = aws_key.session_token if aws_key.session_token else None
    region = 'us-east-1'  # You can change this to the desired region

    # Call the enumerate_iam function from the enumerate-iam library
    results = enumerate_iam(
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        region=region
    )

    # Process and print the results
    print('Enumerated IAM Permissions:')
    for service, actions in results.items():
        print(f'{service}:')
        for action, status in actions.items():
            print(f'  {action}: {status}')

    # Write all the data to the Pacu DB for storage
    iam_data = deepcopy(session.IAM)
    for key, value in results.items():
        if key in iam_data:
            iam_data[key].update(value)
        else:
            iam_data[key] = value
    session.update(pacu_main.database, IAM=iam_data)

    return results

def summary(data, pacu_main):
    out = ""

    total_permissions = 0
    for service in data['bruteforce']:
        total_permissions += len(data['bruteforce'][service])
    out += "Num of IAM permissions found: {} \n".format(total_permissions)
    return out