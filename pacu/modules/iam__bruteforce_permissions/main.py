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
parser.add_argument(
    '--region',
    required=False,
    default=None,
    help='The region to run the enumeration in (default: all regions)'
)

# List of attributes to exclude from permissions
EXCLUDED_ATTRIBUTES = ['arn', 'arn_id', 'arn_path', 'root_account']

def format_permission(action):
    """
    Format the permission to match AWS IAM action format.
    Converts dots to colons and snake_case to camelCase for the action part.
    Removes the "bruteforce:" prefix if present.
    """
    if action.startswith('bruteforce:'):
        action = action[len('bruteforce:'):]
    parts = action.split('.')
    if len(parts) > 1:
        service = parts[0]
        action_part = parts[1].split('_')
        formatted_action = action_part[0].capitalize() + ''.join(word.capitalize() for word in action_part[1:])
        return f'{service}:{formatted_action}'
    return action

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print

    aws_key = session.get_active_aws_key(pacu_main.database)

    access_key = aws_key.access_key_id
    secret_key = aws_key.secret_access_key
    session_token = aws_key.session_token if aws_key.session_token else None
    regions = args.region.split(',') if args.region else ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']  # You can add more regions as needed

    # Process and print the results
    allow_permissions = []
    deny_permissions = []

    print('Enumerated IAM Permissions:')
    for region in regions:
        client = pacu_main.get_boto3_client('apigateway', region)
        print(f"Enumerating {region}")

        try:
            results = enumerate_iam(
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                region=region
            )
        except Exception as e:
            print(f"Failed to enumerate IAM permissions in {region}: {e}")
            continue

        for service, actions in results.items():
            print(f'{service}:')
            for action, result in actions.items():
                print(f'  {action}: {result}')
                formatted_perm = format_permission(action)
                if result:  # If result is not empty or False, consider it allowed
                    allow_permissions.append(formatted_perm)
                else:
                    deny_permissions.append(formatted_perm)

    # Remove non-permission attributes
    allow_permissions = [perm for perm in allow_permissions if ':' in perm and perm.split(':', 1)[1] not in EXCLUDED_ATTRIBUTES]
    deny_permissions = [perm for perm in deny_permissions if ':' in perm and perm.split(':', 1)[1] not in EXCLUDED_ATTRIBUTES]

    # Update the active AWS key with the new permissions
    active_aws_key = session.get_active_aws_key(pacu_main.database)
    active_aws_key.update(
        pacu_main.database,
        allow_permissions=allow_permissions,
        deny_permissions=deny_permissions
    )

    # Write all the data to the Pacu DB for storage
    iam_data = deepcopy(session.IAM)
    if 'permissions' not in iam_data:
        iam_data['permissions'] = {}

    iam_data['permissions']['allow'] = allow_permissions
    iam_data['permissions']['deny'] = deny_permissions

    session.update(pacu_main.database, IAM=iam_data)

    # Prepare the summary data
    summary_data = {
        'allow': allow_permissions,
        'deny': deny_permissions,
    }

    return summary_data

def summary(data, pacu_main):
    out = ""

    total_permissions = len(data['allow'])
    out += "Num of IAM permissions found: {} \n".format(total_permissions)
    return out
