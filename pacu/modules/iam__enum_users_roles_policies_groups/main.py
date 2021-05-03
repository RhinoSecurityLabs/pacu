#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'iam__enum_users_roles_policies_groups',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates users, roles, customer-managed policies, and groups.',

    # Description about what the module does and how it works
    'description': 'This module requests the info for all users, roles, customer-managed policies, and groups in the account. If no arguments are supplied, it will enumerate all four, if any are supplied, it will enumerate those only.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--users', '--roles', '--policies', '--groups'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--users', required=False, action='store_true', help='Enumerate info for users in the account')
parser.add_argument('--roles', required=False, action='store_true', help='Enumerate info for roles in the account')
parser.add_argument('--policies', required=False, action='store_true', help='Enumerate info for policies in the account')
parser.add_argument('--groups', required=False, action='store_true', help='Enumerate info for groups in the account')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    ######
    summary_data = {}
    client = pacu_main.get_boto3_client('iam')

    if args.users is False and args.roles is False and args.policies is False and args.groups is False:
        args.users = args.roles = args.policies = args.groups = True

    if args.users is True:
        users = []
        response = None
        is_truncated = False

        try:
            while response is None or is_truncated is True:
                if is_truncated is False:
                    response = client.list_users()

                else:
                    response = client.list_users(
                        Marker=response['Marker']
                    )

                for user in response['Users']:
                    users.append(user)

                is_truncated = response['IsTruncated']

            print('Found {} users'.format(len(users)))
        except ClientError:
            print('No Users Found')
            print('  FAILURE: MISSING NEEDED PERMISSIONS')

        iam_data = deepcopy(session.IAM)
        iam_data['Users'] = users
        session.update(pacu_main.database, IAM=iam_data)
        summary_data['Users'] = len(users)

    if args.roles is True:
        roles = []
        response = None
        is_truncated = False

        try:
            while response is None or is_truncated is True:
                if is_truncated is False:
                    response = client.list_roles()

                else:
                    response = client.list_roles(
                        Marker=response['Marker']
                    )

                for role in response['Roles']:
                    roles.append(role)

                is_truncated = response['IsTruncated']
            print('Found {} roles'.format(len(roles)))

        except ClientError:
            print('No Roles Found')
            print('  FAILURE: MISSING NEEDED PERMISSIONS')

        iam_data = deepcopy(session.IAM)
        iam_data['Roles'] = roles
        session.update(pacu_main.database, IAM=iam_data)
        summary_data['Roles'] = len(roles)

    if args.policies is True:
        policies = []
        response = None
        is_truncated = False

        try:
            while response is None or is_truncated is True:
                if is_truncated is False:
                    response = client.list_policies(
                        Scope='Local'
                    )

                else:
                    response = client.list_policies(
                        Scope='Local',
                        Marker=response['Marker']
                    )

                for policy in response['Policies']:
                    policies.append(policy)

                is_truncated = response['IsTruncated']
            print('Found {} policies'.format(len(policies)))

        except ClientError:
            print('No Policies Found')
            print('  FAILURE: MISSING NEEDED PERMISSIONS')

        iam_data = deepcopy(session.IAM)
        iam_data['Policies'] = policies
        session.update(pacu_main.database, IAM=iam_data)
        summary_data['Policies'] = len(policies)

    if args.groups is True:
        groups = []
        response = None
        is_truncated = False

        try:
            while response is None or is_truncated is True:

                if is_truncated is False:
                    response = client.list_groups()

                else:
                    response = client.list_groups(
                        Marker=response['Marker']
                    )

                for group in response['Groups']:
                    groups.append(group)

                is_truncated = response['IsTruncated']
            print('Found {} groups'.format(len(groups)))

        except ClientError:
            print('No Groups Found')
            print('  FAILURE: MISSING NEEDED PERMISSIONS')

        iam_data = deepcopy(session.IAM)
        iam_data['Groups'] = groups
        session.update(pacu_main.database, IAM=iam_data)
        summary_data['Groups'] = len(groups)

    return summary_data


def summary(data, pacu_main):
    out = ''
    for key in data:
        out += '  {} {} Enumerated\n'.format(data[key], key)
    out += '  IAM resources saved in Pacu database.\n'
    return out
