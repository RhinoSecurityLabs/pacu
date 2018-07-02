#!/usr/bin/env python3
import boto3, argparse, time, os, sys, botocore
from botocore.exceptions import ClientError
from copy import deepcopy
from functools import partial
from pacu import util

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_users_roles_policies_groups',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

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


def help():
    return [module_info, parser.format_help()]


def main(args, proxy_settings, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    input = partial(util.input, session_name=session.name, database=database)
    ######

    client = boto3.client(
        'iam',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if proxy_settings.target_agent is not None else None
    )

    if args.users == False and args.roles == False and args.policies == False and args.groups == False:
        args.users = args.roles = args.policies = args.groups = True
    if args.users == True:
        users = []
        response = None
        is_truncated = False
        try:
            while response is None or is_truncated == True:
                if is_truncated == False:
                    response = client.list_users()
                else:
                    response = client.list_users(
                        Marker=response['Marker']
                    )
                for user in response['Users']:
                    users.append(user)
                is_truncated = response['IsTruncated']
        except:
            print('The current user is not allowed to describe users.')
        iam_data = deepcopy(session.IAM)
        iam_data['Users'] = users
        session.update(database, IAM=iam_data)
        print(str(users))
    if args.roles == True:
        roles = []
        response = None
        is_truncated = False
        try:
            while response is None or is_truncated == True:
                if is_truncated == False:
                    response = client.list_roles()
                else:
                    response = client.list_roles(
                        Marker=response['Marker']
                    )
                for role in response['Roles']:
                    roles.append(role)
                is_truncated = response['IsTruncated']
        except:
            print('The current user is not allowed to describe roles.')
        iam_data = deepcopy(session.IAM)
        iam_data['Roles'] = roles
        session.update(database, IAM=iam_data)
        print(str(roles))
    if args.policies == True:
        policies = []
        response = None
        is_truncated = False
        try:
            while response is None or is_truncated == True:
                if is_truncated == False:
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
        except:
            print('The current user is not allowed to describe policies.')
        iam_data = deepcopy(session.IAM)
        iam_data['Policies'] = policies
        session.update(database, IAM=iam_data)
        print(str(policies))
    if args.groups == True:
        groups = []
        response = None
        is_truncated = False
        try:
            while response is None or is_truncated == True:
                if is_truncated == False:
                    response = client.list_groups()
                else:
                    response = client.list_groups(
                        Marker=response['Marker']
                    )
                for group in response['Groups']:
                    groups.append(group)
                is_truncated = response['IsTruncated']
        except:
            print('The current user is not allowed to describe groups.')
        iam_data = deepcopy(session.IAM)
        iam_data['Groups'] = groups
        session.update(database, IAM=iam_data)
        print(str(groups))

    print('\n{} completed.'.format(os.path.basename(__file__)))
    return
