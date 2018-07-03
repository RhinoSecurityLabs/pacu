#!/usr/bin/env python3
import argparse
import boto3
import botocore
import json
import os


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'confirm_permissions',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality.
    # This shows up when a user searches for modules.
    'one_liner': 'Tries to get a confirmed list of permissions for the current user.',

    # Description about what the module does and how it works
    'description': 'This module will attempt to use IAM APIs to enumerate a confirmed list of IAM permissions for the current user. This is done by checking attached and inline policies for the user and the groups they are in.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself.
    # That way session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--all-users', '--user-name'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--all-users', required=False, default=False, action='store_true', help='Run this module against every user in the account and store the results to ./sessions/[current_session_name]/downloads/confirmed_permissions/[user_name].json. This data can then be run against the privesc_scan module with the --offline flag enabled.')
parser.add_argument('--user-name', required=False, default=None, help='A single username of a user to run this module against. By default, the user to which the active AWS keys belong to will be used.')
# parser.add_argument('--group-name', required=False, default=None, help='The name of a group to run this module against. By default, this module will be run against the user which the active AWS keys belong to.')
# parser.add_argument('--policy-name', required=False, default=None, help='The name of a specific policy to run this module against. By default, this module will be run against the user which the active AWS keys belong to.')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    proxy_settings = pacu_main.get_proxy_settings()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    ######

    client = boto3.client(
        'iam',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    )

    users = []
    if args.all_users is True:
        if fetch_data(['IAM', 'Users'], 'enum_users_roles_policies_groups', '--users') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        fetched_users = session.IAM['Users']
        for user in fetched_users:
            users.append({
                'UserName': user['UserName'],
                'PermissionsConfirmed': True,
                'Permissions': {
                    'Allow': {},
                    'Deny': {}
                }
            })
    elif args.user_name is not None:
        users.append({
            'UserName': args.user_name,
            'PermissionsConfirmed': True,
            'Permissions': {
                'Allow': {},
                'Deny': {}
            }
        })
    else:
        user = client.get_user()
        active_aws_key = session.get_active_aws_key(pacu_main.database)
        active_aws_key.update(
            pacu_main.database,
            user_name=user['User']['UserName'],
            user_arn=user['User']['Arn'],
            user_id=user['User']['UserId'],
        )
        user = key_info(alias=session.key_alias)
        user['PermissionsConfirmed'] = True
        if 'Permissions' not in user:
            user['Permissions'] = {'Allow': {}, 'Deny': {}}
        users.append(user)

    # list-groups-for-user
    # list-user-policies
    # list-group-policies
    # list-role-policies
    # list-attached-role-policies
    # list-attached-group-policies
    # list-attached-user-policies
    # get-policy
    # get-policy-version
    # get-user-policy
    # get-group-policy
    # get-role-policy

    for user in users:
        user['Groups'] = []
        user['Policies'] = []
        try:
            policies = []

            # Get groups that the user is in
            try:
                response = client.list_groups_for_user(
                    UserName=user['UserName']
                )
                user['Groups'] = response['Groups']
                while 'IsTruncated' in response and response['IsTruncated'] is True:
                    response = client.list_groups_for_user(
                        UserName=user['UserName'],
                        Marker=response['Marker']
                    )
                    user['Groups'] += response['Groups']
            except Exception as error:
                print(f'List groups for user failed: {error}')
                user['PermissionsConfirmed'] = False

            # Get inline and attached group policies
            for group in user['Groups']:
                group['Policies'] = []
                # Get inline group policies
                try:
                    response = client.list_group_policies(
                        GroupName=group['GroupName']
                    )
                    policies = response['PolicyNames']
                    while 'IsTruncated' in response and response['IsTruncated'] is True:
                        response = client.list_group_policies(
                            GroupName=group['GroupName'],
                            Marker=response['Marker']
                        )
                        policies += response['PolicyNames']
                except Exception as error:
                    print(f'List group policies failed: {error}')
                    user['PermissionsConfirmed'] = False

                # Get document for each inline policy
                for policy in policies:
                    group['Policies'].append({  # Add policies to list of policies for this group
                        'PolicyName': policy
                    })
                    try:
                        document = client.get_group_policy(
                            GroupName=group['GroupName'],
                            PolicyName=policy
                        )['PolicyDocument']
                    except Exception as error:
                        print(f'Get group policy failed: {error}')
                        user['PermissionsConfirmed'] = False
                    user = parse_document(document, user)

                # Get attached group policies
                attached_policies = []
                try:
                    response = client.list_attached_group_policies(
                        GroupName=group['GroupName']
                    )
                    attached_policies = response['AttachedPolicies']
                    while 'IsTruncated' in response and response['IsTruncated'] is True:
                        response = client.list_attached_group_policies(
                            GroupName=group['GroupName'],
                            Marker=response['Marker']
                        )
                        attached_policies += response['AttachedPolicies']
                    group['Policies'] += attached_policies
                except Exception as error:
                    print(f'List attached group policies failed: {error}')
                    user['PermissionsConfirmed'] = False
                user = parse_attached_policies(client, attached_policies, user)

            # Get inline user policies
            policies = []
            if 'Policies' not in user:
                user['Policies'] = []
            try:
                response = client.list_user_policies(
                    UserName=user['UserName']
                )
                policies = response['PolicyNames']
                while 'IsTruncated' in response and response['IsTruncated'] is True:
                    response = client.list_user_policies(
                        UserName=user['UserName'],
                        Marker=response['Marker']
                    )
                    policies += response['PolicyNames']
                for policy in policies:
                    user['Policies'].append({
                        'PolicyName': policy
                    })
            except Exception as error:
                print(f'List user policies failed: {error}')
                user['PermissionsConfirmed'] = False

            # Get document for each inline policy
            for policy in policies:
                try:
                    document = client.get_user_policy(
                        UserName=user['UserName'],
                        PolicyName=policy
                    )['PolicyDocument']
                except Exception as error:
                    print(f'Get user policy failed: {error}')
                    user['PermissionsConfirmed'] = False
                user = parse_document(document, user)

            # Get attached user policies
            attached_policies = []
            try:
                response = client.list_attached_user_policies(
                    UserName=user['UserName']
                )
                attached_policies = response['AttachedPolicies']
                while 'IsTruncated' in response and response['IsTruncated'] is True:
                    response = client.list_attached_user_policies(
                        UserName=user['UserName'],
                        Marker=response['Marker']
                    )
                    attached_policies += response['AttachedPolicies']
                user['Policies'] += attached_policies
            except Exception as error:
                print(f'List attached user policies failed: {error}')
                user['PermissionsConfirmed'] = False

            user = parse_attached_policies(client, attached_policies, user)

            if args.user_name is None and args.all_users is False:  # TODO: If this runs and gets all permissions, replace the current set under user['Permissions'] rather than add to it in this module
                active_aws_key.update(
                    pacu_main.database,
                    user_name=user['UserName'],
                    user_arn=user['UserArn'],
                    user_id=user['UserId'],
                    groups=user['Groups'],
                    policies=user['Policies'],
                    permissions_confirmed=user['PermissionsConfirmed'],
                    allow_permissions=user['Permissions']['Allow'],
                    deny_permissions=user['Permissions']['Deny']
                )
            else:
                if not os.path.exists(f'sessions/{session.name}/downloads/confirmed_permissions/'):
                    os.makedirs(f'sessions/{session.name}/downloads/confirmed_permissions/')

                with open(f"sessions/{session.name}/downloads/confirmed_permissions/{user['UserName']}.json", 'w+') as user_permissions_file:
                    json.dump(user, user_permissions_file, indent=2, default=str)

                print(f"User details stored in ./sessions/{session.name}/downloads/confirmed_permissions/{user['UserName']}.json")

        except Exception as error:
            print(f"Error, skipping user {user['UserName']}:\n{error}")

    print(f"{module_info['name']} completed.\n")
    return


def parse_attached_policies(client, attached_policies, user):
    """ Pull permissions from each policy document. """
    for policy in attached_policies:
        document = get_attached_policy(client, policy['PolicyArn'])
        if document is False:
            user['PermissionsConfirmed'] = False
        else:
            user = parse_document(document, user)
    return user


def get_attached_policy(client, policy_arn):
    """ Get the policy document of an attached policy. """
    try:
        policy = client.get_policy(
            PolicyArn=policy_arn
        )['Policy']
        version = policy['DefaultVersionId']
        can_get = True
    except Exception as error:
        print(f'Get policy failed: {error}')
        return False

        # NOTE: If v1, v2, and v3 exist, then v2 is deleted, the next version will be v4 still, so this WILL error currently
        # print('Attempting to enumerate the default version...')
        # can_get = False

    try:
        if can_get is True:
            document = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )['PolicyVersion']['Document']
            return document

        # else:  # If the user can't run get_policy, try to run get_policy_version to enumerate the default version
        #     for version in ['v1', 'v2', 'v3', 'v4', 'v5']:  # This won't error because it will return the default version before fetching a non-existent version
        #         policy_version = client.get_policy_version(
        #             PolicyArn=policy_arn,
        #             VersionId=version
        #         )['PolicyVersion']
        #         if policy_version['IsDefaultVersion'] is True:
        #             return policy_version['Document']

    except Exception as error:
        print(f'Get policy version failed: {error}')
        return False


def parse_document(document, user):
    """ Loop permissions and the resources they apply to """
    if type(document['Statement']) is dict:
        document['Statement'] = [document['Statement']]

    for statement in document['Statement']:

        if statement['Effect'] == 'Allow':

            if 'Action' in statement and type(statement['Action']) is list:  # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][action] = [statement['Resource']]
                    user['Permissions']['Allow'][action] = list(set(user['Permissions']['Allow'][action]))  # Remove duplicate resources

            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']] = [statement['Resource']]  # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['Action']] = list(set(user['Permissions']['Allow'][statement['Action']]))  # Remove duplicate resources

            if 'NotAction' in statement and type(statement['NotAction']) is list:  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action] = [statement['Resource']]
                    user['Permissions']['Deny'][not_action] = list(set(user['Permissions']['Deny'][not_action]))  # Remove duplicate resources

            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']] = [statement['Resource']]  # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['NotAction']] = list(set(user['Permissions']['Deny'][statement['NotAction']]))  # Remove duplicate resources

        if statement['Effect'] == 'Deny':

            if 'Action' in statement and type(statement['Action']) is list:
                statement['Action'] = list(set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][action] = [statement['Resource']]
                    user['Permissions']['Deny'][action] = list(set(user['Permissions']['Deny'][action]))  # Remove duplicate resources

            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']] = [statement['Resource']]  # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['Action']] = list(set(user['Permissions']['Deny'][statement['Action']]))  # Remove duplicate resources

            if 'NotAction' in statement and type(statement['NotAction']) is list:  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action] = [statement['Resource']]
                    user['Permissions']['Allow'][not_action] = list(set(user['Permissions']['Allow'][not_action]))  # Remove duplicate resources

            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']] = [statement['Resource']]  # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['NotAction']] = list(set(user['Permissions']['Allow'][statement['NotAction']]))  # Remove duplicate resources

    return user
