#!/usr/bin/env python3
import argparse
import botocore
import sys


module_info = {
    'name': 'enum_account_ids',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'recon_enum_no_keys',

    'one_liner': 'Enumerates account IDs of existing AWS accounts.',

    'description': 'This module takes in either a list of account IDs or an account ID starting point and a count to try and enumerate existing AWS account IDs. It does so by trying to update the AssumeRole policy document of the role that you pass into --role-name. For your safety, it updates the policy with an explicit deny against the AWS account, so that no security holes are opened in your account during enumeration. NOTE: It is recommended to use personal AWS access keys for this script, as it will spam CloudTrail with "iam:UpdateAssumeRolePolicy" logs. The target account will not see anything in their logs though! The keys used must have the iam:UpdateAssumeRolePolicy permission on the role that you pass into --role-name to be able to identify a valid AWS account ID.',

    'services': ['IAM'],

    'prerequisite_modules': [],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--role-name', '--count', '--starting-point', '--file']
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--role-name', required=True, help='The name of a valid role in the current users account to try and update the AssumeRole policy document for.')
parser.add_argument('--count', required=False, default=None, type=int, help='The number of sequential account IDs to guess. Use with --starting-point.')
parser.add_argument('--starting-point', required=False, default=None, type=str, help='The account ID to start guessing at. Use with --count.')
parser.add_argument('--file', required=False, default=None, help='Path to a file with account IDs to check for validity.')


def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print

    if args.count == args.starting_point == args.file == None:
        print('Error: --count and --starting-point are required, unless you pass in a file with --file.\n')
        return None
    elif args.file and (args.starting_point or args.count):
        print('Error: You cannot pass in --file along with --starting-point or --count.\n')
        return None
    elif not len(args.starting_point) == 12 or not args.starting_point.isdigit():
        print('Error: An AWS account ID is a number of length 12. You supplied: {}\n'.format(args.starting_point))
        return None

    data = {
        'attempts': 0,
        'valid_accounts': []
    }

    print('Starting account ID enumeration...\n')

    client = pacu_main.get_boto3_client('iam')

    if args.file:
        with open('{}'.format(args.file), 'r') as f:
            imported_guesses = f.readlines()
        imported_guesses = [x.strip() for x in imported_guesses]
        for current_guess in imported_guesses:
            data['attempts'] += 1
            data['valid_accounts'].extend(guess(client, args.role_name, current_guess))
    else:
        for n in range(0, args.count):
            data['attempts'] += 1
            current_guess = str(int(args.starting_point) + n)

            # If the account ID starts with a 0, the int conversion will get rid of it, so add it/them back
            while len(current_guess) < 12:
                current_guess = '0{}'.format(current_guess)

            data['valid_accounts'].extend(guess(client, args.role_name, current_guess))

    if len(data['valid_accounts']) > 0:
        print('\nFound {} valid AWS account(s):\n'.format(len(data['valid_accounts'])))
        for aid in data['valid_accounts']:
            print('    {}'.format(aid))

    print('{} completed.\n'.format(module_info['name']))
    return data


def guess(client, role_name, current_guess):
    valid_accounts = []
    root_arn = 'arn:aws:iam::{}:root'.format(current_guess)
    try:
        client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument='{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"{}"}},"Action":"sts:AssumeRole"}}]}}'.format(root_arn)
        )
        print('  Found account: {}'.format(current_guess))
        valid_accounts.append(current_guess)
        return valid_accounts
    except botocore.exceptions.ClientError as error:
        if 'MalformedPolicyDocument' in str(error):
            # Account ID doesn't exist, continue on
            pass
        elif 'NoSuchEntity' in str(error):
            print('  Error: You did not pass in a valid role name. An existing role is required for this script.')
            sys.exit(1)
        else:
            print('  Unhandled error: {}'.format(str(error)))
            sys.exit(1)
    return []


def summary(data, pacu_main):
    return '{} account ID(s) found after {} guess(es).'.format(len(data['valid_accounts']), data['attempts'])
