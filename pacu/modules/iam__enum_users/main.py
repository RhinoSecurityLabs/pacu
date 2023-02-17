#!/usr/bin/env python3
import argparse
from pathlib import Path

import botocore
from copy import deepcopy


module_info = {
    'name': 'iam__enum_users',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'RECON_UNAUTH',

    'one_liner': 'Enumerates IAM users in a separate AWS account, given the account ID.',

    'description': 'This module takes in a valid AWS account ID and tries to enumerate existing IAM users within that account. It does so by trying to update the AssumeRole policy document of the role that you pass into --role-name. For your safety, it updates the policy with an explicit deny against the AWS account/IAM user, so that no security holes are opened in your account during enumeration. NOTE: It is recommended to use personal AWS access keys for this script, as it will spam CloudTrail with "iam:UpdateAssumeRolePolicy" logs. The target account will not see anything in their logs though! The keys used must have the iam:UpdateAssumeRolePolicy permission on the role that you pass into --role-name to be able to identify a valid IAM user.',

    'services': ['IAM'],

    'prerequisite_modules': [],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--word-list', '--role-name', '--account-id']
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--word-list', required=False, default=None, help='File path to a different word list to use. There is a default word list with 1100+ words. The word list should contain words, one on each line, to use to try and guess IAM user names. User names ARE case-sensitive.')
parser.add_argument('--role-name', required=True, help='The name of a valid role in the current users account to try and update the AssumeRole policy document for.')
parser.add_argument('--account-id', required=True, help='The AWS account ID of the target account (12 numeric characters).')


def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print

    if not len(args.account_id) == 12 or not args.account_id.isdigit():
        print('Error: An AWS account ID is a number of length 12. You supplied: {}\n'.format(args.account_id))
        return None

    if args.word_list is None:
        word_list_path = f'{Path(__file__).parent}/default-word-list.txt'
    else:
        word_list_path = args.word_list.strip()

    with open(word_list_path, 'r') as f:
        word_list = f.read().splitlines()

    print('Warning: This script does not check if the keys you supplied have the correct permissions. Make sure they are allowed to use iam:UpdateAssumeRolePolicy on the role that you pass into --role-name!\n')

    data = {
        'attempts': 0,
        'valid_users': []
    }

    client = pacu_main.get_boto3_client('iam')

    print('Targeting account ID: {}\n'.format(args.account_id))
    print('Starting user enumeration...\n')

    for word in word_list:
        user_arn = 'arn:aws:iam::{}:user/{}'.format(args.account_id, word)

        data['attempts'] += 1

        try:
            policy_doc = '''
            {{
                "Version":"2012-10-17",
                "Statement":[{{
                    "Effect":"Deny",
                    "Principal":{{"AWS":"{}"}},
                    "Action":"sts:AssumeRole"
                }}]
            }}'''.format(user_arn).strip()
            client.update_assume_role_policy(
                RoleName=args.role_name.split('/')[-1],  # Handle ARN's if they where accidentally passed here
                PolicyDocument=policy_doc,
            )
            print('  Found user: {}'.format(user_arn))
            data['valid_users'].append(user_arn)
        except botocore.exceptions.ClientError as error:
            if 'MalformedPolicyDocument' in str(error):
                # User doesn't exist, continue on
                pass
            elif 'NoSuchEntity' in str(error):
                print('  Error: You did not pass in a valid role name. An existing role is required for this script.')
                return data
            else:
                print('  Unhandled error: {}'.format(str(error)))
                print(policy_doc)
                raise error

    if len(data['valid_users']) > 0:
        print('\nFound {} user(s):\n'.format(len(data['valid_users'])))
        for user in data['valid_users']:
            print('    {}'.format(user))
        print('')

        update_users_database(pacu_main, data['valid_users'])


    return data


def update_users_database(pacu_main, raw_users):
    session = pacu_main.get_active_session()
    users = [ user_formater(user) for user in raw_users]
    iam_data = deepcopy(session.IAM)

    if iam_data.get('Users') is None:
        iam_data['Users'] = users
    else:
        for user in users:
            if not is_duplicate_user(user, iam_data['Users']):
                iam_data['Users'].append(user)
    session.update(pacu_main.database, IAM=iam_data)


def user_formater(user):
    return {
        "Arn": user,
        "CreateDate": None,
        "Path": "/" + '/'.join(user.split(':')[-1].split('/')[1:-1]),
        "UserId": None,
        "UserName": user.split('/')[-1]
    }


def is_duplicate_user(user, list_users):
    user_arns = [ user["Arn"] for user in list_users]
    return user["Arn"] in user_arns


def summary(data, pacu_main):
    return '  {} user(s) found after {} guess(es).'.format(len(data['valid_users']), data['attempts'])
