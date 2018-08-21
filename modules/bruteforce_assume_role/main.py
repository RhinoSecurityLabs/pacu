#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import os


module_info = {
    'name': 'bruteforce_assume_role',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'recon_enum_no_keys',

    'one_liner': 'Bruteforces existing roles in other AWS accounts to try and gain access via misconfigurations.',

    'description': 'This module takes in an AWS account ID and tries to bruteforce role names within that account. If one is discovered and it is misconfigured to allow role-assumption from a wide group, it is possible to assume that role and gain access to that AWS account through this method. NOTE: This module is listed under the recon_enum_no_keys category because it is not recommended to use compromised keys to run this module. This module DOES require a set of AWS keys, but it will spam CloudTrail logs with "AssumeRole" logs, so it is suggested to use a personal account to run this.',

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

    client = pacu_main.get_boto3_client('sts')

    if args.word_list is None:
        word_list_path = './modules/{}/default-word-list.txt'.format(module_info['name'])
    else:
        word_list_path = args.word_list.strip()

    with open(word_list_path, 'r') as f:
        word_list = f.read().splitlines()


    print('{} completed.\n'.format(module_info['name']))
    return data


def summary(data, pacu_main):
    if 'success' in data.keys() and 'role_arn' in data.keys():
        return 'Successfully found a role we can assume after {} attempts: {}.'.format(data['attempts'], data['role_arn'])
    else:
        return 'Did not find a role to assume after {} attempts.'.format(data['attempts'])
