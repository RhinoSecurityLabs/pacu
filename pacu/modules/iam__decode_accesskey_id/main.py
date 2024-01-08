#!/usr/bin/env python3
import argparse
from pacu.utils import decode_accesskey_id

module_info = {
    'name': 'iam__decode_accesskey_id',
    'author': 'Rhino Security Labs',
    'category': 'enum',
    'one_liner': 'This module decodes an access key ID to get the AWS account ID. Based on: https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489',
    'description': 'This module decodes an access key ID to get the AWS account ID without making and AWS API calls. Based on: https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489',
    'services': ['IAM'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=True, description=module_info['description'])

parser.add_argument('access_key_id', nargs='?', default='', help='The access key ID to decode. If not provided, the current access key ID for the current profile will be used.')


def main(args, pacu_main):

    key_info = pacu_main.key_info
    args = parser.parse_args(args)

    user = key_info()

    if args.access_key_id:
        accesskey_id = args.access_key_id
    else:
        accesskey_id = user['AccessKeyId']

    data = decode_accesskey_id(accesskey_id)
    return data


def summary(data, pacu_main):
    return f"Account ID: {data}"
