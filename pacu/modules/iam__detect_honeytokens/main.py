#!/usr/bin/env python3
import argparse
import re
from botocore.exceptions import ClientError


module_info = {
    'name': 'iam__detect_honeytokens',

    'author': 'Spencer Gietzen of Rhino Security Labs',

    'category': 'ENUM',

    'one_liner': 'Checks if the active set of keys are known to be honeytokens.',

    'description': 'This module checks if the active set of keys are known to be honeytokens and in the process, it enumerates some identifying information about the keys. All of this is done without ever leaving a log in CloudTrail, because it uses AWS SimpleDB for enumeration, which CloudTrail does not support. Note: Even if you know your keys are not honey keys, this module can be used to enumerate information like the account ID, user/role path, user/role name, and role session name if there is one.',

    'services': ['IAM', 'SDB'],

    'prerequisite_modules': [],

    'external_dependencies': [],

    'arguments_to_autocomplete': ['--region'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--region', required=False, default='us-east-1', help='If for some reason you want to target a specific region for the SimpleDB API call. This shouldn\'t ever matter, because the API call is not logged to CloudTrail. The default is "us-east-1".')


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    ######

    data = {}

    client = pacu_main.get_boto3_client('sdb', args.region)

    print('Making test API request...\n')

    try:
        client.list_domains()

        data['summary'] = 'API call was successful! This means you have the SimpleDB ListDomains permission and we could not get your ARN from the API call.'
    except ClientError as error:
        if error.response['Error']['Code'] == 'AuthorizationFailure':
            message = error.response['Error']['Message']

            if 'canarytokens.com' in message or 'canarytokens.org' in message:
                data['summary'] = 'WARNING: Keys are confirmed honeytoken keys from Canarytokens.org! Do not use them!'
            elif 'arn:aws:iam::' in message and '/SpaceCrab/' in message:
                data['summary'] = 'WARNING: Keys are confirmed honeytoken keys from SpaceCrab! Do not use them!'
            elif 'arn:aws:iam::534261010715:' in message or 'arn:aws:sts::534261010715:' in message:
                data['summary'] = 'WARNING: Keys belong to an AWS account owned by Canarytokens.org! Do not use them!'
            else:
                data['summary'] = 'Keys appear to be real (not honeytoken keys)!'

            match = re.search(r'User \(arn:.*\) does not have permission to perform', message)
            if match:
                data['arn'] = match.group().split('(')[1].split(')')[0]

                active_aws_key = session.get_active_aws_key(pacu_main.database)

                if ':assumed-role/' in data['arn']:
                    active_aws_key.update(
                        pacu_main.database,
                        arn=data['arn'],
                        account_id=data['arn'].split('arn:aws:sts::')[1][:12],
                        # -2 will get the role name everytime,
                        # even if there is a role path and
                        # session name
                        role_name=data['arn'].split(':assumed-role/')[1].split('/')[-2]
                    )
                elif ':user/' in data['arn']:
                    active_aws_key.update(
                        pacu_main.database,
                        arn=data['arn'],
                        account_id=data['arn'].split('arn:aws:iam::')[1][:12],
                        # -1 will get the user name everytime,
                        # even if there is a user path
                        user_name=data['arn'].split(':user/')[1].split('/')[-1]
                    )
        else:
            data['summary'] = '  Unhandled error received: {}'.format(error.response['Error']['Code'])

    print('  {}\n'.format(data['summary']))

    return data


def summary(data, pacu_main):
    out = ''
    if 'summary' in data.keys():
        out += '  {}\n'.format(data['summary'])
    if 'arn' in data.keys():
        out += '\n  Full ARN for the active keys (saved to database as well):\n\n    {}\n\n'.format(data['arn'])
    return out
