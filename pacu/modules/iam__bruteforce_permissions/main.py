#!/usr/bin/env python3
import argparse
from datetime import datetime
import json
import os
import re

import boto3

from . import param_generator

module_info = {
    'name': 'iam__bruteforce_permissions',
    'author': 'Alexander Morgenstern at RhinoSecurityLabs',
    'category': 'ENUM',
    'one_liner': 'Enumerates permissions using brute force',
    'description': "This module will automatically run through all possible API calls of supported services in order to enumerate permissions without the use of the IAM API.",
    'services': ['all'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--services'],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--services',
    required=False,
    default=None,
    help='A comma separated list of services to brute force permissions'
)

SUPPORTED_SERVICES = [
    'ec2',
    's3',
    'logs'
]

client = None
current_region = None
current_service = None

summary_data = {
    'unsupported': [],
    'unknown': [],
    'services': [],
    'allow': [],
    'deny': [],
}


def complete_service_list():
    """Returns a list of all supported boto3 services"""
    session = boto3.session.Session()
    return session.get_available_services()


def missing_param(param):
    """Sets param to 'dummydata'"""
    # Don't use an underscore here (or change this in general) since it can result in different and possibly
    # incorrect error codes
    out = {param: 'dummydata'}
    return out


def invalid_param(valid_type):
    """Returns an object matching the requested valid type."""
    print('Checking for invalid types')
    types = {
        'datetime.datetime': datetime(2015, 1, 1),
        'list': ['test'],
        'int': 1,
        'dict': {},
        'bool': True
    }
    return types[valid_type]


def error_delegator(error):
    """Processes the complete error message. Trims the error response to not overwrite missing data with a valid type error"""
    kwargs = {}
    # Ignore first line of error message and process in reverse order.
    for line in str(error).split('\n')[::-1][:-1]:
        if 'Missing required parameter in input' in line:
            if line[line.find('"') + 1:-1] not in kwargs.keys():
                kwargs = {**kwargs, **missing_param(line.split()[-1][1:-1])}
        elif 'Missing required parameter in' in line:
            # Grabs the parameter to build a dictionary of
            dict_name = line.split(':')[0].split()[-1]
            if '[' in dict_name:
                # Need to populate missing parameters for a sub type
                param = dict_name[:dict_name.find('.')]
                sub_param = dict_name[dict_name.find('.') + 1:dict_name.find('[')]
                missing_parameter = line[line.find('"') + 1:-1]
                kwargs.update({param: {sub_param: [missing_param(missing_parameter)]}})
            else:
                param = line.split(':')[1].strip()[1:-1]
                if dict_name not in kwargs:
                    kwargs = {dict_name: {param: ''}}
                else:
                    kwargs[dict_name].update({param: ''})

        elif 'Invalid type for parameter' in line:
            param_name = line.split()[4][:-1]
            if '.' in param_name:
                # This invalid type is a sub type within a parameter
                dict_name = param_name.split('.')[0]
                param_name = param_name.split('.')[1]
                if '[' in param_name:
                    # The invalid parameter is a list within a dict within a dict
                    param_name = param_name[:param_name.find('[')]
                    valid_type = line.split("'")[3]
                    temp_dict = {param_name: [invalid_param(valid_type)]}
                else:
                    # The invalid parameter is a basic key value
                    valid_type = line.split("'")[-2]
                    temp_dict = {param_name: invalid_param(valid_type)}
                if dict_name not in kwargs:
                    kwargs.update({dict_name: temp_dict})
                else:
                    kwargs[dict_name].update(temp_dict)
            else:
                # Convert list of strings to list of dicts of invalid list subtype found.
                if param_name[:-3] == '[0]':
                    kwargs[param_name] = [{'DryRun': True}]
                else:
                    valid_type = line.split("'")[3]
                    kwargs[param_name] = invalid_param(valid_type)
    return kwargs


def generate_preload_actions():
    """Certain actions require parameters that cannot be easily discerned from the
    error message provided by preloading kwargs for those actions.
    """
    module_dir = os.path.dirname(__file__)
    path = os.path.join(module_dir, 'preload_actions.json')
    with open(path) as actions_file:
        data = actions_file.read()
    return json.loads(data)


def read_only_function(service, func):
    """Verifies that actions being ran are ReadOnlyAccess to minimize unexpected
    changes to the AWS environment.
    """
    module_dir = os.path.dirname(__file__)
    path = os.path.join(module_dir, 'ReadOnlyAccessPolicy.json')
    with open(path) as file:
        data = json.load(file)
        formatted_func = service + ':' + camel_case(func)
        for action in data['Statement'][0]['Action']:
            if re.match(action, formatted_func) is not None:
                return True
    return False


def valid_func(service, func):
    """Returns False for service functions that don't correspond to an AWS API action"""
    if func[0] == '_':
        return False
    BAD_FUNCTIONS = [
        # Common boto3 methods.
        'can_paginate',
        'get_waiter',
        'waiter_names',
        'get_paginator',
        'generate_presigned_url',
        'generate_presigned_post',
        'exceptions',
        'meta',

        # S3 Function to manage multipart uploads.
        'list_parts',
    ]
    if func in BAD_FUNCTIONS:
        return False
    return read_only_function(service, func)


def convert_special_params(func, kwargs):
    """Certain actions go through additional argument parsing. If such a case exists, the dummy_data will
    be filled with valid data so that the action can successfully pass validation and reach and query
    correctly determine authorization.
    """
    SPECIAL_PARAMS = [
        'Bucket',
        'Attribute',
        'Key',
    ]
    for param in list(filter(lambda p: kwargs[p] == 'dummydata', kwargs)):
        if param in SPECIAL_PARAMS:
            v = param_generator.get_special_param(client, func, param)
            if v is None:
                return False
            else:
                kwargs[param] = v
                return True
    return False


def build_service_list(services=None):
    """Returns a list of valid services. """
    if not services:
        return SUPPORTED_SERVICES

    unsupported_services = [s for s in services if s not in SUPPORTED_SERVICES]
    summary_data['unsupported'] = unsupported_services

    unknown_services = [service for service in unsupported_services if service not in complete_service_list()]
    summary_data['unknown'] = unknown_services
    service_list = [service for service in services if service in SUPPORTED_SERVICES]
    return service_list


def error_permissions(error):
    """There are certain Exceptions raised that indicate successful authorization. This method will return 'allowed',
    'unknown', or 'denied' based on the whether the error indicates access is allowed or not.
    """
    VALID_EXCEPTIONS = [
        'DryRunOperation',
        # S3
        'NoSuchCORSConfiguration',
        'ServerSideEncryptionConfigurationNotFoundError',
        'NoSuchConfiguration',
        'NoSuchLifecycleConfiguration',
        'ReplicationConfigurationNotFoundError',
        'NoSuchTagSet',
        'NoSuchWebsiteConfiguration',
        'NoSuchKey',
        'NoSuchBucket',
        'NoSuchBucketPolicy',
        'OwnershipControlsNotFoundError',
        'MethodNotAllowed',
        '(403) when calling the HeadBucket operation',
        '(404) when calling the HeadObject operation',
        '(InvalidRequest) when calling the GetObjectLegalHold operation',
        '(InvalidRequest) when calling the GetObjectRetention operation',
        '(ObjectLockConfigurationNotFoundError) when calling the GetObjectLockConfiguration operation',
        '(NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation',

        # EC2
        'InvalidTargetArn.Unknown',
        'Invalid type for parameter ReservedInstanceIds',
        'Invalid type for parameter HostIdSet',
        '(InvalidCertificateArn.Malformed) when calling the GetAssociatedEnclaveCertificateIamRoles operation',
        '(InvalidInstanceID.Malformed) when calling the GetConsoleScreenshot',
        '(InvalidParameterValue) when calling the GetFlowLogsIntegrationTemplate operation',


        # Logs
        '(ResourceNotFoundException) when calling the DescribeLogStreams operation',
        '(ResourceNotFoundException) when calling the DescribeSubscriptionFilters operation',
        '(ResourceNotFoundException) when calling the FilterLogEvents operation',
        '(ResourceNotFoundException) when calling the GetLogEvents operation',
        '(InvalidParameterException) when calling the GetLogRecord operation',
        '(ResourceNotFoundException) when calling the GetQueryResults operation',
        '(ResourceNotFoundException) when calling the ListTagsLogGroup operation',
    ]

    UNKNOWN_EXCEPTIONS = [
        # EC2
        '(InvalidAction) when calling the DescribeAddressesAttribute operation'
        '(InvalidHostId.Malformed) when calling the GetHostReservationPurchasePreview operation:'
    ]

    for exception in VALID_EXCEPTIONS:
        if exception in str(error):
            return 'allowed'

    for exception in UNKNOWN_EXCEPTIONS:
        if exception in str(error):
            return 'unknown'

    return 'denied'


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print

    service_list = build_service_list(args.services.lower().split(',')) if args.services else build_service_list()
    if not service_list:
        return summary_data
    summary_data['services'] = service_list

    preload_actions = generate_preload_actions()

    allow_permissions = {}
    unknown_permissions = {}
    deny_permissions = {}

    for service in service_list:
        global current_service
        current_service = service
        allow_permissions[service] = []
        unknown_permissions[service] = []
        deny_permissions[service] = []

        # Only checking against 'us-east-1'. To store more granular permissions the DB needs to be changed.
        regions = ['us-east-1','us-east-2','us-west-2','us-west-1']
        for region in regions:
            global current_region, client

            current_region = region
            client = pacu_main.get_boto3_client(service, region)

            functions = [func for func in dir(client) if valid_func(service, func)]
            index = 1

            for func in functions:
                index += 1

                op = client.meta.service_model.operation_model(operation_name=client._PY_TO_OP_NAME[func])

                if func in preload_actions:
                    kwargs = preload_actions[func] if func in preload_actions else {}
                else:
                    kwargs = dict(((arg, 'dummydata') for arg in getattr(op.input_shape, 'required_members', [])))

                    members = getattr(op.input_shape, 'members', {})
                    if members.get('DryRun'):
                        kwargs['DryRun'] = True

                    if members.get('AvailabilityZone'):
                        kwargs['AvailabilityZone'] = current_region

                    if members.get('MaxResults'):
                        kwargs['MaxResults'] = 10

                    if members.get('GroupId'):
                        kwargs['GroupId'] = 1

                if members.get('StartTime'):
                    kwargs['StartTime'] = datetime.now()

                convert_special_params(func, kwargs)

                print('Trying {} -- kwargs: {}'.format(func, kwargs))
                caller = getattr(client, func)
                try:
                    caller(**kwargs)
                    allow_permissions[service].append(func)
                    print('    Authorization exists for: {}'.format(func))
                    continue
                except Exception as error:
                    if error_permissions(error) == 'allowed':
                        allow_permissions[service].append(func)
                        print('    Authorization exists for: {}'.format(func))
                        continue
                    elif error_permissions(error) == 'unknown':
                        unknown_permissions[service].append(func)
                        continue
                    print(error)
                    deny_permissions[service].append(func)

    print('Allowed Permissions: \n')
    print_permissions(allow_permissions)
    print('Denied Permissions: \n')
    print_permissions(deny_permissions)

    # Condenses the following dicts to a list that fits the standard service:action format.
    if allow_permissions:
        full_allow = [service + ':' + camel_case(perm) for perm in allow_permissions[service] for service in allow_permissions]
    if deny_permissions:
        full_deny = [service + ':' + camel_case(perm) for perm in deny_permissions[service] for service in deny_permissions]

    active_aws_key = session.get_active_aws_key(pacu_main.database)
    active_aws_key.update(
        pacu_main.database,
        allow_permissions=full_allow,
        deny_permissions=full_deny
    )

    summary_data['allow'] = sum([len(allow_permissions[region]) for region in allow_permissions])
    summary_data['unknown'] = sum([len(allow_permissions[region]) for region in unknown_permissions])
    summary_data['deny'] = sum([len(deny_permissions[region]) for region in deny_permissions])

    return summary_data


def print_permissions(permission_dict):
    """Helper function to print permissions."""
    for service in permission_dict:
        print('  {}:'.format(service))
        for action in permission_dict[service]:
            print('    {}'.format(action))
        print('')


def camel_case(name):
    """Helper function to convert snake_case to CamelCase."""
    split_name = name.split('_')
    return ''.join([name[0].upper() + name[1:] for name in split_name])


def summary(data, pacu_main):
    out = 'Services: \n'
    out += '  Supported: {}.\n'.format(data['services'])
    if 'unsupported' in data:
        out += '  Unsupported: {}.\n'.format(data['unsupported'])
    if 'unknown' in data:
        out += '  Unknown: {}.\n'.format(data['unknown'])
    out += '{} allow permissions found.\n'.format(data['allow'])
    out += '{} unknown permissions found.\n'.format(data['unknown'])
    out += '{} deny permissions found.\n'.format(data['deny'])
    return out
