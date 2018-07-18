#!/usr/bin/env python3
import argparse
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
from botocore.exceptions import UnknownServiceError
import os
from datetime import datetime
import json

module_info = {
    'name': 'enum_permissions_bruteforce',
    'author': 'Alexander Morgenstern at RhinoSecurityLabs',
    'category': 'recon_enum_no_keys',
    'one_liner': 'Enumerates permissions using brute force',
    'description':
        """
        This module will automatically run through all possible
        API calls in order to enumerate permissions without the use of
        IAM permissions
        """,
    'services': ['ALL'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--services',
    required=False,
    default=None,
    help='A comma separated list of services to brute force permissions'
)

allow_permissions = {}
deny_permissions = {}
possible_permissions = {}
bugged_permissions = []

def help():
    return [module_info, parser.format_help()]


def build_service_list():
    try:
        client = boto3.client(
            'bad_dummy_service_name',
            region_name='us-east-1'
        )
        return []
    except UnknownServiceError as error:
        service_string = str(error)[62:]
        return service_string.split(', ').copy()


def missing_param(param):
    """Return a key/value dict in the expected formatting given a common parameter, or defaults to param=>'dummy_data'."""
    common_params = {
        'Storage': {
            'S3': {
                'AWSAccessKeyId': '1',
                'Bucket': 'DryRun',
                'Prefix': 'DryRun',
                'UploadPolicy': 'DryRun',
                'UploadPolicySignature': 'DryRun'
            }
        },
        'LaunchTemplateConfigs': [{'LaunchTemplateSpecification': {}}],
        'TargetCapacitySpecification': {'TotalTargetCapacity': 1},
        'DhcpConfigurations': [{'Key': 'val'}],
        'InstanceId': 'i-07421c1ebf30c2070',
        'NetworkInterfaceId': 'eni-1a2b3c4d',
        'PriceSchedules': [{'CurrencyCode': 'USD'}],
        'RouteTableId': 'rtb-e4ad488d',
        'VolumeId': 'vol-0f0a1f7dd1e7704a0',
        'Tags': [{'Key': 'Value'}],
        'Resources': ['ami-78a54010'],
        'DestinationCidrBlock': '11.12.0.0/16',
        'VpcId': 'vpc-abcd1234',
        'VpnConnectionId': 'vpn-83ad48ea',
        'CustomerGatewayId': 'cgw-0e11f160',
        'InputStorageLocation': {'Bucket': 'key'},
        'LaunchTemplateData': {'ImageId': 'ami-aabbccdd'},
        'PeerVpcId': 'vpc-abcd1235',
        'InternetGatewayId': 'igw-12312312',
        'NetworkAclId': 'acl-123123123',
        'Attribute': 'productCodes',
        'Recurrence': {'Frequency': 'string'},
        'FirstSlotStartTimeRange': {'EarliestTime': datetime(2015, 1, 1), 'LatestTime': datetime(2015, 1, 1)},
        'Volume': {'Size': 123},
        'Image': {'Bytes': 123, 'Format': 'RAW', 'ImportManifestUrl': 'string'},
        'InstanceCreditSpecifications': [{'InstanceId': 'val'}],
        'InstanceIds': ['i-abc123'],
        'HostIdSet': ['idset'],
        'PurchaseRequests': [{'InstanceCount': 5, 'PurchaseToken': 'abc'}],
        'VpcEndpointIds': ['vpcids'],
        'HostIds': ['123'],
        'Status': 'ok',
        'ReasonCodes': ['unresponsive'],
        'Instances': ['i-abc123'],
        'SpotFleetRequestConfig': {'IamFleetRole': 'test', 'TargetCapacity': 1},
        'ImageId': 'test',
        'LaunchSpecification': {'ImageId': 'i-123'},
        'Ipv6Addresses': ['aa:aa:aa:aa:aa:aa'],
        'PrivateIpAddresses': ['1.1.1.1'],
        'IpPermissions': [{'FromPort': 1}],
        'SpotFleetRequestIds': ['test'],
        'SpotInstanceRequestIds': ['test'],
        'ResourceIds': ['test'],
        'ConnectionEvents': ['test'],
        'IamInstanceProfile': {'Name': 'test'},
        'ReservedInstancesIds': ['dummydata'],
        'TargetConfigurations': [{'AvailabilityZone': 'dummydata'}]

    }
    out = {param: common_params[param]} if param in common_params else {param: 'dummy_data'}
    return out


def invalid_param(valid_type):
    """Returns an object matching the requested valid type."""
    print('Checking for invalid types')
    types = {
        'datetime.datetime': datetime(2015, 1, 1),
        'list': ['test'],
        'int': 1,
        'dict': {'DryRun': True},
        'bool': True
    }
    return types[valid_type]


def error_delegator(error):
    """Processes the complete error message. Trims the error response to not overwrite missing data with a valid type error"""
    kwargs = {}
    # Ignore first line of error message and process in reverse order.
    for line in str(error).split('\n')[::-1][:-1]:
        print('    Processing Line: {}'.format(line))
        if 'Missing required parameter' in line:
            if line[line.find('"') + 1:-1] not in kwargs.keys():
                kwargs = {**kwargs, **missing_param(line.split()[-1][1:-1])}
        if 'Invalid type for parameter' in line:
            param_name = line.split()[4][:-1]
            # Convert list of strings to list of dicts of invalid list subtype found.
            if param_name[:-3] == '[0]':
                kwargs[param_name] = [{'DryRun': True}]
            else:
                valid_type = line.split("'")[3]
                kwargs[param_name] = invalid_param(valid_type)
    return kwargs


def generate_preload_actions():
    """Certain actions require parameters that cannot be easily discerned from the error message provided by preloading kwargs for those actions."""
    module_dir = os.path.dirname(__file__)
    path = os.path.join(module_dir, 'preload_actions.json')
    data = open(path).read()
    return json.loads(data)


def valid_func(func):
    """Returns False for service functions that don't correspond to an AWS API action"""
    if func[0] == '_':
        return False
    bad_functions = [
        'can_paginate',
        'get_waiter',
        'waiter_names',
        'get_paginator',
        'generate_presigned_url',
        'exceptions',
        'meta',
    ]
    if func in bad_functions:
        return False
    return True


def convert_special_params(func, kwargs):
    """Certain actions go through additional argument parsing. If such a case exists, the dummy_data will
    be filled with valid data so that the action can successfully pass validation and reach and query
    correctly determine authorization.

    TODO: Go through and actually make sure that when a parameter is requested, it can be programatically
    returned. If you need a valid InstanceID and you have the permission to get one, you should be able to
    fill that valid data and determine authorization.
    
    """
    special_params = {
        'reset_image_attribute': {'Attribute': 'launchPermission'},
        'reset_instance_attribute': {'Attribute': 'kernel'},
        'reset_snapshot_attribute': {'Attribute': 'createVolumePermission'},
    }
    if func in special_params:
        print('    Matching Function Found')
        for param in special_params[func]:
            kwargs[param] = special_params[func][param]
        print('    Replaced Parameters')
        return True
    else:
        print('    No special paramaters found for function: {}'.format(func))
        return False


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    preload_actions = generate_preload_actions()

    service_list = []
    if args.services:
        service_list = args.services.split(',')
    else:
        service_list = build_service_list()

    for service in service_list:
        allow_permissions[service] = []
        deny_permissions[service] = []
        possible_permissions[service] = []

        regions = get_regions(service)
        regions = ['us-east-1']
        for region in regions:
            client = boto3.client(
                service,
                region_name=region,
            )
            functions = [func for func in dir(client) if valid_func(func)]
            index = 1
            for func in functions:
                print('*************************NEW FUNCTION({}/{})*************************'.format(index, len(functions)))
                index += 1
                kwargs = preload_actions[func] if func in preload_actions else {}
                kwargs['DryRun'] = True
                while True:
                    try:
                        print('---------------------------------------------------------')
                        print('Trying {}...'.format(func))
                        print('Kwargs: {}'.format(kwargs))
                        caller = getattr(client, func)
                        caller(**kwargs)
                        allow_permissions[service].append(func)
                        print('Authorization exists for: {}'.format(func))
                        break
                    except ParamValidationError as error:
                        if 'Unknown parameter in input: "DryRun"' in str(error):
                            print('DryRun failed. Retrying without DryRun parameter')
                            del kwargs['DryRun']
                        else:
                            if 'AvailabilityZone' not in kwargs and 'AvailabilityZone' in str(error):
                                print("Adding Availability Zone")
                                kwargs['AvailabilityZone'] = region + 'a'
                            else:
                                print('Parameter Validation Error: {}'.format(error))
                                kwargs = {**kwargs, **error_delegator(error)}
                    except ClientError as error:
                        # DryRun returned true, adding to allowed permissions
                        if error.response['Error']['Code'] == 'DryRunOperation':
                            allow_permissions[service].append(func)
                            print('Authorization exists for: {}'.format(func))
                            break

                        # Error with request raised.
                        print('ClientError: {}'.format(error))
                        code = error.response['Error']['Code']
                        if code == 'AccessDeniedException' or code == 'OptInRequired' or 'Unauthorized' in str(error):
                            print('Unauthorized for permission: {}:{}'.format(service, func))
                            deny_permissions[service].append(func)
                            break
                        elif code == 'MissingParameter':
                            param = str(error).split()[-1]
                            param = param[0].upper() + param[1:]
                            kwargs = {**kwargs, **missing_param(param)}
                        # If action is not supported, skip.
                        elif code == 'UnsupportedOperation':
                            break
                        elif code == 'InvalidRequest' or code == 'InvalidParameterValue' or 'Malformed' in code or 'NotFound' in code or 'Unknown' in code:
                            print('Special Parameter Found')
                            if not convert_special_params(func, kwargs):
                                print('No suitable valid data could be found')
                                possible_permissions[service].append(func)
                                break

                        else:
                            print('Unknown error:')
                            print(error)
                            bugged_permissions.append('{}:{}'.format(service, func))
                            print('*************************END FUNCTION*************************\n')
                            break
            break
        break

    print('Allowed Permissions: ')
    print(allow_permissions)

    print('Denied Permissions: ')
    print(deny_permissions)

    print('Possible Permissions: ')
    print(possible_permissions)

    print('Bugged Actions')
    print(bugged_permissions)

    print(f"{module_info['name']} completed.\n")
    return
