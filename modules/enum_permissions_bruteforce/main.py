#!/usr/bin/env python3
import argparse
import boto3
import botocore
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
from botocore.exceptions import UnknownServiceError
from botocore.exceptions import EndpointConnectionError
from botocore.exceptions import NoRegionError
import os
import urllib

from copy import deepcopy

from .region_parse import RegionParser

import re
import json


# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

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

module_dir = os.path.dirname(__file__)
path = os.path.join(module_dir, 'special_params.json')
data = open(path).read()
special_types = json.loads(data)

region_parser = RegionParser()
complete_regions = region_parser.parse()

service_name_mismatch_mapper = {
    'application-autoscaling':'autoscaling',
    'appstream':'aas2',
    'autoscaling-plans':'as',
    'budgets':'billing-budgets',
    'ce':'billing-ce',
    'cloudformation':'cfn',
    'cloudfront':'any',
    'cloudhsmv2':'cloudhsm',
    'cloudsearchdomain':'cloudsearch',
    'cloudtrail':'ct',
    'cloudwatch':'cw',
    'cognito-identity':'cognito_identity_federated_identities',
    'cognito-idp':'cognito_identity_your_user_pools',
    'cognito-sync':'cognito_sync',
    'config':'awsconfig',
    'cur':'billing-ce',
    'dax':'ddb_dax',
    'directconnect':'dc',
    'dynamodb':'ddb',
    'dynamodbstreams':'ddb_streams',
    'efs':'elasticfilesystem-region',
    'elbv2':'elb',
    'es':'elasticsearch-service-regions',
    'events':'cwe',
    'firehose':'fh',
    'fms':'firewallmanager',
    'health':'default',
    #'importexport':'fixme',
    'iot-data':'iot',
    'iot-jobs-data':'iot',
    'kinesis':'ak',
    'kinesis-video-archived-media':'akv',
    'kinesis-video-media':'akv',
    'kinesisanalytics':'ka',
    'kinesisvideo':'akv',
    'lex-models':'lex',
    'lex-runtime':'lex',
    'logs':'cwl',
    'marketplace-entitlement':'default',
    'marketplacecommerceanalytics':'default',
    'mediastore-data':'mediastore',
    'meteringmarketplace':'default',
    'mgh':'migrationhub-region',
    'mobile':'mobile_analytics',
    'mq':'amazon-mq',
    'mturk':'amt',
    'opsworkscm':'opsworks-for-chef-automate',
    'organizations':'ao',
    'pi':'all',
    'polly':'pol',
    'pricing':'billing-pricing',
    'resource-groups':'arg',
    'resourcegroupstaggingapi':'arg',
    'route53':'r53',
    'route53domains':'r53',
    'sagemaker-runtime':'sagemaker',
    'secretsmanager':'asm',
    'servicediscovery':'r53',
    'sms':'server_migration',
    'stepfunctions':'step-functions',
    'storagegateway':'sg',
    'support':'default',
    'waf-regional':'waf',
    'workmail':'wm',
    'workspaces':'wsp'
}

allow_permissions = {}
deny_permissions = {}
maybe_permissions = {}

def help():
    return [module_info, parser.format_help()]


def build_service_list():
    try:
        client = boto3.client(
            'bad_service_name',
            region_name='us-east-1'
        )
    except UnknownServiceError as error:
        service_string = str(error)[62:]
        return service_string.split(', ').copy()


def get_regions(service):
    if service in service_name_mismatch_mapper:
        service = service_name_mismatch_mapper[service]
    return complete_regions[service]

def missing_param(param):
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
        'LaunchTemplateData': {'ImageId':'ami-aabbccdd'},
        'PeerVpcId': 'vpc-abcd1235',
        'InternetGatewayId': 'igw-12312312'

    }
    out = {param: common_params[param]} if param in common_params else {param: 'DryRun'} 
    return out

def invalid_param(valid_type):
    print('Checking for invalid types')
    types = {
        'list': ['DryRun',],
        'int': 1,
        'dict': {'DryRun': True},
        'bool': True
    }
    
    return types[valid_type]

def error_delegator(error):
    kwargs = {}
    # Ignore first line of error message and process in reverse order.
    for line in str(error).split('\n')[::-1][:-1]:
        print(f'\t Processing Line: {line}')
        if 'Missing required parameter' in line:
            if line[line.find('"') + 1:-1] not in kwargs.keys():
                kwargs = {**kwargs, **missing_param(line.split()[-1][1:-1])}
        if 'Invalid type for parameter' in line:            
            param_name = line.split()[4][:-1]

            valid_type = line.split("'")[3]
            kwargs[param_name] = invalid_param(valid_type)
    return kwargs


def valid_func(func):
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
        # EC2
        'accept_vpc_peering_connection', # Needs valid vpc peering connection ID
        'associate_address', # Needs valid public IP or allocation id
        'associate_iam_instance_profile', # Needs valid instance ID
        'attach_classic_link_vpc', # Needs valid instance ID
        'attach_volume', # Requires valid volume ID
        'authorize_security_group_egress', # Requires valid security group
        'authorize_security_group_ingress', # Requires valid security group
        'create_image', # Requires valid instance ID
        'create_launch_template_version', # Requires valid template ID
        'create_network_interface_permission', # Requires valid interface ID
        'create_snapshot', # Requires valid volume ID
        'create_tags', # Requiresvalid image ID
        'create_volume', # Need to pass current regions availability zone
        'create_vpc_peering_connection', # Requires valid vpc
        'delete_customer_gateway', # Requires valid customer gateway
        'delete_dhcp_options', # Requires valid DhcpOptionsId
        'delete_launch_template', # Requires valid template ID
    ]
    if func in bad_functions:
        return False
    return True

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    
    index = 54

    service_list = []
    if args.services:
        service_list = args.services.split(',')
    else:
        service_list = build_service_list()


    for service in service_list:
        allow_permissions[service] = []
        deny_permissions[service] = []
        maybe_permissions[service] = []
        regions = ['none']
        try:
            client = boto3.client(
                service
            )
        except NoRegionError:
            regions = get_regions(service)

        regions = ['us-east-1']
        for region in regions:
            client = boto3.client(
                service,
                region_name = region,
            )
            functions = [func for func in dir(client) if valid_func(func)]
            for func in functions[index:]:
                print('*************************NEW FUNCTION({})*************************'.format(index))
                index += 1
                kwargs = special_types[func] if func in special_types else {}
                kwargs['DryRun'] = True
                while True:
                    try:                        
                        print('---------------------------------------------------------')
                        print(f'Trying {func}...')
                        print(f'Kwargs: {kwargs}')
                        caller = getattr(client, func)
                        result = caller(**kwargs)
                        allow_permissions[service].append(func)
                        print('Authorization exists for: {}'.format(func))
                        break
                    except ParamValidationError as error:
                        if 'Unknown parameter in input: "DryRun"' in str(error):
                            print('DryRun failed. Retrying without DryRun parameter')
                            del kwargs['DryRun']
                        else:
                            kwargs = {**kwargs, **error_delegator(error)}
                    except ClientError as error:
                        if error.response['Error']['Code'] == 'DryRunOperation':
                            allow_permissions[service].append(func)
                            print('Authorization exists for: {}'.format(func))
                            break

                        print(f'ClientError: {error}')
                        code = error.response['Error']['Code']
                        if code == 'AccessDeniedException' or 'UnauthorizedOperation' in str(error):
                            print(f'Unauthorized for permission: {service}:{func}')
                            deny_permissions[service].append(func)
                            break
                        elif code == 'MissingParameter':
                            param = str(error).split()[-1]
                            param = param[0].upper() + param[1:]
                            kwargs = {**kwargs, **missing_param(param)}
                        #elif 'Malformed' in error.response['Error']['Code']:
                        #    print('Unable to determine authorization')
                        #    maybe_permissions[service].append(func)
                        #    break
                        elif code == 'UnsupportedOperation':
                            break
                        else:
                            print('Unknown error:')
                            print(error)
                            maybe_permissions[service].append(func)                            
                            print('*************************END FUNCTION*************************\n')
                            return
            break
        break

    print('Allowed Permissions: ')
    print(allow_permissions)

    print('Denied Permissions: ')
    print(deny_permissions)

    print('Maybe Permissions: ')
    print(maybe_permissions)





            
        

    #for region in regions:
    #    print('Starting region {}...'.format(region))
    #    client = boto3.client(
    #        'aws_service',
    #        region_name=region,
    #        aws_access_key_id=session.access_key_id,
    #        aws_secret_access_key=session.secret_access_key,
    #        # Even if the session doesn't have a session token, this will work
    #        # because the value will be None and will be ignored.
    #        aws_session_token=session.session_token,
    #        # Proxy boto3's client if currently proxying through an agent:
    #        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    #    )

    print(f"{module_info['name']} completed.\n")
    return
