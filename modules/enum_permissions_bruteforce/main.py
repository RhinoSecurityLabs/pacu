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

def missing_param_builder(error):
    missing_params = {}
    for line in error.split('\n'):
        if 'Missing required parameter' in line:
            index = line.find('"')
            word = line[index+1:-1]
            missing_params[word] = 'string'
    return missing_params

def invalid_param_builder(error):
    param_types = {
        'str':'i-123456789abcde123',
        'list':['string',],
        'int':1,
        'dict':{'Key': 'val'},
        'bool':False
    }    
    invalid_params = {}
    for line in error.split('\n'):
        if 'Invalid type for parameter' in line:

            param_name = line.split()[4][:-1]

            if param_name in special_types.keys():
                invalid_params[param_name] = special_types[param_name]
                continue

            valid_type = line.split()[13]

            if valid_type[-1] == ',':
                valid_type = valid_type[:-1]
            valid_type = valid_type[1:-2]

            print(f'Valid_type found = {line.split()[13]}')

            invalid_params[param_name] = param_types[valid_type]
        if 'Unknown parameter in' in line:
            param_name = line.split()[3][:-1]
            val = line.split()[-1]
            invalid_params[param_name] = {val:'i-123456789abcde123'}

    return invalid_params

def clean_key(key):
    removenonletters = re.compile('[^a-zA-Z]')
    return removenonletters.sub('', key)

def build_kwargs(error):
    missing_params = missing_param_builder(error)
    invalid_params = invalid_param_builder(error)
    kwargs = {**missing_params, **invalid_params}
    return kwargs

def build_args(error):
    args = []
    if 'operation_name' in error:
        args.append('list_objects')
    if 'Waiter does not exist' in error:
        args.append('waiter_name')
    return args

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
    ]
    if func in bad_functions:
        return False
    return True

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    

    service_list = []
    if args.services:
        service_list = args.services.split(',')
    else:
        service_list = build_service_list()


    for service in service_list:
        allow_permissions[service] = []
        deny_permissions[service] = []
        regions = ['none']
        try:
            client = boto3.client(
                service
            )
        except NoRegionError:
            regions = get_regions(service)
        for region in regions:
            client = boto3.client(
                service,
                region_name = region,
                #config=botocore.config.Config(parameter_validation=False)
            )
            functions = [func for func in dir(client) if valid_func(func)]
            #functions = ['create_dhcp_options']
            #functions = ['bundle_instance']
            #functions = ['create_fleet']
            #functions = ['associate_iam_instance_profile']
            for func in functions:
                args = []
                kwargs = {}
                while True:
                    try:   
                        print(f'Trying {func}...')
                        print(f'args: {args}')
                        print(f'Kwargs: {kwargs}')
                        print('\n\n\n\n')
                        caller = getattr(client, func)
                        result = caller(*args, **kwargs)
                        allow_permissions[service].append(func)
                        break
                    #except TypeError as error:
                    #    print(f'TypeError: {error}')
                    #    args = build_args(str(error))
                    #except ValueError as error:
                    #    print(f'ValueError: {error}')
                    #    args = build_args(str(error))
                    except ParamValidationError as error:
                        print(f'ParamValidationError: {error}')
                        kwargs = build_kwargs(str(error))
                    except ClientError as error:
                        if error.response['Error']['Code'] == 'AccessDeniedException':
                            deny_permissions[service].append(func)
                        elif 'UnauthorizedOperation' in str(error):
                            deny_permissions[service].append(func)
                        else:
                            print('Unknown error:')
                            print(error)
                        break    
            break
        break

    print('Allowed Permissions: ')
    print(allow_permissions)

    print('Denied Permissions: ')
    print(deny_permissions)





            
        

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
