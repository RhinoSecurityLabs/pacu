#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError, EndpointConnectionError
import os

from pacu.core.lib import strip_lines, save
from pacu import Main

module_info = {
    'name': 'enum__secrets',
    'author': 'Nick Spagnola From RSL',
    'category': 'ENUM',
    'one_liner': 'Enumerates and dumps secrets from AWS Secrets Manager and AWS parameter store',
    'description': 'This module will enumerate secrets in AWS Secrets Manager and AWS Systems manager parameter store.',
    'services': ['SecretsManager', 'SSM'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions',
                                  '--secrets-manager',
                                  '--parameter-store'
                                  ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, help=strip_lines('''
    One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.
'''))
parser.add_argument('--secrets-manager', required=False, action="store_true", help="Enumerate secrets manager")
parser.add_argument('--parameter-store', required=False, action="store_true",
                    help="Enumerate Systems Manager parameter store")


def main(args, pacu_main: 'Main'):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print

    get_regions = pacu_main.get_regions

    summary_data = {"SecretsManager": 0, "ParameterStore": 0}

    if args.regions is None:
        regions = get_regions('secretsmanager')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print(
                'This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return None
    else:
        regions = args.regions.split(',')

    if args.secrets_manager is False and args.parameter_store is False:
        args.secrets_manager = args.parameter_store = True

    all_secrets_ids_sm = []
    all_secrets_ids_ssm = []

    for region in regions:
        secret_ids = []
        secrets_ssm = []

        print('Starting region {}...'.format(region))
        if args.secrets_manager:
            client = pacu_main.get_boto3_client('secretsmanager', region)

            response = None
            next_token = False
            while (response is None) or 'NextToken' in response:
                if next_token is False:
                    try:
                        response = client.list_secrets()
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        print('FAILURE: ')
                        if code == 'UnauthorizedOperation':
                            print('  Access denied to ListSecrets.')
                        else:
                            print('  ' + code)
                        print('    Could not list secrets... Exiting')
                        response = None
                        break
                    except EndpointConnectionError as error:
                        print(
                            '    Error connecting to SecretsManager Endpoint for listing secrets for region: {}'.format(
                                region))
                        print('        Error: {}, {}'.format(error.__class__, str(error)))
                        response = None
                        break
                    except Exception as error:
                        print('    Generic Error when Listing SecretsManager for region: {}'.format(region))
                        print('        Error: {}, {}'.format(error.__class__, str(error)))
                        response = None
                        break

                else:
                    response = client.list_secrets()

                if response:
                    for secret in response['SecretList']:
                        secret_ids.append({"name": secret["Name"], "region": region})

            all_secrets_ids_sm += secret_ids

        for sec in all_secrets_ids_sm:
            secret_values = []
            client = pacu_main.get_boto3_client('secretsmanager', sec["region"])

            response = None
            while response is None:
                try:
                    response = client.get_secret_value(
                        SecretId=sec["name"]
                    )
                except ClientError as error:
                    code = error.response['Error']['Code']
                    print('FAILURE: ')
                    if code == 'UnauthorizedOperation':
                        print('  Access denied to GetSecretsValue.')
                    else:
                        print(' ' + code)
                    print('    Could not get secrets value... Exiting')
                    response = None
                    break
                except EndpointConnectionError as error:
                    print('    Error connecting to SecretsManager Endpoint for getting secret for region: {}'.format(
                        sec["region"]))
                    print('        Error: {}, {}'.format(error.__class__, str(error)))
                    response = None
                    break
                except Exception as error:
                    print('    Generic Error when getting Secret from Secrets Manager for region: {}'.format(
                        sec["region"]))
                    print('        Error: {}, {}'.format(error.__class__, str(error)))
                    response = None
                    break

            if response:
                with save('secrets/secrets_manager/secrets.txt', 'a') as f:
                    f.write("{}:{}\n".format(sec["name"], response["SecretString"]))

        if args.parameter_store:
            client = pacu_main.get_boto3_client('ssm', region)

            response = None
            while response is None:
                try:
                    response = client.describe_parameters()
                except ClientError as error:
                    code = error.response['Error']['Code']
                    print('FAILURE: ')
                    if code == 'UnauthorizedOperation':
                        print('  Access denied to DescribeParameters.')
                    else:
                        print(' ' + code)
                    print('    Could not list parameters... Exiting')
                    response = None
                    break
                except EndpointConnectionError as error:
                    print('    Error connecting to SSM Endpoint for describing SSM Parameters for region: {}'.format(
                        region))
                    print('        Error: {}, {}'.format(error.__class__, str(error)))
                    response = None
                    break
                except Exception as error:
                    print('    Generic Error when describing SSM Parameters for region: {}'.format(region))
                    print('        Error: {}, {}'.format(error.__class__, str(error)))
                    response = None
                    break

                if response:
                    for param in response["Parameters"]:
                        secrets_ssm.append({"name": param["Name"], "type": param["Type"], "region": region})

            all_secrets_ids_ssm += secrets_ssm

            for param in all_secrets_ids_ssm:
                client = pacu_main.get_boto3_client('ssm', param["region"])

                response = None
                while response is None:
                    if param["type"] != "SecureString":
                        try:
                            response = client.get_parameter(
                                Name=param["name"]
                            )
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('FAILURE: ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to GetParameter.')
                            else:
                                print(' ' + code)
                            print('    Could not get parameter value... Exiting')
                            response = None
                            break
                        except EndpointConnectionError as error:
                            print('    Error connecting to SSM Endpoint for describing SSM '
                                  'Secure parameter for region: {}'.format(param["region"]))
                            print('        Error: {}, {}'.format(error.__class__, str(error)))
                            response = None
                        except Exception as error:
                            print('    Generic Error when describing SSM Secure Parameter '
                                  'for region: {}'.format(param['region']))
                            print('        Error: {}, {}'.format(error.__class__, str(error)))
                            response = None
                            break

                    else:
                        try:
                            response = client.get_parameter(
                                Name=param["name"],
                                WithDecryption=True
                            )
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('FAILURE: ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to GetParameter.')
                            else:
                                print(' ' + code)
                            print('    Could not get parameter value... Exiting')
                            response = None
                            break
                        except EndpointConnectionError as error:
                            print('    Error connecting to SSM Endpoint for describing '
                                  'SSM parameter for region: {}'.format(param["region"]))
                            print('        Error: {}, {}'.format(error.__class__, str(error)))
                            response = None
                            break
                        except Exception as error:
                            print('    Generic Error when describing SSM Parameter for region: {}'.format(
                                param['region']))
                            print('        Error: {}, {}'.format(error.__class__, str(error)))
                            response = None
                            break

                    if response:
                        with save('secrets/parameter_store/parameters.txt', 'a') as f:
                            f.write("{}:{}\n".format(param["name"], response["Parameter"]["Value"]))

    summary_data["SecretsManager"] = len(all_secrets_ids_sm)
    summary_data["ParameterStore"] = len(all_secrets_ids_ssm)

    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    return summary_data


# The summary function will be called by Pacu after running main, and will be
# passed the data returned from main. It should return a single string
# containing a curated summary of every significant thing that the module did,
# whether successful or not; or None if the module exited early and made no
# changes that warrant a summary being displayed. The data parameter can
# contain whatever data is needed in any structure desired. A length limit of
# 1000 characters is enforced on strings returned by module summary functions.
def summary(data, pacu_main: 'Main'):
    output = (
        "    {} Secret(s) were found in AWS secretsmanager\n'"
        "    {} Parameter(s) were found in AWS Systems Manager Parameter Store"
    ).format(data["SecretsManager"], data["ParameterStore"])
    output += "    \n    Check ~/.local/share/pacu/<session name>/downloads/secrets/ to get the values"
    return output
