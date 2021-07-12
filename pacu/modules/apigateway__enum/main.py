#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import pprint
import json
import time

from pacu.core.lib import downloads_dir

module_info = {
    'name': 'enum__apigateway',
    'author': 'Sebastian Mora seb@ruse.tech',
    'category': 'ENUM',
    'one_liner': 'Enumerate API Gateway.',
    'description': 'Enumerate API Gateway. For each API this module enumerates available routes, methods, API keys and ' +
                   'client certificates. Results and Swagger definitions will be exported to the session download directory.',
    'services': ['apigateway'],
    'prerequisite_modules': [''],
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=str(module_info['description']))

parser.add_argument(
    '--regions',
    required=False,
    help='Regions to enumerate'
)

pp = pprint.PrettyPrinter(indent=2)


# Get all resources for  API
#
# return [] dict
def get_api_resources(client, api_id):
    response = client.get_resources(restApiId=api_id)
    return response['items']


# Get All deployment stages of API
#
# returns [] string
def get_api_stages(client, api_id):
    response = client.get_stages(restApiId=api_id)
    names = []
    for stage in response['item']:
        if(stage.get('stageName')):
            names.append(stage['stageName'])
    return names


# Get all supported methods per api resources "/users"
#
# Returns [] dict
def get_api_methods(client, api_id, resource):
    routes = []
    if resource.get('resourceMethods'):
        for method in resource.get('resourceMethods'):
            response = client.get_method(
                restApiId=api_id,
                resourceId=resource['id'],
                httpMethod=method
            )
            routes.append(response)
    return routes


def get_api_keys(client):
    response = client.get_api_keys(limit=500, includeValues=True)
    if response.get('items'):
        return response['items']
    return []


def get_client_certs(client):
    response = client.get_client_certificates(limit=500)
    data = []
    if response.get('items'):
        for cert in response['items']:
            res = client.get_client_certificate(clientCertificateId=cert['clientCertificateId'])
            cert['pemEncodedCertificate'] = res['pemEncodedCertificate']
        data.append(cert)
    return data


# If permissions supported export the API documentaion as Swagger File
def export_api_doc(client, session, api_summary, exportType='swagger'):

    files_names = []
    output_path = downloads_dir()/'apigateway'
    output_path.mkdir(exist_ok=True)

    api_id = api_summary['id']
    api_name = api_summary['name']
    stages = api_summary['stages']

    for stage in stages:
        response = client.get_export(restApiId=api_id, stageName=stage, exportType=exportType)
        filename = f"{api_name}_{stage}_swagger.json"
        with open(output_path / filename, 'w') as f:
            data = json.loads(response['body'].read().decode("utf-8"))
            json.dump(data, f, indent=4)

        files_names.append(filename)

    return files_names


# Take method obj and parse into method summary
def parse_method(base_url, method, path, stages):
    api_method = {
        'uri': "",
        'requestParameters': [],
        'method': "",
        "authorizationType": "",
        "apiKeyRequired": "False",  # if there is a key this will get set to True
        'url': []
    }

    if method.get('methodIntegration') and method['methodIntegration'].get('uri'):
        api_method['uri'] = method['methodIntegration']['uri']

    if method.get('httpMethod'):
        api_method['method'] = method['httpMethod']

    if method.get('authorizationType'):
        api_method['authorizationType'] = method['authorizationType']

    if method.get('apiKeyRequired'):
        api_method['apiKeyRequired'] = method['apiKeyRequired']

    if method.get('methodIntegration') and method['methodIntegration'].get('requestParameters'):
        api_method['requestParameters'] = method['methodIntegration']['requestParameters']

    for stage in stages:
        api_method['url'].append(base_url + stage + path)

    return api_method


def main(args, pacu):
    """Main module function, called from Pacu"""
    print = pacu.print
    session = pacu.get_active_session()
    args = parser.parse_args(args)

    outfile_path = downloads_dir()/'apigateway'

    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = pacu.get_regions('apigateway')

    # Set up summary data object
    # apis[] holds each api object which contains api info an route info
    # apikeys[] holds all api keys
    # clientCerts[] holds all client certs
    summary_data = {'apis': [], 'apiKeys': [], 'clientCerts': []}

    for region in regions:
        client = pacu.get_boto3_client('apigateway', region)
        print(f"Enumerating {region}")

        # Get global API data
        summary_data['apiKeys'] = get_api_keys(client)
        summary_data['clientCerts'] = get_client_certs(client)

        # Currently this only supports REST apis
        # Get all apis in AWS Gatway
        response = client.get_rest_apis()

        items = response['items']

        # for each api in the account
        for api in items:

            # create api objecy summary
            api_summary = {
                'id': '',
                'name': '',
                'stages': [],
                'urlBase': "",
                'urlPaths': [],
                "apiDocs": []
            }

            # Set up base info used by methods
            api_summary['id'] = api['id']
            api_summary['name'] = api['name']
            api_summary['stages'] = get_api_stages(client, api_summary['id'])
            api_summary['urlBase'] = f"https://{api_summary['id']}.execute-api.{region}.amazonaws.com/"

            print(f"Enumerating API: {api_summary['name']}")

            # For each resource get all methods and parse it into it's method summary.
            for resource in get_api_resources(client, api_summary['id']):
                for method in get_api_methods(client, api_summary['id'], resource):
                    api_summary['urlPaths'].append(parse_method(api_summary['urlBase'], method, resource['path'], api_summary['stages']))

            # Append api results to main summary
            summary_data['apis'].append(api_summary)

            # attempt to export api_docs
            api_summary['apiDocs'] = export_api_doc(client, session, api_summary)

        # Write summary all data to downloads file
        if(len(summary_data['apis']) > 0):
            print("Writing all results to file: {}/".format(outfile_path))
            filename = f"apigateway_{region}_{time.time()}.json"
            with open(outfile_path / filename, "w+") as f:
                f.write(
                    json.dumps(summary_data, indent=4, default=str)
                )
            f.close()

    return summary_data


def summary(data, pacu):
    msg = ''
    if not data:
        msg = 'Module execution failed'
    else:
        msg = "Data saved to session file."

        # Display all API routes
        print("-----API Routes-----")
        for api in data['apis']:
            print(f"\n\tAPI Name: {api['name']}")
            print(f"\tAPI Stages: {', '.join(api['stages'])}")
            print(f"\tExported Documentation: { ', '.join(api['apiDocs'])  } ")

            for url_paths in api['urlPaths']:
                # print a new http url for each staged version
                [print(f"\t\t {url_paths['method']}: {url}") for url in url_paths['url']]

        # Display Global API keys
        print("-----API Keys-----")
        for key in data['apiKeys']:
            print(f"\tKey Name: {key['name']} \n\t\tValue: {key['value']} \n\t\tcreatedDate: {key['createdDate']}")

        # Display Gloal Client Certs
        print("-----Client Certs-----")
        for cert in data['clientCerts']:
            print(f"\tCert Id: {cert['clientCertificateId']} \n\t\texpirationDate: {cert['expirationDate']} \n\t\tpem: {cert['pemEncodedCertificate']}")

    return(msg)
