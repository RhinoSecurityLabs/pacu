#!/usr/bin/env python3
import argparse
import os
import time
import pprint

from pacu.core.secretfinder.utils import regex_checker, Color
from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'dynamodb__enum',

    # Name and any other notes about the author
    'author': 'Ng Song Guan (GovTech-CSG)',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates data from DynamoDB.',

    # Full description about what the module does and how it works
    'description': 'This module enumerates information about DynamoDB tables and can also attempt to dump the table values to a file.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['DynamoDB'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions', '--dump'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')
parser.add_argument('--dump', required=False, default=False, action='store_true', help='Attempt to download all information stored in the tables to separate files and scan all stored strings for secrets. Warning this could take a long time.')


def fetch_dynamodb_data(client, func, key, print, **kwargs):
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        data = response[key]
        if isinstance(data, (dict, str)):
            return data
        while 'LastEvaluatedTableName' in response:
            response = caller(ExclusiveStartTableName=response['LastEvaluatedTableName'], **kwargs)
            data.extend(response[key])
        return data
    except client.exceptions.ResourceNotFoundException:
        pass
    except ClientError as error:
        print('  FAILURE:')
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('    MISSING NEEDED PERMISSIONS')
        else:
            print(code)
    return []


def dump_dynamodb_table(client, print, **kwargs):
    caller = getattr(client, 'scan')
    try:
        response = caller(**kwargs)
        data = response
        while 'LastEvaluatedKey' in response:
            response = caller({**kwargs, **{'ExclusiveStartKey': response['LastEvaluatedKey']}})
            data.extend(response)
        return data
    except client.exceptions.ResourceNotFoundException:
        pass
    except ClientError as error:
        print('  FAILURE:')
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('    MISSING NEEDED PERMISSIONS')
        else:
            print(code)
    return []


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = get_regions('dynamodb')

    now = time.time()
    dynamodb_data = {}
    summary_data = {}
    dynamodb_data['Tables'] = []

    summary_data['dump_path'] = False
    if args.dump:
        # Name but do not write until data is found
        summary_data['dump_path'] = os.path.join(os.getcwd(), 'sessions', session.name, 'downloads', 'dynamodb_table_dump_' + str(now))

    for region in regions:
        print('Starting region {}...'.format(region))

        client = pacu_main.get_boto3_client('dynamodb', region)

        dynamodb_tables = fetch_dynamodb_data(client, 'list_tables', 'TableNames', print)
        for table in dynamodb_tables:
            print('  Enumerating info for table: {}'.format(table))
            tableData = fetch_dynamodb_data(client, 'describe_table', 'Table', print, TableName=table)
            dynamodb_data['Tables'].append(tableData)

            if args.dump:
                print('  Downloading data and finding secrets for table: {}'.format(table))
                
                dump = dump_dynamodb_table(client, print, TableName=table)

                check_secrets(session.name, dump)

                del dump['ResponseMetadata']

                writeTableData(summary_data['dump_path'], table, dump)

        if dynamodb_tables:
            summary_data[region] = len(dynamodb_tables)

    session.update(pacu_main.database, DynamoDB=dynamodb_data)

    return summary_data


def summary(data, pacu_main):
    out = ''
    tables_dumped = False
    for region in sorted(data):
        if not region == 'dump_path':
            out += '  {} tables found in {}. View more information in the DB \n'.format(data[region], region)
            tables_dumped = True
    if not out:
        out = '  No tables found'
    if data['dump_path'] and tables_dumped:
        out += '  Tables dumped to {}\n'.format(data['dump_path'])

    return out


def writeTableData(directory, table, data):
    if not os.path.exists(directory):
        os.mkdir(directory)
    path = os.path.join(directory, table + '.txt')
    with open(path, 'w+') as writeTableDump:
        writeTableDump.write(pprint.pformat(data))

def NestedDictValues(d):
    for v in d.values():
        if isinstance(v, dict):
            yield from NestedDictValues(v)
        else:
            yield v


def check_secrets(session_name, tableData):
    acc = []
    for item in tableData['Items']:
        acc += list(NestedDictValues(item))
    for val in acc:
        if isinstance(val, str):
            secrets = regex_checker(val)
            if secrets:
                [Color.print(Color.GREEN, "\t{}: {}".format(key, secrets[key])) for key in secrets]
