#!/usr/bin/env python3
import argparse
import datetime
from copy import deepcopy
import os

from botocore.exceptions import ClientError


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'dl_s3_bucket',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerate and dumps files from S3 buckets.',

    # Description about what the module does and how it works
    'description': 'This module scans the current account for AWS buckets and prints/stores as much data as it can about each one. With no arguments, this module will enumerate all buckets the account has access to, then prompt you to download all files in the bucket or not. Use --names-only or --dl-names to change that. The files will be downloaded to ./sessions/[current_session_name]/downloads/dl_s3_bucket/.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['S3'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--dl-all', '--names-only', '--dl-names'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--dl-all', required=False, action='store_true', help='If specified, automatically download all files from buckets that are allowed instead of asking for each one. WARNING: This could mean you could potentially be downloading terrabytes of data! It is suggested to user --names-only and then --dl-names to download specific files.')
parser.add_argument('--names-only', required=False, action='store_true', help='If specified, only pull the names of files in the buckets instead of downloading. This can help in cases where the whole bucket is a large amount of data and you only want to target specific files for download. This option will store the filenames in a .txt file in ./sessions/[current_session_name]/downloads/dl_s3_bucket/dl_s3_bucket_file_names.txt, one per line, formatted as "filename@bucketname". These can then be used with the "--dl-names" option.')
parser.add_argument('--dl-names', required=False, default=False, help='A path to a file that includes the only files to be downloaded, one per line. The format for these files must be "filename.ext@bucketname", which is what the --names-only argument outputs.')

FILE_SIZE_THRESHOLD = 1073741824


def get_bucket_size(pacu, bucket_name):
    client = pacu.get_boto3_client('cloudwatch', 'us-east-1')
    response = client.get_metric_statistics(
        Namespace='AWS/S3',
        MetricName='BucketSizeBytes',
        Dimensions=[
            {'Name': 'BucketName', 'Value': bucket_name},
            {'Name': 'StorageType', 'Value': 'StandardStorage'}
        ],
        Statistics=['Average'],
        Period=3600,
        StartTime=datetime.datetime.today() - datetime.timedelta(days=1),
        EndTime=datetime.datetime.now().isoformat()
    )
    if response['Datapoints']:
        return response['Datapoints'][0]['Average']
    return 0


def download_s3_file(pacu, key, bucket):
    session = pacu.get_active_session()
    base_directory = 'sessions/{}/downloads/{}/{}/'.format(session.name, module_info['name'], bucket)

    directory = base_directory
    offset_directory = key.split('/')[:-1]
    if offset_directory:
        directory += '/' + ''.join(offset_directory)
    if not os.path.exists(directory):
        os.makedirs(directory)

    s3 = pacu.get_boto3_resource('s3')

    size = s3.Object(bucket, key).content_length
    if size > FILE_SIZE_THRESHOLD:
        pacu.print('  LARGE FILE DETECTED:')
        confirm = pacu.input('    Download {}? Size: {} bytes (y/n) '.format(key, size))
        if confirm != 'y':
            return False
    try:
        s3.Bucket(bucket).download_file(key, base_directory + key)
    except Exception as error:
        pacu.print('  {}'.format(error))
        return False
    return True


def extract_from_file(pacu, file):
    files = {}
    try:
        with open(file, 'r') as bucket_file:
            for line in bucket_file:
                delimiter = line.rfind('@')
                key = line[:delimiter]
                bucket = line[delimiter + 1:-1]
                files[key] = bucket
    except FileNotFoundError:
        pacu.print('  Download File not found...')
    return files


def write_bucket_keys_to_file(pacu, objects):
    pacu.print('  Writing file names to disk...')
    session = pacu.get_active_session()
    file = 'sessions/{}/downloads/{}/'.format(session.name, module_info['name'])
    if not os.path.exists(file):
        os.makedirs(file)
    file += '{}_file_names.txt'.format(module_info['name'])
    try:
        with open(file, 'w') as objects_file:
            for key in objects:
                for file in objects[key]:
                    objects_file.write('{}@{}\n'.format(file, key))
    except Exception as error:
        print(error)
    return True


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    if (args.names_only is True and args.dl_names is True) or (args.names_only is True and args.dl_all is True) or (args.dl_names is True and args.dl_all is True):
        print('Only zero or one options of --dl-all, --names-only, and --dl-names may be specified. Exiting...')
        return {}

    # Download Objects from File
    if args.dl_names:
        pacu_main.print('  Extracting files from file...')
        extracted_files = extract_from_file(pacu_main, args.dl_names)
        total = len(extracted_files.keys())
        success = 0
        for key in extracted_files:
            if download_s3_file(pacu_main, key, extracted_files[key]):
                success += 1
        pacu_main.print('  Finished downloading from file...')
        return {'downloaded_files': success, 'failed': total - success}

    # Enumerate Buckets
    client = pacu_main.get_boto3_client('s3')

    buckets = []
    print('Enumerating buckets...')
    try:
        response = client.list_buckets()
    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDenied':
            print('  FAILURE: MISSING AWS PERMISSIONS')
        else:
            print(code)
        return {}

    s3_data = deepcopy(session.S3)
    s3_data['Buckets'] = deepcopy(response['Buckets'])
    session.update(pacu_main.database, S3=s3_data)
    summary_data = {'buckets': len(response['Buckets'])}
    for bucket in response['Buckets']:
        buckets.append(bucket['Name'])
        print('  Found bucket "{bucket_name}"'.format(bucket_name=bucket['Name']))

    # Process Enuemrated Buckets
    print('Starting enumerating objects in buckets...')
    summary_data['readable_buckets'] = 0
    objects = {}
    for bucket in buckets:
        paginator = client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket)

        objects[bucket] = []
        try:
            for page in page_iterator:
                if 'Contents' in page:
                    keys = [key['Key'] for key in page['Contents']]
                    objects[bucket].extend(keys)
            summary_data['readable_buckets'] += 1
        except ClientError as error:
            print('  Unable to read bucket')
            code = error.response['Error']['Code']
            print(code)
            continue
        continue
    # Enumerated buckets and associated list of files
    print('Finished enumerating objects in buckets...')

    if args.names_only:
        write_bucket_keys_to_file(pacu_main, objects)
        return summary_data
    summary_data['downloaded_files'] = 0
    for bucket in objects:
        print('  Bucket: "{}" Size: {} Bytes'.format(bucket, get_bucket_size(pacu_main, bucket)))
        if input('    Download files (y/n)? ') != 'y':
            continue
        for key in objects[bucket]:
            if not args.dl_all:
                if input('  Download "{}" in "{}" (y/n)? '.format(key, bucket)) != 'y':
                    continue
            fails = 0
            ignore = False
            if not download_s3_file(pacu_main, key, bucket):
                fails += 1
            else:
                summary_data['downloaded_files'] += 1
            if not ignore and fails == 5:
                print('  5 files failed to download.')
                prompt = input('  Continue downloading attempts? (y/n) ')
                if prompt != 'y':
                    break
                ignore = True
    print('All buckets have been analyzed.')
    print('{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    out = ''
    if 'buckets' in data:
        out += '  {} total buckets found.\n'.format(data['buckets'])
    if 'readable_buckets' in data:
        out += '  {} buckets found with read permissions.\n'.format(data['readable_buckets'])
    if 'downloaded_files' in data:
        out += '  {} files downloaded.\n'.format(data['downloaded_files'])
    if 'failed' in data:
        out += '  {} files failed to be downloaded.\n'.format(data['failed'])
    if not out:
        return '  No actions were taken.'
    return out
