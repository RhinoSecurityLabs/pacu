#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import datetime
from copy import deepcopy
import os


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 's3_bucket_dump',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerate and dumps files from S3 buckets.',

    # Description about what the module does and how it works
    'description': 'This module scans the current account for AWS buckets and prints/stores as much data as it can about each one. With no arguments, this module will enumerate all buckets the account has access to, then prompt you to download all files in the bucket or not. Use --names-only or --dl-names to change that. The files will be downloaded to ./sessions/[current_session_name]/downloads/s3_bucket_dump/.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['S3'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--dl-all', '--names-only', '--dl-names'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--dl-all', required=False, action='store_true', help='If specified, automatically download all files from buckets that are allowed instead of asking for each one. WARNING: This could mean you could potentially be downloading terrabytes of data! It is suggested to user --names-only and then --dl-names to download specific files.')
parser.add_argument('--names-only', required=False, action='store_true', help='If specified, only pull the names of files in the buckets instead of downloading. This can help in cases where the whole bucket is a large amount of data and you only want to target specific files for download. This option will store the filenames in a .txt file in ./sessions/[current_session_name]/downloads/s3_bucket_dump/s3_bucket_dump_file_names.txt, one per line, formatted as "filename@bucketname". These can then be used with the "--dl-names" option.')
parser.add_argument('--dl-names', required=False, default=False, help='A path to a file that includes the only files to be downloaded, one per line. The format for these files must be "filename.ext@bucketname", which is what the --names-only argument outputs.')

FILE_SIZE_THRESHOLD = 1073741824
FILE_SIZE_THRESHOLD = 1000

def get_bucket_size(pacu, bucket_name):
    client = pacu.get_boto3_client('cloudwatch', 'us-east-1')
    response = client.get_metric_statistics(Namespace='AWS/S3',
                                        MetricName='BucketSizeBytes',
                                        Dimensions=[
                                            {'Name': 'BucketName', 'Value':bucket_name},
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
    base_directory = 'sessions/{}/downloads/s3_bucket_dump/{}/'.format(session.name, bucket)
    
    directory = base_directory
    offset_directory = key.split('/')[:-1]
    if offset_directory:
        directory += '/' + ''.join(offset_directory)
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    s3 = pacu.get_boto3_resource('s3')

    size = s3.Object(bucket, key).content_length
    if size > FILE_SIZE_THRESHOLD:
        confirm = pacu.input('  Download {}? Size: {} bytes (y/n) '.format(key, size))
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
    except FileNotFoundError as error:
        pacu.print('  Download File not found...')
    return files

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    if (args.names_only is True and args.dl_names is True) or (args.names_only is True and args.dl_all is True) or (args.dl_names is True and args.dl_all is True):
        print('Only zero or one options of --dl-all, --names-only, and --dl-names may be specified. Exiting...')
        return

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
        return {'downloaded_files':success, 'failed':total - success}

    # Enumerate Buckets
    client = pacu_main.get_boto3_client('s3')
    s3 = pacu_main.get_boto3_resource('s3')

    buckets = []
    print('Enumerating buckets...')
    response = client.list_buckets()

    s3_data = deepcopy(session.S3)
    s3_data['Buckets'] = deepcopy(response['Buckets'])
    session.update(pacu_main.database, S3=s3_data)
    summary_data = {'buckets':len(response['Buckets'])}
    for bucket in response['Buckets']:
        buckets.append(bucket['Name'])
        print('  Found bucket "{bucket_name}"'.format(bucket_name=bucket['Name']))

    # Process Enuemrated Buckets
    print('Starting scan process...')
    summary_data['readable_buckets'] = 0
    objects = {}
    for bucket in buckets:
        print('  Bucket: "{}" Size: {} Bytes'.format(bucket, get_bucket_size(pacu_main, bucket)))
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
    print(objects)
    return summary_data

        
        #bucket_download_path = 'sessions/{}/downloads/s3_bucket_dump/{}'.format(session.name, bucket)

        #try:
        #    print('    Checking read permissions...')
        #    response = client.list_objects_v2(
        #        Bucket=bucket,
        #        MaxKeys=10
        #    )

        #    if args.dl_all is False and args.names_only is False and args.dl_names is False:
        #        summary_data['readable_buckets'] += 1
        #        try_to_dl = input('      You have permission to read files in bucket {}, do you want to attempt to download all files in it? (y/n) '.format(bucket))
        #        if try_to_dl == 'n':
        #            print('      Skipping to next bucket.')
        #            continue
        #    elif args.names_only is True:
        #        try_to_dl = 'n'
        #    else:
        #        try_to_dl = 'y'

        #except ClientError:
        #    try_to_dl = 'n'
        #    print('      You do not have permission to view files in bucket {}, skipping to next bucket.'.format(bucket))
        #    continue

        #if try_to_dl == 'y':
        #    try:
        #        print('    Attempting to download a test file...'.format(bucket))
        #        first_obj_key = response['Contents'][0]['Key']
        #        i = 0

        #        while first_obj_key[-1] == '/':
        #            i += 1
        #            first_obj_key = response['Contents'][i]['Key']

        #        if not os.path.exists('tmp/{}'.format(os.path.dirname(first_obj_key))):
        #            os.makedirs('tmp/{}'.format(os.path.dirname(first_obj_key)))

        #        s3.meta.client.download_file(bucket, first_obj_key, 'tmp/{}'.format(first_obj_key))
        #        summary_data['download_files'] += 1

        #        with open('tmp/{}'.format(first_obj_key), 'rb') as test_file:
        #            test_file.read()

        #        print('      Test file has been downloaded to ./tmp and read successfully.')

        #    except Exception as error:
        #        print(error)
        #        print('      Test file has failed to be downloaded and read, skipping to next bucket.')
        #        continue

        #s3_objects = []

        #if args.dl_names is False:
        #    try:
        #        if not os.path.exists(bucket_download_path):
        #            os.makedirs(bucket_download_path)

        #        response = None
        #        continuation_token = False
        #        print('    Finding all files in the bucket...')

        #        while (response is None or 'NextContinuationToken' in response):
        #            if continuation_token is False:
        #                response = client.list_objects_v2(
        #                    Bucket=bucket,
        #                    MaxKeys=100
        #                )
        #            else:
        #                response = client.list_objects_v2(
        #                    Bucket=bucket,
        #                    MaxKeys=100,
        #                    ContinuationToken=continuation_token
        #                )

        #            if 'NextContinuationToken' in response:
        #                continuation_token = response['NextContinuationToken']

        #            for s3_obj in response['Contents']:
        #                if s3_obj['Key'][-1] == '/':
        #                    s3_obj_key_path = os.path.join(bucket_download_path, s3_obj['Key'])
        #                    if not os.path.exists(s3_obj_key_path):
        #                        os.makedirs(s3_obj_key_path)
        #                else:
        #                    #if s3_obj['Size'] > FILE_SIZE_THRESHOLD:
        #                    #    response = input('   Download {} bytes file? (y/n) '.format(s3_obj['Size']))
        #                    #    if response != 'y':
        #                    #        continue
        #                    s3_objects.append(s3_obj['Key'])

        #        print('      Successfully collected all available file names.')

        #    except Exception as error:
        #        print(error)
        #        print('      Failed to collect all available files, skipping to the next bucket...')
        #        continue

        #    file_names_list_path = 'sessions/{}/downloads/s3_bucket_dump/s3_bucket_dump_file_names.txt'.format(session.name)
        #    with open(file_names_list_path, 'w+') as file_names_list:
        #        for file in s3_objects:
        #            file_names_list.write('{}@{}\n'.format(file, bucket))
        #    print('    Saved found file names to ./{}'.format(file_names_list_path))

        #else:
        #    print('    File names were supplied, skipping file name enumeration.')

        #if args.names_only is False:
        #    print('    Starting to download files...')

        #    if args.dl_names is not False:
        #        for file in names_and_buckets:
        #            if '@{}'.format(bucket) in file:
        #                s3_objects.append(file.split('@{}'.format(bucket))[0])

        #    failed_dl = 0
        #    cont = 'y'

        #    for key in s3_objects:
        #        if failed_dl > 4 and cont == 'y':
        #            cont = input('    There have been 5 failed downloads in a row, do you want to continue and ignore this message for the current bucket (y) or move onto the next bucket (n)? ')

        #        if cont == 'y':
        #            try:
        #                print('      Downloading file {}...'.format(key))

        #                nested_key_directory_path, file_name = os.path.split(key)
        #                key_directory_path = os.path.join(bucket_download_path, nested_key_directory_path)

        #                if not os.path.exists(key_directory_path):
        #                    os.makedirs(key_directory_path)

        #                key_file_path = os.path.join(key_directory_path, file_name)
        #                s3.meta.client.download_file(bucket, key, key_file_path)
        #                summary_data['downloaded_files'] += 1

        #                print('        Successful.')
        #                failed_dl = 0

        #            except Exception as error:
        #                print(error)
        #                print('        Failed to download, moving onto next file.')
        #                failed_dl += 1

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
    return out
