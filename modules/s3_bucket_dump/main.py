#!/usr/bin/env python3
import argparse
import boto3
import botocore
from botocore.exceptions import ClientError
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
    'description': 'This module scans the current account for AWS buckets and prints/stores as much data as it can about each one. With no arguments, this module will enumerate all buckets the account has access to, then prompt you to download all files in the bucket or not. Use --names-only or --dl-names to change that. The files will be downloaded to ./sessions/[current_session_name]/downloads/s3_dump/.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['S3'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--dl-all', '--names-only', '--dl-names'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--dl-all', required=False, action='store_true', help='If specified, automatically download all files from buckets that are allowed instead of asking for each one. WARNING: This could mean you could potentially be downloading terrabytes of data! It is suggested to user --names-only and then --dl-names to download specific files.')
parser.add_argument('--names-only', required=False, action='store_true', help='If specified, only pull the names of files in the buckets instead of downloading. This can help in cases where the whole bucket is a large amount of data and you only want to target specific files for download. This option will store the filenames in a .txt file in ./sessions/[current_session_name]/downloads/s3_dump/s3_bucket_dump_file_names.txt, one per line, formatted as "filename@bucketname". These can then be used with the "--dl-names" option.')
parser.add_argument('--dl-names', required=False, default=False, help='A path to a file that includes the only files to be downloaded, one per line. The format for these files must be "filename.ext@bucketname", which is what the --names-only argument outputs.')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    proxy_settings = pacu_main.get_proxy_settings()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    ######

    if (args.names_only is True and args.dl_names is True) or (args.names_only is True and args.dl_all is True) or (args.dl_names is True and args.dl_all is True):
        print('Only zero or one options of --dl-all, --names-only, and --dl-names may be specified. Exiting...')
        return

    client = boto3.client(
        's3',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    )

    s3 = boto3.resource(
        's3',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    )

    buckets = []
    names_and_buckets = None

    if args.dl_names is False:
        print('Finding existing buckets...')
        response = client.list_buckets()

        s3_data = deepcopy(session.S3)
        s3_data['Buckets'] = deepcopy(response['Buckets'])
        session.update(pacu_main.database, S3=s3_data)

        for bucket in response['Buckets']:
            buckets.append(bucket['Name'])
            print('  Found bucket "{bucket_name}".'.format(bucket_name=bucket['Name']))

    else:
        print('Found --dl-names argument, skipping bucket enumeration.')

        with open(args.dl_names, 'r') as files_file:
            names_and_buckets = files_file.read().split('\n')

            for item in names_and_buckets:
                if '@' in item:
                    supplied_bucket = item.split('@')[1]
                    buckets.append(supplied_bucket)

            buckets = list(set(buckets))  # Delete duplicates

        print('Relevant buckets extracted from the supplied list include:\n{}\n'.format('\n'.join(buckets)))

    print('Starting scan process...')

    for bucket in buckets:
        print(f'  Bucket name: "{bucket}"')

        bucket_download_path = f'sessions/{session.name}/downloads/s3_dump/{bucket}'

        try:
            print('    Checking read permissions...')
            response = client.list_objects_v2(
                Bucket=bucket,
                MaxKeys=10
            )

            if args.dl_all is False and args.names_only is False and args.dl_names is False:
                try_to_dl = input(f'      You have permission to read files in bucket {bucket}, do you want to attempt to download all files in it? (y/n) ')
                if try_to_dl == 'n':
                    print('      Skipping to next bucket.')
                    continue
            elif args.names_only is True:
                try_to_dl = 'n'
            else:
                try_to_dl = 'y'

        except ClientError:
            try_to_dl = 'n'
            print(f'      You do not have permission to view files in bucket {bucket}, skipping to next bucket.')
            continue

        if try_to_dl == 'y':
            try:
                print('    Attempting to download a test file...'.format(bucket))
                first_obj_key = response['Contents'][0]['Key']
                i = 0

                while first_obj_key[-1] == '/':
                    i += 1
                    first_obj_key = response['Contents'][i]['Key']

                if not os.path.exists('tmp/{}'.format(os.path.dirname(first_obj_key))):
                    os.makedirs('tmp/{}'.format(os.path.dirname(first_obj_key)))

                s3.meta.client.download_file(bucket, first_obj_key, f'tmp/{first_obj_key}')

                with open(f'tmp/{first_obj_key}', 'rb') as test_file:
                    test_file.read()

                print('      Test file has been downloaded to ./tmp and read successfully.')

            except Exception as error:
                print(error)
                print('      Test file has failed to be downloaded and read, skipping to next bucket.')
                continue

        s3_objects = []

        if args.dl_names is False:
            try:
                if not os.path.exists(bucket_download_path):
                    os.makedirs(bucket_download_path)

                response = None
                continuation_token = False
                print('    Finding all files in the bucket...')

                while (response is None or 'NextContinuationToken' in response):
                    if continuation_token is False:
                        response = client.list_objects_v2(
                            Bucket=bucket,
                            MaxKeys=100
                        )
                    else:
                        response = client.list_objects_v2(
                            Bucket=bucket,
                            MaxKeys=100,
                            ContinuationToken=continuation_token
                        )

                    if 'NextContinuationToken' in response:
                        continuation_token = response['NextContinuationToken']

                    for s3_obj in response['Contents']:
                        if s3_obj['Key'][-1] == '/':
                            s3_obj_key_path = os.path.join(bucket_download_path, s3_obj['Key'])
                            if not os.path.exists(s3_obj_key_path):
                                os.makedirs(s3_obj_key_path)
                        else:
                            s3_objects.append(s3_obj['Key'])

                print('      Successfully collected all available file names.')

            except Exception as error:
                print(error)
                print('      Failed to collect all available files, skipping to the next bucket...')
                continue

            file_names_list_path = f'sessions/{session.name}/downloads/s3_dump/s3_bucket_dump_file_names.txt'
            with open(file_names_list_path, 'w+') as file_names_list:
                for file in s3_objects:
                    file_names_list.write(f'{file}@{bucket}\n')
            print(f'    Saved found file names to ./{file_names_list_path}')

        else:
            print('    File names were supplied, skipping file name enumeration.')

        if args.names_only is False:
            print('    Starting to download files...')

            if args.dl_names is not False:
                for file in names_and_buckets:
                    if f'@{bucket}' in file:
                        s3_objects.append(file.split(f'@{bucket}')[0])

            failed_dl = 0
            cont = 'y'

            for key in s3_objects:
                if failed_dl > 4 and cont == 'y':
                    cont = input('    There have been 5 failed downloads in a row, do you want to continue and ignore this message for the current bucket (y) or move onto the next bucket (n)? ')

                if cont == 'y':
                    try:
                        print(f'      Downloading file {key}...')

                        nested_key_directory_path, file_name = os.path.split(key)
                        key_directory_path = os.path.join(bucket_download_path, nested_key_directory_path)

                        if not os.path.exists(key_directory_path):
                            os.makedirs(key_directory_path)

                        key_file_path = os.path.join(key_directory_path, file_name)
                        s3.meta.client.download_file(bucket, key, key_file_path)

                        print('        Successful.')
                        failed_dl = 0

                    except Exception as error:
                        print(error)
                        print('        Failed to download, moving onto next file.')
                        failed_dl += 1

    print('All buckets have been analyzed.')
    print(f"{module_info['name']} completed.\n")
    return
