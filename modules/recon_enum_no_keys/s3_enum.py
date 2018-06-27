#!/usr/bin/env python3
import argparse
from functools import partial
import logging
import os
from queue import Queue
import subprocess
from threading import Thread

from pacu import util


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 's3_enum',

    # Name and any other notes about the author
    'author': 'Dwight Hohnstein of Rhino Security Labs',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates/bruteforces S3 buckets based on different parameters.',

    # Description about what the module does and how it works
    'description': 'This module searches across every AWS region for a variety of bucket names based on a domain name, subdomains, affixes given and more. Currently the tool will only present to you whether or not the bucket exists or if they are listable.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['S3'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [
        'https://github.com/aboul3la/Sublist3r.git',
        'https://raw.githubusercontent.com/RhinoSecurityLabs/Security-Research/master/tools/aws-pentest-tools/s3/Buckets.txt'
    ],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [
        '-f', '--file',
        '-r', '--regions',
        '-b', '--brute',
        '-t', '--threads',
        '-g', '--grep',
        '--sublist3r',
        '--subbrute',
        '-d', '--domain',
        '-v', '--verbose'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

# Arguments that accept multiple options (such as --usernames) should be comma-separated (such as --usernames bill,mike,tom)
# Arguments that are region-specific (such as --instance-ids) should use an @ symbol to separate the data and its region (such as --instance-ids 123@us-west-1,54252@us-east-1,9999@ap-south-1
parser.add_argument('-f', '--file', help='Read affixes from FILE.')
parser.add_argument('-r', '--regions', default='all', help='Comma separated list of regions to query for bucket names. Default is all.')
parser.add_argument('-b', '--brute', action='store_true', help='Use default brute force list in Buckets.txt')
parser.add_argument('-t', '--threads', default=6, help='Max number of threads, default is 6.')
parser.add_argument('-g', '--grep', help='Will recursively list files from buckets (when listable) and grep for keywords FILE. Ex: -g sensitive_keywords.txt')
parser.add_argument('--sublist3r', action='store_true', default=False, help='Retrieve list of subdomains and use this to query against S3.')
parser.add_argument('--subbrute', action='store_true', default=False, help='Enable sublist3r\'s subbrute module when querying for subdomains.')
parser.add_argument('-d', '--domain', help='Base domain to be queried against.', required=True)
parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug messages in logs.')

bucket_q = Queue()
bucket_q_size = 0

# Bucketlist to sort buckets based on permissions.
bucketlist = {
    'exists': [],
    'listable': [],
}

# Subdomain var to keep track of sublist3r results.
subdomains = []

G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white


def help():
    return [module_info, parser.format_help()]


def main(args, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    get_regions = partial(util.get_regions, database=database)
    install_dependencies = partial(util.install_dependencies, database=database)
    ######

    # Make sure that this only includes regions that are available for the service you are working with. Some services don't require a region at all
    regions = get_regions('s3')

    # Attempt to install the required external dependencies, exit this module if that fails
    if not install_dependencies(module_info['external_dependencies']):
        return

    # List of affixes to append to domain.com and domain in the form of affix.domain.com and affix-domain
    affixes = []

    # Read default keyword list if bruteforcing
    if args.brute:
        with open('./dependencies/Buckets.txt', 'r') as f:
            affixes += [x.strip() for x in f.readlines()]
    # Read filename of user-provided keywords
    elif args.file:
        with open(args.file, 'r') as f:
            affixes += [x.strip() for x in f.readlines()]
    else:
        affixes = []

    # if args.sublister:
    #     from Sublist3r import sublist3r
    #     subdomains = sublist3r.main(args.domain, 30, None, None, False, verbose=True, enable_bruteforce=args.subbrute, engines=None)

    print('Generating bucket permutations list...')
    buckets = create_bucket_list(args.domain, affixes=affixes)

    # for subdomain in subdomains:
    #     subucks = create_bucket_list(subdomain, affixes=affixes)
    #     buckets = buckets.union(subucks)

    for region in regions:
        for bucket in buckets:
            bucket_q.put((region, bucket))

    print(f'Generated {len(buckets)} bucket permutations. Beginning search across {len(regions)} regions.')

    global bucket_q_size
    bucket_q_size = bucket_q.qsize()

    for i in range(args.threads):
        t = Thread(target=bucket_worker, args=())
        t.daemon = True
        t.start()

    bucket_q.join()

    print('')
    print('[+] Results:')
    print(f"    {Y}Number of Buckets that Exist: {len(bucketlist['exists'])}{W}")
    print(f"    {G}Number of Buckets that are Listable: {len(bucketlist['listable'])}{W}")

    if args.grep and bucketlist['listable']:
        print(f'[.] Grepping for keywords in listable buckets from {args.grep}')

        with open(args.grep, 'r') as file:
            keywords = [x.strip().lower() for x in file.readlines() if x.strip()]

        for domain, region in bucketlist['listable']:
            command = f'aws s3 ls s3://{domain}/ --region {region} --recursive'
            command = command.split(' ')
            # with open(os.devnull, 'w') as FNULL:
            output = subprocess.run(command, shell=True, stderr=None)
            output = output.lower()
            if any(x in output for x in keywords):
                print(f'[!] Found sensitive file on bucket {domain} in region {region}')

    print(f'\n{os.path.basename(__file__)} completed.')
    return


def create_bucket_list(domain, affixes=[]):
    """
    Create a set of buckets based on a domain name and a list of affixes.
    Note: This will be very large.

    Args:
        domain   (str): Domain to add affixes to, such as google.com
        regions (list): List of AWS regions to query against.
        affixes (list): List of affixes to prefix and suffix to domain.

    Returns:
        set: Set of domain permutations.

    Example:
        > buckets = create_bucket_list("google.com", ["01"])
        > buckets
        ["google.com", "google", "01.google.com", "01.google", "01-google",
        "01google", "01google.com", "google-01", "google01"]
    """
    perms = set()
    # add domain
    perms.add(domain)
    rootword = '.'.join(domain.split('.')[:-1])
    # add rootword
    perms.add(rootword)
    for affix in affixes:
        # affix.domain
        perms.add(f'{affix}.{domain}')
        # affix.rootword
        perms.add(f'{affix}.{rootword}')
        # affix-rootword
        perms.add(f'{affix}-{rootword}')
        # affixdomain
        perms.add(f'{affix}{domain}')
        # affixrootword
        perms.add(f'{affix}{rootword}')
        # rootword-affix
        perms.add(f'{rootword}-{affix}')
        # rootwordaffix
        perms.add(f'{rootword}{affix}')
    return perms


def bucket_worker():
    """
    Wrapper to fetch items from queue and query s3
    """
    while not bucket_q.empty():
        region, bucket = bucket_q.get(timeout=5)
        currcount = bucket_q_size - bucket_q.qsize()
        percentile = round((float(currcount) / float(bucket_q_size)) * 100, 2)

        print(f'Buckets searched: {percentile}% ({currcount}/{bucket_q_size})', end='\r')

        try:
            ls_s3(region, bucket)
        except subprocess.CalledProcessError:
            pass

        bucket_q.task_done()


def ls_s3(region, domain):
    """
    Takes a region and domain to query awscli and determine if the
    bucket exists or is listable. Pushes results to bucketlist
    dictionary.

    Args:
        region (str): One of the AWS regions specified in settings.py
        domain (str): Domain to target with s3://domain/

    Returns:
        None: No return value as it populates bucketlist
    """
    fails = ['InvalidBucketName', 'NoSuchBucket', 'PermanentRedirect', 'InvalidURI']
    exists = ['AllAccessDisabled', 'AccessDenied', 'InvalidAccessKeyId', 'NoSuchBucketPolicy']

    command = f'aws s3 ls s3://{domain}/ --region {region}'

    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('utf-8')

    logging.debug(f'Running command: {command}')
    logging.debug(f'Output was:\n{output}')

    if not any(x in output for x in fails):
        info = (domain, region)
        if any(x in output for x in exists):
            bucketlist['exists'].append(info)
            print(f'[E] {Y}{domain} {W}on {Y}{region} {W}exists.\n')
            logging.info(f"[EXISTS] {command}\n{output}\n{'-' * 10}\n")
        else:
            bucketlist['exists'].append(info)
            bucketlist['listable'].append(info)
            print(f'[L] {G}{domain} {W}on {G}{region} {W}is listable.\n')
            logging.info(f"[LISTABLE] {command}\n{output}\n{'-' * 10}\n")
