#!/usr/bin/env python3
import boto3, argparse, os, sys, re
from botocore.exceptions import ClientError
from functools import partial

from pacu import util

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'sysman_ec2_rce',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Tries to execute code as root/SYSTEM on EC2 instances.',

    # Full description about what the module does and how it works
    'description': 'This module tries to execute arbitrary code on EC2 instances as root/SYSTEM using EC2 Systems Manager. To do so, it will first try to enumerate EC2 instances that are running operating systems that have the Systems Manager agent installed by default. Then, it will attempt to find the Systems Manager IAM instance profile, or try to create it if it can\'t find it. If successful, it will try to attach it to the instances enumerated earlier. Then it will use EC2 Run Command to execute arbitrary code on the EC2 instances as either root (Linux) or SYSTEM (Windows). By default, this module will execute a PacuProxy stager on the host to give you remote shell access, as well as a PacuProxy agent to route commands through.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_ec2'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


def help():
    return [module_info, parser.format_help()]


def main(args, database):
    session = util.get_active_session(database)

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = partial(util.print, session_name=session.name, database=database)
    input = partial(util.input, session_name=session.name, database=database)
    key_info = partial(util.key_info, database=database)
    fetch_data = partial(util.fetch_data, database=database)
    get_regions = partial(util.get_regions, database=database)
    ######

    if fetch_data(['EC2', 'Instances'], 'enum_ec2', '--instances') is False:
        print('Pre-req module not run successfully. Exiting...')
        return
    instances = session.EC2['Instances']

    # Images
    try:
        client = boto3.client(
            'ec2',
            region_name='us-east-1',
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token
        )
        dryrun = client.describe_images(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_images". Operating system enumeration is no longer trivial.\n')

    regions = get_regions('EC2')

    os_with_default_ssm_agent = [
        '[\s\S]*Windows[\s\S]*Server[\s\S]*2016[\s\S]*',
        '[\s\S]*Amazon[\s\S]*Linux[\s\S]*',
        '[\s\S]*Ubuntu[\s\S]*Server[\s\S]*18\\.04[\s\S]*LTS[\s\S]*'
        #'Windows Server 2003-2012 R2 released after November 2016'
    ]

    for region in regions:
        image_ids = []
        print('Starting region {}...\n'.format(region))
        client = boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token
        )

        for instance in instances:
            if instance['Region'] == region:
                image_ids.append(instance['ImageId'])

        # Describe all images being used in the environment
        images = client.describe_images(
            ImageIds=list(set(image_ids))
        )['Images']

        session.EC2['Images'] = images

        vuln_images = []

        # Iterate images and determine if they are possibly one of the operating systems with SSM agent installed by default
        for image in images:
            os_details = '{} {} {}'.format(image['Description'], image['ImageLocation'], image['Name'])
            for vuln_os in os_with_default_ssm_agent:
                result = re.match(r'{}'.format(vuln_os), os_details)
                if result is not None:
                    vuln_images.append(image['ImageId'])
                    break
        print('Vuln images: {}'.format(vuln_images))


    print('{} completed.'.format(os.path.basename(__file__)))
    return
