#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import boto3, random, string



# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'organizations__assume_role',

    # Name and any other notes about the author.
    'author': 'Scott (@WebbinRoot:/in/webbinroot/)',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'LATERAL_MOVE',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'Tries to assume any roles in a member account in a given organization',

    # Full description about what the module does and how it works.
    'description': 'This module accepts a list of AWS accounts and possible role names to try assuming all roles. You can choose to specify accounts/roles to run it against, or just running the module will use the default role in organizations on whatever accounts it can gain from a call to list_accounts. Note the caller MUST have AssumeRole rights for this module to work correctly.',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['Organizations'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    'prerequisite_modules': ['organizations__enum'],

    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab.
    'arguments_to_autocomplete': ['accounts','accounts-file','roles','roles-file'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--accounts', required=False, nargs='+', default=None,  help='Pass in a list of accounts to try assuming, --accounts 1 2 3')
parser.add_argument('--accounts-file', required=False, nargs=1, default=None, help="Pass in a filename containing a list of accounts to try assuming")
parser.add_argument('--roles', required = False, nargs = '+', default=None,  help='Pass in a list of roles to try assuming. If non are specified uses default OrganizationAccountAccessRole, --roles a b c')
parser.add_argument('--roles-file', required=False, nargs=1, default=None, help='Pass in a filename containing a list of roles to try assuming')
#parser.add_argument('--create-sessions', required=False, action="store_true", help='Will automatically create a session for every successful AssumeRole operation. Can check all of them after with swap_keys command.')

roles_list = []

def assume_role(args, session, role_arn):
    global roles_list
    sts = boto3.client('sts')
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=''.join(random.choice(string.ascii_letters) for _ in range(20)),
        )
        roles_list.append(role_arn)
        print("SUCCESS: " + role_arn)
        
        # See if I can create a key set automatically in background
        #if args.create_sessions:

        #    print("CREATING KEYS FOR: " + role_arn)
        #    new_key_name = f"{resp['AssumedRoleUser']['Arn']}"
        #    aws.create_session
        #    session.set_keys(
        #        key_alias=new_key_name,
        #        access_key_id=resp['Credentials']['AccessKeyId'],
        #        secret_access_key=resp['Credentials']['SecretAccessKey'],
        #        session_token=resp['Credentials']['SessionToken'],
        #    )
        #else:
        #    pass

    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDenied':
            print("FAILURE: "+role_arn)
        else:
            print('(DEFAULT FAILURE: {}'.format(code))


# Main is the first function that is called when this module is executed.
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    accounts = []
    roles = ["OrganizationAccountAccessRole"]
    
    if args.accounts and args.accounts_file:
        print("You must choose either accounts or the accounts-file argument or neither, you cannot choose both")
    if args.roles and args.roles_file:
        print("You must choose either roles or roles-file or neither, you cannot choose both")

    # If user did not specify an account to try brute forcing, then try pre-requisite
    if not args.accounts and not args.accounts_file:
        if fetch_data(['Organizations'], 'organizations__enum', '--accounts') is False:
            return
        accounts = session.Organizations['Accounts']

    # Accounts Set
    if args.accounts:
        accounts = args.accounts
    elif args.accounts_file:
        f = open(args.accounts_file[0],"r")
        accounts = f.read().splitlines()
    
    # Roles Set
    if args.roles:
        roles = args.roles
    elif args.roles_file:
        f = open(args.roles_file[0],"r")
        roles = f.read().splitlines()

    # Go through each AWS account and each role in wordlist or default and try to assume it
    for account in accounts:

        # Accounts from internal Pacu database are dictionaries 
        if isinstance(account, dict) and "Id" in account:
            account = account["Id"]

        for role in roles:
            role_arn = "arn:aws:iam::"+str(account)+":role/"+str(role)
            assume_role(args, session, role_arn)


    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    data = roles_list
    return data

def summary(data, pacu_main):
    if len(data) == 0:
        return "No roles were found that could be assumed"
    else:
        summary = 'The following roles can be assumed as shown below:'
        for vuln in data:
            summary = summary + "\nassume_role " + str(vuln)
        return summary
