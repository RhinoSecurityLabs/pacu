#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import random, string

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
group_accounts = parser.add_mutually_exclusive_group()
group_roles = parser.add_mutually_exclusive_group()

group_accounts.add_argument('--accounts', required=False, nargs='+', default=None,  help='Pass in a list of accounts to try assuming, --accounts 1 2 3')
group_accounts.add_argument('--accounts-file', required=False, nargs=1, default=None, help="Pass in a filename containing a list of accounts to try assuming")
group_roles.add_argument('--roles', required = False, nargs = '+', default=None,  help='Pass in a list of roles to try assuming. If non are specified uses default OrganizationAccountAccessRole, --roles a b c')
group_roles.add_argument('--roles-file', required=False, nargs=1, default=None, help='Pass in a filename containing a list of roles to try assuming')


roles_list = []

def assume_role(args, client, role_arn):
    global roles_list
    try:
        resp = client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=''.join(random.choice(string.ascii_letters) for _ in range(20)),
        )
        roles_list.append(role_arn)
        print("SUCCESS: " + role_arn)
        

    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDenied':
            print("FAILURE: "+role_arn)
        else:
            print('DEFAULT FAILURE: {}'.format(code))


# Main is the first function that is called when this module is executed.
def main(args, pacu_main):

    session = pacu_main.get_active_session()
    client = pacu_main.get_boto3_client('sts')

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    accounts = []
    roles = ["OrganizationAccountAccessRole"]
    
    # If user did not specify an account to try brute forcing, then try pre-requisite
    if not args.accounts and not args.accounts_file:
        if fetch_data(['Organizations'], 'organizations__enum', '--accounts') is False:
            print("Prerequisite module was not run. Exiting...")
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
            assume_role(args, client, role_arn)


    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    data = roles_list
    return data

def summary(data, pacu_main):
    if len(data) == 0:
        return "No roles were found that could be assumed"
    else:
        summary = 'The following roles can be assumed as shown below:'
        for arn in data:
            summary = summary + "\nassume_role " + str(arn)
        return summary
