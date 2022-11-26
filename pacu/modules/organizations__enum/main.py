#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import graphviz

# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'organizations__enum',

    # Name and any other notes about the author.
    'author': 'Scott (@WebbinRoot:/in/webbinroot/), most of template (minus recursive graph) taken from Spencer Gietzen\'s glue__enum module',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'Enumerates AWS Organizations entities and shows tree of OUs and acounts at the end',

    # Full description about what the module does and how it works.
    'description': 'Module tries to list a bunch of different organization resources like accounts, policies, etc. Also builds a nice graph at the end to visually see relationship between root, accounts, and organizational units. Note you need permissions to list each of these in order to make the tree. Also note that you might need to be the "manager" account (as opposed to a member) for some of these APIs to work.',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['Organizations'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab.
    'arguments_to_autocomplete': [],
}

dot = None


# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--description', required=False, default=False, action='store_true',  help='Get overview of org')
parser.add_argument('--roots', required = False, default=False, action='store_true',  help='List Roots in org')
parser.add_argument('--policies', required = False, default=False, action='store_true',  help='List Policies in org')
parser.add_argument('--accounts', required=False, default=False, action='store_true',  help='List Accounts in org')
parser.add_argument('--organizational-units', required=False, default=False, action='store_true', help='List Organizational Units in org')
parser.add_argument('--enabled-services', required=False, default=False, action='store_true', help='List Enabled Service Access in org')
parser.add_argument('--delegated-admins', required=False, default=False, action='store_true', help='List Delegated Administrators in org')
parser.add_argument('--tree', required=False, default=False, action='store_true', help='Generate visual tree using root, accounts, and OUs')


def fetch_org_data(client, func, key, print, **kwargs):
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        data = response[key]

        while 'NextToken' in response and response['NextToken'] != '':
            print({**kwargs, **{'NextToken': response['NextToken']}})
            response = caller({**kwargs, **{'NextToken': response['NextToken']}})
            data.extend(response[key])

        return data

    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('  {} FAILURE: MISSING NEEDED PERMISSIONS'.format(func))
        else:
            print(code)
    return []

# Recursive build for tree
def create_tree(client, print, parent_node):

    parent_node_id, parent_node_name = parent_node["Id"], parent_node["Name"]
    parent_node_title = parent_node_name+" ("+parent_node_id+")"

    # Add root or OU node
    color = "red" if parent_node_name == "Root" else "orange"
    dot.node(parent_node_title, color=color, style="filled")

    # Get list of accounts under OU or Root
    accounts = fetch_org_data(client, 'list_accounts_for_parent', 'Accounts', print, ParentId=parent_node_id)
    for account in accounts:
        dot.node(account["Name"]+" ("+account["Id"]+")", color="green",style="filled")
        dot.edge(parent_node_title, account["Name"]+" ("+account["Id"]+")")
        
    org_units = fetch_org_data(client, 'list_organizational_units_for_parent', 'OrganizationalUnits', print, ParentId = parent_node_id)
    if len(org_units) == 0:
        pass
    else:
        for org in org_units:
            dot.node(org["Name"]+" ("+org["Id"]+")", color="green",style="filled")
            dot.edge(parent_node_title, org["Name"]+" ("+org["Id"]+")")
            create_tree(client, print, org)

# Recursive get for org;
def get_org_units(client, print, parent_node, starting_orgs):
    parent_node_id, parent_node_name = parent_node["Id"], parent_node["Name"]   
    org_units = fetch_org_data(client, 'list_organizational_units_for_parent', 'OrganizationalUnits', print, ParentId = parent_node_id)
    if len(org_units) == 0:
        pass
    else:
        for org in org_units:
            starting_orgs.append(org)
            get_org_units(client, print, org, starting_orgs=starting_orgs)
    return starting_orgs



# Main is the first function that is called when this module is executed.
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    if True not in [ args.description, args.accounts, args.policies, args.roots, args.organizational_units, args.enabled_services, args.delegated_admins]:
        args.description = args.accounts = args.policies = args.roots = args.organizational_units = args.enabled_services = args.delegated_admins = args.tree = True

    all_description = []
    all_accounts = []
    all_policies = []
    all_roots = []
    all_org_units = []
    all_enabled_services = []
    all_delegated_admins = []

    client = pacu_main.get_boto3_client('organizations')

    # General Description
    if args.description:
        description = [fetch_org_data(client, 'describe_organization', 'Organization', print)]
        print('{} general info(s) found.'.format(len(description)))
        all_description += description
    
    # Accounts
    if args.accounts:
        accounts = fetch_org_data(client, 'list_accounts', 'Accounts', print)
        print('{} accounts (s) found.'.format(len(accounts)))
        all_accounts += accounts

    # Policies 
    if args.policies:
        for policy_filter in ["AISERVICES_OPT_OUT_POLICY", "BACKUP_POLICY", "SERVICE_CONTROL_POLICY", "TAG_POLICY"]:
            policies = fetch_org_data(client, 'list_policies', 'Policies', print, Filter=policy_filter)
            print('{} polices of type {} found.'.format(len(policies), policy_filter))
            all_policies += policies


    # Roots
    if args.roots:
        roots = fetch_org_data(client, 'list_roots', 'Roots', print)
        print('{} root(s) found.'.format(len(roots)))
        all_roots += roots

    # Delegated Admins
    if args.delegated_admins:
        delegated_admins = fetch_org_data(client, 'list_delegated_administrators', 'DelegatedAdministrators', print)
        print('{} delegated administrator(s) found.'.format(len(delegated_admins)))
        all_delegated_admins += delegated_admins

    # Organizational Units (no list function, have to check graph)
    if args.organizational_units:
        current_scoped_targets = all_roots
        for root in all_roots:
            all_org_units = get_org_units(client, print, root, starting_orgs = [])
                
        print('{} organizational unit(s) found.'.format(len(all_org_units)))

    # Enabled Services
    if args.enabled_services:
        enabled_services = fetch_org_data(client, 'list_aws_service_access_for_organization', 'EnabledServicePrincipals', print)
        print('{} enabled service(s) found.'.format(len(enabled_services)))
        all_enabled_services += enabled_services


    # Note need root, accounts, and OUs to do this assessment
    if args.tree:
        print("Trying to create tree of all collected so far")
        
        all_roots = fetch_org_data(client, 'list_roots', 'Roots', print)
        for root in all_roots:

            global dot 
            dot = graphviz.Digraph(comment="Organization Hierarchy for Root "+root["Id"])

            create_tree(client, print, root)
            dot.render(directory="GraphOutput/"+root["Id"])

        print("New Organization Chart Created at ./GraphOutput/"+root["Id"])
 

    summary_data = {
        'overviews': len(all_description),
        'accounts': len(all_accounts),
        'policies': len(all_policies),
        'roots': len(all_roots),
        'organizational units': len(all_org_units),
        'enabled services': len(all_enabled_services),
        'delegated admins': len(all_delegated_admins)
    }

    org_data = deepcopy(session.Organizations)
    org_data['Overview'] = all_description
    org_data['Accounts'] = all_accounts
    org_data['Policies'] = all_policies
    org_data['Organizational Units'] = all_org_units
    org_data['Enabled Services'] = all_enabled_services
    org_data['Delegated Administrators'] = all_delegated_admins
    session.update(pacu_main.database, Organizations=org_data)

    # Trim out things we don't want as specifying flags makes summary empty
    for var in vars(args):
        if not getattr(args, var):
            del summary_data[var]
   
    return summary_data


def summary(data, pacu_main):
    out = ''
    for key in data:
        out += '  {} total {}(s) found.\n'.format(data[key], key[:-1])
    out += '\n  Organization resources saved in Pacu database.\n'
    return out

