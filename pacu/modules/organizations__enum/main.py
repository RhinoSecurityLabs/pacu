#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy

# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'organizations__enum',

    # Name and any other notes about the author.
    'author': 'Scott (@WebbinRoot:/in/webbinroot/), some of base template from Spencer Gietzen\'s glue__enum module',

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
parser.add_argument('--delegated-services', required=False, default=False, nargs='*', help='List Delegated Services in org per account ID. If necessary manualy pass in organization IDs.')
parser.add_argument('--delegation-policy', required = False, default=False, action='store_true',  help='Get Organization Resource-Based Delegation Policy')
parser.add_argument('--tree', required=False, default=False, nargs='?', help='Generate visual tree using root, accounts, and OUs')

paginated_operations = [
    "list_accounts",
    "list_accounts_for_parent",
    "list_aws_service_access_for_organization",
    "list_children",
    "list_create_account_status",
    "list_delegated_administrators",
    "list_delegated_services_for_account",
    "list_handshakes_for_account",
    "list_handshakes_for_organization",
    "list_organizational_units_for_parent",
    "list_parents",
    "list_policies",
    "list_policies_for_target",
    "list_roots",
    "list_tags_for_resource",
    "list_targets_for_policy"
]

def fetch_org_data(client, func, key, print, **kwargs):
    try:
        if func in paginated_operations:
            
            response = []
            paginator = client.get_paginator(func)
            page_iterator = paginator.paginate(**kwargs)
            for page in page_iterator:
                response += page[key]
            return response
          
    
        else:
            caller = getattr(client, func)
            response = caller(**kwargs)
            return response[key]

    except ClientError as error:
        code = error.response['Error']['Code']
        
        if code == 'AccessDeniedException':
            print('({}) PERMISSION FAILURE: MISSING NEEDED PERMISSIONS'.format(func))
        
        elif code == 'AccountNotRegisteredException' and func == 'list_delegated_services_for_account':
            print('({}) LOGIC FAILURE: AWS ACCOUNT NOT DELEGATED ADMINISTRATOR'.format(func)) 
        
        else:
            print('({}) DEFAULT FAILURE: {}'.format(func, code))
    
    except Exception as error:
            print('({}) UNABLE TO EXECUTE DUE TO GENERIC FAILURE: {}'.format(func, error))

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
    
    # None is --tree with no argument
    args.tree = True if args.tree == None else args.tree
    args.delegated_services = True if args.delegated_services == [] else args.delegated_services

    # If all false, set all to true for following checks
    if True not in [ args.description, args.accounts, args.policies, args.roots, args.organizational_units, args.enabled_services, args.delegated_admins, bool(args.delegated_services), bool(args.tree), args.delegation_policy]:

        args.description = args.accounts = args.policies = args.roots = args.organizational_units = args.enabled_services = args.delegated_admins = args.delegated_services = args.tree = args.delegation_policy = True
        
        # If empty list passed in retain that value for later
        #args.delegated_services = True if args.delegated_services == None else args.delegated_services

    all_description = []
    all_roots = []
    all_policies = []
    all_accounts = []
    all_org_units = []
    all_enabled_services = []
    all_delegated_admins = []
    all_delegated_services = []
    all_delegation_policy = []

    client = pacu_main.get_boto3_client('organizations')

    # General Description
    if args.description:
        description = fetch_org_data(client, 'describe_organization', 'Organization', print)

        # Dictionary returning means data was found
        if type(description) == dict:
            description = [description]
            
        print('{} general info(s) found.'.format(len(description)))
        all_description += description
    
    # Roots
    if args.roots:

        roots = fetch_org_data(client, 'list_roots', 'Roots', print)
        print('{} root(s) found.'.format(len(roots)))
        all_roots += roots

    # TODO List Attached Policies as Well
    # Policies 
    if args.policies:
        for policy_filter in ["AISERVICES_OPT_OUT_POLICY", "BACKUP_POLICY", "SERVICE_CONTROL_POLICY", "TAG_POLICY"]:
            policies = fetch_org_data(client, 'list_policies', 'Policies', print, Filter=policy_filter)
            print('{} polices of type {} found.'.format(len(policies), policy_filter))
            all_policies += policies

    # Accounts
    if args.accounts:
        accounts = fetch_org_data(client, 'list_accounts', 'Accounts', print)
        print('{} accounts (s) found.'.format(len(accounts)))
        all_accounts += accounts

    # TODO Add multiple ways to get this besides root
    # Organizational Units (no list function, have to check graph)
    if args.organizational_units:
        all_roots_alt = fetch_org_data(client, 'list_roots', 'Roots', print)
        for root in all_roots_alt:
            all_org_units = get_org_units(client, print, root, starting_orgs = [])
                
        print('{} organizational unit(s) found.'.format(len(all_org_units)))

    # Enabled Services
    if args.enabled_services:
        enabled_services = fetch_org_data(client, 'list_aws_service_access_for_organization', 'EnabledServicePrincipals', print)
        print('{} enabled service(s) found.'.format(len(enabled_services)))
        all_enabled_services += enabled_services

    # Delegated Admins
    if args.delegated_admins:
        delegated_admins = fetch_org_data(client, 'list_delegated_administrators', 'DelegatedAdministrators', print)
        print('{} delegated administrator(s) found.'.format(len(delegated_admins)))
        all_delegated_admins += delegated_admins

    # Delegated Services; If list exists either set to true or will default to true
    if bool(args.delegated_services):

        # full list [A,B,C]
        extract_flag = False
        if type(args.delegated_services) == list and len(args.delegated_services) != 0:
            accounts = args.delegated_services
        
        # empty list []
        else:
            extract_flag = True
            accounts = fetch_org_data(client, 'list_accounts', 'Accounts', print)
            if len(accounts) == 0:
                 print('It appears like trying to list Organization AWS Account Numbers returned nothing. If necessary try passing in the same argument with specified organization IDs via --delegated-services ACCOUNT1 ACCOUNT2 ...')

        #TODO fix bug test case of pass in valid account, followed by invalid account, voids previous one
        for account in accounts:
            if extract_flag: 
                account = account['Id']
            delegated_services = fetch_org_data(client, 'list_delegated_services_for_account', 'DelegatedServices', print, AccountId=account)
            print('{} delegated services(s) found in Account {}.'.format(len(delegated_services), account))
            if len(delegated_services) != 0:
                all_delegated_services += [{account: delegated_services}]
          
    # Note need root, accounts, and OUs to do this assessment
    if bool(args.tree):
        print("Trying to create tree of all collected so far")
        
        all_roots_alt = fetch_org_data(client, 'list_roots', 'Roots', print)
        
        try:
            import graphviz
            if len(all_roots_alt) != 0:
                for root in all_roots_alt:

                    global dot 

                    dot = graphviz.Digraph(format="pdf",comment="Organization Hierarchy for Root "+root["Id"])

                    create_tree(client, print, root)
            
                    if type(args.tree) == bool and args.tree == True:
                        file_path = "./GraphOutput/"+root["Id"]+".gv"
                    elif type(args.tree) != bool:
                        file_path = args.tree

                    dot.render(filename=file_path)

                print("New Organization Chart Created at "+file_path)
            else:
                print("No roots were found to begin building a tree. Exiting tree build...")
        except Exception as e:
            print("Graphical Tree could not be created due to following exception: {}".format(e))

    # Resource Policies (Accessible for Delegated Admins)
    if args.delegation_policy:
        delegation_policy = fetch_org_data(client, 'describe_resource_policy', 'ResourcePolicy', print)

        # Dictionary returning means data was found
        if type(delegation_policy) == dict:
            delegation_policy = [delegation_policy]

        print('{} resource-based delegation policy(s) found.'.format(len(delegation_policy)))
        all_delegation_policy += delegation_policy

    summary_data = {}
    org_data = deepcopy(session.Organizations)

    if args.description: 
        summary_data['description'] = len(all_description)
        org_data['Overview'] = all_description

    if args.roots: 
        summary_data['roots'] = len(all_roots)
        org_data['Roots'] = all_roots

    if args.policies: 
        summary_data['policies'] = len(all_policies)
        org_data['Policies'] = all_policies

    if args.accounts: 
        summary_data['accounts'] = len(all_accounts)
        org_data['Accounts'] = all_accounts

    if args.organizational_units: 
        summary_data['organizational units'] = len(all_org_units)
        org_data['Organizational Units'] = all_org_units

    if args.enabled_services: 
        summary_data['enabled services'] = len(all_enabled_services)
        org_data['Enabled Services'] = all_enabled_services

    if args.delegated_admins: 
        summary_data['delegated admins'] = len(all_delegated_admins)
        org_data['Delegated Administrators'] = all_delegated_admins

    if args.delegated_services or args.delegated_services == []: 
        summary_data['delegated services'] = len(all_delegated_services)
        org_data['Delegated Services'] = all_delegated_services

    if args.delegation_policy:
        summary_data['resource-based delegation policies'] = len(all_delegation_policy)
        org_data['Resource-Based Delegation Policy'] = all_delegation_policy       

    session.update(pacu_main.database, Organizations=org_data)   
    return summary_data

def summary(data, pacu_main):
    out = ''
    for key in data:
        out += '{} total {}(s) found.\n'.format(data[key], key)
    out += '\n  Organization resources saved in Pacu database.\n'
    return out

