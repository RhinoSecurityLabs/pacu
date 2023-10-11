import argparse
from copy import deepcopy
from random import choice


from pacu.core.lib import save
from botocore.exceptions import ClientError
from pacu.core.secretfinder.utils import regex_checker, Color

#Using Spencer's iam_enum.py as a template

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'cognito__enum',

    # Name and any other notes about the author
    'author': 'David Kutz-Marks of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates Cognito information in the current AWS account.',

    # Description about what the module does and how it works
    'description': 'The module is used to enumerate the following Cognito data in the current AWS account: users, user pool clients, user pools and identity pools. By default, all data will be enumerated, but if any arguments are passed in indicating what data to enumerate, only that specified data will be enumerated.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['cognito-idp', 'cognito-identity'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself; that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [
        '--regions',
        '--user_pools',
        '--user_pool_clients'
        '--identity_pools'
        '--users' 
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma-separated) AWS regions in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('--user_pools', required=False, default=False, action='store_true', help='Enumerate Cognito user pools')
parser.add_argument('--user_pool_clients', required=False, default=False, action='store_true', help='Enumerate Cognito user pool clients')
parser.add_argument('--identity_pools', required=False, default=False, action='store_true', help='Enumerate Cognito identity pools')
parser.add_argument('--users', required=False, default=False, action='store_true', help='Enumerate users in each user pool')
ARG_FIELD_MAPPER = {
    'user_pools': 'UserPools',
    'user_pool_clients':'UserPoolClients',
    'identity_pools': 'IdentityPools',
    'users': 'Users'
}


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    if args.user_pools is False and args.user_pool_clients is False and args.identity_pools is False and args.users is False:
        args.user_pools = args.identity_pools = args.users = args.user_pool_clients = True

    if args.regions is None:
        regions = get_regions('cognito-idp')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    all_user_pools = []
    all_user_pool_clients = []
    all_identity_pools = []
    all_users_in_pools = []
    for region in regions:
        user_pools = []
        user_pool_clients = []
        identity_pools = []
        users_in_pools = []
       

        if any([args.user_pools, args.identity_pools,args.user_pool_clients, args.users]):
            print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('cognito-idp', region)

        
        try:
            # User Pools
            if args.user_pools:
                client = pacu_main.get_boto3_client('cognito-idp', region)
                response = None
                next_token = False
                while (response is None or 'NextToken' in response):
                    if next_token is False:
                        try:
                            response = client.list_user_pools(
                                MaxResults=60 #60 is maximum
                            )
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('Unable to list user pools in this region (this is normal if the region is disabled in the account): ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to ListUserPools.')
                            else:
                                print('  ' + code)
                            print('  Skipping user pool enumeration...')
                            
                    else:
                        response = client.list_user_pools(
                            NextToken=next_token,
                            MaxResults=60 #60 is maximum
                        )
                    if 'NextToken' in response:
                        next_token = response['NextToken']
                    for userpool in response['UserPools']:
                        print('Scanning user pool ' + userpool['Id'] + ' for vulnerabilities.')
                        userpool['Region'] = region
                        userpool['Description'] = client.describe_user_pool(UserPoolId=userpool['Id'])
                        password_policy = userpool['Description']['UserPool']['Policies']['PasswordPolicy']
                        if password_policy:                                      
                            if password_policy['MinimumLength'] < 12 or password_policy['RequireLowercase'] is False or password_policy['RequireUppercase'] is False or password_policy['RequireNumbers'] is False or password_policy['RequireSymbols'] is False:
                                print('Weak password policy!')
                                if password_policy['MinimumLength'] < 12:
                                    print('Minimum password length is fewer than 12 characters (' + str(password_policy['MinimumLength']) + ').')
                                if password_policy['RequireLowercase'] is False:
                                    print('Password does not require a lowercase letter.')
                                if password_policy['RequireUppercase'] is False:
                                    print('Password does not require an uppercase letter.')
                                if password_policy['RequireNumbers'] is False:
                                    print('Password does not require a number.')
                                if password_policy['RequireSymbols'] is False:
                                    print('Password does not require a symbol.')
                        if userpool['Description']['UserPool']['MfaConfiguration'] == 'OFF' or userpool['Description']['UserPool']['MfaConfiguration'] == 'OPTIONAL':
                            print('MFA is not required for user pool: ' + userpool['Id'] + '.')
                        user_pools.append(userpool)
                print('  {} user pool(s) found.'.format(len(user_pools)))
                all_user_pools += user_pools

            if args.identity_pools:
                client = pacu_main.get_boto3_client('cognito-identity', region)
                response = None
                next_token = False
                while (response is None or 'NextToken' in response):
                    if next_token is False:
                        try:
                            response = client.list_identity_pools(
                                MaxResults=60  # 60 is maximum
                            )
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('FAILURE: ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to ListIdentityPools.')
                            else:
                                print('  ' + code)
                            print('  Skipping identity pool enumeration...')
                            
                    else:
                        response = client.list_identity_pools(
                            NextToken=next_token,
                            MaxResults=60  # 60 is maximum
                        )
                    if 'NextToken' in response:
                        next_token = response['NextToken']
                    for identity_pool in response['IdentityPools']:
                        identity_pool['Region'] = region
                        print("Scanning identity pool " + identity_pool['IdentityPoolId'] + " for vulnerabilities.")
                        print("Attempting unauthenticated retrieval of identity Id")
                        try:
                            identity_id = client.get_id(
                                IdentityPoolId=identity_pool["IdentityPoolId"]
                            )
                            if identity_id is not None:
                                print("Identity id successfully retrieved: " + identity_id["IdentityId"])
                            print(
                            "Attempting unauthenticated retrieval of identity Id credentials"
                            )
                            identity_creds = client.get_credentials_for_identity(
                            IdentityId=identity_id["IdentityId"]
                        )      
                            if identity_creds["Credentials"]["AccessKeyId"] is not None:
                                print("Access Key ID found.")
                                identity_pool["AccessKeyId"] = identity_creds["Credentials"][
                                    "AccessKeyId"
                                ]
                                print(identity_pool["AccessKeyId"])
                            if identity_creds["Credentials"]["SecretKey"] is not None:
                                print("Secret Key found.")
                                identity_pool["SecretKey"] = identity_creds["Credentials"]["SecretKey"]
                                print(identity_pool["SecretKey"])
                            if identity_creds["Credentials"]["SessionToken"] is not None:
                                print("Session Token found.")
                                identity_pool["SessionToken"] = identity_creds["Credentials"][
                                    "SessionToken"
                                ]
                                print(identity_pool["SessionToken"])
                            if identity_creds["Credentials"]["Expiration"] is not None:
                                print("Expiration found.")
                                identity_pool["Expiration"] = identity_creds["Credentials"][
                                    "Expiration"
                                ]
                                print(identity_pool["Expiration"])  
                        except ClientError as error:
                            print("FAILURE: ")
                            code = error.response["Error"]["Code"]
                            print("  " + code)              
                        try:      
                            identity_pool['Roles'] = client.get_identity_pool_roles(IdentityPoolId=identity_pool['IdentityPoolId'])
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to GetIdentityPoolRoles.')
                            else:
                                print('  ' + code)
                        identity_pool['PrincipalTagAttributes'] = []
                        for user_pool in user_pools:
                            try:
                                identity_provider_name = str('cognito-idp.' + region + '.amazonaws.com/' + user_pool['Id'])
                                try:
                                    identity_pool_principal_tag_attributes = client.get_principal_tag_attribute_map(IdentityPoolId=identity_pool['IdentityPoolId'], IdentityProviderName=identity_provider_name)
                                except Exception as e:
                                    print(f"Error: {e}")
                                    identity_pool_principal_tag_attributes = None
                                if identity_pool_principal_tag_attributes is not None:
                                    identity_pool['PrincipalTagAttributes'].append(identity_pool_principal_tag_attributes)
                            except ClientError as error:
                                code = error.response['Error']['Code']
                                if code == 'UnauthorizedOperation':
                                    print('  Access denied to GetPrincipalTagAttributeMap.')
                                elif code == 'ResourceNotFoundException':
                                    print('No principal tags configured for user pool IdP' + identity_provider_name)
                                else:
                                    print('  ' + code)
                                print('  Skipping identity pool principal tag attribute enumeration...')                
                        identity_pools.append(identity_pool)
                print('  {} identity pool(s) found.'.format(len(identity_pools)))
                all_identity_pools += identity_pools

            # User Pool Clients
            if args.user_pool_clients:
                for user_pool in user_pools:
                    client = pacu_main.get_boto3_client('cognito-idp', region)
                    next_token = None
                    while True:
                        try:
                            print(f"Trying to list user pool clients for UserPoolId: {user_pool['Id']}")
                            if next_token is None:
                                response = client.list_user_pool_clients(
                                    UserPoolId=user_pool['Id'],
                                    MaxResults=60
                                )
                            else:
                                response = client.list_user_pool_clients(
                                    UserPoolId=user_pool['Id'],
                                    MaxResults=60,
                                    NextToken=next_token
                                )
                            for user_pool_client in response['UserPoolClients']:
                                resource_server_scopes = []
                                client_info = {}
                                print('User pool client found.')
                                print('Scanning user pool client ' + user_pool_client['ClientId'] + ' in user pool ' + user_pool['Id'] + ' for vulnerabilities.')
                                try:
                                    client_info['ClientId'] = user_pool_client['ClientId']
                                    client_info['UserPoolId'] = user_pool_client['UserPoolId']
                                    client_info['Region'] = region
                                    client_info['Description'] = client.describe_user_pool_client(UserPoolId=user_pool_client['UserPoolId'], ClientId=user_pool_client['ClientId'])
                                    resource_servers = []
                                    next_token_resource = None
                                except error as e:
                                    print(f"Error: {e}")
                                    resource_servers = []
                                    next_token_resource = None
                                except ClientError as error:
                                    print('FAILURE: ')
                                    code = error.response['Error']['Code']
                                while True:
                                    if next_token_resource is None:
                                        resource_servers_response = client.list_resource_servers(UserPoolId=user_pool_client['UserPoolId'], MaxResults=50)
                                    else:
                                        resource_servers_response = client.list_resource_servers(UserPoolId=user_pool_client['UserPoolId'], MaxResults=50, NextToken=next_token_resource)
                                    resource_servers.extend(resource_servers_response['ResourceServers'])
                                    next_token_resource = resource_servers_response.get('NextToken')
                                    if next_token_resource is None:
                                        break
                                try:
                                    for resource_server in resource_servers:
                                        if 'Scopes' in resource_server:
                                            for scope in resource_server['Scopes']:
                                                resource_server_scopes.append(scope['ScopeName'])
                                except Exception as error:
                                    code = error.response['Error']['Code']
                                    if code == 'UnauthorizedOperation':
                                        print('  Access denied to ListResourceServers.')
                                    else:
                                        print('  ' + code)
                                    print('  Skipping resource server enumeration...')
                                if resource_servers:    
                                    user_pool['Description']['UserPool']['ResourceServers'] = resource_servers
                                try:
                                    if client_info.get('Description') and client_info['Description'].get('UserPoolClient') and client_info['Description']['UserPoolClient'].get('WriteAttributes'):
                                        write_attributes = client_info['Description']['UserPoolClient']['WriteAttributes']
                                    else:
                                        write_attributes = []
                                except Exception as error:
                                    code = error.response['Error']['Code']
                                    if code == 'UnauthorizedOperation':
                                        print('  Access denied to ListResourceServers.')
                                    else:
                                        print('  ' + code)
                                    print('  Skipping resource server enumeration...')
                                except error as e:
                                    print(f"Error: {e}")
                                if user_pool.get('Description') and user_pool['Description'].get('UserPool') and user_pool['Description']['UserPool'].get('UserAttributeUpdateSettings') and user_pool['Description']['UserPool']['UserAttributeUpdateSettings'].get('AttributesRequireVerificationBeforeUpdate'):
                                    verify_attributes = user_pool['Description']['UserPool']['UserAttributeUpdateSettings']['AttributesRequireVerificationBeforeUpdate']
                                if client_info.get('Description') and client_info['Description'].get('UserPoolClient') and client_info['Description']['UserPoolClient'].get('AllowedOAuthScopes'):
                                    client_scopes = client_info['Description']['UserPoolClient']['AllowedOAuthScopes']
                                identity_attributes = []
                                identity_claims = []
                                for identity_pool in identity_pools:
                                    if identity_pool.get('PrincipalTagAttributes') and identity_pool['PrincipalTagAttributes'].get('PrincipalTags'):
                                        identity_attributes.append(identity_pool['PrincipalTagAttributes']['PrincipalTags'])
                                    if identity_pool.get('Roles') and identity_pool['Roles'].get('RoleMappings') and identity_pool['Roles']['RoleMappings'].get('RulesConfiguration') and identity_pool['Roles']['RoleMappings']['RulesConfiguration'].get('Rules') and identity_pool['Roles']['RoleMappings']['RulesConfiguration']['Rules'].get('Claim'): 
                                        identity_claims.append(identity_pool['Roles']['RoleMappings']['RulesConfiguration']['Rules']['Claim'])
                                user_writable_attributes = []
                                client_scope_user_writable_attributes = []
                                resource_server_scope_user_writable_attributes = []
                                identity_attributes_user_writable_attributes = []
                                identity_claims_user_writable_attributes = []
                                verify_attributes = []
                                if user_pool.get('Description') and user_pool['Description'].get('UserPool') and user_pool['Description']['UserPool'].get('SchemaAttributes'):                              
                                    for schema_attribute in user_pool['Description']['UserPool']['SchemaAttributes']:
                                        try:
                                            if write_attributes:
                                                if schema_attribute['Name'] in write_attributes:
                                                    if schema_attribute['DeveloperOnlyAttribute'] is False and schema_attribute['Mutable'] is True:
                                                        user_writable_attributes.append(schema_attribute['Name'])
                                        except Exception as e:
                                            print(f"Error: {e}")
                                if user_writable_attributes:
                                    print('The following attributes can be modified by users: ' + str(user_writable_attributes))
                                    client_scope_user_writable_attributes = [
                                        attr for attr in user_writable_attributes
                                        if any(
                                            attr == scope or attr.replace('custom:', '') == scope.split('/')[-1] 
                                            for scope in client_scopes
                                        )
                                    ]
                                    resource_server_scope_user_writable_attributes = [attr for attr in user_writable_attributes if attr in resource_server_scopes or attr.replace('custom:', '') in resource_server_scopes]
                                    identity_attributes_user_writable_attributes = [attr for attr in user_writable_attributes if attr in identity_attributes or attr.replace('custom:', '') in identity_attributes]
                                    identity_claims_user_writable_attributes = [attr for attr in user_writable_attributes if attr in identity_claims or attr.replace('custom:', '') in identity_claims]
                                for user_writable_attribute in user_writable_attributes:
                                    if user_writable_attribute == 'phone_number':  
                                        if user_writable_attribute not in verify_attributes:
                                            print('Attribute \'phone_number\' does not require verification before changing!')
                                    if user_writable_attribute == 'email':  
                                        if user_writable_attribute not in verify_attributes:
                                            print('Attribute \'email\' does not require verification before changing!')
                                if resource_server_scope_user_writable_attributes:
                                    print('The following attributes can be modified by users and are used for access control by a resource server (this may allow privilege escalation): ' + str(resource_server_scope_user_writable_attributes))
                                else:
                                    print('No resource servers found.')
                                if identity_attributes_user_writable_attributes:
                                    print('The following attributes can be modified by users and are used for access control by an identity pool (this may allow privilege escalation): ' + str(identity_attributes_user_writable_attributes))
                                else:
                                    print('No identity pools found.')
                                if identity_claims_user_writable_attributes:
                                    print('The following attributes can be modified by users and may be used for access control by an identity pool rule (this may allow privilege escalation): ' + str(identity_claims_user_writable_attributes))
                                else:
                                    print('No identity pools found.')
                                user_pool_clients.append(client_info)                         
                            if not response.get('NextToken'):
                                break
                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('FAILURE: ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to ListUserPoolClients.')
                            elif code == 'InvalidParameterException':  # Add this block
                                print('  InvalidParameterException')
                                print(f"  UserPoolId causing the issue: {user_pool['Id']}")
                                break
                            else:
                                print('  ' + code)
                            print('  Skipping user pool client enumeration...')
                            break
                    try:
                        print(f'  {len(user_pool_clients)} user pool client(s) found in user pool {user_pool["Id"]}.')
                    except Exception as e:
                        print(f"Error: {e}")
                    all_user_pool_clients += user_pool_clients

        
            # List Users in each User Pool
            if args.users:
                for user_pool in user_pools:
                    client = pacu_main.get_boto3_client('cognito-idp', region)
                    response = None
                    iterate = 0
                    pagination_token = ''
                    while (iterate == 0 or 'PaginationToken' in response):
                        try:
                            iterate += 1
                            print(f"Trying to list users for UserPoolId: {user_pool['Id']}")  # Add this line
                            response = client.list_users(
                                UserPoolId=user_pool['Id'],
                                Limit=60,
                                PaginationToken=pagination_token
                            ) if pagination_token else client.list_users(
                                UserPoolId=user_pool['Id'],
                                Limit=60
                            )
                            pagination_token = response['PaginationToken'] if 'PaginationToken' in response else ''

                            for user in response['Users']:
                                user['UserPoolId'] = user_pool['Id']
                                user['Region'] = region
                                users_in_pools.append(user)

                        except ClientError as error:
                            code = error.response['Error']['Code']
                            print('FAILURE: ')
                            if code == 'UnauthorizedOperation':
                                print('  Access denied to ListUsers.')
                            elif code == 'InvalidParameterException':  # Add this block
                                print('  InvalidParameterException')
                                print(f"  UserPoolId causing the issue: {user_pool['Id']}")
                                break
                            else:
                                print('  ' + code)
                            print('  Skipping user enumeration...')

                print(f'  {len(users_in_pools)} user(s) found in user pool {user_pool["Id"]}.')
                all_users_in_pools += users_in_pools

        except Exception:
            continue
 
    gathered_data = {
        'UserPools': all_user_pools,
        'UserPoolClients': all_user_pool_clients,
        'IdentityPools': all_identity_pools,
        'UsersInPools': all_users_in_pools
    }

    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            if ARG_FIELD_MAPPER[var] in gathered_data:
                del gathered_data[ARG_FIELD_MAPPER[var]]

    cognito_data = deepcopy(session.Cognito)
    for key, value in gathered_data.items():
        cognito_data[key] = value
    session.update(pacu_main.database, Cognito=cognito_data)

    # Add regions to gathered_data for summary output
    gathered_data['regions'] = regions

    if any([args.user_pools, args.identity_pools]):
        return gathered_data
    else:
        print('No data successfully enumerated.\n')
        return None


def summary(data, pacu_main):
    results = []

    results.append('  Regions:')
    for region in data['regions']:
        results.append('     {}'.format(region))

    results.append('')

    if 'UserPools' in data:
        results.append('    {} total user pool(s) found.'.format(len(data['UserPools'])))

    if 'UserPoolClients' in data:
        results.append('    {} total user pool client(s) found.'.format(len(data['UserPoolClients'])))

    if 'IdentityPools' in data:
        results.append('    {} total identity pool(s) found.'.format(len(data['IdentityPools'])))

    if 'UsersInPools' in data:
        results.append('    {} total user(s) in user pool(s) found.'.format(len(data['UsersInPools'])))

    return '\n'.join(results)