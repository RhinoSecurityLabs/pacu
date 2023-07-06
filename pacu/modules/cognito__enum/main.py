import argparse
from copy import deepcopy
from random import choice


from pacu.core.lib import save
from botocore.exceptions import ClientError
from pacu.core.secretfinder.utils import regex_checker, Color

# Using Spencer's iam_enum.py as a template

module_info = {
    # Name of the module (should be the same as the filename)
    "name": "cognito__enum",
    # Name and any other notes about the author
    "author": "David Kutz-Marks of Rhino Security Labs",
    # Category of the module. Make sure the name matches an existing category.
    "category": "ENUM",
    # One liner description of the module functionality. This shows up when a user searches for modules.
    "one_liner": "Enumerates Cognito information in the current AWS account.",
    # Description about what the module does and how it works
    "description": "The module is used to enumerate the following Cognito data in the current AWS account: users, user pool clients, user pools and identity pools. By default, all data will be enumerated, but if any arguments are passed in indicating what data to enumerate, only that specified data will be enumerated.",
    # A list of AWS services that the module utilizes during its execution
    "services": ["cognito-idp", "cognito-identity"],
    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself; that way, session data can stay separated and modular.
    "prerequisite_modules": [],
    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    "external_dependencies": [],
    # Module arguments to autocomplete when the user hits tab
    "arguments_to_autocomplete": [
        "--regions",
        "--user_pools",
        "--user_pool_clients" "--identity_pools" "--users",
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])

parser.add_argument(
    "--regions",
    required=False,
    default=None,
    help='One or more (comma-separated) AWS regions in the format "us-east-1". Defaults to all session regions.',
)
parser.add_argument(
    "--user_pools",
    required=False,
    default=False,
    action="store_true",
    help="Enumerate Cognito user pools",
)
parser.add_argument(
    "--user_pool_clients",
    required=False,
    default=False,
    action="store_true",
    help="Enumerate Cognito user pool clients",
)
parser.add_argument(
    "--identity_pools",
    required=False,
    default=False,
    action="store_true",
    help="Enumerate Cognito identity pools",
)
parser.add_argument(
    "--users",
    required=False,
    default=False,
    action="store_true",
    help="Enumerate users in each user pool",
)
ARG_FIELD_MAPPER = {
    "user_pools": "UserPools",
    "user_pool_clients": "UserPoolClients",
    "identity_pools": "IdentityPools",
    "users": "Users",
}


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    if (
        args.user_pools is False
        and args.user_pool_clients is False
        and args.identity_pools is False
        and args.users is False
    ):
        args.user_pools = (
            args.identity_pools
        ) = args.users = args.user_pool_clients = True

    if args.regions is None:
        regions = get_regions("cognito-idp")
        if regions is None or regions == [] or regions == "" or regions == {}:
            print(
                "This module is not supported in any regions specified in the current sessions region set. Exiting..."
            )
            return
    else:
        regions = args.regions.split(",")

    all_user_pools = []
    all_user_pool_clients = []
    all_identity_pools = []
    all_users_in_pools = []
    for region in regions:
        user_pools = []
        user_pool_clients = []
        identity_pools = []
        users_in_pools = []

        if any(
            [args.user_pools, args.identity_pools, args.user_pool_clients, args.users]
        ):
            print("Starting region {}...".format(region))
        client = pacu_main.get_boto3_client("cognito-idp", region)

        try:
            # User Pools
            if args.user_pools:
                client = pacu_main.get_boto3_client("cognito-idp", region)
                response = None
                next_token = False
                while response is None or "NextToken" in response:
                    if next_token is False:
                        try:
                            response = client.list_user_pools(
                                MaxResults=60  # 60 is maximum
                            )
                        except ClientError as error:
                            code = error.response["Error"]["Code"]
                            print(
                                "Unable to list user pools in this region (this is normal if the region is disabled in the account): "
                            )
                            if code == "UnauthorizedOperation":
                                print("  Access denied to ListUserPools.")
                            else:
                                print("  " + code)
                            print("  Skipping user pool enumeration...")

                    else:
                        response = client.list_user_pools(
                            NextToken=next_token, MaxResults=60  # 60 is maximum
                        )
                    if "NextToken" in response:
                        next_token = response["NextToken"]
                    for userpool in response["UserPools"]:
                        userpool["Region"] = region
                        user_pools.append(userpool)

                print("  {} user pool(s) found.".format(len(user_pools)))
                all_user_pools += user_pools

            # User Pool Clients
            if args.user_pool_clients:
                for user_pool in user_pools:
                    client = pacu_main.get_boto3_client("cognito-idp", region)
                    response = None
                    next_token = False
                    while response is None or "NextToken" in response:
                        if next_token is False:
                            try:
                                print(
                                    f"Trying to list original user pool clients for UserPoolId: {user_pool['Id']}"
                                )  # Add this line
                                response = client.list_user_pool_clients(
                                    UserPoolId=user_pool["Id"], MaxResults=60
                                )

                                print("Testing.")
                                for user_pool_client in response["UserPoolClients"]:
                                    client_info = {}
                                    print("User pool client found.")
                                    client_info["ClientId"] = user_pool_client[
                                        "ClientId"
                                    ]
                                    client_info["UserPoolId"] = user_pool_client[
                                        "UserPoolId"
                                    ]
                                    client_info["Region"] = region
                                    user_pool_clients.append(client_info)

                            except ClientError as error:
                                code = error.response["Error"]["Code"]
                                print("FAILURE: ")
                                if code == "UnauthorizedOperation":
                                    print("  Access denied to ListUserPoolClients.")
                                elif (
                                    code == "InvalidParameterException"
                                ):  # Add this block
                                    print("  InvalidParameterException")
                                    print(
                                        f"  UserPoolId causing the issue: {user_pool['Id']}"
                                    )
                                    break
                                else:
                                    print("  " + code)
                                print("  Skipping user pool client enumeration...")
                        else:
                            try:
                                print(
                                    f"Trying to list else-block user pool clients for UserPoolId: {user_pool['Id']}"
                                )  # Add this line
                                response = client.list_user_pool_clients(
                                    NextToken=next_token,
                                    UserPoolId=user_pool["Id"],
                                    MaxResults=60,
                                )

                                print("Testing.")
                                for user_pool_client in response["UserPoolClients"]:
                                    client_info = {}
                                    print("User pool client found.")
                                    client_info["ClientId"] = user_pool_client[
                                        "ClientId"
                                    ]
                                    client_info["UserPoolId"] = user_pool_client[
                                        "UserPoolId"
                                    ]
                                    client_info["Region"] = region
                                    user_pool_clients.append(client_info)
                            except ClientError as error:
                                code = error.response["Error"]["Code"]
                                print("FAILURE: ")
                                if code == "UnauthorizedOperation":
                                    print("  Access denied to ListUserPoolClients.")
                                elif (
                                    code == "InvalidParameterException"
                                ):  # Add this block
                                    print("  InvalidParameterException")
                                    print(
                                        f"  UserPoolId causing the issue: {user_pool['Id']}"
                                    )
                                    break
                                else:
                                    print("  " + code)
                                print("  Skipping user pool client enumeration...")
                                break

                            if "NextToken" in response:
                                next_token = response["NextToken"]
                            else:
                                next_token = None

                    print(
                        f'  {len(user_pool_clients)} user pool client(s) found in user pool {user_pool["Id"]}.'
                    )
                    all_user_pool_clients += user_pool_clients

            # Identity Pools
            if args.identity_pools:
                client = pacu_main.get_boto3_client("cognito-identity", region)
                response = None
                next_token = False
                while response is None or "NextToken" in response:
                    if next_token is False:
                        try:
                            response = client.list_identity_pools(
                                MaxResults=60  # 60 is maximum
                            )
                        except ClientError as error:
                            code = error.response["Error"]["Code"]
                            print("FAILURE: ")
                            if code == "UnauthorizedOperation":
                                print("  Access denied to ListIdentityPools.")
                            else:
                                print("  " + code)
                            print("  Skipping identity pool enumeration...")

                    else:
                        response = client.list_identity_pools(
                            NextToken=next_token, MaxResults=60  # 60 is maximum
                        )
                    if "NextToken" in response:
                        next_token = response["NextToken"]
                    for identity_pool in response["IdentityPools"]:
                        identity_pool["Region"] = region
                        try:
                            identity_id = client.get_id(
                                IdentityPoolId=identity_pool["IdentityPoolId"]
                            )
                            identity_creds = client.get_credentials_for_identity(
                                IdentityId=identity_id["IdentityId"]
                            )
                            if identity_creds["Credentials"]["AccessKeyId"] is not None:
                                print("Access Key ID found.")
                                identity_pool["AccessKeyId"] = identity_creds[
                                    "Credentials"
                                ]["AccessKeyId"]
                            if identity_creds["Credentials"]["SecretKey"] is not None:
                                print("Secret Key found.")
                                identity_pool["SecretKey"] = identity_creds[
                                    "Credentials"
                                ]["SecretKey"]
                            if (
                                identity_creds["Credentials"]["SessionToken"]
                                is not None
                            ):
                                print("Session Token found.")
                                identity_pool["SessionToken"] = identity_creds[
                                    "Credentials"
                                ]["SessionToken"]
                            if identity_creds["Credentials"]["Expiration"] is not None:
                                print("Expiration found.")
                                identity_pool["Expiration"] = identity_creds[
                                    "Credentials"
                                ]["Expiration"]
                        except ClientError as error:
                            code = error.response["Error"]["Code"]
                            if code == "UnauthorizedOperation":
                                print(
                                    "  Access denied to GetId or GetCredentialsForIdentity."
                                )
                            else:
                                print("  " + code)
                            print("  Skipping identity pool credentials enumeration...")
                        identity_pools.append(identity_pool)

                print("  {} identity pool(s) found.".format(len(identity_pools)))
                all_identity_pools += identity_pools

            # List Users in each User Pool
            if args.users:
                for user_pool in user_pools:
                    client = pacu_main.get_boto3_client("cognito-idp", region)
                    response = None
                    iterate = 0
                    pagination_token = ""
                    while iterate is 0 or "PaginationToken" in response:
                        try:
                            iterate += 1
                            print(
                                f"Trying to list users for UserPoolId: {user_pool['Id']}"
                            )  # Add this line
                            print("Stage two")
                            response = (
                                client.list_users(
                                    UserPoolId=user_pool["Id"],
                                    Limit=60,
                                    PaginationToken=pagination_token,
                                )
                                if pagination_token
                                else client.list_users(
                                    UserPoolId=user_pool["Id"], Limit=60
                                )
                            )
                            pagination_token = (
                                response["PaginationToken"]
                                if "PaginationToken" in response
                                else ""
                            )

                            print("Testing.")
                            for user in response["Users"]:
                                user["UserPoolId"] = user_pool["Id"]
                                user["Region"] = region
                                users_in_pools.append(user)

                        except ClientError as error:
                            code = error.response["Error"]["Code"]
                            print("FAILURE: ")
                            if code == "UnauthorizedOperation":
                                print("  Access denied to ListUsers.")
                            elif code == "InvalidParameterException":  # Add this block
                                print("  InvalidParameterException")
                                print(
                                    f"  UserPoolId causing the issue: {user_pool['Id']}"
                                )
                                break
                            else:
                                print("  " + code)
                            print("  Skipping user enumeration...")

                print(
                    f'  {len(users_in_pools)} user(s) found in user pool {user_pool["Id"]}.'
                )
                all_users_in_pools += users_in_pools

        except Exception:
            continue

    gathered_data = {
        "UserPools": all_user_pools,
        "UserPoolClients": all_user_pool_clients,
        "IdentityPools": all_identity_pools,
        "UsersInPools": all_users_in_pools,
    }

    for var in vars(args):
        if var == "regions":
            continue
        if not getattr(args, var):
            if ARG_FIELD_MAPPER[var] in gathered_data:
                del gathered_data[ARG_FIELD_MAPPER[var]]

    cognito_data = deepcopy(session.Cognito)
    for key, value in gathered_data.items():
        cognito_data[key] = value
    session.update(pacu_main.database, Cognito=cognito_data)

    # Add regions to gathered_data for summary output
    gathered_data["regions"] = regions

    if any([args.user_pools, args.identity_pools]):
        return gathered_data
    else:
        print("No data successfully enumerated.\n")
        return None


def summary(data, pacu_main):
    results = []

    results.append("  Regions:")
    for region in data["regions"]:
        results.append("     {}".format(region))

    results.append("")

    if "UserPools" in data:
        results.append(
            "    {} total user pool(s) found.".format(len(data["UserPools"]))
        )

    if "UserPoolClients" in data:
        results.append(
            "    {} total user pool client(s) found.".format(
                len(data["UserPoolClients"])
            )
        )

    if "IdentityPools" in data:
        results.append(
            "    {} total identity pool(s) found.".format(len(data["IdentityPools"]))
        )

    if "UsersInPools" in data:
        results.append(
            "    {} total user(s) in user pool(s) found.".format(
                len(data["UsersInPools"])
            )
        )

    return "\n".join(results)
