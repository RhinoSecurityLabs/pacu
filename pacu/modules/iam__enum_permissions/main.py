#!/usr/bin/env python3
import argparse
import json
import re

from botocore.exceptions import ClientError
from policyuniverse.statement import Statement

from pacu.core.lib import strip_lines, save, downloads_dir
from pacu import Main


module_info = {
    "name": "iam__enum_permissions",
    "author": "Spencer Gietzen of Rhino Security Labs",
    "category": "ENUM",
    "one_liner": "Tries to get a confirmed list of permissions for the current (or all) user(s).",
    "description": strip_lines(
        """
        This module will attempt to use IAM APIs to enumerate a confirmed list of IAM permissions for users/roles in the
        account. By default, the owner of the active set of keys is targeted. This is done by checking attached and
        inline policies for the user and the groups they are in.
    """
    ),
    "services": ["IAM"],
    "prerequisite_modules": ["iam__enum_users_roles_policies_groups"],
    "arguments_to_autocomplete": ["--all-users", "--user-name"],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])

parser.add_argument(
    "--all-users",
    required=False,
    default=False,
    action="store_true",
    help=strip_lines(
        """
    Run this module against every user in the account and store the results to 
    ~/.local/share/pacu/sessions/[current_session_name]/downloads/confirmed_permissions/user-[user_name].json. This data
    can then be run against the iam__privesc_scan module with the --offline flag enabled.
"""
    ),
)
parser.add_argument(
    "--user-name",
    required=False,
    default=None,
    help=strip_lines(
        """
    A single user name of a user to run this module against. By default, the active AWS keys will be used.
"""
    ),
)
parser.add_argument(
    "--all-roles",
    required=False,
    default=False,
    action="store_true",
    help=strip_lines(
        """
    Run this module against every role in the account and store the results to
    ~/.local/share/pacu/sessions/[current_session_name]/downloads/confirmed_permissions/role-[role_name].json. This data
    can then be run against the iam__privesc_scan module with the --offline flag enabled.
"""
    ),
)
parser.add_argument(
    "--role-name",
    required=False,
    default=None,
    help=strip_lines(
        """
    A single role name of a role to run this module against. By default, the active AWS keys will be used.
"""
    ),
)


def main(args, pacu_main: "Main"):
    session = pacu_main.get_active_session()

    # Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print

    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    # End don't modify

    summary_data = {"users_confirmed": 0, "roles_confirmed": 0}

    users = []
    roles = []

    if args.all_users is True:
        if (
            fetch_data(
                ["IAM", "Users"], module_info["prerequisite_modules"][0], "--users"
            )
            is False
        ):
            print("FAILURE")
            print("  SUB-MODULE EXECUTION FAILED")
            return
        fetched_users = session.IAM["Users"]
        for user in fetched_users:
            users.append(
                {
                    "UserName": user["UserName"],
                    "PermissionsConfirmed": True,
                    "Permissions": {"Allow": {}, "Deny": {}},
                }
            )
    elif args.user_name is not None:
        users.append(
            {
                "UserName": args.user_name,
                "PermissionsConfirmed": True,
                "Permissions": {"Allow": {}, "Deny": {}},
            }
        )
        summary_data["single_user"] = args.user_name

    if args.all_roles is True:
        if (
            fetch_data(
                ["IAM", "Roles"], module_info["prerequisite_modules"][0], "--roles"
            )
            is False
        ):
            print("FAILURE")
            print("  SUB-MODULE EXECUTION FAILED")
            return
        fetched_roles = session.IAM["Roles"]
        for role in fetched_roles:
            roles.append(
                {
                    "RoleName": role["RoleName"],
                    "PermissionsConfirmed": True,
                    "Permissions": {"Allow": {}, "Deny": {}},
                }
            )
    elif args.role_name is not None:
        roles.append(
            {
                "RoleName": args.role_name,
                "PermissionsConfirmed": True,
                "Permissions": {"Allow": {}, "Deny": {}},
            }
        )
        summary_data["single_role"] = args.role_name

    is_user = is_role = False

    if not any([args.all_users, args.user_name, args.all_roles, args.role_name]):
        client = pacu_main.get_boto3_client("sts")
        identity = client.get_caller_identity()
        active_aws_key = session.get_active_aws_key(pacu_main.database)

        if re.match(r"arn:aws:iam::\d{12}:user/", identity["Arn"]) is not None:
            is_user = True
            # GetCallerIdentity away return user's ARN like this if it was a user
            # arn:aws:iam::123456789012:user/username
            username = identity["Arn"].split(":user/")[1]
            active_aws_key.update(
                pacu_main.database,
                user_name=username.split("/")[-1],
                arn=identity["Arn"],
                user_id=identity["UserId"],
                account_id=identity["Account"],
            )
        elif (
            re.match(r"arn:aws:sts::\d{12}:assumed-role/", identity["Arn"]) is not None
        ):
            is_role = True
            active_aws_key.update(
                pacu_main.database,
                role_name=identity["Arn"].split(":assumed-role/")[1].split("/")[-2],
                arn=identity["Arn"],
                user_id=identity["UserId"],
                account_id=identity["Account"],
            )
        else:
            print("Not an IAM user or role. Exiting...\n")
            return False

        if is_user:
            user = key_info(alias=session.key_alias)
            user["PermissionsConfirmed"] = True
            user["Permissions"] = {"Allow": {}, "Deny": {}}
            users.append(user)
            summary_data["single_user"] = user["UserName"]
        elif is_role:
            roles.append(
                {
                    "RoleName": active_aws_key.role_name,
                    "PermissionsConfirmed": True,
                    "Permissions": {"Allow": {}, "Deny": {}},
                }
            )
            summary_data["single_role"] = active_aws_key.role_name

    # list-groups-for-user
    # list-user-policies
    # list-group-policies
    # list-role-policies
    # list-attached-role-policies
    # list-attached-group-policies
    # list-attached-user-policies
    # get-policy
    # get-policy-version
    # get-user-policy
    # get-group-policy
    # get-role-policy

    client = pacu_main.get_boto3_client("iam")
    if any([args.all_users, args.user_name, args.all_roles, args.role_name]):
        print("Permission Document Location:")
        print("  {}/confirmed_permissions/\n".format(downloads_dir()))

    if roles:
        print("Confirming permissions for roles:")
        for role in roles:
            print("  {}...".format(role["RoleName"]))
            role["Policies"] = []

            try:
                # Get inline role policies
                policies = []
                try:
                    response = client.list_role_policies(RoleName=role["RoleName"])
                    policies = response["PolicyNames"]
                    while "IsTruncated" in response and response["IsTruncated"] is True:
                        response = client.list_role_policies(
                            RoleName=role["RoleName"], Marker=response["Marker"]
                        )
                        policies += response["PolicyNames"]
                    for policy in policies:
                        role["Policies"].append({"PolicyName": policy})
                except ClientError as error:
                    print("    List role policies failed")
                    if error.response["Error"]["Code"] == "AccessDenied":
                        print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                    else:
                        print("      {}".format(error.response["Error"]["Code"]))
                    role["PermissionsConfirmed"] = False

                # Get document for each inline policy
                for policy in policies:
                    try:
                        document = client.get_role_policy(
                            RoleName=role["RoleName"], PolicyName=policy
                        )["PolicyDocument"]
                    except ClientError as error:
                        print("    Get role policy failed")
                        if error.response["Error"]["Code"] == "AccessDenied":
                            print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                        else:
                            print("      {}".format(error.response["Error"]["Code"]))
                        role["PermissionsConfirmed"] = False
                    role = parse_document(document, role)

                # Get attached role policies
                attached_policies = []
                try:
                    response = client.list_attached_role_policies(
                        RoleName=role["RoleName"]
                    )
                    attached_policies = response["AttachedPolicies"]
                    while "IsTruncated" in response and response["IsTruncated"] is True:
                        response = client.list_attached_role_policies(
                            RoleName=role["RoleName"], Marker=response["Marker"]
                        )
                        attached_policies += response["AttachedPolicies"]
                    role["Policies"] += attached_policies
                except ClientError as error:
                    print("    List attached role policies failed")
                    if error.response["Error"]["Code"] == "AccessDenied":
                        print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                    else:
                        print("      {}".format(error.response["Error"]["Code"]))
                    role["PermissionsConfirmed"] = False

                role = parse_attached_policies(client, attached_policies, role)
                if role["PermissionsConfirmed"]:
                    summary_data["roles_confirmed"] += 1

                if args.role_name is None and args.all_roles is False:
                    print("    Confirmed permissions for {}".format(role["RoleName"]))
                    active_aws_key.update(
                        pacu_main.database,
                        role_name=role["RoleName"],
                        policies=role["Policies"],
                        permissions_confirmed=role["PermissionsConfirmed"],
                        allow_permissions=role["Permissions"]["Allow"],
                        deny_permissions=role["Permissions"]["Deny"],
                    )
                else:
                    with save(
                        "confirmed_permissions/role-{}.json".format(role["RoleName"]),
                        "w+",
                    ) as f:
                        json.dump(role, f, indent=2, default=str)

                    print(
                        "    Permissions stored in role-{}.json".format(
                            role["RoleName"]
                        )
                    )
            except ClientError as error:
                if error.response["Error"]["Code"] == "AccessDenied":
                    print("  FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                else:
                    print("  {}".format(error.response["Error"]["Code"]))
                print("Skipping {}".format(role["RoleName"]))
        if users:
            print()

    if users:
        print("Confirming permissions for users:")
        for user in users:
            print("  {}...".format(user["UserName"]))
            user["Groups"] = []
            user["Policies"] = []
            try:
                policies = []

                # Get groups that the user is in
                try:
                    response = client.list_groups_for_user(UserName=user["UserName"])
                    user["Groups"] = response["Groups"]
                    while "IsTruncated" in response and response["IsTruncated"] is True:
                        response = client.list_groups_for_user(
                            UserName=user["UserName"], Marker=response["Marker"]
                        )
                        user["Groups"] += response["Groups"]
                except ClientError as error:
                    print("    List groups for user failed")
                    if error.response["Error"]["Code"] == "AccessDenied":
                        print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                    else:
                        print("      {}".format(error.response["Error"]["Code"]))
                    user["PermissionsConfirmed"] = False

                # Get inline and attached group policies
                for group in user["Groups"]:
                    group["Policies"] = []
                    # Get inline group policies
                    try:
                        response = client.list_group_policies(
                            GroupName=group["GroupName"]
                        )
                        policies = response["PolicyNames"]
                        while (
                            "IsTruncated" in response
                            and response["IsTruncated"] is True
                        ):
                            response = client.list_group_policies(
                                GroupName=group["GroupName"], Marker=response["Marker"]
                            )
                            policies += response["PolicyNames"]
                    except ClientError as error:
                        print("     List group policies failed")
                        if error.response["Error"]["Code"] == "AccessDenied":
                            print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                        else:
                            print("      {}".format(error.response["Error"]["Code"]))
                        user["PermissionsConfirmed"] = False

                    # Get document for each inline policy
                    for policy in policies:
                        group["Policies"].append(
                            {  # Add policies to list of policies for this group
                                "PolicyName": policy
                            }
                        )
                        try:
                            document = client.get_group_policy(
                                GroupName=group["GroupName"], PolicyName=policy
                            )["PolicyDocument"]
                        except ClientError as error:
                            print("     Get group policy failed")
                            if error.response["Error"]["Code"] == "AccessDenied":
                                print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                            else:
                                print(
                                    "      {}".format(error.response["Error"]["Code"])
                                )
                            user["PermissionsConfirmed"] = False
                        user = parse_document(document, user)

                    # Get attached group policies
                    attached_policies = []
                    try:
                        response = client.list_attached_group_policies(
                            GroupName=group["GroupName"]
                        )
                        attached_policies = response["AttachedPolicies"]
                        while (
                            "IsTruncated" in response
                            and response["IsTruncated"] is True
                        ):
                            response = client.list_attached_group_policies(
                                GroupName=group["GroupName"], Marker=response["Marker"]
                            )
                            attached_policies += response["AttachedPolicies"]
                        group["Policies"] += attached_policies
                    except ClientError as error:
                        print("    List attached group policies failed")
                        if error.response["Error"]["Code"] == "AccessDenied":
                            print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                        else:
                            print("      {}".format(error.response["Error"]["Code"]))
                        user["PermissionsConfirmed"] = False
                    user = parse_attached_policies(client, attached_policies, user)

                # Get inline user policies
                policies = []
                if "Policies" not in user:
                    user["Policies"] = []
                try:
                    response = client.list_user_policies(UserName=user["UserName"])
                    policies = response["PolicyNames"]
                    while "IsTruncated" in response and response["IsTruncated"] is True:
                        response = client.list_user_policies(
                            UserName=user["UserName"], Marker=response["Marker"]
                        )
                        policies += response["PolicyNames"]
                    for policy in policies:
                        user["Policies"].append({"PolicyName": policy})
                except ClientError as error:
                    print("    List user policies failed")
                    if error.response["Error"]["Code"] == "AccessDenied":
                        print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                    else:
                        print("      {}".format(error.response["Error"]["Code"]))
                    user["PermissionsConfirmed"] = False

                # Get document for each inline policy
                for policy in policies:
                    try:
                        document = client.get_user_policy(
                            UserName=user["UserName"], PolicyName=policy
                        )["PolicyDocument"]
                    except ClientError as error:
                        print("    Get user policy failed")
                        if error.response["Error"]["Code"] == "AccessDenied":
                            print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                        else:
                            print("      {}".format(error.response["Error"]["Code"]))
                        user["PermissionsConfirmed"] = False
                    user = parse_document(document, user)

                # Get attached user policies
                attached_policies = []
                try:
                    response = client.list_attached_user_policies(
                        UserName=user["UserName"]
                    )
                    attached_policies = response["AttachedPolicies"]
                    while "IsTruncated" in response and response["IsTruncated"] is True:
                        response = client.list_attached_user_policies(
                            UserName=user["UserName"], Marker=response["Marker"]
                        )
                        attached_policies += response["AttachedPolicies"]
                    user["Policies"] += attached_policies
                except ClientError as error:
                    print("    List attached user policies failed")
                    if error.response["Error"]["Code"] == "AccessDenied":
                        print("      FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                    else:
                        print("      {}".format(error.response["Error"]["Code"]))
                    user["PermissionsConfirmed"] = False

                user = parse_attached_policies(client, attached_policies, user)
                if user["PermissionsConfirmed"]:
                    summary_data["users_confirmed"] += 1

                if args.user_name is None and args.all_users is False:
                    print("    Confirmed Permissions for {}".format(user["UserName"]))
                    active_aws_key.update(
                        pacu_main.database,
                        user_name=user["UserName"],
                        arn=user["Arn"],
                        user_id=user["UserId"],
                        groups=user["Groups"],
                        policies=user["Policies"],
                        permissions_confirmed=user["PermissionsConfirmed"],
                        allow_permissions=user["Permissions"]["Allow"],
                        deny_permissions=user["Permissions"]["Deny"],
                    )
                else:
                    with save(
                        "confirmed_permissions/user-{}.json".format(user["UserName"]),
                        "w+",
                    ) as f:
                        json.dump(user, f, indent=2, default=str)

                    print(
                        "    Permissions stored in user-{}.json".format(
                            user["UserName"]
                        )
                    )
            except ClientError as error:
                if error.response["Error"]["Code"] == "AccessDenied":
                    print("  FAILURE: MISSING REQUIRED AWS PERMISSIONS")
                else:
                    print("  {}".format(error.response["Error"]["Code"]))
                print("Skipping {}".format(user["UserName"]))

    return summary_data


def summary(data, pacu_main):
    out = ""
    if not data:
        return "  Unable to find users/roles to enumerate permissions\n"
    if data["users_confirmed"] == 1 and data.get("single_user"):
        out += "  Confirmed permissions for user: {}.\n".format(data["single_user"])
    else:
        out += "  Confirmed permissions for {} user(s).\n".format(
            data["users_confirmed"]
        )

    if data["roles_confirmed"] == 1:
        out += "  Confirmed permissions for role: {}.\n".format(data["single_role"])
    else:
        out += "  Confirmed permissions for {} role(s).\n".format(
            data["roles_confirmed"]
        )
    return out


def parse_attached_policies(client, attached_policies, user):
    """Pull permissions from each policy document."""
    for policy in attached_policies:
        document = get_attached_policy(client, policy["PolicyArn"])
        if document is False:
            user["PermissionsConfirmed"] = False
        else:
            user = parse_document(document, user)
    return user


def get_attached_policy(client, policy_arn):
    """Get the policy document of an attached policy."""
    try:
        policy = client.get_policy(PolicyArn=policy_arn)["Policy"]
        version = policy["DefaultVersionId"]
        can_get = True
    except Exception as error:
        print("Get policy failed: {}".format(error))
        return False

        # NOTE: If v1, v2, and v3 exist, then v2 is deleted, the next version will be v4 still, so this WILL error currently
        # print('Attempting to enumerate the default version...')
        # can_get = False

    try:
        if can_get is True:
            document = client.get_policy_version(
                PolicyArn=policy_arn, VersionId=version
            )["PolicyVersion"]["Document"]
            return document

        # else:  # If the user can't run get_policy, try to run get_policy_version to enumerate the default version
        #     for version in ['v1', 'v2', 'v3', 'v4', 'v5']:  # This won't error because it will return the default version before fetching a non-existent version
        #         policy_version = client.get_policy_version(
        #             PolicyArn=policy_arn,
        #             VersionId=version
        #         )['PolicyVersion']
        #         if policy_version['IsDefaultVersion'] is True:
        #             return policy_version['Document']

    except Exception as error:
        print("Get policy version failed: {}".format(error))
        return False


def parse_document(document, user):
    """Loop permissions, resources, and conditions"""
    if isinstance(document["Statement"], dict) or isinstance(document["Statement"], str):
        document["Statement"] = [document["Statement"]]
    statement_actions = get_resources_for_actions_from_statements(document["Statement"])

    for action in statement_actions:
        if statement_actions[action]["Allow_resources"]:
            if user["Permissions"]["Allow"].get(action) is None:
                user["Permissions"]["Allow"][action] = {
                    "Resources": [],
                    "Conditions": [],
                }
            user["Permissions"]["Allow"][action]["Resources"] += statement_actions[
                action
            ]["Allow_resources"]
        if statement_actions[action]["Allow_conditions"]:
            user["Permissions"]["Allow"][action]["Conditions"] += statement_actions[
                action
            ]["Allow_conditions"]
        if statement_actions[action]["Deny_resources"]:
            if user["Permissions"]["Deny"].get(action) is None:
                user["Permissions"]["Deny"][action] = {
                    "Resources": [],
                    "Conditions": [],
                }
            user["Permissions"]["Deny"][action]["Resources"] += statement_actions[
                action
            ]["Deny_resources"]
        if statement_actions[action]["Deny_conditions"]:
            user["Permissions"]["Deny"][action]["Conditions"] += statement_actions[
                action
            ]["Deny_conditions"]

    return user


def get_resources_for_actions_from_statements(list_of_statements):
    """
    Gets the denied and allowed resources with conditions for a given actions query
    from a list of policy statements
    Args: list_of_statements (list): list of statement JSON objects from a policy
    returns: dict: a dictionary of actions with the following structure:

    {

        "someAction": {
            "Deny_resources": set(),
            "Deny_conditions": [],
            "Allow_resources": set(),
            "Allow_conditions": []
        },
        "someOtherAction": {
            "Deny_resources": set(),
            "Deny_conditions": [],
            "Allow_resources": set(),
            "Allow_conditions": []
        }

    }
    """

    class ExtendedStatement(Statement):
        """
        Extends the Statement class to add the notresources and conditions properties
        """

        @property
        def notresources(self):
            # If the statement has NotResource, add a notresources attribute to the PU statement object
            if "NotResource" in self.statement:
                if isinstance(self.statement.get("NotResource"), str):
                    return set([self.statement.get("NotResource")])
                return set(self.statement.get("NotResource"))
            else:
                return set()

        @property
        def conditions(self):
            # Add a conditions attribute to the PU statement object
            return self.statement.get("Condition") or {}

    results = {}

    def new_action_dict():
        # returns a new action dictionary
        return {
            "Deny_resources": set(),
            "Deny_conditions": [],
            "Allow_resources": set(),
            "Allow_conditions": [],
        }

    for st in list_of_statements:
        try:
            statement = ExtendedStatement(st)
        except Exception as e:
            print(e)
            print("[!] Error parsing statement")
            continue

        # iterate through expanded actions
        for action in statement.actions_expanded:
            effect_key = statement.effect

            # Set the action dictionary to the results dictionary if it exists
            # otherwise create a new action dictionary
            action_dict = results.get(action, new_action_dict())

            # Add resources to the Deny_resources set if there is a notresources and effect is Allow
            if statement.notresources and statement.effect == "Allow":
                updated_resources = action_dict["Deny_resources"].union(
                    statement.notresources
                )
                action_dict.update({"Deny_resources": updated_resources})

            if statement.notresources and statement.effect == "Deny":
                # Add a condition in this case since it means access is denied
                # but does not mean any other access is allowed
                # TODO maybe a better way to do this but for now here we are.
                action_dict["Deny_conditions"].append(
                    {"IfResourcesNotIn": statement.notresources}
                )

            if statement.notresources and statement.effect == "Allow":
                # Add a condition in this case since it means access is allowed
                # to everything except the notresources
                # TODO maybe a better way to do this but for now here we are.
                action_dict["Allow_conditions"].append(
                    {"IfResourcesNotIn": statement.notresources}
                )

            # Update the Allow or Deny resources
            updated_resources = action_dict[f"{effect_key}_resources"].union(
                statement.resources
            )
            action_dict.update({f"{effect_key}_resources": updated_resources})

            # Add conditions if any exist
            if statement.conditions:
                action_dict[f"{effect_key}_conditions"].append(statement.conditions)

            # Update the results for the actions
            results[action] = action_dict

    return results
