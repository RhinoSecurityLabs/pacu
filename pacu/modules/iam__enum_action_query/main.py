#!/usr/bin/env python3
import argparse
import json
from colorama import Fore, Style
import os

from pacu.core.lib import strip_lines, downloads_dir

from policyuniverse.statement import Statement

module_info = {
    "name": "iam__enum_action_query",
    "author": "Dave Yesland (@daveysec)",
    "category": "ENUM",
    "one_liner": "Allows you to query enumerated user and role permissions.",
    "description": "This module allows you to query IAM permissions for users and roles and see what resources if any they have those permissions on. For example --query s3:get*,iam:create*.", # noqa
    "services": ["IAM"],
    "prerequisite_modules": ["iam__enum_permissions"],
    "external_dependencies": [],
    "arguments_to_autocomplete": [],
}

parser = argparse.ArgumentParser(description=module_info["description"])
parser.add_argument(
    "--query",
    required=True,
    help=strip_lines(
        """
    Permissions to query. One string like: s3:GetObject or s3:* or s3:GetObject,s3:PutObject.
"""
    ),
)
parser.add_argument(
    "--all-or-none",
    required=False,
    default=False,
    action="store_true",
    help=strip_lines(
        """
    This will check if all actions in the query are allowed, not just some of them, it will only print the principal and resources for those that allow all actions.
"""
    ),
)
parser.add_argument(
    "--role",
    required=False,
    help=strip_lines(
        """
    Filter a to a specific role.
"""
    ),
)
parser.add_argument(
    "--user",
    required=False,
    help=strip_lines(
        """
    Filter a to a specific user.
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


def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data

    class color:
        """
        Colorama color class
        Usage: print(color.red("This is red text"))
        Args: string (str): String to color
        """

        def red(string):
            return f"{Fore.RED}{string}{Style.RESET_ALL}"

        def green(string):
            return f"{Fore.GREEN}{string}{Style.RESET_ALL}"

        def yellow(string):
            return f"{Fore.YELLOW}{string}{Style.RESET_ALL}"

    if args.folder:
        iam_enum_folder = args.folder
    else:
        iam_enum_folder = "{}/confirmed_permissions/".format(downloads_dir())

    if os.path.isdir(iam_enum_folder) is False:
        print(
            f'{iam_enum_folder} not found! Maybe you have not run {module_info["prerequisite_modules"][module_info["prerequisite_modules"].index("iam__enum_permissions")]} yet...\n'
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

    # List all the files in the iam_query_data directory
    # which is created by the iam__enum_permissions module
    files = os.listdir(iam_enum_folder)

    def filter_files(files, filter):
        """
        Filter a list of files based on a filter
        Args: files (list): list of files to filter
        Args: filter (string): filter to apply to the list of files
        returns: list: list of filtered files
        """
        filtered_files = []
        for file in files:
            if filter.lower() in file.lower():
                filtered_files.append(file)
        return filtered_files

    # If the user has specified a role or user to filter by
    # then only use the files that match that role or user
    filtered_files = []
    if args.role:
        for role in args.role.split(","):
            filtered_files += filter_files(files, f"{role}.json")
    if args.user:
        for user in args.user.split(","):
            filtered_files += filter_files(files, f"{user}.json")
    if filtered_files:
        files = filtered_files

    # Setup query
    query_actions = args.query.split(",")
    list_of_actions_to_check = Statement({"Action": query_actions}).actions_expanded

    # Loop through each file and parse the statements
    for file_name in files:

        with open(f"{iam_enum_folder}{file_name}", "r") as principal_file:
            principal = json.load(principal_file)

            # Get principal info
            principal_name = principal.get("RoleName", principal.get("UserName"))
            principal_type = "Role" if "RoleName" in principal else "User"

            # Check if the principal has the action
            for action in list_of_actions_to_check:
                # Check if the any queried actions are allowed for a principal
                if action in principal["Permissions"]["Allow"]:
                    # Print out the info for the principal with relation to
                    # the action that was queried
                    print(
                            f"({principal_type}) {color.green(principal_name)} can perform {color.green(action)} on these resources:"
                        )
                    for resource in principal["Permissions"]["Allow"][action]["Resources"]:
                        print(resource)

                    # If there are conditions on the Allow action, print them out
                    if principal["Permissions"]["Allow"][action]["Conditions"]:
                        print(color.yellow("With the following conditions:"))
                        for condition in principal["Permissions"]["Allow"][action]["Conditions"]:
                            print(condition)

                    # Check if there are any Deny rules for the action
                    # If there are, print them out
                    if action in principal["Permissions"]["Deny"]:
                        print(
                            color.red("If the resources are not included in:")
                        )
                        for resource in principal["Permissions"]["Deny"][action]["Resources"]:
                            print(resource)
                        if principal["Permissions"]["Deny"][action]["Conditions"]:
                            print(color.yellow("These Deny rules only apply if the following conditions are met:"))
                            for condition in principal["Permissions"]["Deny"][action]["Conditions"]:
                                print(condition)
