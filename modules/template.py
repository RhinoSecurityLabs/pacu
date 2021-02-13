#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError


# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'template',

    # Name and any other notes about the author.
    'author': 'You of your company',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'category_name',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'Does this thing.',

    # Full description about what the module does and how it works.
    'description': 'This module does this thing by using xyz and outputs info to abc. Here is a note also.',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['EC2'],

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

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

# The two add_argument calls are placeholders for arguments. Change as needed.
# Arguments that accept multiple options, such as --usernames, should be
# comma-separated. For example:
#     --usernames user_a,userb,UserC
# Arguments that are region-specific, such as --instance-ids, should use
# an @ symbol to separate the data and its region; for example:
#     --instance-ids 123@us-west-1,54252@us-east-1,9999@ap-south-1
# Make sure to add all arguments to module_info['arguments_to_autocomplete']
parser.add_argument('', help='')
parser.add_argument('', required=False, default=None, help='')


# Main is the first function that is called when this module is executed.
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
    install_dependencies = pacu_main.install_dependencies
    ######

    # Use the print and input functions as you normally would. They have been
    # modified to log the data to a history file as well as to the console.

    # key_info fetches information for the currently active set of keys. This
    # returns a dictionary containing information about the AWS key using the
    # session's current key_alias, which includes info like User Name,
    # User Arn, User Id, Account Id, the permissions collected so far for the
    # user, the groups they are a part of, access key id, secret access key,
    # session token, key alias, and a note.
    user = key_info()

    # fetch_data is used when there is a prerequisite module to the current
    # module. The example below shows how to fetch all EC2 security group data
    # to use in this module.
    # This check will be false if the user declines to run the pre-requisite
    # module or it fails. Depending on the module, you may still want to
    # continue execution, so building the check is on you as a developer.
    if fetch_data(['EC2', 'SecurityGroups'], 'ec2__enum', '--security-groups') is False:
        print('Pre-req module not run successfully. Exiting...')
        return

    sec_groups = session.EC2['SecurityGroups']

    # Attempt to install the required external dependencies, exit this module
    # if the download/install fails
    if not install_dependencies(module_info['external_dependencies']):
        return

    # Use the get_regions function to fetch an array of supported regions for
    # the service that you pass into it.
    regions = get_regions('EC2')

    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('aws_service', region)
        data = client.do_something()

    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    return data


# The summary function will be called by Pacu after running main, and will be
# passed the data returned from main. It should return a single string
# containing a curated summary of every significant thing that the module did,
# whether successful or not; or None if the module exited early and made no
# changes that warrant a summary being displayed. The data parameter can
# contain whatever data is needed in any structure desired. A length limit of
# 1000 characters is enforced on strings returned by module summary functions.
def summary(data, pacu_main):
    if 'some_relevant_key' in data.keys():
        return 'This module compromised {} instances in the SomeRelevantKey service.'.format(len(data['some_relevant_key']))
    else:
        return 'No instances of the SomeRelevantKey service were compromised.'
