import importlib
import json
import os
import random
import subprocess
import sys
from typing import Optional, List

import boto3
import botocore

from pacu import cli, io
from pacu.aws import get_regions, validate_region
from pacu.cli import display_command_help
from pacu.core.models import AWSKey, new_session, PacuSession
from pacu.utils import import_module_by_name
from pacu.io import print
from settings import ROOT_DIR

COMMANDS = [
    'aws', 'data', 'exec', 'exit', 'help', 'import_keys', 'list', 'load_commands_file',
    'ls', 'quit', 'regions', 'run', 'search', 'services', 'set_keys', 'set_regions',
    'swap_keys', 'update_regions', 'whoami', 'swap_session', 'sessions',
    'list_sessions', 'delete_session', 'export_keys', 'open_console', 'console'
]

LOGO = """
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⣿⣿⣿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡿⠛⠉⠁⠀⠀⠈⠙⠻⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣷⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⡿⣿⣿⣷⣦⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣈⣉⣙⣛⣿⣿⣿⣿⣿⣿⣿⣿⡟⠛⠿⢿⣿⣷⣦⣄⠀⠀⠈⠛⠋⠀⠀⠀⠈⠻⣿⣷⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣈⣉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣀⣀⣀⣤⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣆⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣬⣭⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⢛⣉⣉⣡⣄⠀⠀⠀⠀⠀⠀⠀⠀⠻⢿⣿⣿⣶⣄⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⣁⣤⣶⡿⣿⣿⠉⠻⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢻⣿⣧⡀
 ⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⣠⣶⣿⡟⠻⣿⠃⠈⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣧
 ⢀⣀⣤⣴⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⢠⣾⣿⠉⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
 ⠉⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⡟
 ⠀⠀⠀⠀⠉⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡟⠁
 ⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⡀⠀⠀⠀⠀⠀⣴⣆⢀⣴⣆⠀⣼⣆⠀⠀⣶⣶⣶⣶⣶⣶⣶⣶⣾⣿⣿⠿⠋⠀⠀
 ⠀⠀⠀⣼⣿⣿⣿⠿⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠓⠒⠒⠚⠛⠛⠛⠛⠛⠛⠛⠛⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀
 ⠀⠀⠀⣿⣿⠟⠁⠀⢸⣿⣿⣿⣿⣿⣿⣿⣶⡀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣷⡄⠀⢀⣾⣿⣿⣿⣿⣿⣿⣷⣆⠀⢰⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠘⠁⠀⠀⠀⢸⣿⣿⡿⠛⠛⢻⣿⣿⡇⠀⢸⣿⣿⡿⠛⠛⢿⣿⣿⡇⠀⢸⣿⣿⡿⠛⠛⢻⣿⣿⣿⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠸⠿⠿⠟⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣧⣤⣤⣼⣿⣿⡇⠀⢸⣿⣿⣧⣤⣤⣼⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢀⣀⣀⣀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡏⠉⠉⠉⠉⠀⠀⠀⢸⣿⣿⡏⠉⠉⢹⣿⣿⡇⠀⢸⣿⣿⣇⣀⣀⣸⣿⣿⣿⠀⢸⣿⣿⣿⣀⣀⣀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⡟
 ⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠃⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠃⠀⠀⠘⠛⠛⠃⠀⠀⠉⠛⠛⠛⠛⠛⠛⠋⠀⠀⠀⠀⠙⠛⠛⠛⠛⠛⠉⠀
"""


def load_categories() -> set:
    categories = set()
    current_directory = os.getcwd()
    for root, directories, files in os.walk('{}/modules'.format(ROOT_DIR)):
        modules_directory_path = os.path.realpath('{}/modules'.format(ROOT_DIR))
        specific_module_directory = os.path.realpath(root)

        # Skip any directories inside module directories.
        if os.path.dirname(specific_module_directory) != modules_directory_path:
            continue
        # Skip the root directory.
        elif modules_directory_path == specific_module_directory:
            continue

        module_name = os.path.basename(root)

        for file in files:
            if file == 'main.py':
                # Make sure the format is correct
                module_path = 'modules/{}/main'.format(module_name).replace('/', '.').replace('\\', '.')
                # Import the help function from the module
                module = __import__(module_path, globals(), locals(), ['module_info'], 0)
                importlib.reload(module)
                categories.add(module.module_info['category'])
    return categories


CATEGORIES: set = load_categories()


def display_module_help(module_name: str) -> None:
    module = import_module_by_name(module_name, include=['module_info', 'parser'])

    if module is not None:
        print('\n{} written by {}.\n'.format(module.module_info['name'], module.module_info['author']))

        if 'prerequisite_modules' in module.module_info and len(module.module_info['prerequisite_modules']) > 0:
            print('Prerequisite Module(s): {}\n'.format(module.module_info['prerequisite_modules']))

        if 'external_dependencies' in module.module_info and len(module.module_info['external_dependencies']) > 0:
            print('External dependencies: {}\n'.format(module.module_info['external_dependencies']))

        parser_help = module.parser.format_help()
        print(parser_help.replace(os.path.basename(__file__), 'run {}'.format(module.module_info['name']), 1))
        return

    else:
        print('Command or module not found. Is it spelled correctly? Try using the module search function, or "help" to view a list of commands.')
        return


def list_modules(session, CATEGORIES, search_term, by_category=False):
    found_modules_by_category = dict()
    current_directory = os.getcwd()
    for root, directories, files in os.walk('{}/modules'.format(ROOT_DIR)):
        modules_directory_path = os.path.realpath('{}/modules'.format(ROOT_DIR))
        specific_module_directory = os.path.realpath(root)

        # Skip any directories inside module directories.
        if os.path.dirname(specific_module_directory) != modules_directory_path:
            continue
        # Skip the root directory.
        elif modules_directory_path == specific_module_directory:
            continue

        module_name = os.path.basename(root)

        for file in files:
            if file == 'main.py':
                # Make sure the format is correct
                module_path = 'modules/{}/main'.format(module_name).replace('/', '.').replace('\\', '.')
                # Import the help function from the module
                module = __import__(module_path, globals(), locals(), ['module_info'], 0)
                importlib.reload(module)
                category = module.module_info['category']
                services = module.module_info['services']

                regions = []
                for service in services:
                    regions += get_regions(service)

                # Skip modules with no regions in the list of set regions.
                if len(regions) == 0:
                    continue

                # Searching for modules by category:
                if by_category and search_term.upper() in category:
                    if category not in found_modules_by_category.keys():
                        found_modules_by_category[category] = list()

                    found_modules_by_category[category].append('  {}'.format(module_name))

                    if search_term:
                        found_modules_by_category[category].append('    {}\n'.format(module.module_info['one_liner']))

                # Searching or listing modules without specifying a category:
                elif not by_category and search_term in module_name:
                    if category not in found_modules_by_category.keys():
                        found_modules_by_category[category] = list()

                    found_modules_by_category[category].append('  {}'.format(module_name))

                    if search_term:
                        found_modules_by_category[category].append('    {}\n'.format(module.module_info['one_liner']))

    if found_modules_by_category:
        for category in CATEGORIES:
            if category in found_modules_by_category:
                search_results = '\n'.join(found_modules_by_category[category]).strip('\n')
                print('\n[Category: {}]\n\n{}'.format(category, search_results))
    else:
        print('\nNo modules found.')
    print()


def all_region_prompt() -> bool:
    print('Automatically targeting regions:')
    for region in get_regions('all'):
        print('  {}'.format(region))
    response = input('Continue? (y/n) ')
    if response.lower() == 'y':
        return True
    else:
        return False


def export_keys() -> None:
    session = PacuSession.active_session()
    export = input('Export the active keys to the AWS CLI credentials file (~/.aws/credentials)? (y/n) ').rstrip()

    if export.lower() == 'y':
        session = session

        if not session.key_alias.access_key_id:
            print('  No access key has been set. Not exporting credentials.')
            return
        if not session.key_alias.secret_access_key:
            print('  No secret key has been set. Not exporting credentials.')
            return

        config = """
\n\n[{}]
aws_access_key_id = {}
aws_secret_access_key = {}
""".format(session.key_alias, session.key_alias.access_key_id, session.key_alias.secret_access_key)
        if session.key_alias.session_token:
            config = config + 'aws_session_token = "{}"'.format(session.key_alias.session_token)

        config = config + '\n'

        with open('{}/.aws/credentials'.format(os.path.expanduser('~')), 'a+') as f:
            f.write(config)

        print('Successfully exported {}. Use it with the AWS CLI like this: aws ec2 describe instances --profile {}'.format(
            session.key_alias, session.key_alias
        ))
    else:
        return


def parse_list_command(command):
    session = PacuSession.active_session()
    if len(command) == 1:
        list_modules(session, CATEGORIES, '')

    elif len(command) == 2:
        if command[1] in ('cat', 'category', 'categories'):
            print("[Categories]:")
            for category in CATEGORIES:
                print('    {}'.format(category))

    # list cat/category <cat_name>
    elif len(command) == 3:
        if command[1] in ('cat', 'category'):
            list_modules(session, CATEGORIES, command[2], by_category=True)


def parse_help_command(COMMANDS, command: List[str]) -> None:
    if len(command) <= 1:
        cli.display_pacu_help()
    elif len(command) > 1 and command[1] in COMMANDS:
        display_command_help(command[1])
    else:
        display_module_help(command[1])


def parse_search_command(command: List[str]) -> None:
    session = PacuSession.active_session()
    if len(command) == 1:
        list_modules(session, CATEGORIES, '')
    elif len(command) == 2:
        list_modules(session, CATEGORIES, command[1])
    elif len(command) >= 3:
        if command[1] in ('cat', 'category'):
            list_modules(session, CATEGORIES, command[2], by_category=True)


def parse_set_regions_command(command):
    session = PacuSession.active_session()

    if len(command) > 1:
        for region in command[1:]:
            if region.lower() == 'all':
                session.update(session_regions=['all'])
                print('  The region set for this session has been reset to the default of all supported regions.')
                return
            if validate_region(region) is False:
                print('  {} is not a valid region.\n  Session regions not changed.'.format(region))
                return
        session.update(session_regions=command[1:])
        print('  Session regions changed: {}'.format(session.session_regions))
    else:
        print('  Error: set_regions requires either "all" or at least one region to be specified. Try the "regions" command to view all regions.')


def exit() -> None:
    sys.exit('SIGINT called')


def check_sessions() -> PacuSession:
    sessions = PacuSession.query.all()

    if not sessions:
        session = new_session()
    else:
        print('Found existing sessions:')
        print('  [0] New session')

        for index, session in enumerate(sessions, 1):
            print('  [{}] {}'.format(index, session.name))

        choice = input('Choose an option: ')

        try:
            if int(choice) == 0:
                session = new_session()
            else:
                session = sessions[int(choice) - 1]
        except (ValueError, IndexError):
            print('Please choose a number from 0 to {}.'.format(len(sessions)))
            return sessions()

    session.activate()

    return session


def run_aws_cli_command(command: List[str]) -> None:
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
    except subprocess.CalledProcessError as error:
        result = error.output.decode('utf-8')

    print(result)


def parse_data_command(command: List[str]) -> None:
    session = PacuSession.active_session()

    if len(command) == 1:
        print('\nSession data:')
        session.print_all_data_in_session()
    else:
        if command[1] not in session.aws_data_field_names:
            print('  Service not found.')
        elif getattr(session, command[1]) == {} or getattr(session, command[1]) == [] or getattr(session, command[1]) == '':
            print('  No data found.')
        else:
            print(json.dumps(getattr(session, command[1]), indent=2, sort_keys=True, default=str))


def set_keys(key_alias: str = None, access_key_id: str = None, secret_access_key: str = None, session_token: str = None) -> None:
    session = PacuSession.active_session()

    # If key_alias is None, then it's being run normally from the command line (set_keys),
    # otherwise it means it is set programmatically and we don't want any prompts if it is
    # done programatically
    if key_alias:
        interactive = False
    else:
        interactive = True
        print('Setting AWS Keys...')
        print('Press enter to keep the value currently stored.')
        print('Enter the letter C to clear the value, rather than set it.')
        print('If you enter an existing key_alias, that key\'s fields will be updated instead of added.\n')

    def ask(msg: str):
        resp = io.input(msg)
        return '' if resp == 'c' else resp or False

    if interactive:
        key_alias = ask('Key alias [{}]: '.format(session.key_alias)) or key_alias
    # key_alias is a foreign key constraint so fallback to access_key_id then a random but awesome name.
    if str(key_alias) == '':
        key_alias = access_key_id or '{}-{}-{}'.format(
            random.choice(['oikura', 'aikawa', 'itoshiki', 'haruhi']),
            random.choice(['san', 'sempai', 'sensei', 'sama']),
            str(random.choice(range(100)))
        )

        access_key_id = ask('Access key ID [{}]: '.format(access_key_id)) or access_key_id
        print('Access key ID [{}]: {}'.format(session.key_alias.access_key_id, access_key_id), output='file')

        # Secret access key (should not be entered in log files)
        if secret_access_key:
            half_length = int(len(secret_access_key) / 2)
            display_name = '{}{}'.format(secret_access_key[:half_length], '*' * half_length)
        else:
            display_name = 'None'
        secret_access_key = ask('Secret access key [{}]: '.format(display_name)) or secret_access_key
        print('Secret access key [******]: ****** (Censored)', output='file')

        # Session token
        session_token = ask('Session token (Optional - for temp AWS keys only) [{}]: '.format(session_token)) or session_token
        print('Session token [{}]: {}'.format(session.key_alias.session_token, session_token), output='file')

    aws_key = AWSKey.create(
        pacu_session=session,
        key_alias=key_alias,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token
    )

    if not session.key_alias:
        session.update(key_alias=aws_key)
        print('Key alias imported and activated [{}]: {}'.format(session.key_alias, key_alias))
    else:
        print('Key alias imported but not active, use swap_keys to activate it [{}]: {}'.format(session.key_alias, key_alias))


def swap_keys() -> None:
    session = PacuSession.active_session()

    # On attr-defined ignore: https://github.com/dropbox/sqlalchemy-stubs/issues/168
    aws_keys: List[AWSKey] = session.aws_keys.all()  # type: ignore[attr-defined]

    if not aws_keys:
        print('\nNo AWS keys set for this session. Run "set_keys" to add AWS keys.\n')
        return

    print('\nSwapping AWS Keys. Press enter to keep the currently active key.')

    print('AWS keys in this session:')

    for index, aws_key in enumerate(aws_keys, 1):
        if aws_key.key_alias == session.key_alias:
            print('  [{}] {} (ACTIVE)'.format(index, aws_key.key_alias))
        else:
            print('  [{}] {}'.format(index, aws_key.key_alias))

    choice = input('Choose an option: ')

    if not str(choice).strip():
        print('The currently active AWS key will remain active. ({})'.format(session.key_alias))
        return

    if not choice.isdigit() or int(choice) not in range(1, len(aws_keys) + 1):
        print('Please choose a number from 1 to {}.'.format(len(aws_keys)))
        return swap_keys()

    chosen_key = aws_keys[int(choice) - 1]
    session.update(key_alias=chosen_key)
    print('AWS key is now {}.'.format(session.key_alias))


def check_user_agent() -> None:
    session = PacuSession.active_session()

    if session.boto_user_agent is None:  # If there is no user agent set for this session already
        boto3_session = boto3.session.Session()
        ua = boto3_session._session.user_agent()
        if 'kali' in ua.lower() or 'parrot' in ua.lower() or 'pentoo' in ua.lower():  # If the local OS is Kali/Parrot/Pentoo Linux
            # GuardDuty triggers a finding around API calls made from Kali Linux, so let's avoid that...
            print('Detected environment as one of Kali/Parrot/Pentoo Linux. Modifying user agent to hide that from GuardDuty...')
            with open('./user_agents.txt', 'r') as file:
                user_agents = file.readlines()
            user_agents = [agent.strip() for agent in user_agents]  # Remove random \n's and spaces
            new_ua = random.choice(user_agents)
            session.update(boto_user_agent=new_ua)
            print('  User agent for this session set to:')
            print('    {}'.format(new_ua))


def import_awscli_key(profile_name: str) -> None:
    try:
        boto3_session = boto3.session.Session(profile_name=profile_name)
        creds = boto3_session.get_credentials()
        set_keys(key_alias='imported-{}'.format(profile_name), access_key_id=creds.access_key, secret_access_key=creds.secret_key,
                 session_token=creds.token)
        print('  Imported keys as "imported-{}"'.format(profile_name))
    except botocore.exceptions.ProfileNotFound:
        print('\n  Did not find the AWS CLI profile: {}\n'.format(profile_name))
        boto3_session = boto3.session.Session()
        print('  Profiles that are available:\n    {}\n'.format('\n    '.join(boto3_session.available_profiles)))


def parse_awscli_keys_import(command):
    if len(command) == 1:
        display_command_help('import_keys')
        return

    boto3_session = boto3.session.Session()

    if command[1] == '--all':
        profiles = boto3_session.available_profiles
        for profile_name in profiles:
            import_awscli_key(profile_name)
        return

    import_awscli_key(command[1])
