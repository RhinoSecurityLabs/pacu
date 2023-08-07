#!/usr/bin/env python3
import copy
import importlib
import json
import os
import random
import re
import shlex
import subprocess
import sys
import time
import traceback
import argparse
import uuid
from pathlib import Path
from typing import List, Optional, Any, Dict, Union, Tuple

from pacu.core import lib
from pacu.core.lib import session_dir
from datetime import datetime

try:
    import jq  # type: ignore
    import requests
    import boto3
    import botocore
    import botocore.config
    import botocore.session
    import botocore.exceptions
    import urllib.parse

    from pacu import settings

    from pacu.core.models import AWSKey, PacuSession, migrations
    from pacu.setup_database import setup_database_if_not_present
    from sqlalchemy import exc, orm  # type: ignore
    from pacu.utils import get_database_connection, set_sigint_handler
except ModuleNotFoundError:
    exception_type, exception_value, tb = sys.exc_info()
    print('Traceback (most recent call last):\n{}{}: {}\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)))
    print('Pacu was not able to start because a required Python package was not found.\nRun `sh install.sh` to check and install Pacu\'s Python requirements.')
    sys.exit(1)


def load_categories() -> set:
    categories = set()
    current_directory = os.getcwd()
    for root, directories, files in os.walk(Path(__file__).parent/'modules'):
        modules_directory_path = os.path.realpath(Path(__file__).parent/'modules')
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
                module_path = str(Path('pacu/modules')/module_name/'main').replace('/', '.').replace('\\', '.')
                # Import the help function from the module
                module = __import__(module_path, globals(), locals(), ['module_info'], 0)
                importlib.reload(module)
                categories.add(module.module_info['category'])
    return categories


def display_pacu_help():
    print("""
    Pacu - https://github.com/RhinoSecurityLabs/pacu
    Written and researched by Spencer Gietzen of Rhino Security Labs - https://rhinosecuritylabs.com/

    This was built as a modular, open source tool to assist in penetration testing an AWS environment.
    For usage and developer documentation, please visit the GitHub page.

    Modules that have pre-requisites will have those listed in that modules help info, but if it is
    executed before its pre-reqs have been filled, it will prompt you to run that module then continue
    once that is finished, so you have the necessary data for the module you want to run.

    Pacu command info:
        list/ls                             List all modules
        load_commands_file <file>           Load an existing file with list of commands to execute
        search [cat[egory]] <search term>   Search the list of available modules by name or category
        help                                Display this page of information
        help <module name>                  Display information about a module
        whoami                              Display information regarding to the active access keys
        data                                Display all data that is stored in this session. Only fields
                                              with values will be displayed
        data <service> [<sub-service>]      Display all data for a specified service in this session
        jq <query> <service> [<sub-service>] Run a jq statement on the specified service's data
        services                            Display a list of services that have collected data in the
                                              current session to use with the "data" command
        regions                             Display a list of all valid AWS regions
        update_regions                      Run a script to update the regions database to the newest
                                              version
        set_regions <region> [<region>...]  Set the default regions for this session. These space-separated
                                              regions will be used for modules where regions are required,
                                              but not supplied by the user. The default set of regions is
                                              every supported region for the service. Supply "all" to this
                                              command to reset the region set to the default of all
                                              supported regions
        set_ua_suffix [<suffix>]            Set the user agent suffix for this session. The suffix will be
                                              appended to the user agent for all API calls. If no suffix is
                                              supplied a UUID-based suffix will be generated.
        unset_ua_suffix                     Remove the user agent suffix for this session.
        run/exec <module name>              Execute a module
        set_keys                            Add a set of AWS keys to the session and set them as the
                                              default
        swap_keys                           Change the currently active AWS key to another key that has
                                              previously been set for this session
        import_keys <profile name>|--all    Import AWS keys from the AWS CLI credentials file (located
                                              at ~/.aws/credentials) to the current sessions database.
                                              Enter the name of a profile you would like to import or
                                              supply --all to import all the credentials in the file.
        assume_role <role arn>              Call AssumeRole on the specified role from the current
                                              credentials, add the resulting temporary keys to the Pacu
                                              key database and start using these new credentials.
        export_keys                         Export the active credentials to a profile in the AWS CLI
                                              credentials file (~/.aws/credentials)
        sessions/list_sessions              List all sessions in the Pacu database
        swap_session <session name>         Change the active Pacu session to another one in the database
        delete_session                      Delete a Pacu session from the database. Note that the output
                                              folder for that session will not be deleted

        exit/quit                           Exit Pacu

    Other command info:
        aws <command>                       Run an AWS CLI command directly. Note: If Pacu detects "aws"
                                              as the first word of the command, the whole command will
                                              instead be run in a shell so that you can use the AWS CLI
                                              from within Pacu. Due to the command running in a shell,
                                              this enables you to pipe output where needed. An example
                                              would be to run an AWS CLI command and pipe it into "jq"
                                              to parse the data returned. Warning: The AWS CLI's
                                              authentication is not related to Pacu. Be careful to
                                              ensure that you are using the keys you want when using
                                              the AWS CLI. It is suggested to use AWS CLI profiles
                                              to solve this problem
        console/open_console                Generate a URL that will log the current user/role in to
                                              the AWS web console
    """)


def import_module_by_name(module_name: str, include: List[str] = []) -> Any:  # TODO: define module type
    file_path = str(Path(__file__).parent/'modules'/module_name/'main.py')
    if os.path.exists(file_path):
        import_path = str(Path('pacu/modules')/module_name/'main').replace('/', '.').replace('\\', '.')
        module = __import__(import_path, globals(), locals(), include, 0)
        importlib.reload(module)
        return module
    return None


def get_data_from_traceback(tb) -> Tuple[Optional[PacuSession], List[str], List[str]]:
    session = None
    global_data_in_all_frames = list()
    local_data_in_all_frames = list()

    for frame, line_number in traceback.walk_tb(tb):
        global_data_in_all_frames.append(str(frame.f_globals))
        local_data_in_all_frames.append(str(frame.f_locals))

        # Save the most recent PacuSession called "session", working backwards.
        if session is None:
            session = frame.f_locals.get('session', None)
            if not isinstance(session, PacuSession):
                session = None

    return session, global_data_in_all_frames, local_data_in_all_frames


class Main:
    COMMANDS = [
        'aws', 'data', 'exec', 'exit', 'help', 'import_keys', 'assume_role', 'list', 'load_commands_file',
        'ls', 'quit', 'regions', 'run', 'search', 'services', 'set_keys', 'set_regions',
        'swap_keys', 'update_regions', 'set_ua_suffix', 'unset_ua_suffix', 'whoami', 'swap_session', 'sessions',
        'list_sessions', 'delete_session', 'export_keys', 'open_console', 'console'
    ]

    def __init__(self):
        # NOTE: self.database is the sqlalchemy session since 'session' is reserved for PacuSession objects.
        self.database: orm.session.Session = None
        self.running_module_names: List[str] = []
        self.CATEGORIES: set = load_categories()

        # Hack so we can use session names without passing around Main.
        lib.get_active_session = self.get_active_session

    # Utility methods
    def log_error(self, text, exception_info=None, session=None, local_data=None, global_data=None) -> None:
        """ Write an error to the file at log_file_path, or a default log file
        if no path is supplied. If a session is supplied, its name will be used
        to determine which session directory to add the error file to. """

        timestamp = time.strftime('%F %T', time.gmtime())

        if session:
            session_tag = '({})'.format(session.name)
        else:
            session_tag = '<No Session>'

        try:
            if session:
                log_file_path = '{}/error_log.txt'.format(session_dir())
            else:
                log_file_path = '{}/global_error_log.txt'.format(session_dir())

            print('\n[{}] Pacu encountered an error while running the previous command. Check {} for technical '
                  'details. [LOG LEVEL: {}]\n\n    {}\n'.format(timestamp, log_file_path,
                                                                settings.ERROR_LOG_VERBOSITY.upper(), exception_info))

            log_file_directory = os.path.dirname(log_file_path)
            if log_file_directory and not os.path.exists(log_file_directory):
                os.makedirs(log_file_directory)

            formatted_text = '[{}] {}: {}'.format(timestamp, session_tag, text)

            if settings.ERROR_LOG_VERBOSITY.lower() in ('low', 'high', 'extreme'):
                if session:
                    session_data = session.get_all_fields_as_dict()
                    # Empty values are not valid keys, and that info should be
                    # preserved by checking for falsiness here.
                    if session_data.get('secret_access_key'):
                        session_data['secret_access_key'] = '****** (Censored)'

                    formatted_text += 'SESSION DATA:\n    {}\n'.format(
                        json.dumps(
                            session_data,
                            indent=4,
                            default=str
                        )
                    )

            if settings.ERROR_LOG_VERBOSITY.lower() == 'high':
                if local_data is not None and global_data is not None:
                    formatted_text += '\nLAST TWO FRAMES LOCALS DATA:\n    {}\n'.format('\n\n    '.join(local_data[:2]))
                    formatted_text += '\nLAST TWO FRAMES GLOBALS DATA:\n    {}\n'.format('\n\n    '.join(global_data[:2]))

            elif settings.ERROR_LOG_VERBOSITY.lower() == 'extreme':
                if local_data is not None and global_data is not None:
                    formatted_text += '\nALL LOCALS DATA:\n    {}\n'.format('\n\n    '.join(local_data))
                    formatted_text += '\nALL GLOBALS DATA:\n    {}\n'.format('\n\n    '.join(global_data))

            formatted_text += '\n'

            with open(log_file_path, 'a+') as log_file:
                log_file.write(formatted_text)

        except Exception as error:
            print('Error while saving exception information. This means the exception was not added to any error log '
                  'and should most likely be provided to the developers.\n    Exception raised: {}'.format(str(error)))
            raise

    # @message: String - message to print and/or write to file
    # @output: String - where to output the message: both, file, or screen
    # @output_type: String - format for message when written to file: plain or xml
    # @is_cmd: boolean - Is the log the initial command that was run (True) or output (False)? Devs won't touch this most likely
    def print(self, message: Union[dict, list, str, Exception] = '', output='both', output_type='plain', is_cmd=False, session_name='') -> bool:
        session = self.get_active_session()

        if session_name == '':
            session_name = session.name

        # Indent output from a command
        if is_cmd is False:
            # Add some recursion here to go through the entire dict for
            # 'SecretAccessKey'. This is to not print the full secret access
            # key into the logs, although this should get most cases currently.
            if isinstance(message, dict):
                if 'SecretAccessKey' in message:
                    message = copy.deepcopy(message)
                    truncated_key = message['SecretAccessKey'][0:int(len(message['SecretAccessKey']) / 2)]
                    message['SecretAccessKey'] = '{}{}'.format(truncated_key, '*' * int(len(message['SecretAccessKey']) / 2))
                message = json.dumps(message, indent=2, default=str)
            elif isinstance(message, list):
                message = json.dumps(message, indent=2, default=str)

        # The next section prepends the running module's name in square
        # brackets in front of the first line in the message containing
        # non-whitespace characters.
        if len(self.running_module_names) > 0 and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = '[{}] {}'.format(self.running_module_names[-1], fragment)
                    break
            message = '\n'.join(split_message)

        if output == 'both' or output == 'file':
            if output_type == 'plain':
                with open(f'{session_dir()}/cmd_log.txt', 'a+') as text_file:
                    text_file.write('{}\n'.format(message))
            elif output_type == 'xml':
                # TODO: Implement actual XML output
                with open(f'{session_dir()}/cmd_log.xml', 'a+') as xml_file:
                    xml_file.write('{}\n'.format(message))
                pass
            else:
                print('  Unrecognized output type: {}'.format(output_type))

        if output == 'both' or output == 'screen':
            print(message)

        return True

    # @message: String - input question to ask and/or write to file
    # @output: String - where to output the message: both or screen (can't write a question to a file only)
    # @output_type: String - format for message when written to file: plain or xml
    def input(self, message, output='both', output_type='plain', session_name='') -> str:
        session = self.get_active_session()

        if session_name == '':
            session_name = session.name

        if len(self.running_module_names) > 0 and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = '[{}] {}'.format(self.running_module_names[-1], fragment)
                    break
            message = '\n'.join(split_message)

        res = input(message)
        if output == 'both':
            if output_type == 'plain':
                with open(f'{session_dir()}/cmd_log.txt', 'a+') as file:
                    file.write('{} {}\n'.format(message, res))
            elif output_type == 'xml':
                # TODO: Implement actual XML output
                # now = time.time()
                with open(f'{session_dir}/cmd_log.xml', 'a+') as file:
                    file.write('{} {}\n'.format(message, res))
            else:
                print('  Unrecognized output type: {}'.format(output_type))
        return res

    def validate_region(self, region) -> bool:
        if region in self.get_regions('All'):
            return True
        return False

    def get_regions(self, service, check_session=True) -> List[Optional[str]]:
        session = self.get_active_session()

        service = service.lower()

        with open(Path(__file__).parent/'modules/service_regions.json', 'r') as regions_file:
            regions = json.load(regions_file)

        # TODO: Add an option for GovCloud regions

        if service == 'all':
            valid_regions = regions['all']
            if 'local' in valid_regions:
                valid_regions.remove('local')
            if 'af-south-1' in valid_regions:
                valid_regions.remove('af-south-1')  # Doesn't work currently
            if 'ap-east-1' in valid_regions:
                valid_regions.remove('ap-east-1')
            if 'eu-south-1' in valid_regions:
                valid_regions.remove('eu-south-1')
            if 'me-south-1' in valid_regions:
                valid_regions.remove('me-south-1')
        if type(regions[service]) == dict and regions[service].get('endpoints'):
            if 'aws-global' in regions[service]['endpoints']:
                return [None]
            if 'all' in session.session_regions:
                valid_regions = list(regions[service]['endpoints'].keys())
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                return valid_regions
            else:
                valid_regions = list(regions[service]['endpoints'].keys())
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                if check_session is True:
                    return [region for region in valid_regions if region in session.session_regions]
                else:
                    return valid_regions
        else:
            if 'aws-global' in regions[service]:
                return [None]
            if 'all' in session.session_regions:
                valid_regions = regions[service]
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                return valid_regions
            else:
                valid_regions = regions[service]
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                if check_session is True:
                    return [region for region in valid_regions if region in session.session_regions]
                else:
                    return valid_regions

    def display_all_regions(self):
        for region in sorted(self.get_regions('all')):
            print('  {}'.format(region))

    # @data: list
    # @module: string
    # @args: string
    def fetch_data(self, data: List[str], module: str, args: str, force=False) -> bool:
        session = self.get_active_session()

        if data is None:
            current = None
        else:
            current = getattr(session, data[0], None)
            for item in data[1:]:
                if current is not None and item in current:
                    current = current[item]
                else:
                    current = None
                    break

        if current is None or current == '' or current == [] or current == {} or current is False:
            if force is False:
                run_prereq = self.input('Data ({}) not found, run module "{}" to fetch it? (y/n) '.format(' > '.join(data), module), session_name=session.name)
            else:
                run_prereq = 'y'
            if run_prereq == 'n':
                return False

            if args:
                self.exec_module(['exec', module] + args.split(' '))
            else:
                self.exec_module(['exec', module])
        return True

    def check_for_updates(self):
        TIME_FORMAT = '%Y-%m-%d'
        UPDATE_CYCLE = 7  # Days
        UPDATE_INFO_PATH = lib.home_dir()/'update_info.json'
        LAST_UPDATE_PATH = lib.pacu_dir()/'last_update.txt'
        UPDATE_MSG = '''Pacu has a new version available! Clone it from GitHub to receive the updates.
        git clone https://github.com/RhinoSecurityLabs/pacu.git'''

        with open(LAST_UPDATE_PATH, 'r') as f:
            local_last_update = f.read().rstrip()

        datetime_now = datetime.now()
        datetime_local = datetime.strptime(local_last_update, TIME_FORMAT)

        datetime_last_check = datetime.min
        latest_cached = datetime.min

        # update_info.json structure:
        # { 'last_check':'YYYY-MM-DD', 'latest_cached':'YYYY-MM-DD'}
        # Create a update_info.json if not exist
        update_info = {}
        if os.path.isfile(UPDATE_INFO_PATH):
            with open(UPDATE_INFO_PATH, 'r') as f:
                update_info = json.load(f)
                datetime_last_check = datetime.strptime(update_info['last_check'], TIME_FORMAT)
                latest_cached = datetime.strptime(update_info['latest_cached'], TIME_FORMAT)

        # Check upstream
        if (datetime_now - datetime_last_check).days >= UPDATE_CYCLE:
            latest_update = requests.get(
                'https://raw.githubusercontent.com/RhinoSecurityLabs/pacu/master/pacu/last_update.txt').text.rstrip()
            latest = datetime.strptime(latest_update, TIME_FORMAT)

            update_info['latest_cached'] = latest.strftime(TIME_FORMAT)
            update_info['last_check'] = datetime_now.strftime(TIME_FORMAT)
            with open(UPDATE_INFO_PATH, 'w') as f:
                json.dump(update_info, f)

            if datetime_local < latest:
                print(UPDATE_MSG)
                return True
        # Local check
        elif datetime_local < latest_cached:
            print(datetime_local, latest_cached)
            print(UPDATE_MSG)
            return True
        return False

    def key_info(self, alias='') -> Union[Dict[str, Any], bool]:
        """ Return the set of information stored in the session's active key
        or the session's key with a specified alias, as a dictionary. """
        session = self.get_active_session()

        if alias == '':
            alias = session.key_alias

        aws_key = self.get_aws_key_by_alias(alias)

        if aws_key is not None:
            return aws_key.get_fields_as_camel_case_dictionary()
        else:
            return False

    def print_key_info(self):
        self.print(self.key_info())

    def print_all_service_data(self, command):
        session = self.get_active_session()
        services = session.get_all_aws_data_fields_as_dict()
        for service in services.keys():
            print('  {}'.format(service))

    def install_dependencies(self, external_dependencies) -> bool:
        if len(external_dependencies) < 1:
            return True
        answer = self.input('This module requires external dependencies: {}\n\nInstall them now? (y/n) '.format(external_dependencies))
        if answer == 'n':
            self.print('Not installing dependencies, exiting...')
            return False
        self.print('\nInstalling {} total dependencies...'.format(len(external_dependencies)))
        for dependency in external_dependencies:
            split = dependency.split('/')
            name = split[-1]
            if name.split('.')[-1] == 'git':
                name = name.split('.')[0]
                author = split[-2]
                dir = session_dir()/'dependencies'/author/name
                if dir.exists():
                    self.print('  Dependency {}/{} already installed.'.format(author, name))
                else:
                    try:
                        self.print('  Installing dependency {}/{} from {}...'.format(author, name, dependency))
                        subprocess.run(['git', 'clone', dependency, dir])
                    except subprocess.CalledProcessError as error:
                        self.print('{} failed, view the error below. If you are unsure, some potential causes are '
                                   'that you are missing "git" on your command line, your git credentials are not '
                                   'properly set, or the GitHub link does not exist.'.format(error.cmd))
                        self.print('    stdout: {}\nstderr: {}'.format(error.cmd, error.stderr))
                        self.print('  Exiting module...')
                        return False
            else:
                dir = session_dir()/'dependencies'/name
                if dir.exists():
                    self.print('  Dependency {} already installed.'.format(name))
                else:
                    try:
                        self.print('  Installing dependency {}...'.format(name))
                        r = requests.get(dependency, stream=True)
                        if r.status_code == 404:
                            raise Exception('File not found.')
                        with open(dir, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=1024):
                                if chunk:
                                    f.write(chunk)
                    except Exception as error:
                        self.print('    Downloading {} has failed, view the error below.'.format(dependency))
                        self.print(error)
                        self.print('  Exiting module...')

                        return False
        self.print('Dependencies finished installing.')
        return True

    def get_active_session(self) -> PacuSession:
        """ A wrapper for PacuSession.get_active_session, removing the need to
        import the PacuSession model. """
        return PacuSession.get_active_session(self.database)

    def get_aws_key_by_alias(self, alias: str) -> AWSKey:
        """ Return an AWSKey with the supplied alias that is assigned to the
        currently active PacuSession from the database, or None if no AWSKey
        with the supplied alias exists. If more than one key with the alias
        exists for the active session, an exception will be raised. """
        session = self.get_active_session()
        key = self.database.query(AWSKey) \
            .filter(AWSKey.session_id == session.id) \
            .filter(AWSKey.key_alias == alias) \
            .scalar()
        return key

    def get_aws_key_by_alias_from_db(self, alias: str) -> AWSKey:
        """ Return an AWSKey with the supplied alias that is assigned to the
         PacuSession from the database, or None if no AWSKey
        with the supplied alias exists. If more than one key with the alias
        exists for the active session, an exception will be raised. """
        # session = self.get_active_session()
        key = self.database.query(AWSKey) \
            .filter(AWSKey.key_alias == alias) \
            .scalar()
        return key

    # Pacu commands and execution

    def parse_command(self, command):
        command = command.strip()

        if command.split(' ')[0] == 'aws':
            # command_lowercase = command.lower()
            command_splitted = command.split(' ')
            if '--profile' in command_splitted or '--p' in command_splitted:
                # user sets profile, so we don't use our pacu keys
                self.run_aws_cli_command(command)
            else:
                session_dir = lib.session_dir()
                active_session = self.get_active_session()
                if active_session.access_key_id and active_session.secret_access_key:
                    credentials_file_name = '{}/credentials.tmp'.format(session_dir)
                    config_file_name = '{}/config.tmp'.format(session_dir)
                    fd_credentials = open(credentials_file_name, 'w')
                    fd_config = open(config_file_name, 'w')
                    fd_credentials.write('[default]\n')
                    fd_credentials.write('aws_access_key_id = %s\n' % active_session.access_key_id)
                    fd_credentials.write('aws_secret_access_key = %s\n' % active_session.secret_access_key)
                    if active_session.session_token:
                        fd_credentials.write('aws_session_token = %s\n' % active_session.session_token)
                    # if region only one, then use it as a default region
                    # else left it empty, so user should use --region manually
                    regions = self.get_regions('all')
                    if len(regions) == 1:
                        fd_credentials.write('region=%s' % regions[0])
                    if len(regions) == 1:
                        fd_config.write('[default]\n')
                        fd_config.write('region=%s' % regions[0])
                    fd_credentials.close()
                    fd_config.close()
                    command_with_new_env = 'AWS_SHARED_CREDENTIALS_FILE=%s AWS_CONFIG_FILE=%s %s' % (credentials_file_name, config_file_name, command)
                    self.run_aws_cli_command(command_with_new_env)
                    os.remove(credentials_file_name)
                    os.remove(config_file_name)
                else:
                    raise UserWarning(''' You didn\'t set Keys and didn\'t set --profile argument. If you want to use default system aws credentials,
                     use --profile arg. For example: aws --profile default. In another case - set default keys in session.''')
            return

        try:
            command = shlex.split(command)
        except ValueError:
            self.print('  Error: Unbalanced quotes in command')
            return

        if not command or command[0] == '':
            return
        elif command[0] == 'data':
            self.parse_data_command(command)
        elif command[0] == 'jq':
            self.parse_jq_command(command)
        elif command[0] == 'sessions' or command[0] == 'list_sessions':
            self.list_sessions()
        elif command[0] == 'swap_session':
            self.check_sessions(command)
        elif command[0] == 'delete_session':
            self.delete_session()
        elif command[0] == 'export_keys':
            self.export_keys(command)
        elif command[0] == 'help':
            self.parse_help_command(command)
        elif command[0] == 'console' or command[0] == 'open_console':
            self.print_web_console_url()
        elif command[0] == 'import_keys':
            self.parse_awscli_keys_import(command)
        elif command[0] == 'assume_role':
            self.assume_role(command[1])
        elif command[0] == 'list' or command[0] == 'ls':
            self.parse_list_command(command)
        elif command[0] == 'load_commands_file':
            self.parse_commands_from_file(command)
        elif command[0] == 'regions':
            self.display_all_regions()
        elif command[0] == 'run' or command[0] == 'exec':
            self.print_user_agent_suffix()
            self.parse_exec_module_command(command)
        elif command[0] == 'search':
            self.parse_search_command(command)
        elif command[0] == 'services':
            self.print_all_service_data(command)
        elif command[0] == 'set_keys':
            self.set_keys()
        elif command[0] == 'set_regions':
            self.parse_set_regions_command(command)
        elif command[0] == 'swap_keys':
            try:
                self.swap_keys(command[1])
            except IndexError:
                self.swap_keys()
        elif command[0] == 'update_regions':
            self.update_regions()
        elif command[0] == 'set_ua_suffix':
            self.parse_set_ua_suffix_command(command)
        elif command[0] == 'unset_ua_suffix':
            self.unset_user_agent_suffix()
        elif command[0] == 'whoami':
            self.print_key_info()
        elif command[0] == 'exit' or command[0] == 'quit':
            self.exit()
        else:
            print('  Error: Unrecognized command')
        return

    def parse_commands_from_file(self, command):
        if len(command) == 1:
            self.display_command_help('load_commands_file')
            return

        commands_file = command[1]

        if not os.path.isfile(commands_file):
            self.display_command_help('load_commands_file')
            return

        with open(commands_file, 'r+') as f:
            commands = f.readlines()
            for command in commands:
                print("Executing command: {} ...".format(command))
                command_without_space = command.strip()
                if command_without_space:
                    self.parse_command(command_without_space)

    def parse_awscli_keys_import(self, command):
        if len(command) == 1:
            self.display_command_help('import_keys')
            return

        boto3_session = boto3.session.Session()

        if command[1] == '--all':
            profiles = boto3_session.available_profiles
            for profile_name in profiles:
                self.import_awscli_key(profile_name)
            return

        self.import_awscli_key(command[1])

    def import_awscli_key(self, profile_name: str) -> None:
        try:
            boto3_session = boto3.session.Session(profile_name=profile_name)
            creds = boto3_session.get_credentials()
            self.set_keys(key_alias='imported-{}'.format(profile_name), access_key_id=creds.access_key, secret_access_key=creds.secret_key,
                          session_token=creds.token)
            self.print('  Imported keys as "imported-{}"'.format(profile_name))
        except botocore.exceptions.ProfileNotFound:
            self.print('\n  Did not find the AWS CLI profile: {}\n'.format(profile_name))
            boto3_session = boto3.session.Session()
            print('  Profiles that are available:\n    {}\n'.format('\n    '.join(boto3_session.available_profiles)))

    def run_aws_cli_command(self, command: List[str]) -> None:
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        except subprocess.CalledProcessError as error:
            result = error.output.decode('utf-8')

        self.print(result)

    def parse_data_command(self, command: List[str]) -> None:
        session = self.get_active_session()

        if len(command) == 1:
            self.print('\nSession data:')
            session.print_all_data_in_session()
        else:
            self.print(self._parse_data_command(command, session))

    def _parse_data_command(self, command: List[str], session: PacuSession) -> str:
        service = command[1].upper()
        service_map = dict([(key.upper(), key) for key in session.aws_data_field_names])
        name = service_map.get(service.upper())

        if not name or name not in session.aws_data_field_names:
            return '  Service not found. Please use the service name below.\n' + \
                   '\t'.join(list(session.aws_data_field_names))
        service_data = getattr(session, name)
        if not service_data:
            return '  No data found.'
        elif len(command) == 3:
            return self._parse_data_command_sub_service(service_data, command[2])
        else:
            return json.dumps(service_data, indent=2, sort_keys=True, default=str)

    def _parse_data_command_sub_service(self, service_data: dict, sub_service: str) -> str:
        sub_service_map = dict([(key.upper(), key) for key in service_data.keys()])
        name = sub_service_map.get(sub_service.upper())

        if not name or name not in service_data.keys():
            return '  Sub-service not found. Please use the sub-service name below.\n' + \
                   '\t'.join(service_data.keys())
        elif not service_data[name]:
            return '  No data found.'
        else:
            return json.dumps(service_data[name], indent=2, sort_keys=True, default=str)

    def parse_jq_command(self, command):
        session = self.get_active_session()
        data_command = ["data"] + command[2:]
        data = self._parse_data_command(data_command, session)
        try:
            data = json.loads(data)
        except json.decoder.JSONDecodeError:
            print(data)
            return
        try:
            jq_output = jq.all(command[1], data)
        except ValueError as e:
            print(e)
            return
        print(json.dumps(jq_output, indent=2, sort_keys=True, default=str))

    def parse_set_regions_command(self, command):
        session = self.get_active_session()

        if len(command) > 1:
            for region in command[1:]:
                if region.lower() == 'all':
                    session.update(self.database, session_regions=['all'])
                    print('  The region set for this session has been reset to the default of all supported regions.')
                    return
                if self.validate_region(region) is False:
                    print('  {} is not a valid region.\n  Session regions not changed.'.format(region))
                    return
            session.update(self.database, session_regions=command[1:])
            print('  Session regions changed: {}'.format(session.session_regions))
        else:
            print('  Error: set_regions requires either "all" or at least one region to be specified. Try the "regions" command to view all regions.')

    def parse_help_command(self, command: List[str]) -> None:
        if len(command) <= 1:
            display_pacu_help()
        elif len(command) > 1 and command[1] in self.COMMANDS:
            self.display_command_help(command[1])
        else:
            self.display_module_help(command[1])

    def parse_list_command(self, command):

        if len(command) == 1:
            self.list_modules('')

        elif len(command) == 2:
            if command[1] in ('cat', 'category', 'categories'):
                print("[Categories]:")
                for category in self.CATEGORIES:
                    print('    {}'.format(category))

        # list cat/category <cat_name>
        elif len(command) == 3:
            if command[1] in ('cat', 'category'):
                self.list_modules(command[2], by_category=True)

    def parse_exec_module_command(self, command: List[str]) -> None:
        if len(command) > 1:
            self.exec_module(command)
        else:
            print('The {} command requires a module name. Try using the module search function.'.format(command))

    def parse_search_command(self, command: List[str]) -> None:
        if len(command) == 1:
            self.list_modules('')
        elif len(command) == 2:
            self.list_modules(command[1])
        elif len(command) >= 3:
            if command[1] in ('cat', 'category'):
                self.list_modules(command[2], by_category=True)

    def parse_set_ua_suffix_command(self, command: List[str]) -> None:
        if len(command) == 1:
            user_agent_suffix = f"Pacu-Session-{uuid.uuid4()}"
        elif len(command) == 2:
            user_agent_suffix = command[1]
        self.set_user_agent_suffix(user_agent_suffix)
        self.print_user_agent_suffix()

    def set_user_agent_suffix(self, user_agent_suffix: str) -> None:
        self.get_active_session().update(self.database, user_agent_suffix=user_agent_suffix)

    def unset_user_agent_suffix(self) -> None:
        self.get_active_session().update(self.database, user_agent_suffix=None)

    def print_user_agent_suffix(self) -> None:
        user_agent_suffix = self.get_active_session().user_agent_suffix
        if user_agent_suffix is not None:
            print(f"Using user agent suffix {user_agent_suffix}")

    def update_regions(self) -> None:
        py_executable = sys.executable
        # Update botocore to fetch the latest version of the AWS region_list

        cmd = [py_executable, '-m', 'pip', 'install', '--upgrade', 'botocore']
        try:
            self.print('  Fetching latest botocore...\n')
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            self.print('"{}" returned {}'.format(' '.join(cmd), e.returncode))
            pip = self.input('Could not use pip3 or pip to update botocore to the latest version. Enter the name of '
                             'your pip binary to continue: ').strip()
            subprocess.run(['{}'.format(pip), 'install', '--upgrade', 'botocore'])

        path = ''

        try:
            self.print('  Using pip3 to locate botocore...\n')
            output = subprocess.check_output('{} -m pip show botocore'.format(py_executable), shell=True)
        except subprocess.CalledProcessError as e:
            self.print('Cmd: "{}" returned {}'.format(' '.join(cmd), e.returncode))
            path = self.input('Could not use pip to determine botocore\'s location. Enter the path to your Python '
                              '"dist-packages" folder (example: /usr/local/bin/python3.6/lib/dist-packages): ').strip()

        if path == '':
            # Account for Windows \r and \\ in file path (Windows)
            rows = output.decode('utf-8').replace('\r', '').replace('\\\\', '/').split('\n')
            for row in rows:
                if row.startswith('Location: '):
                    path = row.split('Location: ')[1]

        with open('{}/botocore/data/endpoints.json'.format(path), 'r+') as regions_file:
            endpoints = json.load(regions_file)

        for partition in endpoints['partitions']:
            if partition['partition'] == 'aws':
                regions: Dict[str, Any] = dict()
                regions['all'] = list(partition['regions'].keys())
                for service in partition['services']:
                    # fips regions are an alternate endpoint for already existing regions, to prevent duplicates we'll
                    # filter these out for now.
                    regions[service] = {'endpoints': {}}
                    for region in filter(lambda r: 'fips' not in r, partition['services'][service]['endpoints'].keys()):
                        regions[service]['endpoints'][region] = partition['services'][service]['endpoints'][region]

        with open(Path(__file__).parent/'modules/service_regions.json', 'w+') as services_file:
            json.dump(regions, services_file, default=str, sort_keys=True)

        self.print('  Region list updated to the latest version!')

    def print_web_console_url(self) -> None:
        active_session = self.get_active_session()

        if active_session.key_alias is None:
            print('  No keys have been set. Not generating the URL.')
            return
        if not active_session.access_key_id:
            print('  No access key has been set. Not generating the URL.')
            return
        if not active_session.secret_access_key:
            print('  No secret key has been set. Not generating the URL.')
            return

        sts = self.get_boto3_client('sts')

        if active_session.session_token:
            # Roles can't use get_federation_token
            res = {
                'Credentials': {
                    'AccessKeyId': active_session.access_key_id,
                    'SecretAccessKey': active_session.secret_access_key,
                    'SessionToken': active_session.session_token
                }
            }
        else:
            res = sts.get_federation_token(  # type: ignore[attr-defined]
                Name=active_session.key_alias,
                Policy=json.dumps({
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }
                    ]
                })
            )

        params = {
            'Action': 'getSigninToken',
            'Session': json.dumps({
                'sessionId': res['Credentials']['AccessKeyId'],
                'sessionKey': res['Credentials']['SecretAccessKey'],
                'sessionToken': res['Credentials']['SessionToken']
            })
        }

        fed_resp = requests.get(url='https://signin.aws.amazon.com/federation', params=params)

        signin_token = fed_resp.json()['SigninToken']

        params = {
            'Action': 'login',
            'Issuer': active_session.key_alias or '',
            'Destination': 'https://console.aws.amazon.com/console/home',
            'SigninToken': signin_token
        }

        url = 'https://signin.aws.amazon.com/federation?' + urllib.parse.urlencode(params)

        print('Paste the following URL into a web browser to login as session {}...\n'.format(active_session.name))

        print(url)

    def all_region_prompt(self) -> bool:
        print('Automatically targeting regions:')
        for region in self.get_regions('all'):
            print('  {}'.format(region))
        response = input('Continue? (y/n) ')
        if response.lower() == 'y':
            return True
        else:
            return False

    def export_keys(self, command) -> None:
        export = input('Export the active keys to the AWS CLI credentials file (~/.aws/credentials)? (y/n) ').rstrip()

        if export.lower() == 'y':
            session = self.get_active_session()

            if not session.access_key_id:
                print('  No access key has been set. Not exporting credentials.')
                return
            if not session.secret_access_key:
                print('  No secret key has been set. Not exporting credentials.')
                return

            config = """
\n\n[{}]
aws_access_key_id = {}
aws_secret_access_key = {}
""".format(session.key_alias, session.access_key_id, session.secret_access_key)
            if session.session_token:
                config = config + 'aws_session_token = "{}"'.format(session.session_token)

            config = config + '\n'

            with open('{}/.aws/credentials'.format(os.path.expanduser('~')), 'a+') as f:
                f.write(config)

            print('Successfully exported {}. Use it with the AWS CLI like this: aws ec2 describe instances --profile {}'.format(
                session.key_alias, session.key_alias
            ))
        else:
            return

    # ***** Some module notes *****
    # For any argument that needs a value and a region for that value, use the form
    # value@region
    # Arguments that accept multiple values should be comma separated.
    #
    def exec_module(self, command: List[str]) -> None:
        session = self.get_active_session()

        # Run key checks so that if no keys have been set, Pacu doesn't default to
        # the AWSCLI default profile:
        if not session.access_key_id:
            print('  No access key has been set. Not running module.')
            return
        if not session.secret_access_key:
            print('  No secret key has been set. Not running module.')
            return

        module_name = command[1].lower()
        module = import_module_by_name(module_name, include=['main', 'module_info', 'summary'])

        if module is not None:
            # Plaintext Command Log
            self.print('{} ({}): {}'.format(session.access_key_id, time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime()), ' '.join(command).strip()),
                       output='file', is_cmd=True)

            # TODO: XML Command Log - Figure out how to auto convert to XML
            # self.print('<command>{}</command>'.format(cmd), output_type='xml', output='file')

            self.print('  Running module {}...'.format(module_name))

            try:
                args = module.parser.parse_args(command[2:])
                if 'regions' in args and args.regions is None:
                    session = self.get_active_session()
                    if session.session_regions == ['all']:
                        if not self.all_region_prompt():
                            return
            except SystemExit:
                print('  Error: Invalid Arguments')
                return

            self.running_module_names.append(module.module_info['name'])
            try:
                summary_data = module.main(command[2:], self)
                # If the module's return value is None, it exited early.
                if summary_data is not None:
                    summary = module.summary(summary_data, self)
                    if len(summary) > 10000:
                        raise ValueError('The {} module\'s summary is too long ({} characters). Reduce it to 10000 '
                                         'characters or fewer.'.format(module.module_info['name'], len(summary)))

                    if not isinstance(summary, str):
                        raise TypeError('The {} module\'s summary is {}-type instead of str. Make summary return a '
                                        'string.'.format(module.module_info['name'], type(summary)))

                    self.print('{} completed.\n'.format(module.module_info['name']))
                    self.print('MODULE SUMMARY:\n\n{}\n'.format(summary.strip('\n')))
            except SystemExit as exception_value:
                exception_type, _, tb = sys.exc_info()

                if 'SIGINT called' in exception_value.args:
                    self.print('^C\nExiting the currently running module.')
                else:
                    traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(
                        ''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)
                    )
                    pacu_session, global_data, local_data = get_data_from_traceback(tb)
                    self.log_error(
                        traceback_text,
                        exception_info='{}: {}\n\nPacu caught a SystemExit error. '.format(exception_type, exception_value),
                        session=pacu_session,
                        local_data=local_data,
                        global_data=global_data
                    )
            finally:
                self.running_module_names.pop()
        elif module_name in self.COMMANDS:
            print('Error: "{}" is the name of a Pacu command, not a module. Try using it without "run" or "exec" in front.'.format(module_name))
        else:
            print('Module not found. Is it spelled correctly? Try using the module search function.')

    def display_command_help(self, command_name: str) -> None:
        if command_name == 'list' or command_name == 'ls':
            print('\n    list/ls\n        List all modules\n')
        elif command_name == 'import_keys':
            print('\n    import_keys <profile name>|--all\n      Import AWS keys from the AWS CLI credentials file (located at ~/.aws/credentials) to the '
                  'current sessions database. Enter the name of a profile you would like to import or supply --all to import all the credentials in the '
                  'file.\n')
        elif command_name == 'assume_role':
            print('\n    assume_role <role arn>\n        Call AssumeRole on the specified role from the current credentials, add the resulting temporary '
                  'keys to the Pacu key database and start using these new credentials.')
        elif command_name == 'aws':
            print('\n    aws <command>\n        Use the AWS CLI directly. This command runs in your local shell to use the AWS CLI. Warning: The AWS CLI\'s '
                  'authentication is not related to Pacu. Be careful to ensure that you are using the keys you want when using the AWS CLI. It is suggested '
                  'to use AWS CLI profiles to help solve this problem\n')
        elif command_name == 'console' or command_name == 'open_console':
            print('\n    console/open_console\n        Generate a URL to login to the AWS web console as the current user/role\n')
        elif command_name == 'export_keys':
            print('\n    export_keys\n        Export the active credentials to a profile in the AWS CLI credentials file (~/.aws/credentials)\n')
        elif command_name == 'search':
            print('\n    search [cat[egory]] <search term>\n        Search the list of available modules by name or category\n')
        elif command_name == 'sessions' or command_name == 'list_sessions':
            print('\n    sessions/list_sessions\n        List all sessions stored in the Pacu database\n')
        elif command_name == 'swap_session':
            print('\n    swap_session\n        Swap the active Pacu session for another one stored in the database or a brand new session\n')
        elif command_name == 'delete_session':
            print('\n    delete_session\n        Delete a session from the Pacu database. Note that this does not delete the output folder for that session\n')
        elif command_name == 'help':
            print('\n    help\n        Display information about all Pacu commands\n    help <module name>\n        Display information about a module\n')
        elif command_name == 'whoami':
            print('\n    whoami\n        Display information regarding to the active access keys\n')
        elif command_name == 'data':
            print('\n    data\n        Display all data that is stored in this session. Only fields with values will be displayed\n    data <service>\n       '
                  ' Display all data for a specified service in this session\n')
        elif command_name == 'services':
            print('\n    services\n        Display a list of services that have collected data in the current session to use with the "data"\n          '
                  'command\n')
        elif command_name == 'regions':
            print('\n    regions\n        Display a list of all valid AWS regions\n')
        elif command_name == 'update_regions':
            print('\n    update_regions\n        Run a script to update the regions database to the newest version\n')
        elif command_name == 'set_regions':
            print('\n    set_regions <region> [<region>...]\n        Set the default regions for this session. These space-separated regions will be used for '
                  'modules where\n          regions are required, but not supplied by the user. The default set of regions is every supported\n          '
                  'region for the service. Supply "all" to this command to reset the region set to the default of all\n          supported regions\n')
        elif command_name == 'set_ua_suffix':
            print('\n    set_ua_suffix [<suffix>]\n        Set the user agent suffix for this session. The suffix will be appended to the user agent for all\n'
                  '        API calls. If no suffix is supplied a UUID-based suffix will be generated in the form Pacu-Session-<UUID>.\n')
        elif command_name == 'unset_ua_suffix':
            print('\n    unset_ua_suffix\n        Remove the user agent suffix for this session\n')
        elif command_name == 'run' or command_name == 'exec':
            print('\n    run/exec <module name>\n        Execute a module\n')
        elif command_name == 'set_keys':
            print('\n    set_keys\n        Add a set of AWS keys to the session and set them as the default\n')
        elif command_name == 'swap_keys':
            print('\n    swap_keys\n        Change the currently active AWS key to another key that has previously been set for this session\n')
        elif command_name == 'exit' or command_name == 'quit':
            print('\n    exit/quit\n        Exit Pacu\n')
        elif command_name == 'load_commands_file':
            print('\n    load_commands_file <commands_file>\n        Load an existing file with a set of commands to execute')
        else:
            print('Command or module not found. Is it spelled correctly? Try using the module search function.')
        return

    def display_module_help(self, module_name: str) -> None:
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

    def list_modules(self, search_term, by_category=False):
        found_modules_by_category = dict()
        current_directory = os.getcwd()
        for root, directories, files in os.walk(Path(__file__).parent/'modules'):
            modules_directory_path = os.path.realpath(Path(__file__).parent/'modules')
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
                    module_path = str(Path('pacu/modules')/module_name/'main').replace('/', '.').replace('\\', '.')
                    # Import the help function from the module
                    module = __import__(module_path, globals(), locals(), ['module_info'], 0)
                    importlib.reload(module)
                    category = module.module_info['category']
                    services = module.module_info['services']

                    regions = []
                    for service in services:
                        try:
                            regions += self.get_regions(service)
                        # If there is no session, the get_regions function will throw an AttributeError.
                        # This happens when running from CLI with no sessions created.
                        # Just skip and list the modules anyways.
                        except AttributeError:
                            regions = ['all']

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
            for category in self.CATEGORIES:
                if category in found_modules_by_category:
                    found_modules_by_category[category].sort()
                    search_results = '\n'.join(found_modules_by_category[category]).strip('\n')
                    print('\n[Category: {}]\n\n{}'.format(category, search_results))
        else:
            print('\nNo modules found.')
        print()

    def set_keys(self, key_alias: str = None, access_key_id: str = None, secret_access_key: str = None, session_token: str = None):
        session = self.get_active_session()

        # If key_alias is None, then it's being run normally from the command line (set_keys),
        # otherwise it means it is set programmatically and we don't want any prompts if it is
        # done programmatically
        if key_alias is None:
            self.print('Setting AWS Keys...')
            self.print('Press enter to keep the value currently stored.')
            self.print('Enter the letter C to clear the value, rather than set it.')
            self.print('If you enter an existing key_alias, that key\'s fields will be updated instead of added.')
            self.print('Key alias must be at least 2 characters\n')

        # Key alias
        if key_alias is None:
            new_value = ""
            while (new_value.strip().lower() != 'c') and (len(new_value) < 2):
                new_value = self.input('Key alias [{}]: '.format(session.key_alias))
                if new_value == '':
                    new_value = str(session.key_alias)
        else:
            new_value = key_alias.strip()
            self.print('Key alias [{}]: {}'.format(session.key_alias, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.key_alias = None
        elif not len(new_value) < 2:
            session.key_alias = new_value.strip()

        # Access key ID
        if key_alias is None:
            new_value = self.input('Access key ID [{}]: '.format(session.access_key_id))
        else:
            new_value = access_key_id or ''
            self.print('Access key ID [{}]: {}'.format(session.access_key_id, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.access_key_id = None
        elif str(new_value) != '':
            session.access_key_id = new_value.strip()

        # Secret access key (should not be entered in log files)
        if key_alias is None:
            if session.secret_access_key is None:
                new_value = input('Secret access key [None]: ')
            else:
                truncated_key = session.secret_access_key[0:int(len(session.secret_access_key) / 2)]
                new_value = input('Secret access key [{}{}]: '.format(truncated_key, '*' * int(len(session.secret_access_key) / 2)))
        else:
            new_value = secret_access_key or ''
        self.print('Secret access key [******]: ****** (Censored)', output='file')
        if str(new_value.strip().lower()) == 'c':
            session.secret_access_key = None
        elif str(new_value) != '':
            session.secret_access_key = new_value.strip()

        # Session token (optional)
        if key_alias is None:
            new_value = self.input('Session token (Optional - for temp AWS keys only) [{}]: '.format(session.session_token))
        else:
            new_value = session_token or 'c'
            self.print('Session token [{}]: {}'.format(session.session_token, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.session_token = None
        elif str(new_value) != '':
            session.session_token = new_value.strip()

        self.database.add(session)

        aws_key = session.get_active_aws_key(self.database)
        if aws_key:
            aws_key.key_alias = session.key_alias
            aws_key.access_key_id = session.access_key_id
            aws_key.secret_access_key = session.secret_access_key
            aws_key.session_token = session.session_token
        else:
            aws_key = AWSKey(
                session=session,
                key_alias=session.key_alias,
                access_key_id=session.access_key_id,
                secret_access_key=session.secret_access_key,
                session_token=session.session_token
            )
        self.database.add(aws_key)

        self.database.commit()

        if key_alias is None:
            self.print('\nKeys saved to database.\n')

    def swap_keys(self, key_name: str = None) -> None:
        session: PacuSession = self.get_active_session()

        # On attr-defined ignore: https://github.com/dropbox/sqlalchemy-stubs/issues/168
        aws_keys: List[AWSKey] = session.aws_keys.all()  # type: ignore[attr-defined]

        if not aws_keys:
            self.print('\nNo AWS keys set for this session. Run "set_keys" to add AWS keys.\n')
            return

        if key_name:
            chosen_key = self.get_aws_key_by_alias(key_name)
            if not chosen_key:
                print(f'No key with the alias {key_name} found.')
                return
        else:
            self.print('\nSwapping AWS Keys. Press enter to keep the currently active key.')

            print('AWS keys in this session:')

            for index, aws_key in enumerate(aws_keys, 1):
                if aws_key.key_alias == session.key_alias:
                    print('  [{}] {} (ACTIVE)'.format(index, aws_key.key_alias))
                else:
                    print('  [{}] {}'.format(index, aws_key.key_alias))

            choice = input('Choose an option: ')

            if not str(choice).strip():
                self.print('The currently active AWS key will remain active. ({})'.format(session.key_alias))
                return

            if not choice.isdigit() or int(choice) not in range(1, len(aws_keys) + 1):
                print('Please choose a number from 1 to {}.'.format(len(aws_keys)))
                return self.swap_keys()

            chosen_key = aws_keys[int(choice) - 1]

        session.key_alias = chosen_key.key_alias
        session.access_key_id = chosen_key.access_key_id
        session.secret_access_key = chosen_key.secret_access_key
        session.session_token = chosen_key.session_token
        self.database.add(session)
        self.database.commit()
        self.print('AWS key is now {}.'.format(session.key_alias))

    def activate_session(self, session_name) -> None:
        sessions = self.database.query(PacuSession).all()
        found_session = False
        for _session in sessions:
            if getattr(_session, 'name').upper() == session_name.upper():
                session = _session
                found_session = True
        if not found_session:
            print('Session not found! Please use the session name below:')
            print('\t'.join([getattr(_session, 'name') for _session in sessions]))
            return

        session.activate(self.database)

    def check_sessions(self, command: List[str] = []) -> None:
        sessions = self.database.query(PacuSession).all()

        if not sessions:
            session = self.new_session()
        elif len(command) == 2:
            session_name = command[1]
            found_session = False
            for _session in sessions:
                if getattr(_session, 'name').upper() == session_name.upper():
                    session = _session
                    found_session = True
            if not found_session:
                print('Session not found! Please use the session name below:')
                print('\t'.join([getattr(_session, 'name') for _session in sessions]))
                return
        else:
            while True:
                print('Found existing sessions:')
                print('  [0] New session')

                for index, session in enumerate(sessions, 1):
                    print('  [{}] {}'.format(index, session.name))

                choice = input('Choose an option: ')

                try:
                    if int(choice) == 0:
                        session = self.new_session()
                    else:
                        session = sessions[int(choice) - 1]
                except (ValueError, IndexError):
                    print('Please choose a number from 0 to {}.'.format(len(sessions)))
                    continue
                break

        session.activate(self.database)

    def list_sessions(self) -> None:
        active_session = self.get_active_session()
        all_sessions = self.database.query(PacuSession).all()

        print('Found existing sessions:')

        for index, session in enumerate(all_sessions, 0):
            if session.name == active_session.name:
                print('- ' + str(session.name) + ' (ACTIVE)')
            else:
                print('- ' + str(session.name))

        print('\nUse "swap_session" to change to another session.')

        return

    def new_session(self, name=None) -> PacuSession:
        session_data: Dict[str, str] = dict()
        while True:
            if not name:
                name = input('What would you like to name this new session? ').strip()
                if not name:
                    print('A session name is required.')
            else:
                existing_sessions = self.database.query(PacuSession).filter(PacuSession.name == name).all()
                if existing_sessions:
                    print('A session with that name already exists.')
                    name = None
                else:
                    break

        session_data['name'] = name

        session = PacuSession(**session_data)
        self.database.add(session)
        self.database.commit()
        print('Session {} created.'.format(name))

        return session

    def delete_session(self) -> None:
        active_session = self.get_active_session()
        all_sessions = self.database.query(PacuSession).all()
        print('Delete which session?')

        for index, session in enumerate(all_sessions, 0):
            if session.name == active_session.name:
                print('  [{}] {} (ACTIVE)'.format(index, session.name))
            else:
                print('  [{}] {}'.format(index, session.name))

        choice = input('Choose an option: ')

        try:
            session = all_sessions[int(choice)]
            if session.name == active_session.name:
                print('Cannot delete the active session! Switch sessions and try again.')
                return
        except (ValueError, IndexError):
            print('Please choose a number from 0 to {}.'.format(len(all_sessions) - 1))
            return self.delete_session()

        self.database.delete(session)
        self.database.commit()

        print('Deleted {} from the database!'.format(session.name))
        print('Note that the output folder at ~/.local/share/pacu/sessions/{}/ will not be deleted. Do it manually '
              'if necessary.'.format(session.name))

        return

    def check_user_agent(self) -> None:
        session = self.get_active_session()

        if session.boto_user_agent is None:  # If there is no user agent set for this session already
            boto3_session = boto3.session.Session()
            ua = boto3_session._session.user_agent()
            if 'kali' in ua.lower() or 'parrot' in ua.lower() or 'pentoo' in ua.lower():  # If the local OS is Kali/Parrot/Pentoo Linux
                # GuardDuty triggers a finding around API calls made from Kali Linux, so let's avoid that...
                self.print('Detected environment as one of Kali/Parrot/Pentoo Linux. Modifying user agent to hide that from GuardDuty...')
                with open(Path(__file__).parent/'user_agents.txt', 'r') as f:
                    user_agents = f.readlines()
                user_agents = [agent.strip() for agent in user_agents]  # Remove random \n's and spaces
                new_ua = random.choice(user_agents)
                session.update(self.database, boto_user_agent=new_ua)
                self.print('  User agent for this session set to:')
                self.print('    {}'.format(new_ua))

    def get_boto_session(self, region: str = None) -> boto3.session.Session:
        session = self.get_active_session()

        if not session.access_key_id:
            raise UserWarning('  No access key has been set. Failed to generate boto3 Client.')

        if not session.secret_access_key:
            raise UserWarning('  No secret key has been set. Failed to generate boto3 Client.')

        return boto3.session.Session(
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
        )

    def get_botocore_conf(
        self,
        region: Optional[str] = None,
        user_agent: Optional[str] = None,
        parameter_validation: bool = True,
    ) -> botocore.config.Config:
        session = self.get_active_session()

        # If there is not a custom user_agent passed into this function
        # and session.boto_user_agent is set, use that as the user agent
        # for this client. If both are set, the incoming user_agent will
        # override the session.boto_user_agent. If neither are set, it
        # will be None, and will default to the OS's regular user agent
        if user_agent is None and session.boto_user_agent is not None:
            user_agent = session.boto_user_agent

        return botocore.config.Config(  # type: ignore[attr-defined]
            region_name=region,
            user_agent=user_agent,  # If user_agent=None, botocore will use the real UA which is what we want
            user_agent_extra=session.user_agent_suffix,
            retries={
                'max_attempts': 10,
                'mode': 'adaptive',
            },
            parameter_validation=parameter_validation,
        )

    def get_boto3_client(
            self,
            service: str,
            region: Optional[str] = None,
            user_agent: Optional[str] = None,
            parameter_validation: bool = True,
    ) -> Any:
        try:
            aws_sess = self.get_boto_session()
        except UserWarning as e:
            print(e.args)
            return None

        conf = self.get_botocore_conf(region, user_agent, parameter_validation)
        return aws_sess.client(service, config=conf)

    def get_boto3_resource(
            self,
            service: str,
            region: Union[str, None] = None,
            user_agent: Union[str, None] = None,
            parameter_validation: bool = True
    ) -> Any:
        try:
            aws_sess = self.get_boto_session()
        except UserWarning as e:
            print(e.args)
            return None

        conf = self.get_botocore_conf(region, user_agent, parameter_validation)
        return aws_sess.resource(service, region_name=region, config=conf)

    def initialize_tab_completion(self) -> None:
        try:
            import readline
            # Big thanks to samplebias: https://stackoverflow.com/a/5638688
            MODULES = []
            CATEGORIES = []

            for root, directories, files in os.walk(Path(__file__).parent/'modules'):
                modules_directory_path = os.path.realpath(Path(__file__)/'modules')
                category_path = os.path.realpath(root)

                # Skip any directories inside module directories.
                if os.path.dirname(category_path) != modules_directory_path:
                    continue
                # Skip the root directory.
                elif modules_directory_path == category_path:
                    continue

                for file in files:
                    if file == 'main.py':
                        module_name = os.path.basename(root)
                        MODULES.append(module_name)

                        # Make sure the format is correct
                        module_path = str(Path('pacu/modules')/module_name/'main').replace('/', '.').replace('\\', '.')

                        # Import the help function from the module
                        module = __import__(module_path, globals(), locals(), ['module_info'], 0)
                        importlib.reload(module)
                        CATEGORIES.append(module.module_info['category'])

            RE_SPACE = re.compile(r'.*\s+$', re.M)
            readline.set_completer_delims(' \t\n`~!@#$%^&*()=+[{]}\\|;:\'",<>/?')

            class Completer(object):
                def complete(completer, text, state):
                    buffer = readline.get_line_buffer()
                    line = readline.get_line_buffer().split()

                    # If nothing has been typed, show all commands. If help, exec, or run has been typed, show all modules
                    if not line:
                        return [c + ' ' for c in self.COMMANDS][state]

                    if len(line) == 1 and (line[0] == 'help'):
                        return [c + ' ' for c in MODULES + self.COMMANDS][state]

                    if len(line) == 1 and (line[0] == 'exec' or line[0] == 'run'):
                        return [c + ' ' for c in MODULES][state]

                    # account for last argument ending in a space
                    if RE_SPACE.match(buffer):
                        line.append('')

                    # Resolve command to the implementation function
                    if len(line) == 1:
                        cmd = line[0].strip()
                        results = [c + ' ' for c in self.COMMANDS if c.startswith(cmd)] + [None]

                    elif len(line) == 2:
                        cmd = line[1].strip()
                        if line[0].strip() == 'search':
                            results = [c + ' ' for c in MODULES + ['category'] if c.startswith(cmd)] + [None]
                        elif line[0].strip() == 'help':
                            results = [c + ' ' for c in MODULES + self.COMMANDS if c.startswith(cmd)] + [None]
                        else:
                            results = [c + ' ' for c in MODULES if c.startswith(cmd)] + [None]

                    elif len(line) == 3 and line[0] == 'search' and line[1] in ('cat', 'category'):
                        cmd = line[2].strip()
                        results = [c + ' ' for c in CATEGORIES if c.startswith(cmd)] + [None]

                    elif len(line) >= 3:
                        if line[0].strip() == 'run' or line[0].strip() == 'exec':
                            module_name = line[1].strip()
                            module = import_module_by_name(module_name, include=['module_info'])
                            autocomplete_arguments = module.module_info.get('arguments_to_autocomplete', list())
                            current_argument = line[-1].strip()
                            results = [c + ' ' for c in autocomplete_arguments if c.startswith(current_argument)] + [None]

                    return results[state]

            comp = Completer()
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)
        except Exception as error:  # noqa: F841 TODO: narrow down this exception
            # Error means most likely on Windows where readline is not supported
            # TODO: Implement tab-completion for Windows
            # print(error)
            pass

    def exit(self) -> None:
        sys.exit('SIGINT called')

    def idle(self) -> None:
        session = self.get_active_session()

        if session.key_alias:
            alias = session.key_alias
        else:
            alias = 'No Keys Set'

        command = input('Pacu ({}:{}) > '.format(session.name, alias))

        self.parse_command(command)

        self.idle()

    def run_cli(self, *args) -> None:
        self.database = get_database_connection(settings.DATABASE_CONNECTION_PATH)
        migrations(self.database)
        sessions: List[PacuSession] = self.database.query(PacuSession).all()

        arg = args[0]

        new_session = arg.new_session
        activate_session = arg.activate_session
        session: str = arg.session
        module_name: str = arg.module_name
        service = arg.data
        list_mods: bool = arg.list_modules
        list_cmd = ['ls']
        set_keys = arg.set_keys
        import_keys = arg.import_keys

        pacu_help: bool = arg.pacu_help
        pacu_help_cmd = ['help']

        if new_session is not None:
            n_session = self.new_session(new_session)
            n_session.activate(self.database)
        if activate_session is True:
            self.activate_session(session)
        if session is not None:
            session_names = [x.name for x in sessions]

            if session not in session_names:
                print('Choose from the following sessions:')
                for _session in sessions:
                    print('  {}'.format(_session.name))
                print('Session could not be found. Exiting...')
                self.exit()

            self.activate_session(session)

        if import_keys is not None:
            self.import_awscli_key(import_keys)

        if set_keys is not None:
            keys = set_keys.split(',')
            alias = keys[0]
            access_key = keys[1]
            secret_key = keys[2]
            if len(keys) > 3:
                self.set_keys(alias, access_key, secret_key, keys[3])
            else:
                self.set_keys(alias, access_key, secret_key)

        if module_name is not None:
            module = ['exec', module_name]
            if arg.module_args is not None:
                args_list = arg.module_args.split(' ')
                for i in args_list:
                    if i != '':
                        module.append(i)

            if arg.exec is True:
                self.exec_module(module)

        if service is not None:
            if service == 'all':
                service_cmd = ['data']
            else:
                service_cmd = ['data', service.upper()]
            self.parse_data_command(service_cmd)

        if list_mods is True:
            self.parse_list_command(list_cmd)

        if pacu_help is True:
            self.parse_help_command(pacu_help_cmd)

        if arg.module_info is True:
            if module_name is None:
                print('Specify a module to get information on')
            pacu_help_cmd.append(module_name)
            self.parse_help_command(pacu_help_cmd)

        if arg.set_regions is not None:
            regions = arg.set_regions
            regions.insert(0, 'set_regions')
            self.parse_set_regions_command(regions)

        if arg.whoami is True:
            self.print_key_info()

    def run_gui(self) -> None:
        idle_ready = False

        while True:
            try:
                if not idle_ready:
                    try:
                        print("""
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
""")
                    except UnicodeEncodeError:
                        pass

                    set_sigint_handler(exit_text='\nA database must be created for Pacu to work properly.')
                    setup_database_if_not_present(settings.DATABASE_FILE_PATH)
                    set_sigint_handler(exit_text=None, value='SIGINT called')

                    self.database = get_database_connection(settings.DATABASE_CONNECTION_PATH)

                    migrations(self.database)

                    self.check_sessions()

                    self.initialize_tab_completion()
                    display_pacu_help()

                    self.check_for_updates()

                    idle_ready = True

                self.check_user_agent()
                self.idle()

            except (Exception, SystemExit) as exception_value:
                exception_type, _, tb = sys.exc_info()

                if exception_type == SystemExit:
                    if 'SIGINT called' in exception_value.args:
                        print('\nBye!')
                        return
                    else:
                        traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(
                            ''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)
                        )
                        session, global_data, local_data = get_data_from_traceback(tb)
                        self.log_error(
                            traceback_text,
                            exception_info='{}: {}\n\nPacu caught a SystemExit error. This may be due to incorrect module arguments received by argparse in '
                                           'the module itself. Check to see if any required arguments are not being received by the module when it '
                                           'executes.'.format(exception_type, exception_value),
                            session=session,
                            local_data=local_data,
                            global_data=global_data
                        )

                # Catch sqlalchemy error
                elif exception_type == exc.OperationalError:
                    traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(
                        ''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)
                    )
                    session, global_data, local_data = get_data_from_traceback(tb)
                    self.log_error(
                        traceback_text,
                        exception_info='{}: {}\n\nPacu database error. This could be caused by a recent update in Pacu\'s database\'s structure. If your Pacu '
                                       'has been updated recently, try removing your old db.sqlite3 database file.'.format(exception_type, exception_value),
                        session=session,
                        local_data=local_data,
                        global_data=global_data
                    )

                else:
                    traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(
                        ''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)
                    )
                    session, global_data, local_data = get_data_from_traceback(tb)
                    self.log_error(
                        traceback_text,
                        exception_info='{}: {}'.format(exception_type, exception_value),
                        session=session,
                        local_data=local_data,
                        global_data=global_data
                    )

                if not idle_ready:
                    print('Pacu is unable to start. Try backing up Pacu\'s sqlite.db file and deleting the old '
                          'version. If the error persists, try reinstalling Pacu in a new directory.')
                    return

    def run(self) -> None:
        setup_database_if_not_present(settings.DATABASE_FILE_PATH)
        parser = argparse.ArgumentParser()
        parser.add_argument('--session', required=False, default=None, help='<session name>', metavar='')
        parser.add_argument('--activate-session', action='store_true', help='activate session, use session arg to set session name')
        parser.add_argument('--new-session', required=False, default=None, help='<session name>', metavar='')
        parser.add_argument('--set-keys', required=False, default=None, help='alias, access id, secret key, token', metavar='')
        parser.add_argument('--import-keys', required=False, default=None, help='AWS profile name to import keys from', metavar='')
        parser.add_argument('--module-name', required=False, default=None, help='<module name>', metavar='')
        parser.add_argument('--data', required=False, default=None, help='<service name/all>', metavar='')
        parser.add_argument('--module-args', default=None, help='<--module-args=\'--regions us-east-1,us-east-1\'>', metavar='')
        parser.add_argument('--list-modules', action='store_true', help='List arguments')
        parser.add_argument('--pacu-help', action='store_true', help='List the Pacu help window')
        parser.add_argument('--module-info', action='store_true', help='Get information on a specific module, use --module-name')
        parser.add_argument('--exec', action='store_true', help='exec module')
        parser.add_argument('--set-regions', nargs='+', default=None, help='<region1 region2 ...> or <all> for all', metavar='')
        parser.add_argument('--whoami', action='store_true', help='Display information on current IAM user')
        args = parser.parse_args()

        if any([args.session, args.data, args.module_args, args.exec, args.set_regions, args.whoami, args.new_session, args.set_keys, args.activate_session]):
            if args.session is None and args.new_session is None:
                print('When running Pacu from the CLI, a session is necessary')
                exit()
            self.run_cli(args)
        elif any([args.list_modules, args.pacu_help, args.module_info]):
            self.check_for_updates()
            self.run_cli(args)
        else:
            self.run_gui()

    def assume_role(self, role_arn: str):
        sts = self.get_boto3_client('sts')
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='assume-role',
        )
        cur_key_name = self.get_active_session().name
        new_key_name = f"{cur_key_name}/{resp['AssumedRoleUser']['Arn']}"
        self.set_keys(
            key_alias=new_key_name,
            access_key_id=resp['Credentials']['AccessKeyId'],
            secret_access_key=resp['Credentials']['SecretAccessKey'],
            session_token=resp['Credentials']['SessionToken'],
        )
        self.swap_keys(new_key_name)


if __name__ == '__main__':
    Main().run()
