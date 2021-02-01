#!/usr/bin/env python3
import argparse
import os
import re
import shlex
import subprocess
import sys
import time
import traceback
from typing import List, Union

from pacu import console, io
from pacu.aws import display_all_regions, print_web_console_url, update_regions
from pacu.cli import display_command_help, display_pacu_help, initialize_tab_completion
from pacu.console import check_sessions, check_user_agent, parse_awscli_keys_import, parse_data_command, run_aws_cli_command, set_keys, swap_keys
from pacu.io import print_all_service_data
from pacu.logging import get_data_from_traceback, log_error
from pacu.utils import import_module_by_name

try:
    import requests

    import settings

    from pacu.core.models import AWSKey, delete_session, key_info, list_sessions, new_session, PacuSession
    from setup_database import setup_database_if_not_present
    from sqlalchemy import exc, orm  # type: ignore
    from pacu.utils import check_for_updates, get_database_connection, set_sigint_handler
except ModuleNotFoundError:
    exception_type, exception_value, tb = sys.exc_info()
    print('Traceback (most recent call last):\n{}{}: {}\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)))
    print('Pacu was not able to start because a required Python package was not found.\nRun `sh install.sh` to check and install Pacu\'s Python requirements.')
    sys.exit(1)


class Main:
    def __init__(self) -> None:
        # NOTE: self.database is the sqlalchemy session since 'session' is reserved for PacuSession objects.
        self.session: PacuSession = None
        self.database: orm.session.Session = None
        self.running_module_names: List[str] = []

    # Utility methods

    # @message: String - message to print and/or write to file
    # @output: String - where to output the message: both, file, or screen
    # @output_type: String - format for message when written to file: plain or xml
    # @is_cmd: boolean - Is the log the initial command that was run (True) or output (False)? Devs won't touch this most likely
    def print(self, message: Union[dict, list, str, Exception] = '', output: str='both', output_type: str='plain', is_cmd: bool=False) -> None:
        return io.print(self.module_path(message))

    # @message: String - input question to ask and/or write to file
    # @output: String - where to output the message: both or screen (can't write a question to a file only)
    # @output_type: String - format for message when written to file: plain or xml
    def input(self, message, output='both', output_type='plain') -> str:
        return io.input(self.module_path(message))

    def module_path(self, message: str) -> str:
        # This prepends the running module's name in square brackets in front of the first line in the message
        # containing non-whitespace characters.
        if len(self.running_module_names) > 0 and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = '[{}] {}'.format(self.running_module_names[-1], fragment)
                    break
            message = '\n'.join(split_message)
        return message

    # @data: list
    # @module: string
    # @args: string
    def fetch_data(self, data: List[str], module: str, args: str, force=False) -> bool:
        session = self.session

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
                run_prereq = self.input('Data ({}) not found, run module "{}" to fetch it? (y/n) '.format(' > '.join(data), module))
            else:
                run_prereq = 'y'
            if run_prereq == 'n':
                return False

            if args:
                self.exec_module(['exec', module] + args.split(' '))
            else:
                self.exec_module(['exec', module])
        return True

    def install_dependencies(self, external_dependencies) -> bool:
        if len(external_dependencies) < 1:
            return True
        answer = self.input('This module requires external dependencies: {}\n\nInstall them now? (y/n) '.format(external_dependencies))
        if answer == 'n':
            print('Not installing dependencies, exiting...')
            return False
        print('\nInstalling {} total dependencies...'.format(len(external_dependencies)))
        for dependency in external_dependencies:
            split = dependency.split('/')
            name = split[-1]
            if name.split('.')[-1] == 'git':
                name = name.split('.')[0]
                author = split[-2]
                if os.path.exists('./dependencies/{}/{}'.format(author, name)):
                    print('  Dependency {}/{} already installed.'.format(author, name))
                else:
                    try:
                        print('  Installing dependency {}/{} from {}...'.format(author, name, dependency))
                        subprocess.run(['git', 'clone', dependency, './dependencies/{}/{}'.format(author, name)])
                    except subprocess.CalledProcessError as error:
                        print('{} failed, view the error below. If you are unsure, some potential causes are '
                              'that you are missing "git" on your command line, your git credentials are not '
                              'properly set, or the GitHub link does not exist.'.format(error.cmd))
                        print('    stdout: {}\nstderr: {}'.format(error.cmd, error.stderr))
                        print('  Exiting module...')
                        return False
            else:
                if os.path.exists('./dependencies/{}'.format(name)):
                    print('  Dependency {} already installed.'.format(name))
                else:
                    try:
                        print('  Installing dependency {}...'.format(name))
                        r = requests.get(dependency, stream=True)
                        if r.status_code == 404:
                            raise Exception('File not found.')
                        with open('./dependencies/{}'.format(name), 'wb') as f:
                            for chunk in r.iter_content(chunk_size=1024):
                                if chunk:
                                    f.write(chunk)
                    except Exception as error:
                        print('    Downloading {} has failed, view the error below.'.format(dependency))
                        print(error)
                        print('  Exiting module...')

                        return False
        print('Dependencies finished installing.')
        return True

    # Pacu commands and execution

    def parse_command(self, command: str) -> None:
        command = command.strip()

        if command.split(' ')[0] == 'aws':
            run_aws_cli_command(command)
            return

        try:
            command = shlex.split(command)
        except ValueError:
            print('  Error: Unbalanced quotes in command')
            return

        if not command or command[0] == '':
            return
        elif command[0] == 'data':
            parse_data_command(command)
        elif command[0] == 'sessions' or command[0] == 'list_sessions':
            list_sessions(PacuSession.active_session())
        elif command[0] == 'swap_session':
            check_sessions()
        elif command[0] == 'delete_session':
            delete_session()
        elif command[0] == 'export_keys':
            console.export_keys()
        elif command[0] == 'help':
            console.parse_help_command(console.COMMANDS, command)
        elif command[0] == 'console' or command[0] == 'open_console':
            print_web_console_url()
        elif command[0] == 'import_keys':
            parse_awscli_keys_import(command)
        elif command[0] == 'list' or command[0] == 'ls':
            console.parse_list_command(command)
        elif command[0] == 'load_commands_file':
            self.parse_commands_from_file(command)
        elif command[0] == 'regions':
            display_all_regions()
        elif command[0] == 'run' or command[0] == 'exec':
            self.parse_exec_module_command(command)
        elif command[0] == 'search':
            console.parse_search_command(command)
        elif command[0] == 'services':
            print_all_service_data(PacuSession.active_session())
        elif command[0] == 'set_keys':
            set_keys()
        elif command[0] == 'set_regions':
            console.parse_set_regions_command(command)
        elif command[0] == 'swap_keys':
            swap_keys()
        elif command[0] == 'update_regions':
            update_regions()
        elif command[0] == 'whoami':
            print(key_info())
        elif command[0] == 'exit' or command[0] == 'quit':
            console.exit()
        else:
            print('  Error: Unrecognized command')
        return

    def parse_commands_from_file(self, command):
        if len(command) == 1:
            display_command_help('load_commands_file')
            return

        commands_file = command[1]

        if not os.path.isfile(commands_file):
            display_command_help('load_commands_file')
            return

        with open(commands_file, 'r+') as f:
            commands = f.readlines()
            for command in commands:
                print("Executing command: {} ...".format(command))
                command_without_space = command.strip()
                if command_without_space:
                    self.parse_command(command_without_space)

    def parse_exec_module_command(self, command: List[str]) -> None:
        if len(command) > 1:
            self.exec_module(command)
        else:
            print('The {} command requires a module name. Try using the module search function.'.format(command))

    # ***** Some module notes *****
    # For any argument that needs a value and a region for that value, use the form
    # value@region
    # Arguments that accept multiple values should be comma separated.
    #
    def exec_module(self, command: List[str]) -> None:
        session = PacuSession.active_session()

        # Run key checks so that if no keys have been set, Pacu doesn't default to
        # the AWSCLI default profile:
        if not session.key_alias.access_key_id:
            print('  No access key has been set. Not running module.')
            return
        if not session.key_alias.secret_access_key:
            print('  No secret key has been set. Not running module.')
            return

        module_name = command[1].lower()
        module = import_module_by_name(module_name, include=['main', 'module_info', 'summary'])

        if module is not None:
            # Plaintext Command Log
            io.print('{} ({}): {}'.format(session.key_alias.access_key_id, time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime()), ' '.join(command).strip()),
                  output='file', is_cmd=True)

            # TODO: XML Command Log - Figure out how to auto convert to XML
            # self.print('<command>{}</command>'.format(cmd), output_type='xml', output='file')

            print('  Running module {}...'.format(module_name))

            # TODO: Remove or fix this code. It reset's the global region settings every time a submodule is called with the --region flag.
            try:
                args = module.parser.parse_args(command[2:])
                if 'regions' in args and args.regions is None:
                    session = self.session
                    if session.session_regions == ['all']:
                        if not self.session:
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

                    print('{} completed.\n'.format(module.module_info['name']))
                    print('MODULE SUMMARY:\n\n{}\n'.format(summary.strip('\n')))
            except SystemExit as exception_value:
                exception_type, _, tb = sys.exc_info()

                if 'SIGINT called' in exception_value.args:
                    print('^C\nExiting the currently running module.')
                else:
                    traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(
                        ''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)
                    )
                    pacu_session, global_data, local_data = get_data_from_traceback(tb)
                    log_error(
                        traceback_text,
                        exception_info='{}: {}\n\nPacu caught a SystemExit error. '.format(exception_type, exception_value),
                        session=pacu_session,
                        local_data=local_data,
                        global_data=global_data
                    )
            finally:
                self.running_module_names.pop()
        elif module_name in console.COMMANDS:
            print('Error: "{}" is the name of a Pacu command, not a module. Try using it without "run" or "exec" in front.'.format(module_name))
        else:
            print('Module not found. Is it spelled correctly? Try using the module search function.')

    def idle(self) -> None:
        session = PacuSession.active_session()

        command = input('Pacu ({}:{}) > '.format(session.name, session.key_alias_id or 'No Keys Set'))
        self.parse_command(command)

        self.idle()

    def run_cli(self, arg) -> None:
        module_name: str = arg.module_name
        service = arg.data

        if arg.session:
            PacuSession.activate_by_name(arg.session)
        else:
            self.session = new_session()

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
            parse_data_command(service_cmd)

        if arg.list_modules is True:
            console.parse_list_command(['ls'])

        if arg.pacu_help is True:
            console.parse_help_command(console.COMMANDS, ['help'])

        if arg.module_info is True:
            if module_name is None:
                print('Specify a module to get information on')
            console.parse_help_command(console.COMMANDS, ['help', module_name])

        if arg.set_regions is not None:
            regions = arg.set_regions
            regions.insert(0, 'set_regions')
            console.parse_set_regions_command(regions)

        if arg.whoami is True:
            print(key_info())

    def run_gui(self) -> None:
        idle_ready = False

        while True:
            try:
                if not idle_ready:
                    try:
                        print(console.LOGO)
                    except UnicodeEncodeError:
                        pass

                    self.session = check_sessions()

                    initialize_tab_completion(console.COMMANDS)
                    display_pacu_help()

                    check_for_updates()

                    idle_ready = True

                check_user_agent()
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
                        log_error(
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
                    log_error(
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
                    log_error(
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
        parser = argparse.ArgumentParser()
        parser.add_argument('--session', required=False, default=None, help='<session name>', metavar='')
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

        db_sess = get_database_connection(settings.DATABASE_CONNECTION_PATH)
        PacuSession.set_session(db_sess)
        AWSKey.set_session(db_sess)

        set_sigint_handler(exit_text='\nA database must be created for Pacu to work properly.')
        setup_database_if_not_present(settings.DATABASE_CONNECTION_PATH, settings.DATABASE_FILE_PATH)
        set_sigint_handler(exit_text=None, value='SIGINT called')

        if any([args.session, args.data, args.module_args, args.exec, args.set_regions, args.whoami]):
            if args.session is None:
                print('When running Pacu from the CLI, a session is necessary')
                console.exit()
            self.run_cli(args)
        elif any([args.list_modules, args.pacu_help, args.module_info]):
            check_for_updates()
            self.run_cli(args)
        else:
            self.run_gui()