import importlib
import os
import re

import pacu.utils
from settings import ROOT_DIR


def initialize_tab_completion(COMMANDS) -> None:
    try:
        import readline
        # Big thanks to samplebias: https://stackoverflow.com/a/5638688
        MODULES = []
        CATEGORIES = []

        for root, directories, files in os.walk('{}/modules'.format(ROOT_DIR)):
            modules_directory_path = os.path.realpath('{}/modules'.format(ROOT_DIR))
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
                    module_path = os.path.join('modules/{}/main'.format(module_name).replace('/', '.').replace('\\', '.'))

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
                    return [c + ' ' for c in COMMANDS][state]

                if len(line) == 1 and (line[0] == 'help'):
                    return [c + ' ' for c in MODULES + COMMANDS][state]

                if len(line) == 1 and (line[0] == 'exec' or line[0] == 'run'):
                    return [c + ' ' for c in MODULES][state]

                # account for last argument ending in a space
                if RE_SPACE.match(buffer):
                    line.append('')

                # Resolve command to the implementation function
                if len(line) == 1:
                    cmd = line[0].strip()
                    results = [c + ' ' for c in COMMANDS if c.startswith(cmd)] + [None]

                elif len(line) == 2:
                    cmd = line[1].strip()
                    if line[0].strip() == 'search':
                        results = [c + ' ' for c in MODULES + ['category'] if c.startswith(cmd)] + [None]
                    elif line[0].strip() == 'help':
                        results = [c + ' ' for c in MODULES + COMMANDS if c.startswith(cmd)] + [None]
                    else:
                        results = [c + ' ' for c in MODULES if c.startswith(cmd)] + [None]

                elif len(line) == 3 and line[0] == 'search' and line[1] in ('cat', 'category'):
                    cmd = line[2].strip()
                    results = [c + ' ' for c in CATEGORIES if c.startswith(cmd)] + [None]

                elif len(line) >= 3:
                    if line[0].strip() == 'run' or line[0].strip() == 'exec':
                        module_name = line[1].strip()
                        module = pacu.utils.import_module_by_name(module_name, include=['module_info'])
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


def display_command_help(command_name: str) -> None:
    if command_name == 'list' or command_name == 'ls':
        print('\n    list/ls\n        List all modules\n')
    elif command_name == 'import_keys':
        print('\n    import_keys <profile name>|--all\n      Import AWS keys from the AWS CLI credentials file (located at ~/.aws/credentials) to the '
              'current sessions database. Enter the name of a profile you would like to import or supply --all to import all the credentials in the '
              'file.\n')
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


def display_pacu_help() -> None:
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
        data <service>                      Display all data for a specified service in this session
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
        run/exec <module name>              Execute a module
        set_keys                            Add a set of AWS keys to the session and set them as the
                                              default
        swap_keys                           Change the currently active AWS key to another key that has
                                              previously been set for this session
        import_keys <profile name>|--all    Import AWS keys from the AWS CLI credentials file (located
                                              at ~/.aws/credentials) to the current sessions database.
                                              Enter the name of a profile you would like to import or
                                              supply --all to import all the credentials in the file.
        export_keys                         Export the active credentials to a profile in the AWS CLI
                                              credentials file (~/.aws/credentials)
        sessions/list_sessions              List all sessions in the Pacu database
        swap_session                        Change the active Pacu session to another one in the database
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