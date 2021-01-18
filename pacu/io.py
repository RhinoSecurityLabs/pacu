import copy
import json
import sys
from typing import Dict, List, TypeVar, Union

from pacu.core.models import PacuSession


def print_all_service_data(session1: PacuSession) -> None:
    session = session1
    services = session.get_all_aws_data_fields_as_dict()
    for service in services.keys():
        print('  {}'.format(service))


T = TypeVar('T', Dict, List)


def clean_object(obj: T) -> T:
    # Add some recursion here to go through the entire dict for
    # 'SecretAccessKey'. This is to not print the full secret access
    # key into the logs, although this should get most cases currently.
    if isinstance(obj, dict):
        if 'SecretAccessKey' in obj:
            obj = copy.deepcopy(obj)
            truncated_key = obj['SecretAccessKey'][0:int(len(obj['SecretAccessKey']) / 2)]
            obj['SecretAccessKey'] = '{}{}'.format(truncated_key, '*' * int(len(obj['SecretAccessKey']) / 2))
        obj = json.dumps(obj, indent=2, default=str)
    elif isinstance(obj, list):
        obj = json.dumps(obj, indent=2, default=str)
    return obj


def cmd_log(message: str, output_type: str, session_name: str) -> None:
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


# **** NOTE ****
# This version of print/input is not meant for use in the console it differs from print/input in Main in
# that it doesn't include a list of running modules in the log. The reason for two versions is so methods
# that do not depend on anything else in Main can be pulled out into methods.

def print(message: Union[dict, list, str, Exception] = '', output: str='both', output_type: str='plain', is_cmd: bool=False) -> None:
    # Indent output from a command
    if not is_cmd:
        message = clean_object(message)
    if output == 'both' or output == 'file':
        cmd_log(message, output_type, PacuSession.active_session().name)
    if output == 'both' or output == 'screen':
        sys.stdout.write(message + '\n')


# Save builtin input to avoid recursion in our input function
rinput = input


# @message: String - input question to ask and/or write to file
# @output: String - where to output the message: both or screen (can't write a question to a file only)
# @output_type: String - format for message when written to file: plain or xml
def input(message, output='both', output_type='plain') -> str:
    session_name = PacuSession.active_session().name
    resp = rinput(message)
    if output == 'both':
        cmd_log('{} {}'.format(message, resp), output_type, session_name)
    return resp
