import json
import os
import time
import traceback
from typing import List, Optional, Tuple

import settings
from pacu.core.models import PacuSession


def log_error(text, exception_info=None, session=None, local_data=None, global_data=None) -> None:
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


def get_data_from_traceback(tb) -> Tuple[Optional['PacuSession'], List[str], List[str]]:
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