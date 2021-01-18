import importlib
import os
import signal
import sys
import typing
from typing import Any, List, Optional, Union

import requests
from sqlalchemy import create_engine, orm, engine
from sqlalchemy.orm import sessionmaker

from settings import DATABASE_CONNECTION_PATH, ISOLATION_LEVEL, ROOT_DIR
from datetime import datetime, date
from sqlalchemy.engine.base import Engine
from sqlalchemy.orm.session import Session


def get_database_engine(conn: str = DATABASE_CONNECTION_PATH, isolation: str = ISOLATION_LEVEL) -> engine.Engine:
    return create_engine(conn, isolation_level=isolation)


def get_database_connection(conn: str = DATABASE_CONNECTION_PATH) -> orm.session.Session:
    """ Unlike database file paths, database connection paths must begin with sqlite:/// """
    assert conn.startswith('sqlite:///'), 'Database connection path must start with sqlite:///'

    eng = get_database_engine(conn)
    return sessionmaker(bind=eng)()


def remove_empty_from_dict(d: Union[dict, list, typing.Any]) -> Union[dict, list, typing.Any]:
    """ Reference: https://stackoverflow.com/a/24893252 """
    if type(d) is dict:
        d = typing.cast(dict, d)
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))

    elif type(d) is list:
        d = typing.cast(list, d)
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]

    else:
        return d


def stringify_datetime(obj: Union[dict, list, datetime]) -> Union[dict, list, str]:
    """ The sqlalchemy-pacu' JSONType doesn't accept Python datetime objects.
    This method converts all datetime objects in JSONizable data structures
    into strings, allowing the ORM to save them. """

    if isinstance(obj, dict):
        # If obj is a dict, iterate over its items and recusrively call
        # stringify_datetime on each of them.
        new_dict = dict()
        for k, v in obj.items():
            new_dict[k] = stringify_datetime(v)
        return new_dict

    elif isinstance(obj, list):
        # If obj is a list, iterate over its elements and recusrively call
        # stringify_datetime on each of them.
        new_list = list()
        for v in obj:
            new_list.append(stringify_datetime(v))
        return new_list

    elif isinstance(obj, datetime):
        # If obj is a datetime, return a formatted string version of it
        return str(obj.strftime("%a, %d %b %Y %H:%M:%S"))

    else:
        return obj


def set_sigint_handler(exit_text: Optional[str] = None, value: Union[str, int] = 0) -> None:
    def sigint_handler(signum, frame):
        """ This is to stop the error printed when CTRL+Cing out of the program so it can exit gracefully."""
        if exit_text is not None:
            print(exit_text)

        sys.exit(value)

    signal.signal(signal.SIGINT, sigint_handler)


def check_for_updates() -> None:
    with open('./last_update.txt', 'r') as f:
        local_last_update = f.read().rstrip()

    latest_update = requests.get('https://raw.githubusercontent.com/RhinoSecurityLabs/pacu/master/last_update.txt').text.rstrip()

    local_year, local_month, local_day = local_last_update.split('-')
    datetime_local = date(int(local_year), int(local_month), int(local_day))

    latest_year, latest_month, latest_day = latest_update.split('-')
    datetime_latest = date(int(latest_year), int(latest_month), int(latest_day))

    if datetime_local < datetime_latest:
        print('Pacu has a new version available! Clone it from GitHub to receive the updates.\n    git clone '
              'https://github.com/RhinoSecurityLabs/pacu.git\n')


def import_module_by_name(module_name: str, include: List[str] = []) -> Any:  # TODO: define module type
    file_path = os.path.join(ROOT_DIR, 'modules', module_name, 'main.py')
    if os.path.exists(file_path):
        import_path = 'modules.{}.main'.format(module_name).replace('/', '.').replace('\\', '.')
        module = __import__(import_path, globals(), locals(), include, 0)
        importlib.reload(module)
        return module
    return None
