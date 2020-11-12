import signal
import sys
import datetime

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from core.base import DATABASE_CONNECTION_PATH


def get_database_connection(database_connection_path=DATABASE_CONNECTION_PATH):
    """ Unlike database file paths, database connection paths must begin with
    sqlite:/// """
    assert database_connection_path.startswith('sqlite:///'), 'Database connection path must start with sqlite:///'

    engine = create_engine(database_connection_path)
    Base = declarative_base()
    Base.metadata.bind = engine
    Session = sessionmaker(bind=engine)

    return Session()


def remove_empty_from_dict(d):
    """ Reference: https://stackoverflow.com/a/24893252 """
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))

    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]

    else:
        return d


def stringify_datetime(obj):
    """ The sqlalchemy-utils' JSONType doesn't accept Python datetime objects.
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

    elif isinstance(obj, datetime.datetime):
        # If obj is a datetime, return a formatted string version of it
        return str(obj.strftime("%a, %d %b %Y %H:%M:%S"))

    else:
        return obj


def set_sigint_handler(exit_text=None, value=0):

    def sigint_handler(signum, frame):
        """ This is to stop the error printed when CTRL+Cing out of the program
        so it can exit gracefully. """
        if exit_text is not None:
            print(exit_text)

        sys.exit(value)

    signal.signal(signal.SIGINT, sigint_handler)
