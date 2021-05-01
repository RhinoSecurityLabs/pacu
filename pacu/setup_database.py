import os

from pacu.core.base import Base, engine
from pacu.utils import set_sigint_handler


def setup_database_if_not_present(database_file_path: str, auto_proceed: bool=True) -> bool:
    if os.path.exists(database_file_path):
        return True
    else:
        print('No database found at {}'.format(database_file_path))
        return attempt_to_create_database(database_file_path, auto_proceed)


def attempt_to_create_database(database_file_path, auto_proceed=True):
    if auto_proceed:
        proceed = 'y'
    else:
        print('A database will be created at the following location:\n    {}'.format(database_file_path))

        if os.path.exists(database_file_path):
            question = 'A file already exists at this location.\nAre you sure you want to delete and recreate it? [y/n]\n> '
        else:
            question = 'Create a new database file? [y/n]\n> '

        proceed = input(question)

    if proceed.strip().lower() == 'y':
        if os.path.exists(database_file_path):
            os.remove(database_file_path)

        # Base.metadata.create_all requires all models to be loaded before
        # tables can be created. It's is placed here for emphasis.
        from pacu.core.models import AWSKey, PacuSession
        Base.metadata.create_all(engine)

        print('Database created at {}\n'.format(database_file_path))
        return True

    else:
        print('Database creation cancelled.\n')
        return False


if __name__ == '__main__':
    from pacu.settings import DATABASE_FILE_PATH
    set_sigint_handler(exit_text='\nDatabase creation cancelled.')
    attempt_to_create_database(DATABASE_FILE_PATH, auto_proceed=False)
