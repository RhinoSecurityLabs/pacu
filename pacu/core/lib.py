# This module provides utilities for common tasks involving the with statement.
import contextlib

# This module provides a portable way of using operating system dependent functionality. 
import os

# This module provides runtime support for type hints. 
from typing import Optional, cast, Callable, Generator, IO, Any

# This module offers classes representing filesystem paths with semantics appropriate
# for different operating systems. 
from pathlib import Path

# This module contains settings for pacu.
from pacu import settings

# A global variable that's optionally a Callable or None.
get_active_session: Optional[Callable] = None


class PacuException(Exception):
    pass

# https://docs.python.org/3/library/stdtypes.html#str.strip
# Return a copy of the string with the leading and trailing characters removed.
def strip_lines(text: str) -> str:
    out = []
    for line in text.splitlines():
        out.append(line.strip('\t '))
    return ' '.join(out)


def home_dir() -> Path:
    return settings.home_dir

# Per the documentation:
#  https://docs.python.org/3/reference/datamodel.html
#  __file__ is the pathname of the file from which the module was loaded, if it was loaded from a file.
#  The __file__ attribute is not present for C modules that are statically linked into the interpreter;
#  for extension modules loaded dynamically from a shared library, it is the pathname of the shared 
#  library file.
def pacu_dir() -> Path:
    # https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.parents
    # An immutable sequence providing access to the logical ancestors of the path.
    return Path(__file__).parents[1]


def session_dir() -> Path:
    if not get_active_session:
        raise UserWarning("No session_name set.")
        
    # Cast a value to a type.
    p = (home_dir()/cast(Callable, get_active_session)().name).absolute()
    os.makedirs(p, exist_ok=True)
    return p


def downloads_dir() -> Path:
    p = (session_dir()/'downloads').absolute()
    os.makedirs(p, exist_ok=True)
    return p


def module_data_dir(module: str) -> Path:
    p = (session_dir()/'modules'/module).absolute()
    os.makedirs(p, exist_ok=True)
    return p


# This function is a decorator that can be used to define a factory function 
# for 'with' statement context managers, without needing to create
# a class or separate __enter__() and __exit__() methods.
@contextlib.contextmanager
def save(
    file_name: str, 
    mode: str = 'w', 
    header: Optional[str] = None, 
    **kwargs) -> Generator[IO[Any], None, None]:
    """Saves the contents of text to {pacu_home}/{session}/downloads/{file_name}.

    Use append to avoid overwriting existing content.
    Setting the header will write the value to the first line if the file doesn't already exist.
        Used for CSV headers.

    By default the home directory is ~/.pacu.
    """
    p = Path(downloads_dir()) / file_name
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    with open(str(p), mode, **kwargs) as f:
        if header and not p.exists():
            f.write(header + '\n')
        try:
            yield f
        finally:
            f.close()
