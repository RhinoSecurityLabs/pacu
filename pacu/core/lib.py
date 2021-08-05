import contextlib
import os
from typing import Optional, cast, Callable, Generator, IO, Any

from pathlib import Path

from pacu import settings

get_active_session: Optional[Callable] = None


class PacuException(Exception):
    pass


def strip_lines(text: str) -> str:
    out = []
    for line in text.splitlines():
        out.append(line.strip('\t '))
    return ' '.join(out)


def home_dir() -> Path:
    return settings.home_dir


def pacu_dir() -> Path:
    return Path(__file__).parents[1]


def session_dir() -> Path:
    if not get_active_session:
        raise UserWarning("No session_name set.")
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


@contextlib.contextmanager
def save(file_name: str, mode: str = 'w', header: Optional[str] = None, **kwargs) -> Generator[IO[Any], None, None]:
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
