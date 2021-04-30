import pytest
from sqlalchemy import orm, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from pacu import settings
from pacu import core
from pacu.core.models import PacuSession

# Import base and models after settings are set up
settings.DATABASE_CONNECTION_PATH = "sqlite:///:memory:"


@pytest.fixture(scope='function')
def db() -> core.base:
    # Recreate the engine and session maker each run
    core.base.engine: Engine = create_engine(settings.DATABASE_CONNECTION_PATH)
    core.base.Session: sessionmaker = sessionmaker(bind=core.base.engine)
    core.base.Base.metadata.create_all(core.base.engine)
    yield core.base.Session()


def test_sanity(db: orm.session.Session):
    assert PacuSession().__class__ == PacuSession


@pytest.fixture(scope='function')
def pacu_session(db: orm.session.Session):
    query: orm.Query = db.query(PacuSession)
    assert query.count() == 0

    pacu_session = PacuSession()
    db.add(pacu_session)
    yield pacu_session


def test_pacu_session_in_db(db, pacu_session: PacuSession):
    query: orm.Query = db.query(PacuSession)
    result: PacuSession = query.first()
    assert result.id == pacu_session.id


@pytest.fixture(scope='function')
def active_session(db, pacu_session: PacuSession):
    pacu_session.activate(db)
    yield pacu_session


def test_active_session(active_session: PacuSession):
    assert active_session.is_active
