import pytest
from sqlalchemy import orm

from pacu import core
# Import base and models after settings are set up
from pacu.core.models import AWSKey, PacuSession
from pacu.utils import get_database_connection

DATABASE_CONNECTION_PATH = "sqlite:///:memory:"


@pytest.fixture(scope='function')
def db() -> orm.session.Session:
    # Recreate the engine and session maker each run
    session = get_database_connection(DATABASE_CONNECTION_PATH)
    core.models.Base.metadata.create_all(session.connection())
    PacuSession.set_session(session)
    AWSKey.set_session(session)
    yield session


def test_sanity(db: orm.session.Session):
    assert PacuSession().__class__ == PacuSession


@pytest.fixture(scope='function')
def pacu_session(db: orm.session.Session):
    assert PacuSession.query.count() == 0
    yield PacuSession.create(name='test1')


def test_pacu_session_in_db(pacu_session: PacuSession):
    assert PacuSession.query.count() == 1
    assert PacuSession.query.first().id == pacu_session.id


@pytest.fixture(scope='function')
def active_session(db, pacu_session: PacuSession):
    pacu_session.activate()
    yield pacu_session


def test_active_session(active_session: PacuSession):
    assert active_session.is_active


def test_get_all_fields_as_dict(active_session: PacuSession):
    resp = active_session.get_all_fields_as_dict()
    assert 'name' in resp
    assert resp['name'] == 'test1'
    assert 'is_active' in resp
    assert 'key_alias' in resp
