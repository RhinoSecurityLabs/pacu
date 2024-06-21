import os
import pytest
import sqlalchemy.exc
from sqlalchemy import orm

from pacu.core.models import PacuSession, migrations


def test_sanity(db: orm.session.Session):
    assert PacuSession().__class__ == PacuSession


def test_migrations(db_new_column):
    with pytest.raises(sqlalchemy.exc.OperationalError):
        PacuSession.get_active_session(db_new_column)

    migrations(db_new_column)

    assert PacuSession.get_active_session(db_new_column) is None


def test_pacu_session_in_db(db, pacu_session: PacuSession):
    query: orm.Query = db.query(PacuSession)
    result: PacuSession = query.first()
    assert result.id == pacu_session.id


def test_active_session(active_session: PacuSession):
    assert active_session.is_active
