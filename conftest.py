import os
import pytest
from pacu import settings, Main
from pacu import core
from pacu.core.models import PacuSession
from sqlalchemy import orm, Column, create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy_utils import JSONType
from sqlalchemy.engine import Engine

from pacu.modules.cognito__attack.tests.dataclasses import AWSCredentials

settings.DATABASE_CONNECTION_PATH = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def db() -> core.base:
    core.base.engine: Engine = create_engine(settings.DATABASE_CONNECTION_PATH)
    core.base.Session: sessionmaker = sessionmaker(bind=core.base.engine)
    core.base.Base.metadata.create_all(core.base.engine)
    yield core.base.Session()


@pytest.fixture(scope="function")
def pacu(db, aws_credentials: AWSCredentials, active_session: PacuSession):
    pacu = Main()
    pacu.database = db

    pacu.set_keys(
        key_alias="pytest",
        access_key_id=aws_credentials.access_key_id,
        secret_access_key=aws_credentials.secret_access_key,
        session_token=aws_credentials.session_token,
    )

    yield pacu


@pytest.fixture(scope="function")
def active_session(db, pacu_session: PacuSession):
    pacu_session.activate(db)
    yield pacu_session


@pytest.fixture(scope="function")
def pacu_session(db: orm.session.Session):
    query: orm.Query = db.query(PacuSession)
    assert query.count() == 0

    pacu_session = PacuSession(name="test")
    db.add(pacu_session)
    yield pacu_session


@pytest.fixture(scope="function")
def db_new_column(db: Session):
    PacuSession.TestSvc = Column(JSONType, nullable=False, default=dict)
    PacuSession.aws_data_field_names = PacuSession.aws_data_field_names + ("TestSvc",)
    core.base.Session: sessionmaker = sessionmaker(bind=core.base.engine)
    yield core.base.Session()


@pytest.fixture(scope="function")
def pacu_with_data(pacu: Main, active_session: PacuSession):
    active_session.update(pacu.database, CloudWatch={"test_key": "test_value"})
    yield pacu


@pytest.fixture(autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto."""

    value = "testing"
    creds = AWSCredentials(
        access_key_id=value,
        secret_access_key=value,
        session_token=value,
        security_token=value,
    )

    os.environ["AWS_ACCESS_KEY_ID"] = creds.access_key_id
    os.environ["AWS_SECRET_ACCESS_KEY"] = creds.secret_access_key
    os.environ["AWS_SECURITY_TOKEN"] = creds.session_token
    os.environ["AWS_SESSION_TOKEN"] = creds.session_token

    yield creds
