import os
import pytest
import sqlalchemy.exc
from unittest.mock import patch
from sqlalchemy import orm

from pacu import Main, settings
from pacu.core.models import AWSKey, PacuSession, migrations


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


# --- new_session ---

def test_new_session_creates_session(pacu: Main):
    session = pacu.new_session(name="new_test_session")
    assert session.name == "new_test_session"

    result = pacu.database.query(PacuSession).filter(PacuSession.name == "new_test_session").first()
    assert result is not None
    assert result.id == session.id


def test_new_session_rejects_duplicate_name(pacu: Main):
    pacu.new_session(name="duplicate")
    with patch("builtins.input", side_effect=["unique_name"]):
        session = pacu.new_session(name="duplicate")
    assert session.name == "unique_name"


def test_new_session_prompts_when_no_name(pacu: Main):
    with patch("builtins.input", return_value="prompted_session"):
        session = pacu.new_session()
    assert session.name == "prompted_session"


# --- activate_session ---

def test_activate_session_switches_active(pacu: Main):
    session_a = pacu.new_session(name="session_a")
    session_a.activate(pacu.database)

    session_b = pacu.new_session(name="session_b")
    assert not session_b.is_active

    pacu.activate_session("session_b")

    pacu.database.refresh(session_a)
    pacu.database.refresh(session_b)
    assert session_b.is_active
    assert not session_a.is_active


def test_activate_session_case_insensitive(pacu: Main):
    session = pacu.new_session(name="MySession")
    pacu.activate_session("mysession")

    pacu.database.refresh(session)
    assert session.is_active


def test_activate_session_not_found(pacu: Main, capsys):
    pacu.activate_session("nonexistent")
    output = capsys.readouterr().out
    assert "Session not found" in output


# --- list_sessions ---

def test_list_sessions_shows_all(pacu: Main, active_session: PacuSession, capsys):
    pacu.new_session(name="other_session")

    pacu.list_sessions()
    output = capsys.readouterr().out

    assert active_session.name in output
    assert "other_session" in output
    assert "ACTIVE" in output


# --- delete_session ---

def test_delete_session_removes_from_db(pacu: Main, active_session: PacuSession):
    to_delete = pacu.new_session(name="deleteme")

    with patch("builtins.input", side_effect=["1", "n"]):
        pacu.delete_session()

    result = pacu.database.query(PacuSession).filter(PacuSession.name == "deleteme").first()
    assert result is None


def test_delete_session_cannot_delete_active(pacu: Main, active_session: PacuSession, capsys):
    # The active session is index 0, so choosing "0" should skip it
    with patch("builtins.input", side_effect=["0", "n"]):
        pacu.delete_session()

    output = capsys.readouterr().out
    assert "cannot delete the active session" in output.lower()

    result = pacu.database.query(PacuSession).filter(PacuSession.name == active_session.name).first()
    assert result is not None


def test_delete_session_removes_files(pacu: Main, active_session: PacuSession, tmp_path):
    to_delete = pacu.new_session(name="deleteme_files")

    session_dir = os.path.join(settings.home_dir, "deleteme_files")
    os.makedirs(session_dir, exist_ok=True)
    with open(os.path.join(session_dir, "test.txt"), "w") as f:
        f.write("test data")

    with patch("builtins.input", side_effect=["1", "y"]):
        pacu.delete_session()

    assert not os.path.exists(session_dir)


def test_delete_session_no_files_prints_message(pacu: Main, active_session: PacuSession, capsys):
    pacu.new_session(name="no_files_session")

    with patch("builtins.input", side_effect=["1", "y"]):
        pacu.delete_session()

    output = capsys.readouterr().out
    assert "No files found" in output


def test_delete_session_invalid_choice(pacu: Main, active_session: PacuSession, capsys):
    with patch("builtins.input", side_effect=["999", "n"]):
        pacu.delete_session()

    output = capsys.readouterr().out
    assert "Invalid selection" in output


# --- set_keys ---

def test_set_keys_programmatic(pacu: Main):
    pacu.set_keys(
        key_alias="testkey",
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token="FwoGZXIvYXdzEBY",
    )
    session = pacu.get_active_session()
    assert session.key_alias == "testkey"
    assert session.access_key_id == "AKIAIOSFODNN7EXAMPLE"
    assert session.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert session.session_token == "FwoGZXIvYXdzEBY"


def test_set_keys_creates_aws_key_record(pacu: Main):
    pacu.set_keys(
        key_alias="newkey",
        access_key_id="AKIAI44QH8DHBEXAMPLE",
        secret_access_key="je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    )
    session = pacu.get_active_session()
    key = pacu.database.query(AWSKey).filter(
        AWSKey.session_id == session.id,
        AWSKey.key_alias == "newkey",
    ).first()

    assert key is not None
    assert key.access_key_id == "AKIAI44QH8DHBEXAMPLE"


def test_set_keys_updates_existing_key(pacu: Main):
    pacu.set_keys(
        key_alias="pytest",
        access_key_id="AKIANEWKEY1234567890",
        secret_access_key="newsecret",
    )
    session = pacu.get_active_session()
    assert session.access_key_id == "AKIANEWKEY1234567890"

    keys = pacu.database.query(AWSKey).filter(
        AWSKey.session_id == session.id,
        AWSKey.key_alias == "pytest",
    ).all()
    assert len(keys) == 1
    assert keys[0].access_key_id == "AKIANEWKEY1234567890"


# --- swap_keys ---

def test_swap_keys_by_name(pacu: Main):
    pacu.set_keys(
        key_alias="second_key",
        access_key_id="AKIASECONDEXAMPLE123",
        secret_access_key="secondsecret",
    )
    # Swap back to the original key
    pacu.swap_keys(key_name="pytest")

    session = pacu.get_active_session()
    assert session.key_alias == "pytest"


def test_swap_keys_nonexistent(pacu: Main, capsys):
    pacu.swap_keys(key_name="does_not_exist")
    output = capsys.readouterr().out
    assert "No key with the alias" in output


def test_swap_keys_no_keys(db: orm.session.Session, active_session: PacuSession):
    p = Main()
    p.database = db
    # No keys set — session has no aws_keys
    p.swap_keys(key_name="anything")
    # Should not raise, just print a message


# --- delete_keys ---

def test_delete_keys_removes_inactive_key(pacu: Main):
    pacu.set_keys(
        key_alias="to_delete",
        access_key_id="AKIADELETEME12345678",
        secret_access_key="deletesecret",
    )
    # Swap back so "to_delete" is inactive
    pacu.swap_keys(key_name="pytest")

    session = pacu.get_active_session()
    all_keys = pacu.database.query(AWSKey).filter(AWSKey.session_id == session.id).all()
    # Find the index of "to_delete"
    delete_idx = next(i for i, k in enumerate(all_keys) if k.key_alias == "to_delete")

    with patch("builtins.input", return_value=str(delete_idx)):
        pacu.delete_keys()

    remaining = pacu.database.query(AWSKey).filter(
        AWSKey.session_id == session.id,
        AWSKey.key_alias == "to_delete",
    ).first()
    assert remaining is None


def test_delete_keys_cannot_delete_active(pacu: Main, capsys):
    session = pacu.get_active_session()
    all_keys = pacu.database.query(AWSKey).filter(AWSKey.session_id == session.id).all()
    active_idx = next(i for i, k in enumerate(all_keys) if k.key_alias == session.key_alias)

    with patch("builtins.input", return_value=str(active_idx)):
        pacu.delete_keys()

    output = capsys.readouterr().out
    assert "Cannot delete the active keys" in output


# --- get_aws_key_by_alias ---

def test_get_aws_key_by_alias_found(pacu: Main):
    key = pacu.get_aws_key_by_alias("pytest")
    assert key is not None
    assert key.key_alias == "pytest"


def test_get_aws_key_by_alias_not_found(pacu: Main):
    key = pacu.get_aws_key_by_alias("nonexistent")
    assert key is None


# --- PacuSession model methods ---

def test_session_activate_deactivates_others(db: orm.session.Session):
    s1 = PacuSession(name="s1")
    s2 = PacuSession(name="s2")
    db.add_all([s1, s2])
    db.commit()

    s1.activate(db)
    assert s1.is_active
    assert not s2.is_active

    s2.activate(db)
    db.refresh(s1)
    assert s2.is_active
    assert not s1.is_active


def test_session_get_active_aws_key(pacu: Main):
    session = pacu.get_active_session()
    key = session.get_active_aws_key(pacu.database)
    assert key is not None
    assert key.key_alias == session.key_alias


def test_session_get_all_fields_as_dict(db: orm.session.Session, active_session: PacuSession):
    fields = active_session.get_all_fields_as_dict()
    assert isinstance(fields, dict)
    assert "name" in fields
    assert fields["name"] == "test"
    assert "is_active" in fields


def test_session_get_all_aws_data_fields_as_dict(pacu_with_data: Main):
    session = pacu_with_data.get_active_session()
    data = session.get_all_aws_data_fields_as_dict()
    assert "CloudWatch" in data
    assert data["CloudWatch"]["test_key"] == "test_value"


def test_session_get_all_aws_data_fields_empty(db: orm.session.Session, active_session: PacuSession):
    data = active_session.get_all_aws_data_fields_as_dict()
    assert data == {}


def test_session_repr_with_keys(pacu: Main):
    session = pacu.get_active_session()
    r = repr(session)
    assert "ACTIVE" in r
    assert session.name in r
    assert session.key_alias in r


def test_session_repr_no_keys(db: orm.session.Session):
    session = PacuSession(name="bare")
    db.add(session)
    db.commit()
    r = repr(session)
    assert "No Keys Set" in r


# --- AWSKey model ---

def test_aws_key_get_fields_as_camel_case(pacu: Main):
    key = pacu.get_aws_key_by_alias("pytest")
    fields = key.get_fields_as_camel_case_dictionary()

    assert fields["KeyAlias"] == "pytest"
    assert fields["AccessKeyId"] == key.access_key_id
    assert "Permissions" in fields
    assert "Allow" in fields["Permissions"]
    assert "Deny" in fields["Permissions"]


def test_aws_key_repr(pacu: Main):
    key = pacu.get_aws_key_by_alias("pytest")
    r = repr(key)
    assert "AWSKey" in r
    assert "pytest" in r
