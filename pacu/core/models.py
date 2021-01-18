import copy
import datetime
import json
import os
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import orm
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import relationship
from sqlalchemy.sql.schema import Column, ForeignKey
from sqlalchemy.sql.sqltypes import Boolean, DateTime, Integer, Text
from sqlalchemy_mixins import ActiveRecordMixin, SerializeMixin
from sqlalchemy_utils import JSONType

from pacu.core import Base
from pacu.utils import remove_empty_from_dict, stringify_datetime


class AWSKey(Base, ActiveRecordMixin):
    __tablename__ = 'aws_key'

    id = Column(Integer, primary_key=True)

    # ActiveRecordMixin uses cls.session, take care to not override that.
    pacu_session_id: int = Column(Integer, ForeignKey('pacu_session.id', ondelete='CASCADE'))
    pacu_session = relationship('PacuSession', foreign_keys=[pacu_session_id], back_populates="aws_keys")

    user_name = Column(Text)
    role_name = Column(Text)
    arn = Column(Text)
    account_id = Column(Text)
    user_id = Column(Text)
    roles = Column(JSONType)
    groups = Column(JSONType)
    policies = Column(JSONType)
    access_key_id = Column(Text)
    secret_access_key = Column(Text)
    session_token = Column(Text)
    key_alias = Column(Text, nullable=False)
    permissions_confirmed = Column(JSONType)
    allow_permissions = Column(JSONType, nullable=False, default=dict)
    deny_permissions = Column(JSONType, nullable=False, default=dict)

    def __repr__(self) -> str:
        return '<AWSKey #{}: {}>'.format(self.id, self.key_alias)

    def get_fields_as_camel_case_dictionary(self) -> dict:
        # Deep copy because Permissions->allow_permissions and deny_permissions were dicts that were being passed as reference
        return copy.deepcopy({
            'UserName': self.user_name,
            'RoleName': self.role_name,
            'Arn': self.arn,
            'AccountId': self.account_id,
            'UserId': self.user_id,
            'Roles': self.roles,
            'Groups': self.groups,
            'Policies': self.policies,
            'AccessKeyId': self.access_key_id,
            'SecretAccessKey': self.secret_access_key,
            'SessionToken': self.session_token,
            'KeyAlias': self.key_alias,
            'PermissionsConfirmed': self.permissions_confirmed,
            'Permissions': {
                'Allow': remove_empty_from_dict(self.allow_permissions),
                'Deny': remove_empty_from_dict(self.deny_permissions),
            },
        })

    @classmethod
    def get_by_alias(cls, alias: str) -> 'AWSKey':
        try:
            return cls.query.filter(AWSKey.key_alias == alias).scalar()
        except IndexError:
            raise UserWarning("No AWSKey named {} found.".format(alias))


class PacuSession(Base, ActiveRecordMixin):
    __tablename__ = 'pacu_session'
    aws_data_field_names = (
        'APIGateway',
        'CloudTrail',
        'CloudWatch',
        'CodeBuild',
        'Config',
        'DataPipeline',
        'DynamoDB',
        'EC2',
        'ECS',
        'Glue',
        'GuardDuty',
        'IAM',
        'Inspector',
        'Lambda',
        'Lightsail',
        'S3',
        'SecretsManager',
        'Shield',
        'SSM',
        'VPC',
        'WAF',
        'Account',
        'AccountSpend'
    )

    key_alias_id: Optional[str] = Column(Text, ForeignKey("aws_key.id"))
    key_alias: 'AWSKey' = relationship('AWSKey', foreign_keys=[key_alias_id])
    aws_keys: List['AWSKey'] = relationship('AWSKey', foreign_keys=[AWSKey.pacu_session_id], uselist=True, cascade='all, delete-orphan', lazy='dynamic')

    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, nullable=False, default=False)
    name = Column(Text)
    boto_user_agent = Column(Text)
    session_regions = Column(JSONType, nullable=False, default=['all'])

    APIGateway = Column(JSONType, nullable=False, default=dict)
    CloudTrail = Column(JSONType, nullable=False, default=dict)
    CloudWatch = Column(JSONType, nullable=False, default=dict)
    CodeBuild = Column(JSONType, nullable=False, default=dict)
    Config = Column(JSONType, nullable=False, default=dict)
    DataPipeline = Column(JSONType, nullable=False, default=dict)
    DynamoDB = Column(JSONType, nullable=False, default=dict)
    EC2 = Column(JSONType, nullable=False, default=dict)
    ECS = Column(JSONType, nullable=False, default=dict)
    Glue = Column(JSONType, nullable=False, default=dict)
    GuardDuty = Column(JSONType, nullable=False, default=dict)
    IAM = Column(JSONType, nullable=False, default=dict)
    Inspector = Column(JSONType, nullable=False, default=dict)
    Lambda = Column(JSONType, nullable=False, default=dict)
    Lightsail = Column(JSONType, nullable=False, default=dict)
    S3 = Column(JSONType, nullable=False, default=dict)
    SecretsManager = Column(JSONType, nullable=False, default=dict)
    SSM = Column(JSONType, nullable=False, default=dict)
    Shield = Column(JSONType, nullable=False, default=dict)
    VPC = Column(JSONType, nullable=False, default=dict)
    WAF = Column(JSONType, nullable=False, default=dict)
    WAFRegional = Column(JSONType, nullable=False, default=dict)
    Account = Column(JSONType, nullable=False, default=dict)
    AccountSpend = Column(JSONType, nullable=False, default=dict)

    def __repr__(self) -> str:
        key_alias = self.key_alias and self.key_alias.key_alias
        if self.is_active:
            return '<PacuSession #{} ({}:{}) (ACTIVE)>'.format(str(self.id), self.name, key_alias)
        else:
            return '<PacuSession #{} ({}:{})>'.format(self.id, self.name, key_alias)

    # This attribute exists in the ActiveRecordMixin class
    query: orm.Query

    def activate(self) -> None:
        self.activate_by_name(self.name)

    @classmethod
    def activate_by_name(cls, name: str) -> 'PacuSession':
        """Activates PacuSession with name if it exists."""
        for sess in cls.query.filter(PacuSession.is_active == True).all():
            sess.update(is_active=False)

        obj = cls.get_by_name(name)
        obj.update(is_active=True)
        return obj

    @classmethod
    def get_by_name(cls, name: str) -> 'PacuSession':
        try:
            res = cls.query.filter(PacuSession.name == name)
            return res[0]
        except IndexError:
            raise UserWarning("No session named {} found.".format(name))

    @classmethod
    def active_session(cls) -> 'PacuSession':
        # SQLAlchemy's query filters disallow the use of `cond is True`.
        #return cls.query.filter(PacuSession.is_active == True).scalar()  # noqa: E712
        return cls.query.filter(PacuSession.is_active == True).scalar()  # noqa: E712

    def print_all_data_in_session(self) -> None:
        text = list()
        mapper = inspect(self)

        # mapper.attrs stores all model fields in order of definition.
        for column in mapper.attrs:
            cleaned_value = remove_empty_from_dict(column.value)

            if column.key == 'aws_keys':
                owned_keys = column.value.all()
                if owned_keys:
                    text.append('aws_keys: [')
                    for each_key in owned_keys:
                        text.append('    <AWSKey: {}>'.format(each_key.key_alias))
                    text.append(']')

            elif column.key == 'secret_access_key':
                text.append('secret_access_key: "******" (Censored)')

            elif cleaned_value:
                text.append('{}: {}'.format(column.key, json.dumps(cleaned_value, indent=4, default=str)))

        if text:
            print('\n'.join(text))
        else:
            print('This session has no data.')

    def json_update(self, **kwargs) -> None:
        """Stringifies passed values and updates column. Meant to be used with JSON column types."""
        for key, value in kwargs.items():
            value = stringify_datetime(value)
            kwargs[key] = value

        self.update(**kwargs)

    def get_all_fields_as_dict(self) -> dict:
        all_data = dict()
        mapper = inspect(self)
        for attribute in mapper.attrs:
            all_data[attribute.key] = attribute.value
        return all_data

    def get_all_aws_data_fields_as_dict(self):
        all_data = dict()
        mapper = inspect(self)

        for attribute in mapper.attrs:
            if attribute.key in self.aws_data_field_names:
                if attribute.value:
                    all_data[attribute.key] = attribute.value

        return remove_empty_from_dict(all_data)


def new_session() -> PacuSession:
    name = None

    while not name:
        name = input('What would you like to name this new session? ').strip()
        if not name:
            print('A session name is required.')
        else:
            try:
                PacuSession.get_by_name(name)
                print('A session with that name already exists.')
                name = None
            except UserWarning:
                pass

    session = PacuSession.create(name=name)
    session.active_session()

    session_downloads_directory = './sessions/{}/downloads/'.format(name)
    if not os.path.exists(session_downloads_directory):
        os.makedirs(session_downloads_directory)

    print('Session {} created.'.format(name))

    return session


def delete_session() -> None:
    active_session = PacuSession.active_session()
    all_sessions = PacuSession.all()
    print('Delete which session?')

    session: PacuSession
    for index, session in enumerate(all_sessions, 0):
        if session.name == active_session.name:
            print('  [{}] {} (ACTIVE)'.format(index, session.name))
        else:
            print('  [{}] {}'.format(index, session.name))

    choice = input('Choose an option: ')

    try:
        session = all_sessions[int(choice)]
        if session.name == active_session.name:
            print('Cannot delete the active session! Switch sessions and try again.')
            return
    except (ValueError, IndexError):
        print('Please choose a number from 0 to {}.'.format(len(all_sessions) - 1))
        return delete_session()

    session.delete()

    print('Deleted {} from the database!'.format(session.name))
    print('Note that the output folder at ./sessions/{}/ will not be deleted. Do it manually if necessary.'.format(session.name))

    return


def list_sessions(session1) -> None:
    print('Found existing sessions:')

    for index, session in enumerate(PacuSession.all(), 0):
        if session.name == session1.name:
            print('- ' + session.name + ' (ACTIVE)')
        else:
            print('- ' + session.name)

    print('\nUse "swap_session" to change to another session.')


def key_info(alias='') -> Union[Dict[str, Any], bool]:
    """ Return the set of information stored in the session's active key
    or the session's key with a specified alias, as a dictionary. """
    if alias == '':
        sess = PacuSession.active_session()
        return sess.key_alias.get_fields_as_camel_case_dictionary()

    aws_key = AWSKey.get_by_alias(alias)
    return aws_key and aws_key.get_fields_as_camel_case_dictionary()
