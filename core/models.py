import datetime
import json
import copy

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, ForeignKey, inspect, Integer, Text
)
from sqlalchemy.orm import relationship
from sqlalchemy_utils import JSONType

from core.base import Base
from core.mixins import ModelUpdateMixin
from utils import remove_empty_from_dict


class AWSKey(Base, ModelUpdateMixin):
    __tablename__ = 'aws_key'

    id = Column(Integer, primary_key=True)

    session_id = Column(Integer, ForeignKey('pacu_session.id', ondelete='CASCADE'))

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
    key_alias = Column(Text)
    permissions_confirmed = Column(JSONType)
    allow_permissions = Column(JSONType, nullable=False, default=dict)
    deny_permissions = Column(JSONType, nullable=False, default=dict)

    def __repr__(self):
        return '<AWSKey #{}: {}>'.format(self.id, self.key_alias)

    def get_fields_as_camel_case_dictionary(self):
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


class ProxySettings(Base, ModelUpdateMixin):
    __tablename__ = 'proxy_settings'

    id = Column(Integer, primary_key=True)

    ip = Column(Text, nullable=True, default='0.0.0.0')
    target_agent = Column(JSONType, nullable=False, default=[])
    port = Column(Integer, nullable=False, default=80)
    listening = Column(Boolean, nullable=False, default=False)
    ssh_username = Column(Text, nullable=True, default='')
    ssh_password = Column(Text, nullable=True, default='')
    ssh_shm_name = Column(Text, nullable=True, default='')

    @classmethod
    def get_proxy_settings(cls, database):
        return database.query(ProxySettings).scalar()

    def activate(self, database):
        database.add(self)
        database.commit()

    # How to add a positive-integer-only constraint to a column in SQLAlchemy.
    __table_args__ = (
        CheckConstraint(
            'port > 0',
            name='check_port_is_positive'
        ),
        {}
    )

    def __repr__(self):
        return '<PacuProxy {}:{} Target {} Listening {}>'.format(self.ip, self.port, self.target_agent, self.listening)


class PacuSession(Base, ModelUpdateMixin):
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
        'Glue',
        'GuardDuty',
        'IAM',
        'Inspector',
        'Lambda',
        'Lightsail',
        'S3',
        'Shield',
        'VPC',
        'WAF',
        'Account',
        'AccountSpend'
    )

    aws_keys = relationship('AWSKey', backref='session', cascade='all, delete-orphan', lazy='dynamic')

    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, nullable=False, default=False)
    name = Column(Text)
    boto_user_agent = Column(Text)
    key_alias = Column(Text)
    access_key_id = Column(Text)
    secret_access_key = Column(Text)
    session_token = Column(Text)
    session_regions = Column(JSONType, nullable=False, default=['all'])

    APIGateway = Column(JSONType, nullable=False, default=dict)
    CloudTrail = Column(JSONType, nullable=False, default=dict)
    CloudWatch = Column(JSONType, nullable=False, default=dict)
    CodeBuild = Column(JSONType, nullable=False, default=dict)
    Config = Column(JSONType, nullable=False, default=dict)
    DataPipeline = Column(JSONType, nullable=False, default=dict)
    DynamoDB = Column(JSONType, nullable=False, default=dict)
    EC2 = Column(JSONType, nullable=False, default=dict)
    Glue = Column(JSONType, nullable=False, default=dict)
    GuardDuty = Column(JSONType, nullable=False, default=dict)
    IAM = Column(JSONType, nullable=False, default=dict)
    Inspector = Column(JSONType, nullable=False, default=dict)
    Lambda = Column(JSONType, nullable=False, default=dict)
    Lightsail = Column(JSONType, nullable=False, default=dict)
    S3 = Column(JSONType, nullable=False, default=dict)
    Shield = Column(JSONType, nullable=False, default=dict)
    VPC = Column(JSONType, nullable=False, default=dict)
    WAF = Column(JSONType, nullable=False, default=dict)
    WAFRegional = Column(JSONType, nullable=False, default=dict)
    Account = Column(JSONType, nullable=False, default=dict)
    AccountSpend = Column(JSONType, nullable=False, default=dict)

    def __repr__(self):
        if self.key_alias:
            key_alias = self.key_alias
        else:
            key_alias = 'No Keys Set'
        if self.is_active:
            return '<PacuSession #{} ({}:{}) (ACTIVE)>'.format(self.id, self.name, key_alias)
        return '<PacuSession #{} ({}:{})>'.format(self.id, self.name, key_alias)

    @classmethod
    def get_active_session(cls, database):
        # SQLAlchemy's query filters disallow the use of `cond is True`.
        return database.query(PacuSession).filter(PacuSession.is_active == True).scalar()

    def get_active_aws_key(self, database):
        """ Return the AWSKey with the same key_alias as the PacuSession.
        A temporary function that will be replaced with a foreign key to AWSKey
        after future refactoring. """
        return self.aws_keys.filter(AWSKey.key_alias == self.key_alias).scalar()
        # return database.query(AWSKey).filter(AWSKey.key_alias == self.key_alias).filter(AWSKey.pacu_session_id == self.id).scalar()

    def activate(self, database):
        for other_session in database.query(PacuSession).filter(PacuSession.id != self.id):
            other_session.is_active = False
            database.add(other_session)

        self.is_active = True
        database.add(self)

        database.commit()

    def print_all_data_in_session(self):
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

    def get_all_fields_as_dict(self):
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
