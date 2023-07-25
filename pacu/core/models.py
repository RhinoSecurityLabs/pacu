import datetime
import json
import copy

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, inspect, Integer, Text, orm
)
from sqlalchemy.orm import relationship, Session
from sqlalchemy_utils import JSONType  # type: ignore

from pacu.core.base import Base, engine
from pacu.core.mixins import ModelUpdateMixin
from pacu.utils import remove_empty_from_dict


class AWSKey(Base, ModelUpdateMixin):
    __tablename__ = 'aws_key'

    id = Column(Integer, primary_key=True)

    session_id = Column(Integer, ForeignKey('pacu_session.id', ondelete='CASCADE'))
    session = relationship("PacuSession", back_populates="aws_keys")

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



class PacuSession(Base, ModelUpdateMixin):
    __tablename__ = 'pacu_session'
    aws_data_field_names = (
        'APIGateway',
        'CloudTrail',
        'CloudWatch',
        'CodeBuild',
        'Cognito',
        'Config',
        'DataPipeline',
        'DynamoDB',
        'EC2',
        'ECS',
        'EKS',
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
        'AccountSpend',
        'Route53',
        'RDS',
        'Transfer',
        'Organizations'
    )

    aws_keys = relationship('AWSKey', back_populates='session', cascade='all, delete-orphan', lazy='dynamic')

    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, nullable=False, default=False)
    name = Column(Text)
    boto_user_agent = Column(Text)
    user_agent_suffix = Column(Text)
    key_alias = Column(Text)
    access_key_id = Column(Text)
    secret_access_key = Column(Text)
    session_token = Column(Text)
    session_regions = Column(JSONType, nullable=False, default=['all'])

    APIGateway = Column(JSONType, nullable=False, default=dict)
    CloudTrail = Column(JSONType, nullable=False, default=dict)
    CloudWatch = Column(JSONType, nullable=False, default=dict)
    CodeBuild = Column(JSONType, nullable=False, default=dict)
    Cognito = Column(JSONType, nullable=False, default=dict)
    Config = Column(JSONType, nullable=False, default=dict)
    DataPipeline = Column(JSONType, nullable=False, default=dict)
    DynamoDB = Column(JSONType, nullable=False, default=dict)
    EC2 = Column(JSONType, nullable=False, default=dict)
    ECS = Column(JSONType, nullable=False, default=dict)
    EKS = Column(JSONType, nullable=False, default=dict)
    Glue = Column(JSONType, nullable=False, default=dict)
    GuardDuty = Column(JSONType, nullable=False, default=dict)
    IAM = Column(JSONType, nullable=False, default=dict)
    Inspector = Column(JSONType, nullable=False, default=dict)
    Lambda = Column(JSONType, nullable=False, default=dict)
    Lightsail = Column(JSONType, nullable=False, default=dict)
    RDS = Column(JSONType, nullable=False, default=dict)
    S3 = Column(JSONType, nullable=False, default=dict)
    SecretsManager = Column(JSONType, nullable=False, default=dict)
    SSM = Column(JSONType, nullable=False, default=dict)
    Shield = Column(JSONType, nullable=False, default=dict)
    VPC = Column(JSONType, nullable=False, default=dict)
    WAF = Column(JSONType, nullable=False, default=dict)
    WAFRegional = Column(JSONType, nullable=False, default=dict)
    Account = Column(JSONType, nullable=False, default=dict)
    AccountSpend = Column(JSONType, nullable=False, default=dict)
    Route53 = Column(JSONType, nullable=False, default=dict)
    RDS = Column(JSONType, nullable=False, default=dict)
    Transfer = Column(JSONType, nullable=False, default=dict)
    Organizations = Column(JSONType, nullable=False, default=dict)

    def __repr__(self) -> str:
        if self.key_alias:
            key_alias = self.key_alias
        else:
            key_alias = 'No Keys Set'
        if self.is_active:
            return '<PacuSession #{} ({}:{}) (ACTIVE)>'.format(self.id, self.name, key_alias)
        return '<PacuSession #{} ({}:{})>'.format(self.id, self.name, key_alias)

    @classmethod
    def get_active_session(cls, database: Session) -> 'PacuSession':
        # SQLAlchemy's query filters disallow the use of `cond is True`.
        return database.query(PacuSession).filter(PacuSession.is_active == True).scalar()  # noqa: E712


    def get_active_aws_key(self, database: Session) -> AWSKey:
        """ Return the AWSKey with the same key_alias as the PacuSession.
        A temporary function that will be replaced with a foreign key to AWSKey
        after future refactoring. """

        # On attr-defined ignore: https://github.com/dropbox/sqlalchemy-stubs/issues/168
        return self.aws_keys.filter(AWSKey.key_alias == self.key_alias).scalar()  # type: ignore[attr-defined]
        # return database.query(AWSKey).filter(AWSKey.key_alias == self.key_alias).filter(AWSKey.pacu_session_id == self.id).scalar()

    def activate(self, database: orm.session.Session) -> None:
        for other_session in database.query(PacuSession).filter(PacuSession.id != self.id):
            other_session.is_active = False
            database.add(other_session)

        self.is_active = True
        database.add(self)

        database.commit()

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


def migrations(database: 'Session'):
    """Very hacky migrations for the pacu_session table.

    This exists to prevent broken installs on update when modules add new columns to the PacuSession table. This will
    only add columns that are included in PacuSession.aws_data_field_names and will assume the columns should be NOT
    NULL.
    """
    rows = []
    for row in database.execute(f'pragma table_info({PacuSession.__tablename__})').fetchall():
        rows.append(row[1])

    # If more rows are added here change this to update the db dynamically. Not worrying about this for now since it
    # doesn't happen often, and we'll likely rewrite things before then.
    if "user_agent_suffix" not in rows:
        column_type = PacuSession.user_agent_suffix.type.compile(engine.dialect)
        database.execute('ALTER TABLE %s ADD COLUMN user_agent_suffix %s' % (PacuSession.__tablename__, column_type))

    for svc in PacuSession.aws_data_field_names:
        if svc not in rows:
            column = getattr(PacuSession, svc)
            column_type = column.type.compile(engine.dialect)
            database.execute(
                'ALTER TABLE %s ADD COLUMN %s %s DEFAULT "{}" NOT NULL'
                % (PacuSession.__tablename__, svc, column_type)
            )


