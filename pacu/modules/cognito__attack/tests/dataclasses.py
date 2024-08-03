from dataclasses import dataclass

from botocore.client import BaseClient


@dataclass
class CognitoServiceConfig:
    client: BaseClient
    user_pool_id: str
    client_id: str
    client_name: str
    identity_pool_id: str


@dataclass
class AWSCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    security_token: str
