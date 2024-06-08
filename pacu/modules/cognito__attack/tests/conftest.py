import boto3
import moto
import pytest

from pacu.modules.cognito__attack.tests.dataclasses import CognitoServiceConfig
from pacu.settings import REGION


@pytest.fixture
def mock_cognito_user_pool():

    with moto.mock_cognitoidp():

        client = boto3.client(
            "cognito-idp",
            region_name=REGION,
        )

        response = client.create_user_pool(
            PoolName="TestUserPool", UsernameAttributes=["email"]
        )

        user_pool_id = response["UserPool"]["Id"]

        client_response = client.create_user_pool_client(
            ClientName="AppClient",
            GenerateSecret=False,
            UserPoolId=user_pool_id,
        )

        with moto.mock_cognitoidentity():
            c = boto3.client(
                "cognito-identity",
                region_name=REGION,
            )

            c_resposnse = c.create_identity_pool(
                IdentityPoolName="TestIdentityPool",
                AllowUnauthenticatedIdentities=False,
            )

        yield CognitoServiceConfig(
            client=client,
            user_pool_id=user_pool_id,
            client_id=client_response["UserPoolClient"]["ClientId"],
            client_name=client_response["UserPoolClient"]["ClientName"],
            identity_pool_id=c_resposnse["IdentityPoolId"],
        )
