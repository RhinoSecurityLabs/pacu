import unittest.mock

import boto3
import moto
from pacu import settings
from pacu.main import Main
from pacu.modules.cognito__attack.main import main
from pacu.modules.cognito__attack.tests.dataclasses import (
    AWSCredentials,
    CognitoCredentials,
)
import builtins


EMAIL = "test@example.com"
USERNAME = "random"
PASSWORD = "XXXXXXXXXXXXX"


def test_me(
    pacu: Main,
):

    with moto.mock_cognitoidp():

        client = boto3.client(
            "cognito-idp",
            region_name=settings.REGION,
        )

        response = client.create_user_pool(
            PoolName="TestUserPool",
            UsernameAttributes=[
                "email",
            ],
            # Schema=[
            #     {
            #         "AttributeName": "email",
            #         "AttributeDataType": "String",
            #     }
            # ],
        )

        user_pool_id = response["UserPool"]["Id"]

        client_response = client.create_user_pool_client(
            ClientName="AppClient",
            GenerateSecret=False,
            UserPoolId=user_pool_id,
        )

        cog = CognitoCredentials(
            client=client,
            user_pool_id=user_pool_id,
            client_id=client_response["UserPoolClient"]["ClientId"],
            client_name=client_response["UserPoolClient"]["ClientName"],
            identity_pool_id=None,
        )

        with moto.mock_cognitoidentity():
            c = boto3.client(
                "cognito-identity",
                region_name=settings.REGION,
            )

            c_resposnse = c.create_identity_pool(
                IdentityPoolName="TestIdentityPool",
                AllowUnauthenticatedIdentities=False,
            )

            cog.identity_pool_id = c_resposnse["IdentityPoolId"]

        args = [
            "--username",
            EMAIL,
            "--email",
            EMAIL,
            "--password",
            PASSWORD,
            "--identity_pools",
            cog.identity_pool_id,
            "--user_pool_clients",
            f"{cog.client_id}@{cog.user_pool_id}",
        ]

        with unittest.mock.patch.object(
            builtins, "input", side_effect=["n", "", "", "", ""]
        ):
            main(args=args, pacu_main=pacu)

        response = client.admin_get_user(UserPoolId=cog.user_pool_id, Username=EMAIL)

        user_status = response["UserStatus"]
