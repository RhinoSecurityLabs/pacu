import base64
import builtins
import hashlib
import hmac
import unittest.mock
import uuid

from pacu.main import Main
from pacu.modules.cognito__attack.main import main
from pacu.modules.cognito__attack.tests.dataclasses import CognitoServiceConfig
from pacu.settings import REGION

EMAIL = "test@example.com"
USERNAME = "random"
PASSWORD = "XXXXXXXXXXXXX"


def test_cognito__attack_minimal(
    pacu: Main, mock_cognito_user_pool: CognitoServiceConfig
):

    args = [
        "--username",
        EMAIL,
        "--email",
        EMAIL,
        "--password",
        PASSWORD,
        "--identity_pools",
        mock_cognito_user_pool.identity_pool_id,
        "--user_pool_clients",
        f"{mock_cognito_user_pool.client_id}@{mock_cognito_user_pool.user_pool_id}",
    ]

    input_list = ["n", "", "n", "n", "n"]

    with unittest.mock.patch.object(builtins, "input", side_effect=input_list):
        main(args=args, pacu_main=pacu)

    response = mock_cognito_user_pool.client.admin_get_user(
        UserPoolId=mock_cognito_user_pool.user_pool_id, Username=EMAIL
    )

    user_status = response["UserStatus"]

    assert user_status == "CONFIRMED"

def test_sanity(pacu: Main, mock_cognito_user_pool: CognitoServiceConfig):
    conn = pacu.get_boto3_client("cognito-idp", REGION)
    pool_id = mock_cognito_user_pool.user_pool_id
    client_id = mock_cognito_user_pool.client_id

    conn.admin_create_user(
        UserPoolId=pool_id,
        Username=USERNAME,
        TemporaryPassword=PASSWORD,
    )

    key = bytes(str(PASSWORD).encode("latin-1"))
    msg = bytes(str(USERNAME + client_id).encode("latin-1"))
    new_digest = hmac.new(key, msg, hashlib.sha256).digest()
    secret_hash = base64.b64encode(new_digest).decode()
    result = conn.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_SRP_AUTH",
        AuthParameters={
            "USERNAME": USERNAME,
            "SRP_A": uuid.uuid4().hex,
            "SECRET_HASH": secret_hash,
        },
    )

    result = conn.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName=result["ChallengeName"],
        ChallengeResponses={
            "PASSWORD_CLAIM_SIGNATURE": str(uuid.uuid4()),
            "PASSWORD_CLAIM_SECRET_BLOCK": result["Session"],
            "TIMESTAMP": str(uuid.uuid4()),
            "USERNAME": USERNAME,
        },
    )

    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
