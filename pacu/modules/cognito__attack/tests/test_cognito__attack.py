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
PASSWORD = "1R@nd0mP4$$word"


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

    user_input_list = [
        "random_token",  # Enter verification code for user
        "",  # Enter attribute name to modify for user
        "",  # Enter attribute value to set for user
        "",  # Modify more custom attributes? (y/n)
        "n",  # Enter the number of the role you want to assume (or "n" to skip):
    ]

    with unittest.mock.patch.object(builtins, "input", side_effect=user_input_list):
        main(args=args, pacu_main=pacu)

    response = mock_cognito_user_pool.client.admin_get_user(
        UserPoolId=mock_cognito_user_pool.user_pool_id, Username=EMAIL
    )

    user_status = response["UserStatus"]

    assert user_status == "CONFIRMED"
    assert response["UserAttributes"][0]["Value"] == EMAIL
    assert response["Username"] == response["UserAttributes"][1]["Value"]


def test_cognito__attack_sanity(
    pacu: Main, mock_cognito_user_pool: CognitoServiceConfig
):
    conn = pacu.get_boto3_client("cognito-idp", REGION)
    pool_id = mock_cognito_user_pool.user_pool_id
    client_id = mock_cognito_user_pool.client_id

    conn.admin_create_user(
        UserPoolId=pool_id,
        Username=EMAIL,
        TemporaryPassword=PASSWORD,
    )

    key = bytes(str(PASSWORD).encode("latin-1"))
    msg = bytes(str(EMAIL + client_id).encode("latin-1"))
    new_digest = hmac.new(key, msg, hashlib.sha256).digest()
    secret_hash = base64.b64encode(new_digest).decode()
    result = conn.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_SRP_AUTH",
        AuthParameters={
            "USERNAME": EMAIL,
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
            "USERNAME": EMAIL,
        },
    )

    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
