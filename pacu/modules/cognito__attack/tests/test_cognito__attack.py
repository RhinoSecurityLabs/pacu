import builtins
import unittest.mock

from pacu.main import Main
from pacu.modules.cognito__attack.main import main
from pacu.modules.cognito__attack.tests.dataclasses import CognitoServiceConfig

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
