import pytest
from pacu import Main
from pacu.core.models import PacuSession


def test_parse_data_command_returns_help(pacu: Main, active_session: PacuSession):
    msg = pacu._parse_data_command(["data", "non-existent-service"], active_session)
    assert "Service not found. Please use the service name below." in msg
    assert "APIGateway	CloudTrail	CloudWatch	CodeBuild	Cognito" in msg


def test_parse_data_command_returns_no_data_found(
    pacu: Main, active_session: PacuSession
):
    msg = pacu._parse_data_command(["data", "CloudWatch"], active_session)
    assert "No data found" in msg


def test_parse_data_command_returns_no_data_found_case_insensitive(
    pacu: Main, active_session: PacuSession
):
    msg = pacu._parse_data_command(["data", "cloudwatch"], active_session)
    assert "No data found" in msg


def test_parse_data_command_returns_data(
    pacu_with_data: Main, active_session: PacuSession
):
    msg = pacu_with_data._parse_data_command(["data", "CloudWatch"], active_session)
    assert "test_key" in msg
    assert "test_value" in msg


def test_parse_data_command_returns_data_case_insensitive(
    pacu_with_data: Main, active_session: PacuSession
):
    msg = pacu_with_data._parse_data_command(["data", "cloudwatch"], active_session)
    assert "test_key" in msg
    assert "test_value" in msg


service_data = {
    "lowercase_key": "lowercase_key_value",
    "UPERCASE_KEY": "upercase_key_value",
    "MixCase_Key": "mixcase_key_value",
    "no_data_key": None,
}


def test_parse_data_command_sub_service_returns_help(pacu: Main):
    msg = pacu._parse_data_command_sub_service(service_data, "non_existent_sub_service")
    assert "Sub-service not found. Please use the sub-service name below." in msg
    assert "lowercase_key\tUPERCASE_KEY\tMixCase_Key\tno_data_key" in msg


def test_parse_data_command_sub_service_lowercase(pacu: Main):
    msg = pacu._parse_data_command_sub_service(service_data, "lowercase_key")
    assert '"lowercase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "upercase_key")
    assert '"upercase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "mixcase_key")
    assert '"mixcase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "no_data_key")
    assert "  No data found." == msg


def test_parse_data_command_sub_service_upercase(pacu: Main):
    msg = pacu._parse_data_command_sub_service(service_data, "LOWERCASE_KEY")
    assert '"lowercase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "UPERCASE_KEY")
    assert '"upercase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "MIXCASE_KEY")
    assert '"mixcase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "NO_DATA_KEY")
    assert "  No data found." == msg


def test_parse_data_command_sub_service_mixcase(pacu: Main):
    msg = pacu._parse_data_command_sub_service(service_data, "LowerCase_Key")
    assert '"lowercase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "UperCase_Key")
    assert '"upercase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "MixCase_Key")
    assert '"mixcase_key_value"' == msg
    msg = pacu._parse_data_command_sub_service(service_data, "No_Data_Key")
    assert "  No data found." == msg
