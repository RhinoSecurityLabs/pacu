import pytest
import moto
import boto3
import os


@pytest.fixture(scope="function")
def s3(aws_credentials):
    with moto.mock_s3():
        yield boto3.client("s3", region_name="us-east-1")


@pytest.fixture
def environ():
    os.environ["PRINCIPAL"] = "asdf"
