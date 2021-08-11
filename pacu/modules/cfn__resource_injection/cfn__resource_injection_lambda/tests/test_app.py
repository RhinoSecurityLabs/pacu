import os
import re
import boto3
import moto
import pytest

from chalice.test import Client
from pacu.modules.cfn__resource_injection.cfn__resource_injection_lambda.app import app, add_role_dict, add_role_bytes, fetch, update


@pytest.fixture
def environ():
    os.environ['PRINCIPAL'] = 'asdf'


def test_add_role_dict(environ):
    cfn = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Test CloudFormation Template",
        "Globals": {},
        "Outputs": {},
        "Resources": {
            "OurBucket": {
                "Properties": {},
                "Type": "AWS::S3::Bucket"
            }
        }
    }

    assert {
               'AWSTemplateFormatVersion': '2010-09-09',
               'Description': 'Test CloudFormation Template',
               'Globals': {},
               'Outputs': {},
               'Resources': {
                   'MaintenanceRole': {
                       'Properties': {
                           'AssumeRolePolicyDocument': '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
                                                       '"Principal": {"AWS": "asdf"}, "Action": "sts:AssumeRole"}]}',
                           'Policies': [
                               {
                                   'PolicyDocument': {
                                       'Statement': [
                                           {
                                               'Action': '*',
                                               'Effect': 'Allow',
                                               'Resource': '*'
                                           }
                                       ],
                                       'Version': '2012-10-17',
                                   },
                                   'PolicyName': 'default',
                               }
                           ]
                       },
                       'Type': 'AWS::IAM::Role',
                   },
                   'OurBucket': {
                       'Properties': {},
                       'Type': 'AWS::S3::Bucket',
                   }
               }
           } == add_role_dict(cfn)


new_cfn_json = b"""
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Test CloudFormation Template",
    "Globals": {},
    "Outputs": {},
    "Resources": {
        "OurBucket": {
            "Properties": {},
            "Type": "AWS::S3::Bucket"
        }
    }
}
"""

modified_cfn_json = b"""
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Test CloudFormation Template",
  "Globals": {},
  "Outputs": {},
  "Resources": {
    "OurBucket": {
      "Properties": {},
      "Type": "AWS::S3::Bucket"
    },
    "MaintenanceRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": "{\\"Version\\": \\"2012-10-17\\", \\"Statement\\": [{\\"Effect\\": \\"Allow\\", \\"Principal\\": {\\"AWS\\": \\"asdf\\"}, \\"Action\\": \\"sts:AssumeRole\\"}]}",
        "Policies": [
          {
            "PolicyName": "default",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": "*",
                  "Resource": "*"
                }
              ]
            }
          }
        ]
      }
    }
  }
}
"""

new_cfn_yaml = b"""
AWSTemplateFormatVersion: '2010-09-09'
Description: Test CloudFormation Template
Globals: {}
Outputs: {}
Resources:
  OurBucket:
    Properties: {}
    Type: 'AWS::S3::Bucket'
"""


def test_add_role_bytes_json(environ):
    add_role_bytes(new_cfn_json)


def test_add_role_bytes_yaml(environ):
    add_role_bytes(new_cfn_yaml)


@pytest.fixture
def upload_json(environ, s3):
    s3.create_bucket(Bucket='test-bucket')
    s3.put_object(Bucket='test-bucket', Key='test-key', Body=new_cfn_json)
    return 'test-bucket', 'test-key', new_cfn_json


@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'


@pytest.fixture(scope='function')
def s3(aws_credentials):
    with moto.mock_s3():
        yield boto3.client('s3', region_name='us-east-1')


def test_update(s3, upload_json):
    bucket, key, _ = upload_json[0], upload_json[1], upload_json[2]

    body = s3.get_object(Bucket=bucket, Key=key)['Body'].read()
    assert clean_json(new_cfn_json.decode()) == clean_json(body.decode())

    update(s3, bucket, key)

    body = s3.get_object(Bucket=bucket, Key=key)['Body'].read()
    assert clean_json(modified_cfn_json.decode()) == clean_json(body.decode())


def test_update_second_time(s3, upload_json):
    bucket, key, body = upload_json[0], upload_json[1], upload_json[2]
    update(s3, bucket, key)
    resp = s3.get_object(Bucket=bucket, Key=key)
    a = clean_json(modified_cfn_json.decode())
    b = clean_json(resp['Body'].read().decode())
    assert a == b


def clean_json(s: str):
    c = re.compile(r'\s')
    return c.sub('', s)
