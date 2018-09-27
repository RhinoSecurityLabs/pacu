import boto3
def lambda_handler(event, context):
    if event['detail']['eventName'] == 'CreateSecurityGroup':
        rule=[{'FromPort':FROM_PORT,'ToPort':TO_PORT,'CidrIp':'IP_RANGE','IpProtocol':'IP_PROTOCOL'}]
        name=event['detail']['requestParameters']['groupName']
        c=boto3.client('ec2')
        response=c.authorize_security_group_ingress(GroupName=name,CidrIp=rule['CidrIp'],FromPort=rule['FromPort'],ToPort=rule['ToPort'],IpProtocol=rule['IpProtocol'])
    return