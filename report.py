import sqlite3
import re
import json
import os

# Function to extract data from tables and identify AWS resources
def generate_report():
    # Connect to the SQLite database
    home_dir = os.path.expanduser('~')
    sql_dir = f"{home_dir}/.local/share/pacu/sqlite.db"
    conn = sqlite3.connect(sql_dir)  # Using the path 'sqlite.db'
    cursor = conn.cursor()

    print("Building PACU Framework report....")
    # Check the available columns in each table
    cursor.execute("PRAGMA table_info(pacu_session);")
    pacu_session_columns = cursor.fetchall()
    print("Columns in the pacu_session table:", pacu_session_columns)

    cursor.execute("PRAGMA table_info(aws_key);")
    aws_key_columns = cursor.fetchall()
    print("Columns in the aws_key table:", aws_key_columns)

    # Extract relevant data from the pacu_session table
    cursor.execute("SELECT * FROM pacu_session;")
    pacu_session_data = cursor.fetchall()

    # Extract relevant data from the aws_key table
    cursor.execute("SELECT * FROM aws_key;")
    aws_key_data = cursor.fetchall()

    # Process and display the extracted data
    print("\nData from the pacu_session table:")
    for row in pacu_session_data:
        print(row)

    print("\nData from the aws_key table:")
    for row in aws_key_data:
        print(row)

    # Combine the extracted data into a string to apply regexes
    combined_data = pacu_session_data + aws_key_data
    output_content = ' '.join(str(row) for row in combined_data)

    # Patterns to identify different types of AWS resources
    patterns = {
        # pacu_session_data
        "AccountId": r'account_id": "([^"]+)',
        "InstanceId": r'InstanceId": "([^"]+)',
        "VolumeId": r'VolumeId": "([^"]+)',
        "SecurityGroupId": r'GroupId": "([^"]+)',
        "VPCId": r'VpcId": "([^"]+)',
        "SubnetId": r'SubnetId": "([^"]+)',
        "LambdaFunctionName": r'FunctionName": "([^"]+)',
        "BucketName": r's3://([^/"]+)',
        "RDSInstanceId": r'DBInstanceIdentifier": "([^"]+)',
        "IAMRole": r'Role": "arn:aws:iam::[^:]+:role/([^"]+)',
        "IAMUser": r'UserName": "([^"]+)',
        "DynamoDBTable": r'TableName": "([^"]+)',
        "KMSKeyId": r'KeyId": "([^"]+)',
        "EIPId": r'AllocationId": "([^"]+)',
        "NatGatewayId": r'NatGatewayId": "([^"]+)',
        "ElasticLoadBalancer": r'LoadBalancerName": "([^"]+)',
        "AutoScalingGroup": r'AutoScalingGroupName": "([^"]+)',
        "CloudFormationStack": r'StackName": "([^"]+)',
        "SQSQueue": r'QueueName": "([^"]+)',
        "SNSArn": r'TopicArn": "([^"]+)',
        "CloudWatchAlarm": r'AlarmName": "([^"]+)',
        "ElasticBeanstalkEnv": r'EnvironmentName": "([^"]+)',
        "EFSFileSystemId": r'FileSystemId": "([^"]+)',
        "TransitGatewayId": r'TransitGatewayId": "([^"]+)',
        "RouteTableId": r'RouteTableId": "([^"]+)',
        "VpcPeeringConnectionId": r'VpcPeeringConnectionId": "([^"]+)',
        "GlueJobName": r'JobName": "([^"]+)',
        "CodeBuildProject": r'ProjectName": "([^"]+)',
        "CodePipelineName": r'PipelineName": "([^"]+)',
        "SecretsManagerSecret": r'SecretName": "([^"]+)',
        "WAFRuleId": r'RuleId": "([^"]+)',
        "WAFWebACL": r'WebACLName": "([^"]+)',
        "IAMPolicy": r'PolicyName": "([^"]+)',
        "IAMGroup": r'GroupName": "([^"]+)',
        # aws_key_data
        "IAMRoleARN": r'arn:aws:iam::(?:aws|\d{12}):role/([^"]+)',
        "IAMPolicyARN": r'arn:aws:iam::(?:aws|\d{12}):policy/([^"]+)'
    }

    # Dictionary to store the found resources
    aws_resources = {key: set() for key in patterns.keys()}  # Using set to avoid duplicates

    # Extract the resources
    for resource_type, pattern in patterns.items():
        matches = re.findall(pattern, output_content)
        aws_resources[resource_type].update(matches)  # Add items to the set, avoiding duplicates

    # Convert sets to lists for JSON serialization
    aws_resources = {key: list(values) for key, values in aws_resources.items()}

    # Generate the JSON file
    with open('pacu/reports/data/aws_resources.json', 'w') as json_file:
        json.dump(aws_resources, json_file, indent=4)

    print("JSON file 'aws_resources.json' successfully created.")

    # Close the database connection
    conn.close()
generate_report()
