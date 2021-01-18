import json
import os
import subprocess
import sys
import urllib.parse
from typing import Any, List, Optional, Union

import boto3
import botocore
import botocore.config
import requests

from pacu.core.models import PacuSession
from pacu import io
from pacu.io import print
from settings import ROOT_DIR
from settings_template import ROOT_DIR


def get_regions(service, check_session=True) -> List[Optional[str]]:
    session = PacuSession.active_session()

    service = service.lower()

    with open('./modules/service_regions.json', 'r+') as regions_file:
        regions = json.load(regions_file)

    # TODO: Add an option for GovCloud regions

    if service == 'all':
        valid_regions = regions['all']
        if 'local' in valid_regions:
            valid_regions.remove('local')
        if 'af-south-1' in valid_regions:
            valid_regions.remove('af-south-1')  # Doesn't work currently
        if 'ap-east-1' in valid_regions:
            valid_regions.remove('ap-east-1')
        if 'eu-south-1' in valid_regions:
            valid_regions.remove('eu-south-1')
        if 'me-south-1' in valid_regions:
            valid_regions.remove('me-south-1')
    if type(regions[service]) == dict and regions[service].get('endpoints'):
        if 'aws-global' in regions[service]['endpoints']:
            return [None]
        if 'all' in session.session_regions:
            valid_regions = list(regions[service]['endpoints'].keys())
            if 'local' in valid_regions:
                valid_regions.remove('local')
            if 'af-south-1' in valid_regions:
                valid_regions.remove('af-south-1')
            if 'ap-east-1' in valid_regions:
                valid_regions.remove('ap-east-1')
            if 'eu-south-1' in valid_regions:
                valid_regions.remove('eu-south-1')
            if 'me-south-1' in valid_regions:
                valid_regions.remove('me-south-1')
            return valid_regions
        else:
            valid_regions = list(regions[service]['endpoints'].keys())
            if 'local' in valid_regions:
                valid_regions.remove('local')
            if 'af-south-1' in valid_regions:
                valid_regions.remove('af-south-1')
            if 'ap-east-1' in valid_regions:
                valid_regions.remove('ap-east-1')
            if 'eu-south-1' in valid_regions:
                valid_regions.remove('eu-south-1')
            if 'me-south-1' in valid_regions:
                valid_regions.remove('me-south-1')
            if check_session is True:
                return [region for region in valid_regions if region in session.session_regions]
            else:
                return valid_regions
    else:
        if 'aws-global' in regions[service]:
            return [None]
        if 'all' in session.session_regions:
            valid_regions = regions[service]
            if 'local' in valid_regions:
                valid_regions.remove('local')
            if 'af-south-1' in valid_regions:
                valid_regions.remove('af-south-1')
            if 'ap-east-1' in valid_regions:
                valid_regions.remove('ap-east-1')
            if 'eu-south-1' in valid_regions:
                valid_regions.remove('eu-south-1')
            if 'me-south-1' in valid_regions:
                valid_regions.remove('me-south-1')
            return valid_regions
        else:
            valid_regions = regions[service]
            if 'local' in valid_regions:
                valid_regions.remove('local')
            if 'af-south-1' in valid_regions:
                valid_regions.remove('af-south-1')
            if 'ap-east-1' in valid_regions:
                valid_regions.remove('ap-east-1')
            if 'eu-south-1' in valid_regions:
                valid_regions.remove('eu-south-1')
            if 'me-south-1' in valid_regions:
                valid_regions.remove('me-south-1')
            if check_session is True:
                return [region for region in valid_regions if region in session.session_regions]
            else:
                return valid_regions


def display_all_regions():
    for region in sorted(get_regions('all')):
        print('  {}'.format(region))


def validate_region(region) -> bool:
    if region in get_regions('all', check_session=False):
        return True
    return False


def get_boto3_client(service, region=None, user_agent=None, parameter_validation=True) -> Any:
    session: PacuSession = PacuSession.active_session()
    if (not session.key_alias.access_key_id) or (not session.key_alias.secret_access_key):
        print('  Both access key and secret access key need to be set. Failed to generate boto3 Client.')
        return

    # If there is not a custom user_agent passed into this function
    # and session.boto_user_agent is set, use that as the user agent
    # for this client. If both are set, the incoming user_agent will
    # override the session.boto_user_agent. If niether are set, it
    # will be None, and will default to the OS's regular user agent
    if session and session.boto_user_agent:
        user_agent = session.boto_user_agent

    boto_config = botocore.config.Config(  # type: ignore[attr-defined]
        user_agent=user_agent,  # If user_agent=None, botocore will use the real UA which is what we want
        parameter_validation=parameter_validation
    )

    return boto3.client(
        service,
        region_name=region,  # Whether region has a value or is None, it will work here
        aws_access_key_id=session.key_alias.access_key_id,
        aws_secret_access_key=session.key_alias.secret_access_key,
        aws_session_token=session.key_alias.session_token,
        config=boto_config
    )


def get_boto3_resource(service: str,
                       region: Union[str, None] = None,
                       user_agent: Union[str, None] = None,
                       parameter_validation: bool = True
                       ) -> Any:
    session = PacuSession.active_session()

    # All the comments from get_boto3_client apply here too
    if (not session.key_alias.access_key_id) or (not session.key_alias.secret_access_key):
        print('  Both access key and secret access key need to be set. Failed to generate boto3 Resource.')
        return

    if session and session.boto_user_agent:
        user_agent = session.boto_user_agent

    boto_config = botocore.config.Config(  # type: ignore[attr-defined]
        user_agent=user_agent,
        parameter_validation=parameter_validation
    )

    return boto3.resource(
        service,
        region_name=region,
        aws_access_key_id=session.key_alias.access_key_id,
        aws_secret_access_key=session.key_alias.secret_access_key,
        aws_session_token=session.key_alias.session_token,
        config=boto_config
    )


def print_web_console_url() -> None:
    active_session = PacuSession.active_session()

    if not active_session.key_alias.access_key_id:
        print('  No access key has been set. Not generating the URL.')
        return
    if not active_session.key_alias.secret_access_key:
        print('  No secret key has been set. Not generating the URL.')
        return

    sts = get_boto3_client('sts')

    if active_session.key_alias.session_token:
        # Roles cant use get_federation_token
        res = {
            'Credentials': {
                'AccessKeyId': active_session.key_alias.access_key_id,
                'SecretAccessKey': active_session.key_alias.secret_access_key,
                'SessionToken': active_session.key_alias.session_token
            }
        }
    else:
        res = sts.get_federation_token(  # type: ignore[attr-defined]
            Name=active_session.key_alias,
            Policy=json.dumps({
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }
                ]
            })
        )

    params = {
        'Action': 'getSigninToken',
        'Session': json.dumps({
            'sessionId': res['Credentials']['AccessKeyId'],
            'sessionKey': res['Credentials']['SecretAccessKey'],
            'sessionToken': res['Credentials']['SessionToken']
        })
    }

    fed_resp = requests.get(url='https://signin.aws.amazon.com/federation', params=params)

    signin_token = fed_resp.json()['SigninToken']

    params = {
        'Action': 'login',
        'Issuer': active_session.key_alias or '',
        'Destination': 'https://console.aws.amazon.com/console/home',
        'SigninToken': signin_token
    }

    url = 'https://signin.aws.amazon.com/federation?' + urllib.parse.urlencode(params)

    print('Paste the following URL into a web browser to login as session {}...\n'.format(active_session.name))

    print(url)


def get_boto3_session(region=None) -> Any:
    session = PacuSession.active_session()
    if not session.key_alias.access_key_id:
        print('  No access key has been set. Failed to generate boto3 Client.')
        return
    if not session.key_alias.secret_access_key:
        print('  No secret key has been set. Failed to generate boto3 Client.')
        return

    return boto3.session.Session(
        aws_access_key_id=session.key_alias.access_key_id,
        aws_secret_access_key=session.key_alias.secret_access_key,
        aws_session_token=session.key_alias.session_token,
        region_name=region
    )


def update_regions() -> None:
    py_executable = sys.executable
    # Update botocore to fetch the latest version of the AWS region_list

    cmd = [py_executable, '-m', 'pip', 'install', '--upgrade', 'botocore']
    try:
        print('  Fetching latest botocore...\n')
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print('"{}" returned {}'.format(' '.join(cmd), e.returncode))
        pip = io.input('Could not use pip3 or pip to update botocore to the latest version. Enter the name of '
                         'your pip binary to continue: ').strip()
        subprocess.run(['{}'.format(pip), 'install', '--upgrade', 'botocore'])

    path = ''

    try:
        print('  Using pip3 to locate botocore...\n')
        output = subprocess.check_output('{} -m pip show botocore'.format(py_executable), shell=True)
    except subprocess.CalledProcessError as e:
        print('Cmd: "{}" returned {}'.format(' '.join(cmd), e.returncode))
        path = io.input('Could not use pip to determine botocore\'s location. Enter the path to your Python '
                          '"dist-packages" folder (example: /usr/local/bin/python3.6/lib/dist-packages): ').strip()

    if path == '':
        # Account for Windows \r and \\ in file path (Windows)
        rows = output.decode('utf-8').replace('\r', '').replace('\\\\', '/').split('\n')
        for row in rows:
            if row.startswith('Location: '):
                path = row.split('Location: ')[1]

    with open('{}/botocore/data/endpoints.json'.format(path), 'r+') as regions_file:
        endpoints = json.load(regions_file)

    for partition in endpoints['partitions']:
        if partition['partition'] == 'aws':
            regions = dict()
            regions['all'] = list(partition['regions'].keys())
            for service in partition['services']:
                regions[service] = partition['services'][service]

    with open(os.path.join(ROOT_DIR, 'modules/service_regions.json'), 'w+') as services_file:
        json.dump(regions, services_file, default=str, sort_keys=True)

    print('  Region list updated to the latest version!')


