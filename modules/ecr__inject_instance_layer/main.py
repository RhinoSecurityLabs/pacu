#!/usr/bin/env python3
import argparse
import docker
from botocore.exceptions import ClientError
import base64
import subprocess32 as subprocess

module_info = {
    'name': 'my_module',
    'author': 'David Fentz',
    'category': 'EXPLOIT',
    'one_liner': 'Does this thing.',
    'description': 'This module does this thing by using xyz and outputs info to abc. Here is a note also.',
    'services': ['API.ECR'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

# The two add_argument calls are placeholders for arguments. Change as needed.
# Arguments that accept multiple options, such as --usernames, should be
# comma-separated. For example:
#     --usernames user_a,userb,UserC
# Arguments that are region-specific, such as --instance-ids, should use
# an @ symbol to separate the data and its region; for example:
#     --instance-ids 123@us-west-1,54252@us-east-1,9999@ap-south-1
# Make sure to add all arguments to module_info['arguments_to_autocomplete']
# parser.add_argument('', help='')
# parser.add_argument('', required=False, default=None, help='')

def check_ecr_enum_results():
    pass


def push_image(image, repo):
    pass


def wrap_image(base_image, wrapper_image):
    pass


def download_image(image_url):
    target = docker_client.images.pull(image_url)
    target_image = cli.get_image(target)
    with open(f"./{image_url}.tar", 'wb') as a_file:
        for chunk in target_image:
            a_file.write(chunk)
    


# Main is the first function that is called when this module is executed.
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    # These can be removed if you are not using the function.
    # args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
    # install_dependencies = pacu_main.install_dependencies
    user = key_info()
    print(user)
   # TODO: get results from enum_ecr

    # docker_client = docker.from_env()
    # docker_client.login()



    # this loads AWS access token and secret from env and returns an ECR client
    ecr_client = pacu_main.get_boto3_client('ecr', 'us-east-1')
    token = ecr_client.get_authorization_token()
    username, password = base64.b64decode(token['authorizationData'][0]['authorizationToken']).decode().split(':')
    registry = token['authorizationData'][0]['proxyEndpoint']
    # loggin in via the docker sdk doesnt work so we're gonna go with this workaround
    # command = 'docker login -u %s -p %s %s' % (username, password, registry)

    print(username)
    print(password)
    print(registry)



    p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True, bufsize=1)
    for line in iter(p.stdout.readline, b''):
        print(line)
    p.communicate()  # close p.stdout, wait for the subprocess to exit

    docker_client = docker.from_env()

    # download_image("187263833631.dkr.ecr.us-east-1.amazonaws.com/apline")
        
    # print(regions)
    # user = key_info()
    # print(f"user info looks like this: {user}")


    # Attempt to install the required external dependencies, exit this module
    # if the download/install fails
    # if not install_dependencies(module_info['external_dependencies']):
    #     return

    



    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    data = ""
    return data


# The summary function will be called by Pacu after running main, and will be
# passed the data returned from main. It should return a single string
# containing a curated summary of every significant thing that the module did,
# whether successful or not; or None if the module exited early and made no
# changes that warrant a summary being displayed. The data parameter can
# contain whatever data is needed in any structure desired. A length limit of
# 1000 characters is enforced on strings returned by module summary functions.
def summary(data, pacu_main):
    return str(data)
