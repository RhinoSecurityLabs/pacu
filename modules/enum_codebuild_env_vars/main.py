#!/usr/bin/env python3
import argparse
import boto3
import botocore
from botocore.exceptions import ClientError
import os


module_info = {
    'name': 'enum_codebuild_env_vars',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'recon_enum_with_keys',
    'one_liner': 'Enumerates environment variables stored in CodeBuild to find sensitive data',
    'description': 'This module enumerates environment variables in all CodeBuild projects, with the goal of finding sensitive information like passwords, secrets, or API keys.',
    'services': ['CodeBuild'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    proxy_settings = pacu_main.get_proxy_settings()

    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
    install_dependencies = pacu_main.install_dependencies

    regions = get_regions('CodeBuild')

    for region in regions:
        print(f'Starting region {region}...')
        client = pacu_main.get_boto3_client('codebuild', region)

    print(f"{module_info['name']} completed.\n")
    return
