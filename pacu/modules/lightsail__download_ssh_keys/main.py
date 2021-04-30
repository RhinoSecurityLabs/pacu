#!/usr/bin/env python3
import argparse
from pathlib import Path

from pacu.core.lib import downloads_dir
from pacu import Main

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'lightsail__download_ssh_keys',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'EXPLOIT',

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


def main(args, pacu_main: 'Main'):
    ###### Don't modify these. They can be removed if you are not using the function.
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######
    summary_data = {'region_key_pairs': []}
    regions = get_regions('lightsail')

    summary_data['dl_path'] = str(downloads_dir())
    for region in regions:
        print('  Downloading default keys for {}...'.format(region))
        cur_path = downloads_dir()/region
        if not cur_path.exists():
            cur_path.mkdir()
        client = pacu_main.get_boto3_client('lightsail', region)
        downloaded_keys = client.download_default_key_pair()
        restructured_keys = {
            'publicKey': downloaded_keys['publicKeyBase64'],
            'privateKey': downloaded_keys['privateKeyBase64']
        }

        private_path = cur_path / 'default'
        with private_path.open('w', encoding='utf-8') as key_file:
            key_file.write(restructured_keys['privateKey'])
        public_path = cur_path / 'default.pub'
        with public_path.open('w', encoding='utf-8') as key_file:
            key_file.write(restructured_keys['publicKey'])

        summary_data['region_key_pairs'].append(region)
    return summary_data


def summary(data, pacu_main):
    out = '  Keys downloaded to:\n'
    out += '    ' + data['dl_path'] + '\n'
    out += '  Downloaded Key Pairs for the following regions: \n'
    for region in sorted(data['region_key_pairs']):
        out += '    {}\n'.format(region)
    return out
