#!/usr/bin/env python3
import argparse
from copy import deepcopy
from botocore.exceptions import ClientError

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_waf',

    # Name and any other notes about the author
    'author': 'Alexander Morgenstern alexander.morgenstern@rhinosecuritylabs.com',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'logging_monitoring',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Detects rules and rule groups for WAF.',

    # Description about what the module does and how it works
    'description': 'This module will enumerate WAF.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['waf',],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

METHODS = [
            #('activated_rules_in_rule_group', 'ActivatedRules'),
            ('byte_match_sets', 'ByteMatchSets'),
            ('geo_match_sets', 'GeoMatchSets'),
            ('ip_sets', 'IPSets'),
            ('rate_based_rules', 'Rules'),
            ('regex_match_sets', 'RegexMatchSets'),
            ('regex_pattern_sets', 'RegexPatternSets'),
            ('rule_groups', 'RuleGroups'),
            ('rules', 'Rules'),
            ('size_constraint_sets', 'SizeConstraintSets'),
            ('sql_injection_match_sets', 'SqlInjectionMatchSets'),
            #('subscribed_rule_groups', 'RuleGroups'),
            ('web_acls', 'WebACLs'),
            ('xss_match_sets', 'XssMatchSets'),
        ]


def grab_data(client, function, key):
    out = []
    caller = getattr(client, function)
    response = caller()
    out.extend(response[key])
    while 'NextMarker' in response:
        response = caller(NextMarker=response['NextMarker'])
        out.extend(response[key])
    print('   Found {} {}'.format(len(out), key))
    return out

def grab_id_data(client, func, param):
    caller = getattr(client, func)
    response = caller(**param)
    del response['ResponseMetadata']
    # Pull out the actual fields from the response and return them.
    for key in response:
        return response[key]
    return {}


def consistentCase(name):
    splitted = name.split('_')
    out = ''.join([word[0].upper() + word[1:] for word in splitted])
    return out

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    regions = get_regions('waf-regional') if args.regions is None else args.regions.split(',')
    waf_regional_data = {}
    waf_global_data = {}
    for key, val in METHODS:
        waf_regional_data[val] = []
        waf_global_data[val] = []
    for region in regions:
        print('  Staring enumeration of region: {}...'.format(region))
        client = pacu_main.get_boto3_client('waf-regional', region)   
        for func, key in METHODS:
            items = grab_data(client, 'list_' + func, key)
            for index, item in enumerate(items):
                param_key = key[:-1] + 'Id'
                param = {param_key: item[param_key]}
                new_data = grab_id_data(client, 'get_' + func[:-1], param)
                new_data['region'] = region
                items[index] = new_data
            waf_regional_data[key].extend(items)

    if args.regions is None:
        client = pacu_main.get_boto3_client('waf')
        print('  Starting enumeration for global WAF...')
        for func, key in METHODS:
            items = grab_data(client, 'list_' + func, key)
            for index, item in enumerate(items):
                param_key = key[:-1] + 'Id'
                param = {param_key: item[param_key]}
                new_data = grab_id_data(client, 'get_' + func[:-1], param)
                new_data['region'] = region
                items[index] = new_data
            waf_global_data[key].extend(items)

    print(waf_regional_data)
    print(waf_global_data)

    print('{} completed.\n'.format(module_info['name']))
    summary_data = {}
    return summary_data


def summary(data, pacu_main):
    out = ''
    return out