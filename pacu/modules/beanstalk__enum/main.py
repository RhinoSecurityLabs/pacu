#!/usr/bin/env python3
import argparse
import datetime
from copy import deepcopy

from botocore.exceptions import ClientError
from pacu.core.secretfinder.utils import regex_checker, Color
from pacu.core.lib import save

module_info = {
    'name': 'elasticbeanstalk__enum',
    'author': 'Your Name or Team',
    'category': 'ENUM',
    'one_liner': 'Enumerates Elastic Beanstalk applications, environments, checks for secrets.',
    'description': (
        'Enumerates Elastic Beanstalk applications, environments, configuration settings '
        'and tags, scanning for possible secrets in environment variables.'
    ),
    # Updated service name in module info.
    'services': ['BeanStalk'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
        '--regions',
        '--applications',
        '--environments',
        '--config',
        '--tags'
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None,
    help='Comma-separated AWS regions, e.g., "us-east-1". Defaults to all session regions.')
parser.add_argument('--applications', required=False, default=False, action='store_true',
    help='Enumerate EB applications.')
parser.add_argument('--environments', required=False, default=False, action='store_true',
    help='Enumerate EB environments for each application.')
parser.add_argument('--config', required=False, default=False, action='store_true',
    help='Enumerate configuration settings (including environment variables).')
parser.add_argument('--tags', required=False, default=False, action='store_true',
    help='Enumerate resource tags for environments.')

ARG_FIELD_MAPPER = {
    'applications': 'Applications',
    'environments': 'Environments',
    'config': 'ConfigurationSettings',
    'tags': 'Tags'
}


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    # Use "beanstalk" (lowercase) to get regions from the session configuration.
    get_regions = pacu_main.get_regions

    # If no flags are specified, enumerate everything
    if not any([args.applications, args.environments, args.config, args.tags]):
        args.applications = args.environments = args.config = args.tags = True

    # Use "beanstalk" to get regions
    if args.regions is None:
        regions = get_regions('beanstalk')
        if not regions:
            print('No supported regions found for BeanStalk in this session. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    all_applications = []
    all_environments = []
    all_config_settings = []
    all_tags = []
    all_secrets = []  # Collect secrets across regions

    for region in regions:
        region_apps = []
        region_envs = []
        region_cfgs = []
        region_tags = []
        region_secrets = []  # Secrets found in this region

        try:
            # Use the official AWS service name for boto3 client
            client = pacu_main.get_boto3_client('elasticbeanstalk', region)
        except Exception as e:
            print(f'Could not create BeanStalk client for {region}: {e}')
            continue

        if any([args.applications, args.environments, args.config, args.tags]):
            print(f'Enumerating BeanStalk data in region {region}...')

        # 1) Applications
        if args.applications:
            try:
                resp = client.describe_applications()
                apps = resp.get('Applications', [])
                for a in apps:
                    a['Region'] = region
                region_apps += apps
                print(f'  {len(apps)} application(s) found in {region}.')
            except ClientError as err:
                handle_eb_client_error(err, 'DescribeApplications', print)

        # 2) Environments
        if args.environments:
            # If we haven't enumerated apps yet, do so now
            if not region_apps and not args.applications:
                try:
                    resp = client.describe_applications()
                    region_apps = resp.get('Applications', [])
                except ClientError as err:
                    handle_eb_client_error(err, 'DescribeApplications', print)
                    region_apps = []

            for app in region_apps:
                try:
                    env_resp = client.describe_environments(ApplicationName=app['ApplicationName'])
                    envs = env_resp.get('Environments', [])
                    for e in envs:
                        e['Region'] = region
                        e['ApplicationName'] = app['ApplicationName']
                    region_envs += envs
                except ClientError as err:
                    handle_eb_client_error(err, 'DescribeEnvironments', print)

            if region_envs:
                print(f'  {len(region_envs)} environment(s) found in {region}.')
            else:
                print(f'  No environments found in {region}.')

        # 3) Configuration settings
        if args.config:
            if not region_envs and not args.environments:
                try:
                    resp = client.describe_environments()
                    region_envs = resp.get('Environments', [])
                except ClientError as err:
                    handle_eb_client_error(err, 'DescribeEnvironments', print)
                    region_envs = []

            for env in region_envs:
                try:
                    cfg_resp = client.describe_configuration_settings(
                        ApplicationName=env['ApplicationName'],
                        EnvironmentName=env['EnvironmentName']
                    )
                    cfgs = cfg_resp.get('ConfigurationSettings', [])
                    for c in cfgs:
                        c['Region'] = region
                        # Scan environment variables for secrets and collect them
                        os_list = c.get('OptionSettings', [])
                        scan_option_settings_for_secrets(os_list, region_secrets)
                    region_cfgs += cfgs

                except ClientError as err:
                    print_failure_for_resource(err, f"DescribeConfigurationSettings for {env['EnvironmentName']}")
                    continue

            if region_cfgs:
                print(f'  {len(region_cfgs)} configuration setting(s) found in {region}.')

            # Save discovered secrets to file using "beanstalk" in the filename.
            if region_secrets:
                p = 'beanstalk_secrets_{}_{}.txt'.format(session.name, region)
                with save(p, 'w+') as f:
                    for secret in region_secrets:
                        f.write('{}: {}\n'.format(secret['OptionName'], secret['Value']))
                print(f'  {len(region_secrets)} potential secret(s) found and saved to: ~/.local/share/pacu/{session.name}/downloads/{p}')

        # 4) Tags
        if args.tags:
            if not region_envs and not args.environments:
                try:
                    resp = client.describe_environments()
                    region_envs = resp.get('Environments', [])
                except ClientError as err:
                    handle_eb_client_error(err, 'DescribeEnvironments', print)
                    region_envs = []

            for env in region_envs:
                arn = env.get('EnvironmentArn')
                if not arn:
                    continue
                try:
                    tag_resp = client.list_tags_for_resource(ResourceArn=arn)
                    eb_tags = tag_resp.get('ResourceTags', [])
                    for t in eb_tags:
                        val = t.get('Value', '')
                        if val and regex_checker(val):
                            Color.print(Color.GREEN,
                                f'\tPossible secret in tag value "{val}" for environment {env["EnvironmentName"]}'
                            )
                    region_tags.append({
                        'EnvironmentArn': arn,
                        'EnvironmentName': env['EnvironmentName'],
                        'Region': region,
                        'Tags': eb_tags
                    })
                except ClientError as err:
                    print_failure_for_resource(err, f"ListTagsForResource for {env['EnvironmentName']}")
                    continue

            if region_tags:
                print(f'  {len(region_tags)} environment(s) with tags found in {region}.')

        # Aggregate data for this region
        all_applications += region_apps
        all_environments += region_envs
        all_config_settings += region_cfgs
        all_tags += region_tags
        all_secrets += region_secrets

    # Prepare final gathered data
    gathered_data = {
        'Applications': all_applications,
        'Environments': all_environments,
        'ConfigurationSettings': all_config_settings,
        'Tags': all_tags,
        'Secrets': all_secrets,
        'Regions': regions
    }
    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            if ARG_FIELD_MAPPER[var] in gathered_data:
                del gathered_data[ARG_FIELD_MAPPER[var]]

    # Update the session using the new service key "BeanStalk"
    bs_data = deepcopy(getattr(session, 'BeanStalk', {}))
    for key, value in gathered_data.items():
        bs_data[key] = value
    # Sanitize the data to convert any datetime objects to strings
    bs_data = sanitize_for_json(bs_data)
    session.update(pacu_main.database, BeanStalk=bs_data)
    setattr(session, 'BeanStalk', bs_data)

    # (Optional) Register "BeanStalk" in the session's services list so it shows in the "data" command.
    services = getattr(session, 'services', [])
    if 'BeanStalk' not in services:
        services.append('BeanStalk')
    session.update(pacu_main.database, services=services)
    setattr(session, 'services', services)

    # Return the gathered data so summary() can print final results.
    if any([args.applications, args.environments, args.config, args.tags]):
        return gathered_data
    else:
        print('No BeanStalk data was successfully enumerated.\n')
        return None


def handle_eb_client_error(error, operation_name, print_func):
    """
    Top-level calls (e.g. describing all apps in a region) => skip entire step but not the entire region.
    """
    code = error.response['Error']['Code']
    print_func(Color.RED + 'FAILURE:' + Color.ENDC)
    print_func(f'  {code}')
    print_func(f'  Skipping {operation_name} for this region. '
               'This may be due to the environment or configuration not being in a functioning state '
               'or missing required permissions.\n')


def print_failure_for_resource(error, resource_action):
    """
    Per-environment error => skip only that environment, continue enumerating others.
    Prints a user-friendly message indicating likely environment issues or partial config.
    """
    code = error.response["Error"]["Code"]
    print(Color.RED + 'FAILURE:' + Color.ENDC)
    print(f'  {code}')
    print(f'  Skipping {resource_action}. '
          'This environment may be in a broken or partial state, or you may lack necessary permissions.\n')


def scan_option_settings_for_secrets(option_settings, secrets):
    """
    Scans environment variable settings for possible secrets using regex_checker.
    Collects any discovered secrets in the provided secrets list.
    """
    for option in option_settings:
        val = option.get('Value', '')
        if val and regex_checker(val):
            Color.print(
                Color.GREEN,
                f'\tPotential secret in environment variable: {option["OptionName"]} => {val}'
            )
            secrets.append({'OptionName': option['OptionName'], 'Value': val})


def summary(data, pacu_main):
    """
    Summarize the results after the module completes.
    """
    print = pacu_main.print
    results = []
    regions = data.get('Regions', [])
    results.append('  Regions:')
    for region in regions:
        results.append(f'    {region}')

    if 'Applications' in data:
        results.append(f'    {len(data["Applications"])} total application(s) found.')
    if 'Environments' in data:
        results.append(f'    {len(data["Environments"])} total environment(s) found.')
    if 'ConfigurationSettings' in data:
        results.append(f'    {len(data["ConfigurationSettings"])} total configuration setting group(s) found.')
    if 'Tags' in data:
        results.append(f'    {len(data["Tags"])} environment(s) with tags enumerated.')
    if 'Secrets' in data:
        results.append(f'    {len(data["Secrets"])} potential secret(s) discovered.')

    return '\n'.join(results)


def sanitize_for_json(obj):
    """
    Recursively convert datetime objects to strings for JSON serialization.
    """
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(item) for item in obj]
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj
