import argparse
import datetime
import os
import tempfile
import zipfile
from copy import deepcopy

from botocore.exceptions import ClientError
from pacu.core.secretfinder.utils import regex_checker, Color
from pacu.core.lib import save, downloads_dir

module_info = {
    'name': 'elasticbeanstalk__enum',
    'author': 'Tyler Ramsbey',
    'category': 'ENUM',
    'one_liner': 'Enumerates Elastic Beanstalk applications, environments, checks for secrets.',
    'description': (
        'Enumerates Elastic Beanstalk applications, environments, configuration settings, '
        'and tags, scanning for possible secrets in environment variables and source code. '
        'By default, this will not download the source code. To download the source code, '
        'use the --source flag.'
    ),
    'services': ['BeanStalk'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [
        '--regions',
        '--applications',
        '--environments',
        '--config',
        '--tags',
        '--source'
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
# New argument for downloading and scanning source code
parser.add_argument('--source', required=False, default=False, action='store_true',
    help='Download the source code of the deployed application and scan it for secrets.')

ARG_FIELD_MAPPER = {
    'applications': 'Applications',
    'environments': 'Environments',
    'config': 'ConfigurationSettings',
    'tags': 'Tags',
    'source': 'Source'
}


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    # Use "beanstalk" (lowercase) to get regions from the session configuration.
    get_regions = pacu_main.get_regions

    # If no flags are specified, enumerate everything except source code
    if not any([args.applications, args.environments, args.config, args.tags, args.source]):
        args.applications = args.environments = args.config = args.tags = True

    # Use "beanstalk" to get regions
    if args.regions is None:
        regions = get_regions('elasticbeanstalk')
        if not regions:
            print('No supported regions found for BeanStalk in this session. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    all_applications = []
    all_environments = []
    all_config_settings = []
    all_tags = []
    all_secrets = []  # Secrets found in config settings
    all_source_secrets = []  # Secrets discovered in source code

    for region in regions:
        region_apps = []
        region_envs = []
        region_cfgs = []
        region_tags = []
        region_secrets = []  # Secrets from configuration settings in this region
        region_source_secrets = []  # Secrets from source code in this region

        try:
            # Use the official AWS service name for boto3 client
            client = pacu_main.get_boto3_client('elasticbeanstalk', region)
        except Exception as e:
            print(f'Could not create BeanStalk client for {region}: {e}')
            continue

        if any([args.applications, args.environments, args.config, args.tags, args.source]):
            print(f'Enumerating BeanStalk data in region {region}...')

        # Applications
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

        # Environments
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

        # Configuration settings
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

            # Save discovered config secrets to file using "beanstalk" in the filename.
            if region_secrets:
                p = 'beanstalk_secrets_{}_{}.txt'.format(session.name, region)
                with save(p, 'w+') as f:
                    for secret in region_secrets:
                        f.write('{}: {}\n'.format(secret['OptionName'], secret['Value']))
                print(f'  {len(region_secrets)} potential secret(s) found in config settings and saved to: {str(downloads_dir())}/{p}')

        # Tags
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

        # Source Code Download and Scan
        if args.source:
            # For each environment, use its VersionLabel to retrieve source bundle info
            for env in region_envs:
                version_label = env.get('VersionLabel')
                if not version_label:
                    print(f"  Skipping {env['EnvironmentName']}: No VersionLabel found.")
                    continue
                app_name = env['ApplicationName']
                try:
                    ver_resp = client.describe_application_versions(
                        ApplicationName=app_name,
                        VersionLabels=[version_label]
                    )
                except ClientError as err:
                    print_failure_for_resource(err, f"DescribeApplicationVersions for {env['EnvironmentName']}")
                    continue
                app_versions = ver_resp.get('ApplicationVersions', [])
                if not app_versions:
                    print(f"  No application version info found for {env['EnvironmentName']} (version: {version_label}).")
                    continue
                # Assume the first matching version
                app_version = app_versions[0]
                source_bundle = app_version.get('SourceBundle', {})
                bucket = source_bundle.get('S3Bucket')
                key = source_bundle.get('S3Key')
                if not bucket or not key:
                    print(f"  No source bundle info for environment {env['EnvironmentName']}.")
                    continue

                # Build a filename similar to how secrets are saved
                download_filename = f'beanstalk_source_{session.name}_{env["EnvironmentName"]}_{version_label}.zip'
                # Construct the full download path (the save() function saves in ~/.local/share/pacu/{session.name}/downloads/)
                download_path = str(downloads_dir()/{download_filename})
                s3_client = pacu_main.get_boto3_client('s3', region)
                try:
                    s3_client.download_file(bucket, key, download_path)
                    print(f"  Source bundle for environment {env['EnvironmentName']} downloaded to: {download_path}")
                except ClientError as err:
                    print_failure_for_resource(err, f"Downloading source bundle for {env['EnvironmentName']}")
                    continue

                # Now scan the downloaded file for secrets
                found_source_secrets = []
                if zipfile.is_zipfile(download_path):
                    with zipfile.ZipFile(download_path, 'r') as zip_ref:
                        with tempfile.TemporaryDirectory() as tempdir:
                            zip_ref.extractall(tempdir)
                            # Walk through the extracted files
                            for root, _, files in os.walk(tempdir):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    try:
                                        with open(file_path, 'r', errors='ignore') as f:
                                            for i, line in enumerate(f, start=1):
                                                if regex_checker(line):
                                                    secret_info = f'{env["EnvironmentName"]} - {file_path} (line {i}): {line.strip()}'
                                                    found_source_secrets.append(secret_info)
                                    except Exception:
                                        continue
                else:
                    # Not a zip file; scan directly
                    try:
                        with open(download_path, 'r', errors='ignore') as f:
                            for i, line in enumerate(f, start=1):
                                if regex_checker(line):
                                    secret_info = f'{env["EnvironmentName"]} - {download_path} (line {i}): {line.strip()}'
                                    found_source_secrets.append(secret_info)
                    except Exception:
                        continue

                if found_source_secrets:
                    secrets_output_filename = f'beanstalk_source_secrets_{session.name}_{env["EnvironmentName"]}_{version_label}.txt'
                    with save(secrets_output_filename, 'w+') as f:
                        for secret in found_source_secrets:
                            f.write(secret + "\n")
                    print(f"  {len(found_source_secrets)} potential secret(s) found in source code for environment {env['EnvironmentName']}, saved to: {str(downloads_dir())}/{secrets_output_filename}")
                    region_source_secrets += found_source_secrets

        # Aggregate data for this region
        all_applications += region_apps
        all_environments += region_envs
        all_config_settings += region_cfgs
        all_tags += region_tags
        all_secrets += region_secrets
        all_source_secrets += region_source_secrets

    # Prepare final gathered data
    gathered_data = {
        'Applications': all_applications,
        'Environments': all_environments,
        'ConfigurationSettings': all_config_settings,
        'Tags': all_tags,
        'Secrets': all_secrets,
        'Source': all_source_secrets,
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
    bs_data = sanitize_for_json(bs_data)
    session.update(pacu_main.database, BeanStalk=bs_data)
    setattr(session, 'BeanStalk', bs_data)

    services = getattr(session, 'services', [])
    if 'BeanStalk' not in services:
        services.append('BeanStalk')
    session.update(pacu_main.database, services=services)
    setattr(session, 'services', services)

    if any([args.applications, args.environments, args.config, args.tags, args.source]):
        return gathered_data
    else:
        print('No BeanStalk data was successfully enumerated.\n')
        return None


def handle_eb_client_error(error, operation_name, print_func):
    code = error.response['Error']['Code']
    print_func(Color.RED + 'FAILURE:' + Color.ENDC)
    print_func(f'  {code}')
    print_func(f'  Skipping {operation_name} for this region. '
               'This may be due to the environment or configuration not being in a functioning state '
               'or missing required permissions.\n')


def print_failure_for_resource(error, resource_action):
    code = error.response["Error"]["Code"]
    print(Color.RED + 'FAILURE:' + Color.ENDC)
    print(f'  {code}')
    print(f'  Skipping {resource_action}. '
          'This environment may be in a broken or partial state, or you may lack necessary permissions.\n')


def scan_option_settings_for_secrets(option_settings, secrets):
    for option in option_settings:
        val = option.get('Value', '')
        if val and regex_checker(val):
            Color.print(
                Color.GREEN,
                f'\tPotential secret in environment variable: {option["OptionName"]} => {val}'
            )
            secrets.append({'OptionName': option['OptionName'], 'Value': val})


def summary(data, pacu_main):
    results = []

    if 'Applications' in data:
        results.append(f'    {len(data["Applications"])} total application(s) found.')
    if 'Environments' in data:
        results.append(f'    {len(data["Environments"])} total environment(s) found.')
    if 'ConfigurationSettings' in data:
        results.append(f'    {len(data["ConfigurationSettings"])} total configuration setting group(s) found.')
    if 'Tags' in data:
        results.append(f'    {len(data["Tags"])} environment(s) with tags enumerated.')
    if 'Secrets' in data:
        results.append(f'    {len(data["Secrets"])} potential secret(s) discovered in config settings.')
    if 'Source' in data:
        results.append(f'    {len(data["Source"])} potential secret(s) discovered in source code.')

    return '\n'.join(results)


def sanitize_for_json(obj):
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(item) for item in obj]
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj
