import argparse
from botocore.exceptions import ClientError
import json, os, datetime
from json import JSONEncoder

from pacu.core.lib import downloads_dir, strip_lines
from pacu.core.secretfinder.utils import regex_checker, Color

module_info = {
    'name': 'cloudformation__download_data',
    'author': 'David Yesland',
    'category': 'ENUM',
    'one_liner': 'Downloads all templates, parameters, and exports from CloudFormation Stacks.',
    'description': strip_lines('''
        Downloads all templates, parameters, and exports from CloudFormation Stacks. Looks for secrets in all and saves data
        to files.
    '''),
    'services': [
        'cloudformation'
    ],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': []
}

parser = argparse.ArgumentParser(add_help=False, description=(module_info['description']))

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format '
                                                                    'us-east-1. Defaults to all regions.')

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    regions = get_regions('cloudformation')

    def find_secrets(string):
        detections = regex_checker(string)
        [Color.print(Color.GREEN, '\tDetected {}: {}'.format(itemkey, detections[itemkey])) for itemkey in detections]

    def outfile(subdir, filename):
        base_path = downloads_dir()/f"{module_info['name']}/{subdir}/"
        if not os.path.exists(base_path):
            os.makedirs(base_path)
        return open(base_path/filename, 'a+')

    class DateTimeEncoder(JSONEncoder):

        def default(self, obj):
            if isinstance(obj, (datetime.date, datetime.datetime)):
                return obj.isoformat()

    all_stacks = []
    found_regions = []
    for region in regions:
        client = pacu_main.get_boto3_client('cloudformation', region)
        print('Looking for CloudFormation Stacks in region {}...'.format(region))
        stacks_data = client.describe_stacks()
        stacks = stacks_data['Stacks']
        all_stacks += stacks

        if stacks_data['Stacks']:
            print('Getting exports for region: {}'.format(region))
            exports = client.list_exports()
            if exports:
                with outfile('exports', region) as (f):
                    json.dump(exports, f, indent=1)
                find_secrets(json.dumps(exports))
        while 'NextToken' in stacks_data:
            stacks_data = client.describe_stacks(NextToken=(stacks_data['NextToken']))
            stacks += stacks_data['Stacks']

        if stacks_data['Stacks']:
            found_regions.append(region)
            for stack in stacks:
                with outfile('stacks/{}'.format(region), stack['StackId'].replace('/', '-')) as (f):
                    json.dump(stack, f, indent=1, cls=DateTimeEncoder)
                print('Getting template for stack: {}'.format(stack['StackId']))
                find_secrets(json.dumps(stack, cls=DateTimeEncoder))
                try:
                    templates = client.get_template(StackName=(stack['StackId']))
                    with outfile('templates/{}'.format(region), stack['StackId'].replace('/', '-')) as (f):
                        json.dump(templates, f, indent=1)
                except:
                    continue

                find_secrets(json.dumps(templates))

        stacks_data = {}

    return {
        'region_count': len(found_regions),
        'stack_count': len(all_stacks),
        'output_path': downloads_dir()/f"{module_info['name']}/*",
    }


def summary(data, pacu_main):
    number_of_parameters = 0
    if data.keys():
        return 'Downloaded data from {} CloudFormation stacks, from {} region(s).\n        Saved to: {}'.format(
            data['stack_count'], data['region_count'], data['output_path'])
    else:
        return 'No CloudFormation stacks found.'
