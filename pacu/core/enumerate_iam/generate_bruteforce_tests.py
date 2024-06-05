import re
import os
import json

OUTPUT_FMT = 'BRUTEFORCE_TESTS = %s'
OUTPUT_FILE = 'bruteforce_tests.py'

API_DEFINITIONS = 'aws-sdk-js/apis/'

OPERATION_CONTAINS = {
    'list_',
    'describe_',
    'get_',
}

BLACKLIST_OPERATIONS = {
    'get_apis',
    'get_bucket_notification',
    'get_bucket_notification_configuration',
    'list_web_ac_ls',
    'get_hls_streaming_session_url',
    'describe_scaling_plans',
    'list_certificate_authorities',
    'list_event_sources',
    'get_geo_location',
    'get_checker_ip_ranges',
    'list_geo_locations',
    'list_public_keys',

    # https://twitter.com/AndresRiancho/status/1106680434442809350
    'describe_stacks',
    'describe_service_errors',
    'describe_application_versions',
    'describe_applications',
    'describe_environments',
    'describe_events',
    'list_available_solution_stacks',
    'list_platform_versions',
}


def extract_service_name(filename, api_json):
    try:
        endpoint = api_json['metadata']['endpointPrefix']
    except:
        return None

    endpoint = endpoint.replace('api.', '')
    endpoint = endpoint.replace('opsworks-cm', 'opworks')
    endpoint = endpoint.replace('acm-pca', 'acm')

    return endpoint


def is_dangerous(operation_name):
    for safe in OPERATION_CONTAINS:
        if safe in operation_name:
            return False

    return True


def extract_operations(api_json):
    operations = []

    items = api_json['operations'].items()

    for operation_name, operation_data in items:
        operation_name = to_underscore(operation_name)

        if is_dangerous(operation_name):
            continue

        if operation_name in BLACKLIST_OPERATIONS:
            continue

        inputs = operation_data.get('input', None)

        if inputs is None:
            operations.append(operation_name)
            continue

        inputs = str(inputs)

        if "required" not in inputs:
            operations.append(operation_name)
            continue

    operations = list(set(operations))
    operations.sort()
    return operations


def to_underscore(name):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def main():
    bruteforce_tests = dict()

    for filename in os.listdir(API_DEFINITIONS):

        if not filename.endswith('.min.json'):
            continue

        api_json_data = open(os.path.join(API_DEFINITIONS, filename)).read()

        api_json = json.loads(api_json_data)

        service_name = extract_service_name(filename, api_json)

        if service_name is None:
            print('%s does not define a service name' % filename)
            continue

        operations = extract_operations(api_json)

        if not operations:
            continue

        if service_name in bruteforce_tests:
            bruteforce_tests[service_name].extend(operations)
        else:
            bruteforce_tests[service_name] = operations

    output = OUTPUT_FMT % json.dumps(bruteforce_tests,
                                     indent=4,
                                     sort_keys=True)

    open(OUTPUT_FILE, 'w').write(output)


if __name__ == '__main__':
    main()
