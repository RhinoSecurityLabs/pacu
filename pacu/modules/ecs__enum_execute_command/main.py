import argparse
from botocore.exceptions import ClientError

module_info = {
    'name': 'ecs__enum_execute_command',
    'author': 'Jisoo Kim (TF) @tf-nat of Ajou University',
    'category': 'ENUM',
    'one_liner': 'Enumerate ECS tasks with ExecuteCommandAgent enabled.',
    'description': (
        'Finds ECS containers with ExecuteCommandAgent running, '
        'indicating ecs:ExecuteCommand may be possible.'
    ),
    'services': ['ECS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(
    add_help=False,
    description=module_info['description']
)


def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    regions = get_regions('ecs')

    results = []

    for region in regions:
        print('Starting region {}...'.format(region))
        client = pacu_main.get_boto3_client('ecs', region)

        try:
            response = client.list_clusters()
        except ClientError as e:
            print('FAILURE: {}'.format(e.response['Error']['Code']))
            continue

        clusters = response['clusterArns']

        for cluster in clusters:
            try:
                response = client.list_tasks(cluster=cluster)
            except ClientError as e:
                print('FAILURE: {}'.format(e.response['Error']['Code']))
                continue

            tasks = response['taskArns']
            if not tasks:
                continue

            try:
                detail = client.describe_tasks(cluster=cluster, tasks=tasks)
            except ClientError as e:
                print('FAILURE: {}'.format(e.response['Error']['Code']))
                continue

            for task in detail['tasks']:
                for container in task.get('containers', []):
                    agents = container.get('managedAgents', [])

                    for agent in agents:
                        if agent['name'] == 'ExecuteCommandAgent':
                            print(
                                f"[+] Found! cluster: {cluster}, "
                                f"container: {container['name']}"
                            )
                            task_id = task['taskArn'].split('/')[-1]
                            cmd = (
                                f"    aws ecs execute-command "
                                f"--cluster {cluster} "
                                f"--task {task_id} "
                                f"--container {container['name']} "
                                f"--interactive --command /bin/sh"
                            )
                            print(cmd)
                            results.append({
                                'cluster': cluster,
                                'task': task['taskArn'],
                                'container': container['name'],
                                'region': region,
                            })

    return results


def summary(data, pacu_main):
    if not data:
        return 'No ECS containers with ExecuteCommandAgent found.'
    return '{} container(s) with ExecuteCommandAgent found.'.format(len(data))
