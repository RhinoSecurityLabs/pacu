#!/usr/bin/env python3
from botocore.exceptions import ClientError

import argparse
import os
import json

from pacu.core.lib import strip_lines, save, session_dir
from pacu import Main

module_info = {
    'name': 'ecs__enum_task_def',
    'author': 'Nicholas Spagnola of Rhino Security Labs',
    'category': 'ENUM',
    'one_liner': 'Parses task definitions from ECS tasks',
    'description': 'This module will pull task definitions for ECS clusters.',
    'services': ['ECS'],
    'prerequisite_modules': ['ecs__enum'],
    'arguments_to_autocomplete': ['--task_definitions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--task_definitions', required=False, default=None, help=strip_lines('''
    A comma separated list of ECS task defintion ARNs 
    (arn:aws:ecs:us-east-1:273486424706:task-definition/first-run-task-definition:latest)
'''))


def main(args, pacu_main: 'Main'):
    session = session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print

    fetch_data = pacu_main.fetch_data
    ######

    task_definitions = []
    summary_data = {"task_definitions": 0}

    if args.task_definitions is not None:
        for task_def in args.task_definitions.split(','):
            task_definitions.append({
                'Task Defintion ID': task_def
            })
    else:
        if fetch_data(['ECS', 'TaskDefinitions'], module_info['prerequisite_modules'][0], '--taskdef') is False:
            print('Pre-req module not run successfully. Exiting...')
            return None
        task_definitions = session.ECS['TaskDefinitions']

    if task_definitions:
        print("Targeting {} task definition(s)...".format(len(task_definitions)))

        for task_def in task_definitions:
            region = task_def.split(':')[3]
            client = pacu_main.get_boto3_client('ecs', region)

            try:
                task_def_data = client.describe_task_definition(
                    taskDefinition=task_def,
                )
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'AccessDenied':
                    print('  Access denied to DescribeTaskDefinition.')
                    print('Skipping the rest of the task definitions...')
                    break
                else:
                    print('  ' + code)

            formatted_data = "{}@{}\n{}\n\n".format(
                task_def,
                region,
                json.dumps(task_def_data['taskDefinition'], indent=4, default=str)
            )

            with save('ecs_task_def_data/all_task_def.txt'.format(session.name), 'a+') as f:
                f.write(formatted_data)
            with save('ecs_task_def_data/{}.txt'.format(session.name, task_def.split('/')[1].split(':')[0])) as f:
                f.write(formatted_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
            summary_data['task_definitions'] += 1

    return summary_data


def summary(data, pacu_main):
    return (
        '  ECS Task Definition Data for {} task definition(s) was written to {}'
        '/downloads/ecs_task_def_data/'
    ).format(data['task_definitions'], session_dir())
