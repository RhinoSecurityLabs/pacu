#!/usr/bin/env python3
import argparse
import collections
import json
import os
import sys

import boto3

import principalmapper.common
from modules.iam__pivot.escalation import StsEscalationChecker
from modules.iam__pivot.graph import create_graph
from principalmapper.graphing import graph_actions
from principalmapper.querying.query_utils import get_search_list
from principalmapper.graphing import gathering
from principalmapper.common import Graph

module_info = {
    'name': 'pivot',
    'author': 'Ryan Gerstenkorn',
    'category': 'ESCALATE',
    'one_liner': 'Pivots current user based on IAM data.',
    'description': 'Updates aws_key info based on existing data found through other modules. Currently this looks for '
                   'roles that can be assumed and allows you to pivot to them for the current user.',
    'services': ['IAM'],
}

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=json.dumps(module_info['description']))
parser.add_argument('--rebuild-db', required=False, default=True, action='store_true',
                    help='Rebuild db used in this module, this will not affect other modules. This is needed to pick '
                         'up new or changed permissions.')


def main(args, pacu_main):
    args = parser.parse_args(args)
    session = pacu_main.get_active_session()
    print = pacu_main.print
    input = pacu_main.input
    aws_sess = pacu_main._get_boto3_session()

    permissions_data = pacu_main.fetch_data(None, 'iam__enum_permissions', [], force=True)
    if permissions_data is False:
        print('FAILURE')
        print('  SUB-MODULE EXECUTION FAILED')
        return

    iam_data = pacu_main.fetch_data(
        ['IAM'], 'iam__enum_users_roles_policies_groups', '--users --roles --policies --groups --instance-profiles'
    )
    if iam_data is False:
        print('FAILURE')
        print('  SUB-MODULE EXECUTION FAILED')
        return

    principalmapper.graphing.gathering.edge_identification.checker_map = checker_map

    graph_path = os.path.abspath("./sessions/{}/pmapper".format(session.name))
    os.makedirs(graph_path, 0o0700, True)
    if args.rebuild_db or not os.path.exists(graph_path):
        graph = create_graph(session, aws_session=aws_sess._session, service_list=['sts'], output=sys.stdout, debug=False)
        graph.store_graph_as_json(graph_path)
    else:
        graph = graph_actions.get_graph_from_disk(graph_path)

    source_node = get_current_node(graph, pacu_main.key_info())
    data = collections.OrderedDict()
    for edge_list in get_search_list(graph, source_node):
        data[edge_list[-1]] = edge_list

    if not data:
        return False

    target = ask_for_target(data, input, print)

    # TODO: construct summary from each target response
    for edge in data[target]:
        edge.run(pacu_main)

    return target.destination


checker_map = {
    'sts': StsEscalationChecker,
}


def summary(data, pacu_main):
    if not data:
        return "No assumable roles found"
    return "KeyAlias: {} RoleArn: {}".format(pacu_main.key_info()["KeyAlias"], data.arn)


def sess_from_h(user) -> boto3.session.Session:
    return boto3.session.Session(aws_access_key_id=user['AccessKeyId'], aws_secret_access_key=user['SecretAccessKey'],
                                 aws_session_token=user['SessionToken'])


def get_current_node(graph: Graph, user):
    if user["UserName"]:
        source_name = 'user/{}'.format(user["UserName"])
    elif user["RoleName"]:
        source_name = 'role/{}'.format(user["RoleName"])
    else:
        raise UserWarning("No current user or role found")

    return graph.get_node_by_searchable_name(source_name)


def ask_for_target(data, input, print):
    keys = list(data.keys())
    item = 1
    for target, edge_list in data.items():
        print("    ({}) {}".format(item, target.destination.searchable_name()))
        for edge in edge_list:
            print("          * {} -> {} -> {}".format(edge.source.arn, edge.reason, edge.destination.arn))
        print("          * {} is the target".format(edge.destination.arn))
        item += 1
    response = int(input("Choose role to assume: "))
    target = keys[response - 1]
    return target
