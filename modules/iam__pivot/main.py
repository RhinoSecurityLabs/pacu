#!/usr/bin/env python3
import argparse
import collections

import boto3
from principalmapper.common import Graph
from principalmapper.graphing import graph_actions
from principalmapper.querying.query_utils import get_search_list

module_info = {
    'name': 'iam_pivot',
    'author': 'Ryan Gerstenkorn',
    'category': 'ESCALATE',
    'one_liner': 'Pivots current user based on IAM data.',
    'description': 'Updates aws_key info based on existing data found through other modules. Currently this looks for '
                   'roles that can be assumed and allows you to pivot to them for the current user.',
    'services': ['IAM'],
    'prerequisite_modules': ['iam_enum_permissions'],
    'arguments_to_autocomplete': ['--rebuild-db'],
}

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--rebuild-db', required=False, default=False, action='store_true',
                    help='Rebuild db used in this module, this will not affect other modules. This is needed to pick '
                         'up new or changed permissions.')


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info

    user = key_info()



    if pacu_main.fetch_data(['IAM'], 'iam_enum_permissions', '') is False:
        print('Pre-req module not run successfully. Continuing anyways')


    root = 'sessions/{}/pmmapper'.format(session.name)
    sess = pacu_main._get_boto3_session()


    graph = get_graph(sess, root, args.rebuild_db)

    if user["UserName"]:
        source_name = 'user/{}'.format(user["UserName"])
    elif user["RoleName"]:
        source_name = 'role/{}'.format(user["RoleName"])
    else:
        raise UserWarning("No current user or role found, you can try rebuilding the db with --rebuild-db to pick up " \
                          "new IAM resources or use swap_keys to try with a different user.")

    source_node = graph.get_node_by_searchable_name(source_name)
    if not source_node:
        raise UserWarning("could not find current user")

    data = collections.OrderedDict()
    for edge_list in get_search_list(graph, source_node):
        data[edge_list[-1]] = edge_list

    if not data:
        return False

    target = ask_for_target(data, input, print)

    for edge in data[target]:
        print("Assuming Role: " + edge.destination.arn)
        creds = sess.client('sts').assume_role(RoleArn=edge.destination.arn, RoleSessionName="pacu")['Credentials']
        sess = sess_from_h(creds)
        pacu_main.set_keys(edge.destination.searchable_name(), creds['AccessKeyId'], creds['SecretAccessKey'],
                           creds['SessionToken'])

    return target.destination


def summary(data, pacu_main):
    if not data:
        return "No assumable roles found"
    return "KeyAlias: {} RoleArn: {}".format(pacu_main.key_info()["KeyAlias"], data.arn)


def sess_from_h(user) -> boto3.session.Session:
    return boto3.session.Session(aws_access_key_id=user['AccessKeyId'], aws_secret_access_key=user['SecretAccessKey'],
                                 aws_session_token=user['SessionToken'])

def get_graph(sess, root, rebuild: bool = False):
    if rebuild:
        graph = rebuild_db(sess, root)
    else:
        try:
            graph = graph_actions.get_graph_from_disk(root)
        except ValueError:
            rebuild_db(sess, root)
            graph = graph_actions.get_graph_from_disk(root)
    return graph

def rebuild_db(sess, root) -> Graph:
    graph = graph_actions.create_new_graph(sess._session, ['sts'])
    graph.store_graph_as_json(root)
    return graph

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
