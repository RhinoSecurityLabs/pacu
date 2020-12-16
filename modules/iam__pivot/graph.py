import io
import os

import botocore.session
import principalmapper
from core.models import PacuSession
from principalmapper.common import Node, Group, Policy, Graph
from principalmapper.graphing import edge_identification, gathering
from principalmapper.querying import query_interface
from principalmapper.util import arns
from principalmapper.util.debug_print import dprint
from typing import List, Optional, TextIO


def create_graph(session: PacuSession, aws_session: botocore.session.Session, service_list: list, output: TextIO = open(os.devnull),
                 debug=False) -> Graph:
    """Constructs a Graph object.

    Information about the graph as it's built will be written to the IO parameter `output`.
    """
    stsclient = aws_session.create_client('sts')
    caller_identity = stsclient.get_caller_identity()
    dprint(debug, "Caller Identity: {}".format(caller_identity['Arn']))
    metadata = {
        'account_id': caller_identity['Account'],
        'pmapper_version': principalmapper.__version__
    }

    iamclient = aws_session.create_client('iam')

    # Gather users and roles, generating a Node per user and per role
    nodes_result = get_unfilled_nodes(session, iamclient, output, debug)

    # Gather groups from current list of nodes (users), generate Group objects, attach to nodes in-flight
    groups_result = get_unfilled_groups(session, iamclient, nodes_result, output, debug)

    # Resolve all policies, generate Policy objects, attach to all groups and nodes
    policies_result = gathering.get_policies_and_fill_out(iamclient, nodes_result, groups_result, output, debug)

    # Determine which nodes are admins and update node objects
    gathering.update_admin_status(nodes_result, output, debug)

    # Generate edges, generate Edge objects
    edges_result = edge_identification.obtain_edges(aws_session, service_list, nodes_result, output, debug)

    return Graph(nodes_result, edges_result, policies_result, groups_result, metadata)


def get_unfilled_nodes(session: PacuSession, iamclient, output: io.StringIO = os.devnull, debug=False) -> List[Node]:
    """Using an IAM.Client object, return a list of Node object for each IAM user and role in an account.

    Does not set Group or Policy objects. Those have to be filled in later.

    Writes high-level information on progress to the output file
    """
    result = []
    # Get users, paginating results, still need to handle policies + group memberships + is_admin
    output.write("Obtaining IAM users in account\n")
    for user in session.IAM["Users"]:
        result.append(Node(
            arn=user['Arn'],
            id_value=user['UserId'],
            attached_policies=[],
            group_memberships=[],
            trust_policy=None,
            instance_profile=None,
            num_access_keys=0,
            active_password='PasswordLastUsed' in user,
            is_admin=False
        ))
        dprint(debug, 'Adding Node for user ' + user['Arn'])

    # Get roles, paginating results, still need to handle policies + is_admin
    output.write("Obtaining IAM roles in account\n")
    for role in session.IAM['Roles']:
        result.append(Node(
            arn=role['Arn'],
            id_value=role['RoleId'],
            attached_policies=[],
            group_memberships=[],
            trust_policy=role['AssumeRolePolicyDocument'],
            instance_profile=None,
            num_access_keys=0,
            active_password=False,
            is_admin=False
        ))

    try:
        # Get instance profiles, paginating results, and attach to roles as appropriate
        output.write("Obtaining EC2 instance profiles in account\n")
        for iprofile in session.IAM['InstanceProfiles']:
            iprofile_arn = iprofile['Arn']
            role_arns = []
            for role in iprofile['Roles']:
                role_arns.append(role['Arn'])
            for node in result:
                if ':role/' in node.arn and node.arn in role_arns:
                    node.instance_profile = iprofile_arn
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            output.write("Access denied for ListInstanceProfiles.. continuing anyways\n")
        else:
            raise e

    try:
        # Handle access keys
        output.write("Obtaining Access Keys data for IAM users\n")
        for node in result:
            if arns.get_resource(node.arn).startswith('user/'):
                # Grab access-key count and update node
                user_name = arns.get_resource(node.arn)[5:]
                if '/' in user_name:
                    user_name = user_name.split('/')[-1]
                    dprint(debug, 'removed path from username {}'.format(user_name))
                access_keys_data = iamclient.list_access_keys(UserName=user_name)
                node.access_keys = len(access_keys_data['AccessKeyMetadata'])
                dprint(debug, 'Access Key Count for {}: {}'.format(user_name, len(access_keys_data['AccessKeyMetadata'])))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            output.write("Access denied for ListAccessKeys.. continuing anyways\n")
        else:
            raise e

    return result


def get_unfilled_groups(session, iamclient, nodes: List[Node], output: io.StringIO = os.devnull, debug=False) -> List[Group]:
    """Using an IAM.Client object, returns a list of Group objects. Adds to each passed Node's group_memberships
    property.

    Does not set Policy objects. Those have to be filled in later.

    Writes high-level progress information to parameter output
    """
    result = []

    # paginate through groups and build result
    output.write("Obtaining IAM groups in the account.\n")
    for group in session.IAM['Groups']:
        result.append(Group(
            arn=group['Arn'],
            attached_policies=[]
        ))

    # loop through group memberships
    output.write("Connecting IAM users to their groups.\n")
    for node in nodes:
        if not arns.get_resource(node.arn).startswith('user/'):
            continue  # skip when not an IAM user
        dprint(debug, 'finding groups for user {}'.format(node.arn))
        user_name = arns.get_resource(node.arn)[5:]
        if '/' in user_name:
            user_name = user_name.split('/')[-1]
            dprint(debug, 'removed path from username {}'.format(user_name))
        group_list = iamclient.list_groups_for_user(UserName=user_name)
        for group in group_list['Groups']:
            for group_obj in result:
                if group['Arn'] == group_obj.arn:
                    node.group_memberships.append(group_obj)

    return result

