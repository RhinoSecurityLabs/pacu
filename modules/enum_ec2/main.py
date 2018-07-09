#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
from random import choice


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_ec2_instances',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates a ton of relevant EC2 info.',

    # Description about what the module does and how it works
    'description': 'The module is used to enumerate the following EC2 data from a set of regions on an AWS account: instances, security groups, elastic IP addresses, VPN customer gateways, dedicated hosts, network ACLs, NAT gateways, network interfaces, route tables, subnets, VPCs, and VPC endpoints. By default, all data will be enumerated, but if any arguments are passed in indicating what data to enumerate, only that specific data will be enumerated.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [
        '--regions',
        '--instances',
        '--security-groups',
        '--elastic-ips',
        '--customer-gateways',
        '--dedicated-hosts',
        '--network-acls',
        '--nat-gateways',
        '--network-interfaces',
        '--route-tables',
        '--subnets',
        '--vpcs',
        '--vpc-endpoints',
    ],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('--instances', required=False, default=False, action='store_true', help='Enumerate EC2 instances')
parser.add_argument('--security-groups', required=False, default=False, action='store_true', help='Enumerate EC2 security groups')
parser.add_argument('--elastic-ips', required=False, default=False, action='store_true', help='Enumerate EC2 elastic IP addresses')
parser.add_argument('--customer-gateways', required=False, default=False, action='store_true', help='Enumerate EC2 VPN customer gateways')
parser.add_argument('--dedicated-hosts', required=False, default=False, action='store_true', help='Enumerate EC2 dedicated hosts')
parser.add_argument('--network-acls', required=False, default=False, action='store_true', help='Enumerate EC2 network ACLs')
parser.add_argument('--nat-gateways', required=False, default=False, action='store_true', help='Enumerate EC2 NAT gateways')
parser.add_argument('--network-interfaces', required=False, default=False, action='store_true', help='Enumerate EC2 network interfaces')
parser.add_argument('--route-tables', required=False, default=False, action='store_true', help='Enumerate EC2 route tables')
parser.add_argument('--subnets', required=False, default=False, action='store_true', help='Enumerate EC2 subnets')
parser.add_argument('--vpcs', required=False, default=False, action='store_true', help='Enumerate EC2 VPCs')
parser.add_argument('--vpc-endpoints', required=False, default=False, action='store_true', help='Enumerate EC2 VPC endpoints')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions

    all = False
    if args.instances is False and args.security_groups is False and args.elastic_ips is False and args.customer_gateways is False and args.dedicated_hosts is False and args.network_acls is False and args.nat_gateways is False and args.network_interfaces is False and args.route_tables is False and args.subnets is False and args.vpcs is False and args.vpc_endpoints is False:
        all = True

    if args.regions is None:
        regions = get_regions('ec2')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    client = pacu_main.get_boto3_client('ec2', choice(regions))

    # Check permissions before hammering through each region

    # Instances
    try:
        dryrun = client.describe_instances(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.instances = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_instances".\nSkipping instance enumeration.')
            return
    # Security Groups
    try:
        dryrun = client.describe_security_groups(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.security_groups = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_security_groups".\nSkipping security group enumeration.')
            return
    # Elastic IPs
    try:
        dryrun = client.describe_addresses(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.elastic_ips = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_addresses".\nSkipping elastic IP enumeration.')
            return
    # VPN Customer Gateways
    try:
        dryrun = client.describe_customer_gateways(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.customer_gateways = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_customer_gateways".\nSkipping VPN customer gateway enumeration.')
            return
    # Network ACLs
    try:
        dryrun = client.describe_network_acls(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.network_acls = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_network_acls".\nSkipping network ACL enumeration.')
            return
    # Network Interfaces
    try:
        dryrun = client.describe_network_interfaces(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.network_interfaces = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_network_interfaces".\nSkipping network interface enumeration.')
            return
    # Route Tables
    try:
        dryrun = client.describe_route_tables(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.route_tables = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_route_tables".\nSkipping route table enumeration.')
            return
    # Subnets
    try:
        dryrun = client.describe_subnets(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.subnets = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_subnets".\nSkipping subnet enumeration.')
            return
    # VPCs
    try:
        dryrun = client.describe_vpcs(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.vpcs = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_vpcs".\nSkipping VPC enumeration.')
            return
    # VPC Endpoints
    try:
        dryrun = client.describe_vpc_endpoints(
            DryRun=True
        )
    except ClientError as error:
        if not str(error).find('UnauthorizedOperation') == -1:
            all = False
            args.vpc_endpoints = False
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "describe_vpc_endpoints".\nSkipping VPC endpoint enumeration.')
            return

    all_instances = []
    all_security_groups = []
    all_elastic_ips = []
    all_vpn_customer_gateways = []
    all_dedicated_hosts = []
    all_network_acls = []
    all_nat_gateways = []
    all_network_interfaces = []
    all_route_tables = []
    all_subnets = []
    all_vpcs = []
    all_vpc_endpoints = []
    for region in regions:
        instances = []
        security_groups = []
        elastic_ips = []
        vpn_customer_gateways = []
        dedicated_hosts = []
        network_acls = []
        nat_gateways = []
        network_interfaces = []
        route_tables = []
        subnets = []
        vpcs = []
        vpc_endpoints = []

        print('Starting region {}...\n'.format(region))
        client = pacu_main.get_boto3_client('ec2', region)

        # Instances
        if args.instances is True or all is True:
            response = None
            next_token = False
            while (response is None or 'NextToken' in response):
                if next_token is False:
                    response = client.describe_instances(
                        MaxResults=1000  # To prevent timeouts if there are too many instances
                    )
                else:
                    response = client.describe_instances(
                        MaxResults=1000,
                        NextToken=next_token
                    )
                if 'NextToken' in response:
                    next_token = response['NextToken']
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        instance['Region'] = region
                        instances.append(instance)
            print(f'  {len(instances)} instance(s) found.')
            all_instances += instances

        # Security Groups
        if args.security_groups is True or all is True:
            response = None
            next_token = False
            while (response is None or 'NextToken' in response):
                if next_token is False:
                    response = client.describe_security_groups(
                        MaxResults=1000
                    )
                else:
                    response = client.describe_security_groups(
                        NextToken=next_token,
                        MaxResults=1000
                    )
                if 'NextToken' in response:
                    next_token = response['NextToken']
                for group in response['SecurityGroups']:
                    group['Region'] = region
                    security_groups.append(group)
            print(f'  {len(security_groups)} security groups(s) found.')
            all_security_groups += security_groups

        # Elastic IPs
        if args.elastic_ips is True or all is True:
            response = client.describe_addresses()
            for ip in response['Addresses']:
                ip['Region'] = region
                elastic_ips.append(ip)
            print(f'  {len(elastic_ips)} elastic IP address(es) found.')
            all_elastic_ips += elastic_ips

        # VPN Customer Gateways
        if args.customer_gateways is True or all is True:
            response = client.describe_customer_gateways()
            for gateway in response['CustomerGateways']:
                gateway['Region'] = region
                vpn_customer_gateways.append(gateway)
            print(f'  {len(vpn_customer_gateways)} VPN customer gateway(s) found.')
            all_vpn_customer_gateways += vpn_customer_gateways

        # Dedicated Hosts
        if args.dedicated_hosts is True or all is True:
            response = None
            next_token = False
            while (response is None or 'NextToken' in response):
                if next_token is False:
                    response = client.describe_hosts(
                        MaxResults=500
                    )
                else:
                    response = client.describe_hosts(
                        NextToken=next_token,
                        MaxResults=500
                    )
                if 'NextToken' in response:
                    next_token = response['NextToken']
                for host in response['Hosts']:
                    host['Region'] = region
                    dedicated_hosts.append(host)
            print(f'  {len(dedicated_hosts)} dedicated host(s) found.')
            all_dedicated_hosts += dedicated_hosts

        # Network ACLs
        if args.network_acls is True or all is True:
            response = client.describe_network_acls()
            for acl in response['NetworkAcls']:
                acl['Region'] = region
                network_acls.append(acl)
            print(f'  {len(network_acls)} network ACL(s) found.')
            all_network_acls += network_acls

        # NAT Gateways
        if args.nat_gateways is True or all is True:
            response = None
            next_token = False
            while (response is None or 'NextToken' in response):
                if next_token is False:
                    response = client.describe_nat_gateways(
                        MaxResults=1000
                    )
                else:
                    response = client.describe_nat_gateways(
                        NextToken=next_token,
                        MaxResults=1000
                    )
                if 'NextToken' in response:
                    next_token = response['NextToken']
                for gateway in response['NatGateways']:
                    gateway['Region'] = region
                    nat_gateways.append(gateway)
            print(f'  {len(nat_gateways)} NAT gateway(s) found.')
            all_nat_gateways += nat_gateways

        # Network Interfaces
        if args.network_interfaces is True or all is True:
            response = client.describe_network_interfaces()
            for interface in response['NetworkInterfaces']:
                interface['Region'] = region
                network_interfaces.append(interface)
            print(f'  {len(network_interfaces)} network interface(s) found.')
            all_network_interfaces += network_interfaces

        # Route Tables
        if args.route_tables is True or all is True:
            response = client.describe_route_tables()
            for table in response['RouteTables']:
                table['Region'] = region
                route_tables.append(table)
            print(f'  {len(route_tables)} route table(s) found.')
            all_route_tables += route_tables

        # Subnets
        if args.subnets is True or all is True:
            response = client.describe_subnets()
            for subnet in response['Subnets']:
                subnet['Region'] = region
                subnets.append(subnet)
            print(f'  {len(subnets)} subnet(s) found.')
            all_subnets += subnets

        # VPCs
        if args.vpcs is True or all is True:
            response = client.describe_vpcs()
            for vpc in response['Vpcs']:
                vpc['Region'] = region
                vpcs.append(vpc)
            print(f'  {len(vpcs)} VPC(s) found.')
            all_vpcs += vpcs

        # VPC Endpoints
        if args.vpc_endpoints is True or all is True:
            response = None
            next_token = False
            while (response is None or 'NextToken' in response):
                if next_token is False:
                    response = client.describe_vpc_endpoints(
                        MaxResults=1000
                    )
                else:
                    response = client.describe_vpc_endpoints(
                        NextToken=next_token,
                        MaxResults=1000
                    )
                if 'NextToken' in response:
                    next_token = response['NextToken']
                for endpoint in response['VpcEndpoints']:
                    endpoint['Region'] = region
                    vpc_endpoints.append(endpoint)
            print(f'  {len(vpc_endpoints)} VPC endpoint(s) found.')
            all_vpc_endpoints += vpc_endpoints

        print('')  # Break the line after each region. This isn't on the end of another print because they won't always be all used and isn't before the region print because it would double break lines at the beginning

    ec2_data = deepcopy(session.EC2)
    ec2_data['Instances'] = all_instances
    ec2_data['SecurityGroups'] = all_security_groups
    ec2_data['ElasticIPs'] = all_elastic_ips
    ec2_data['VPNCustomerGateways'] = all_vpn_customer_gateways
    ec2_data['DedicatedHosts'] = all_dedicated_hosts
    ec2_data['NetworkACLs'] = all_network_acls
    ec2_data['NATGateways'] = all_nat_gateways
    ec2_data['NetworkInterfaces'] = all_network_interfaces
    ec2_data['RouteTables'] = all_route_tables
    ec2_data['Subnets'] = all_subnets
    ec2_data['VPCs'] = all_vpcs
    ec2_data['VPCEndpoints'] = all_vpc_endpoints
    session.update(pacu_main.database, EC2=ec2_data)

    print(f'{len(all_instances)} total instance(s) found.')
    print(f'{len(all_security_groups)} total security group(s) found.')
    print(f'{len(all_elastic_ips)} total elastic IP address(es) found.')
    print(f'{len(all_vpn_customer_gateways)} total VPN customer gateway(s) found.')
    print(f'{len(all_dedicated_hosts)} total dedicated hosts(s) found.')
    print(f'{len(all_network_acls)} total network ACL(s) found.')
    print(f'{len(all_nat_gateways)} total NAT gateway(s) found.')
    print(f'{len(all_network_interfaces)} total network interface(s) found.')
    print(f'{len(all_route_tables)} total route table(s) found.')
    print(f'{len(all_subnets)} total subnets(s) found.')
    print(f'{len(all_vpcs)} total VPC(s) found.')
    print(f'{len(all_vpc_endpoints)} total VPC endpoint(s) found.')

    print('')  # Same line break as above

    print('All data has been saved to the current session.\n')
    print(f"{module_info['name']} completed.\n")
    return
