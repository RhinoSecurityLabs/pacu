#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from copy import deepcopy


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_lateral_movement',

    # Name and any other notes about the author
    'author': 'Chris Farris <chris@room17.com>',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Looks for Network Plane lateral movement opportunities.',

    # Full description about what the module does and how it works
    'description': 'Looks for DirectConnect, VPN or VPC Peering to understand where you can go once you compromise an instance inside a VPC.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2', 'DirectConnect'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--versions-all'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--versions-all', required=False, default=False, action='store_true', help='Grab all versions instead of just the latest')


# For when "help module_name" is called, don't modify this
def help():
    return [module_info, parser.format_help()]


# Main is the first function that is called when this module is executed
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    ######

    regions = get_regions('DirectConnect')

    # Insert all VPCs into a dict indexed by ID for deduplication.
    vpcs_by_id = dict()
    for vpc in session.VPC:
        if 'VPC' in vpc.keys():
            vpcs_by_id[vpc['VPC']['VpcId']] = deepcopy(vpc)

    vpcs_found = 0
    vgw_assoc = {}
    for region in regions:
        print('Starting region {}...'.format(region))

        dx_client = pacu_main.get_boto3_client('directconnect', region)

        print("  Enumerating DirectConnect")
        try:
            gw_response = dx_client.describe_direct_connect_gateways()
            if 'directConnectGateways' in gw_response:
                for dx_gw in gw_response['directConnectGateways']:
                    dx_gw_id = dx_gw['directConnectGatewayId']
                    assoc_response = dx_client.describe_direct_connect_gateway_associations(directConnectGatewayId=dx_gw_id)
                    if 'directConnectGatewayAssociations' in assoc_response:
                        for dx_assoc in assoc_response['directConnectGatewayAssociations']:
                            vgw_id = dx_assoc['virtualGatewayId']
                            vgw_region = dx_assoc['virtualGatewayRegion']
                            # Apparently Direct Connects work across region. The Gateway can be in Virgina, but the VGW in Ohio.
                            vgw_attachment, vpc_data = get_vpc_by_vgw(pacu_main, vgw_id, vgw_region)
                            if vpc_data is not None:
                                vpc_id = vpc_data['VpcId']
                                # Ok, if we get here, we have a active DX VPC and opportunities for more exploration
                                # for analysis, we bundle up all the data, and key it off the VPC_ID
                                vpcs_by_id[vpc_id] = {}
                                vpcs_by_id[vpc_id]['VPC'] = vpc_data
                                vpcs_by_id[vpc_id]['VPC']['VGW'] = vgw_attachment
                                vpcs_by_id[vpc_id]['VPC']['DirectConnectAssociation'] = dx_assoc
                                vpcs_by_id[vpc_id]['VPC']['DirectConnectGateway'] = dx_gw
                                vpcs_found += 1
                                vgw_assoc[vgw_id] = vpc_data
        except ClientError as e:
            print("ClientError mapping DirectConnect to VPCs: {}".format(e))

        print("  Enumerating VPNs")
        # Now we look for VPN Connections
        ec2_client = pacu_main.get_boto3_client('ec2', region)
        vpn_response = ec2_client.describe_vpn_connections()
        if 'VpnConnections' in vpn_response:
            for vpn in vpn_response['VpnConnections']:
                vgw_id = vpn['VpnGatewayId']
                if vgw_id in vgw_assoc:
                    vpc_data = vgw_assoc[vgw_id]
                else:
                    vgw_attachment, vpc_data = get_vpc_by_vgw(pacu_main, vgw_id, region)
                if vpc_data is not None:
                    vpc_id = vpc_data['VpcId']
                    if vpc_id not in vpcs_by_id:
                        vpcs_by_id[vpc_id] = {}
                    vpcs_by_id[vpc_id]['VPC'] = vpc_data
                    vpcs_by_id[vpc_id]['VPC']['VPN'] = vpn
                    vpcs_by_id[vpc_id]['VPC']['VGW'] = vgw_attachment
                    vpcs_found += 1

        print("  Enumerating Peering")
        # And now VPC Peering
        pcx_response = ec2_client.describe_vpc_peering_connections()
        if 'VpcPeeringConnections' in pcx_response:
            for pcx in pcx_response['VpcPeeringConnections']:
                if pcx['AccepterVpcInfo']['VpcId'] not in vpcs_by_id:
                    vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']] = {}
                    # Go get the VPC data and put into results
                    vpc_data = get_vpc_by_id(pacu_main, pcx['AccepterVpcInfo']['VpcId'], pcx['AccepterVpcInfo']['Region'])
                    if vpc_data is not None:
                        vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']]['VPC'] = vpc_data
                        vpcs_found += 1
                    else:
                        vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']]['VPC'] = {'VpcId': pcx['AccepterVpcInfo']['VpcId']}
                vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']]['VPC']['Peering'] = pcx

                if pcx['RequesterVpcInfo']['VpcId'] not in vpcs_by_id:
                    vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']] = {}
                    # Go get the VPC data and put into results
                    vpc_data = get_vpc_by_id(pacu_main, pcx['RequesterVpcInfo']['VpcId'], pcx['RequesterVpcInfo']['Region'])
                    if vpc_data is not None:
                        vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']]['VPC'] = vpc_data
                        vpcs_found += 1
                    else:
                        vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']]['VPC'] = {'VpcId': pcx['RequesterVpcInfo']['VpcId']}
                vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']]['VPC']['Peering'] = pcx

    updated_dx_vpcs = list(vpcs_by_id.values())
    session.update(pacu_main.database, VPC=updated_dx_vpcs)

    summary_data = {
        'vpcs_found': vpcs_found,
        'updated_dx_vpcs': updated_dx_vpcs
    }
    print('{} completed.\n'.format(module_info['name']))
    return summary_data


def summary(data, pacu_main):
    out = '  {} VPCs were found and updated.\n'.format(data.get('vpcs_found', 0))
    out += '  {} VPCs are now known.'.format(len(data.get('updated_dx_vpcs', [])))
    return out


def get_vpc_by_vgw(pacu_main, vgw_id, vgw_region):
    ec2_client = pacu_main.get_boto3_client('ec2', vgw_region)
    vgw_response = ec2_client.describe_vpn_gateways(VpnGatewayIds=[vgw_id])
    if 'VpnGateways' in vgw_response and len(vgw_response['VpnGateways']) > 0:
        for vgw_attachment in vgw_response['VpnGateways'][0]['VpcAttachments']:
            vpc_id = vgw_attachment['VpcId']
            vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
            return(vgw_attachment, vpc_response['Vpcs'][0])


def get_vpc_by_id(pacu_main, vpc_id, region):
    try:
        ec2_client = pacu_main.get_boto3_client('ec2', region)
        vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        return(vpc_response['Vpcs'][0])
    except ClientError as e:
        print("Cannot find {} in {} for this account: {}".format(vpc_id, region, e))
        return(None)
