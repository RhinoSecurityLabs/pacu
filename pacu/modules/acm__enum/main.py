#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import copy
import string
import random
import json
import time

from pacu.core.lib import downloads_dir

module_info = {
    'name': 'acm__enum',
    'author': 'Manas Bellani',
    'category': 'ENUM',
    'one_liner': 'Enumerate Information about the AWS Certificate Manager',
    'description': 'This module is used to list and get information about ACM certificates, list expired certificates, and get info about private CAs which can generate certs. Expired certificates can provide an opportunity for takeover if domain has expired OR can be abused for client interaction as well. All certs, cert chains, CAs discovered is written to \"downloads\" folder in relevant \'sessions\' folder',
    'services': ['ACM'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions', '--all', '--certs-list', '--certs-chain',
        '--certs-info', '--certs-expired-list', '--ca-list'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', required=False, default='all',
    help='Regions to enumerate ACM in (defaults to "all" session regions)')
parser.add_argument('--all', action='store_true', help="Get all info from ACM")
parser.add_argument('--certs-list',  action="store_true",
    help="Get list about all certs")
parser.add_argument('--certs-info',  action="store_true",
    help="Get info about each certificate")
parser.add_argument('--certs-chain',  action="store_true",
    help="Get certs and the certificate chain as well")
parser.add_argument('--certs-expired-list', action='store_true',
    help="List expired certificates which could potentially be taken over")
parser.add_argument('--ca-list', action='store_true',
    help="List private certificate authorities created within ACM")


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions

    data = {'num_certs': 0, 'certs': {}, 'certs_info': {}, 'certs_chain': {},
            'num_cas': 0, 'cas': {},
            'num_certs_expired': 0, 'certs_expired': {}}

    # Get the regions to check
    if args.regions == "all":
        regions = get_regions('all')
    else:
        regions = args.regions.split(',')

    for region in regions:

        # Get the ACM client for the region
        client = pacu_main.get_boto3_client('acm', region)
        ca_client = pacu_main.get_boto3_client('acm-pca', region)

        if args.all or args.certs_list:

            # To get to each certs page
            next_token = None
            finished = False

            certs_list = []
            while not finished:
                try:
                    print("Listing ACM certificate ARNs for region: {}".format(region))
                    if next_token:
                        response = client.list_certificates(NextToken=next_token, MaxItems=50)
                    else:
                        response = client.list_certificates(MaxItems=50)

                    certs_list = response['CertificateSummaryList']
                    if certs_list:
                        num_certs_found = len(certs_list)
                        print('Found {} certs for region: {}'.format(len(certs_list), region))
                        data['num_certs'] += num_certs_found

                        if region not in data['certs']:
                            data['certs'][region] = []
                        data['certs'][region].extend(certs_list)

                    if 'NextToken' in response:
                        next_token = response['NextToken']
                    else:
                        finished = True

                except Exception as err:
                    print("Exception listing ACM Certificate ARNs for region: {}".format(region))
                    print("    Error: {}, {}".format(err.__class__, str(err)))

        if args.all or args.certs_expired_list:

            # To get to each certs page
            next_token = None
            finished = False

            certs_list = []
            while not finished:
                try:
                    print("Listing ACM certificate ARNs which are EXPIRED for region: {}".format(region))
                    if next_token:
                        response = client.list_certificates(
                            CertificateStatuses=['EXPIRED'],
                            NextToken=next_token,
                            MaxItems=50
                        )
                    else:
                        response = client.list_certificates(
                            CertificateStatuses=['EXPIRED'],
                            MaxItems=50
                        )

                    certs_list = response['CertificateSummaryList']
                    if certs_list:
                        num_certs_found = len(certs_list)
                        print('Found {} expired cert(s) for region: {}'.format(len(certs_list), region))
                        data['num_certs_expired'] += num_certs_found

                        if region not in data['certs_expired']:
                            data['certs_expired'][region] = []
                        data['certs_expired'][region].extend(certs_list)

                    if 'NextToken' in response:
                        next_token = response['NextToken']
                    else:
                        finished = True

                except Exception as err:
                    print("Exception listing Expired ACM Certificate ARNs for region: {}".format(region))
                    print("    Error: {}, {}".format(err.__class__, str(err)))

        if args.all or args.certs_chain:

            if region in data['certs'] and data['certs'][region]:
                print("Getting certs, and their chain for region: {}".format(region))
                try:
                    for cert_arn_domain in data['certs'][region]:
                        cert_arn = cert_arn_domain.get('CertificateArn', '')
                        domain = cert_arn_domain.get('DomainName', '')

                        print("Getting info about cert: {} for region: {}".format(cert_arn, region))
                        response = client.get_certificate(CertificateArn=cert_arn)

                        data['certs_chain'][cert_arn] = response

                except Exception as err:
                    print("Exception getting ACM Certificate ARN: {}, Domain: {} for region: {}".format(cert_arn, domain, region))
                    print("    Error: {}, {}".format(err.__class__, str(err)))

        if args.all or args.certs_info:

            if region in data['certs'] and data['certs'][region]:
                print("Describing certs: {}".format(region))

                try:
                    for cert_arn_domain in data['certs'][region]:
                        cert_arn = cert_arn_domain.get('CertificateArn', '')
                        domain = cert_arn_domain.get('DomainName', '')

                        print("Getting info about cert: {} for region: {}".format(cert_arn, region))
                        response = client.describe_certificate(CertificateArn=cert_arn)

                        data['certs_info'][cert_arn] = response

                except Exception as err:
                    print("Exception getting ACM Certificate ARN: {}, Domain: {} for region: {}".format(cert_arn, domain, region))
                    print("    Error: {}, {}".format(err.__class__, str(err)))

        if args.all or args.ca_list:

            # To get to each certs page
            next_token = None
            finished = False

            while not finished:
                try:
                    print("Listing ACM Private CAs for region: {}".format(region))
                    if next_token:
                        response = ca_client.list_certificate_authorities(
                            NextToken=next_token,
                            MaxResults=50
                        )
                    else:
                        response = ca_client.list_certificate_authorities(
                            MaxResults=50
                        )

                    ca_list = response['CertificateAuthorities']
                    if ca_list:
                        num_cas_found = len(ca_list)
                        print('Found {} CAs for region: {}'.format(len(ca_list),
                            region))
                        data['num_cas'] += num_cas_found

                        if region not in data['cas']:
                            data['cas'][region] = []
                        data['certs'][region].extend(ca_list)

                    if 'NextToken' in response:
                        next_token = response['NextToken']
                    else:
                        finished = True

                except Exception as err:
                    print("Exception listing ACM CAs for region: {}".format(region))
                    print("    Error: {}, {}".format(err.__class__, str(err)))


    # Prepare the out file names to write output data to
    now = time.time()
    outfiles = {}
    outfiles['certs'] = str(downloads_dir()/'acm_enum_certs_{}.json').format(now)
    outfiles['certs_info'] = str(downloads_dir()/'acm_enum_certs_info_{}.json'.format(now))
    outfiles['certs_chain'] = str(downloads_dir()/'acm_enum_certs_chain_{}.json').format(now)
    outfiles['cas'] = str(downloads_dir()/'acm_enum_cas_{}.json').format(now)
    outfiles['certs_expired'] = str(downloads_dir()/'acm_enum_certs_expired_{}.json').format(now)

    # Write the relevant output to the output files
    for info_type, outfile in outfiles.items():
        if data[info_type]:
            print("Writing info: {} to outfile: {}".format(info_type, outfile))
            with open(outfile, 'w+') as f:
                f.write(
                    json.dumps(
                        data[info_type],
                        indent=4,
                        default=str
                    )
                )

    # Write the info about certs to outfile
    return data


def summary(data, pacu_main):
    msg = """
Found {} certificate(s) in ACM

Found {} Private CA(s) in ACM

Found {} expired certificate(s) in ACM
""".format(
        data['num_certs'],
        data['num_cas'],
        data['num_certs_expired']
)

    return msg
