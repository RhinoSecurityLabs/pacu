#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import json
import os

from pacu.core.lib import downloads_dir

module_info = {
    'name': 'systemsmanager__download_parameters',
    'author': 'David Yesland',
    'category': 'ENUM',
    'one_liner': 'Downloads all parameters and decrypted values from SSM.',
    'description': 'This module downloads all Systems Manager parameters and their value from all regions.',
    'services': ['SSM'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ["--regions"],
}

# client.get_parameters() only takes a list of 10 max
SMS_GET_PARAM_MAX = 10

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all regions.')

def main(args, pacu_main):
    session = pacu_main.get_active_session()

    print = pacu_main.print

    args = parser.parse_args(args)

    if args.regions:
        regions = args.regions.split(',')
    else:
        get_regions = pacu_main.get_regions
        regions = get_regions('ssm')

    data = {}
    for region in regions:
        param_objs = []
        NextToken = ""

        print('Looking for parameters in region {}...'.format(region))
        client = pacu_main.get_boto3_client('ssm', region)

        #Catch errors with the ssm-* regions
        try:
            param_data = client.describe_parameters()
        except:
            print('ERROR: retrieving parameters from {}'.format(region))
            continue

        #Check if any params in the region and add them to param_objs
        if param_data["Parameters"]:
            data[region] = {}
            print('    Found parameters in region {}...'.format(region))
            param_objs += (param_data["Parameters"])
        else:
            continue
        
        try:
            NextToken = param_data["NextToken"]
        except KeyError:
            pass
        
        #Paginate the results if needed, add them to param_objs
        if NextToken:
            while True:
                param_data = client.describe_parameters(NextToken=NextToken)
                param_objs += (param_data["Parameters"])
                try:
                    NextToken = param_data["NextToken"]
                except KeyError:
                        break
        
        #Dump all param_objs Name fields into the data for the region
        for param_obj in param_objs:
            name = param_obj["Name"]
            data[region][name] = ""

        #Pull all param names for the region to then grab the values
        param_names = list(data[region].keys())
        
        #client.get_parameters() only takes a list of 10 max, so break it up into 10s
        #Reference: https://www.geeksforgeeks.org/break-list-chunks-size-n-python/   
        param_names_by_max = [param_names[i * SMS_GET_PARAM_MAX:(i + 1) * SMS_GET_PARAM_MAX] for i in range((len(param_names) + SMS_GET_PARAM_MAX - 1) // SMS_GET_PARAM_MAX )]
        
        for names in param_names_by_max:
            full_params = client.get_parameters(Names=names,
                                                WithDecryption=True)

            for param_obj in full_params["Parameters"]:
                data[region][param_obj["Name"]] = param_obj["Value"]

    #data is a JSON object like 
    # {"us-east-1":
    #              {
    #               "param_name1":"param_value1",
    #               "param_name2":"param_value2"
    #               }
    # }

    for ssm_region in data.keys():
        with open(downloads_dir()/'ssm_parameters/{}.txt'.format(ssm_region), 'w+') as f:
            json.dump(data[ssm_region], f, indent=2)

    info = {}
    info["save_path"] = str(downloads_dir()/'ssm_parameters/')
    info["region_count"] = str(len(data.keys()))
    total_params = 0
    for param_region in data.keys():
        total_params += len(data[param_region].keys())
    info["total_params"] = str(total_params)
    return info


# The summary function will be called by Pacu after running main
def summary(data, pacu_main):
    
    if data.keys():
        return 'Downloaded {} SSM parameters and values from {} region(s).\nSaved to: {}'.format(data["total_params"],data["region_count"],data["save_path"])
    else:
        return 'No SSM parameters found.'
