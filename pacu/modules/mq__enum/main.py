#!/usr/bin/env python3
import argparse
import time
import json

from pacu.core.lib import downloads_dir
from pacu.core.lib import strip_lines
from pacu import Main
from copy import deepcopy

module_info = {
    "name": "mq__enum",
    "author": "6a6f656c & h00die of nDepth Security",
    "category": "ENUM",
    "one_liner": "List and describe brokers",
    "description": strip_lines(
        """
        This module will attempt to list and gather information from available brokers.
        """
    ),
    "services": ["MQ"],
    "prerequisite_modules": [],
    "arguments_to_autocomplete": [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])

parser.add_argument(
    "--regions",
    required=False,
    default=None,
    help=strip_lines(
        """
    One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.
"""
    ),
)


def main(args, pacu_main: "Main"):
    session = pacu_main.get_active_session()

    # Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print

    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data

    # End don't modify
    get_regions = pacu_main.get_regions
    if not args.regions:
        regions = get_regions("mq")
    else:
        regions = args.regions.split(",")

    summary_data = {}
    summary_data["mq"] = {}

    for region in regions:
        print("Starting region {}...".format(region))
        summary_data["mq"][region] = {}

        try:
            client = pacu_main.get_boto3_client("mq", region)
        except Exception as error:
            print("Unable to connect to MQ service. Error: {}".format(error))
            continue

        try:
            response = client.list_brokers(
                MaxResults=100,
            )

        except Exception as error:
            print(
                "Unable to list brokers; Check credentials or No brokers are available. Error: {}".format(
                    error
                )
            )
            continue
        print("  Found {} brokers".format(len(response["BrokerSummaries"])))
        for broker in response["BrokerSummaries"]:
            broker_details = client.describe_broker(BrokerId=broker["BrokerId"])
            summary_data["mq"][region][broker["BrokerId"]] = {}
            summary_data["mq"][region][broker["BrokerId"]]["AuthenticationStrategy"] = (
                broker_details["AuthenticationStrategy"]
            )
            summary_data["mq"][region][broker["BrokerId"]]["PubliclyAccessible"] = (
                broker_details["PubliclyAccessible"]
            )
            summary_data["mq"][region][broker["BrokerId"]]["BrokerName"] = (
                broker_details["BrokerName"]
            )
            summary_data["mq"][region][broker["BrokerId"]]["BrokerState"] = (
                broker_details["BrokerState"]
            )
            summary_data["mq"][region][broker["BrokerId"]]["Users"] = broker_details[
                "Users"
            ]
            summary_data["mq"][region][broker["BrokerId"]]["EngineType"] = (
                broker_details["EngineType"]
            )
            summary_data["mq"][region][broker["BrokerId"]]["ConsoleURL"] = [
                url["ConsoleURL"] for url in broker_details["BrokerInstances"]
            ]


    mq_data = deepcopy(session.MQ)
    for key, value in summary_data.items():
        mq_data[key] = value
    session.update(pacu_main.database, MQ=mq_data)

    return summary_data


def summary(data, pacu_main):
    out = ""

    total_users = 0
    total_brokers = 0
    for region in data["mq"]:
        total_brokers += len(data["mq"][region])
        for broker in data["mq"][region]:
            total_users += len(data["mq"][region][broker]["Users"])
    out += "Num of MQ brokers found: {} \n".format(total_brokers)
    out += "Num of MQ users found: {} \n".format(total_users)
    return out
