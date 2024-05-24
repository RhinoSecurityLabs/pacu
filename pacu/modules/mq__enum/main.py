#!/usr/bin/env python3
import argparse
import time
import json

from pacu.core.lib import downloads_dir
from pacu.core.lib import strip_lines
from pacu import Main

module_info = {
    "name": "mq__enum",
    "author": "6a6f656c & h00die of nDepth Security",
    "category": "ENUM",  # or maybe persistence? kind of depends what may come over the topic, like creds
    "one_liner": "List and describer brokers",
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


def main(args, pacu_main: "Main"):
    session = pacu_main.get_active_session()

    # Don't modify these. They can be removed if you are not using the function.
    # args = parser.parse_args(args)
    print = pacu_main.print

    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data

    # End don't modify

    client = pacu_main.get_boto3_client("mq")

    # Prepare output file to store ECR data
    now = time.time()
    outfile_path = str(downloads_dir() / f"mq_enum_{now}.json")

    try:
        response = client.list_brokers(
            MaxResults=10_000,
        )

    except Exception as error:
        print(
            "Unable to list brokers; Check credentials or No brokers are available. Error: {}".format(
                error
            )
        )
        return

    summary_data = {}
    summary_data["mq"] = {}

    for broker in response["BrokerSummaries"]:
        broker_details = client.describe_broker(BrokerId=broker["BrokerId"])
        summary_data["mq"][broker["BrokerId"]] = {}
        summary_data["mq"][broker["BrokerId"]]["AuthenticationStrategy"] = (
            broker_details["AuthenticationStrategy"]
        )
        summary_data["mq"][broker["BrokerId"]]["PubliclyAccessible"] = broker_details[
            "PubliclyAccessible"
        ]
        summary_data["mq"][broker["BrokerId"]]["BrokerName"] = broker_details[
            "BrokerName"
        ]
        summary_data["mq"][broker["BrokerId"]]["BrokerState"] = broker_details[
            "BrokerState"
        ]
        summary_data["mq"][broker["BrokerId"]]["Users"] = broker_details["Users"]
        summary_data["mq"][broker["BrokerId"]]["EngineType"] = broker_details[
            "EngineType"
        ]
        summary_data["mq"][broker["BrokerId"]]["ConsoleURL"] = [
            url["ConsoleURL"] for url in broker_details["BrokerInstances"]
        ]

    # Write all the data to the output file
    print("Writing all MQ results to file: {}".format(outfile_path))
    with open(outfile_path, "w+") as f:
        f.write(json.dumps(summary_data, indent=4, default=str))

    return summary_data


def summary(data, pacu_main):
    out = ""
    out += "Num of MQ brokers found: {} \n".format(len(data["mq"]))
    total_users = 0
    for broker in data["mq"]:
        total_users += len(broker["Users"])
    out += "Num of MQ users found: {} \n".format(total_users)
    return out
