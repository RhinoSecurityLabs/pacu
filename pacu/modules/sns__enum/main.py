#!/usr/bin/env python3
import argparse
import time
import json

from pacu.core.lib import downloads_dir
from pacu.core.lib import strip_lines
from pacu import Main

module_info = {
    "name": "sns__enum",
    "author": "h00die & 6a6f656c of nDepth Security",
    "category": "ENUM",
    "one_liner": "List and describe Simple Notification Service topics",
    "description": strip_lines(
        """
        This module will attempt to list and gather information from Simple Notification service topics.
        """
    ),
    "services": ["SNS"],
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
        regions = get_regions("sns")
    else:
        regions = args.regions.split(",")

    summary_data = {}
    summary_data["sns"] = {}

    for region in regions:
        print("Starting region {}...".format(region))
        summary_data["sns"][region] = {}

        try:
            client = pacu_main.get_boto3_client("sns", region)
        except Exception as error:
            print("Unable to connect to SNS service. Error: {}".format(error))
            continue

        # Prepare output file to store SNS data
        now = time.time()
        outfile_path = str(downloads_dir() / f"sns_enum_{now}.json")

        try:
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns/client/list_topics.html
            response = client.list_topics()

        except Exception as error:
            print(
                "Unable to list Topics; Check credentials or No topics are available. Error: {}".format(
                    error
                )
            )
            continue
        print("  Found {} topics".format(len(response["Topics"])))
        for topic in response["Topics"]:
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns/client/get_topic_attributes.html
            topic_details = client.get_topic_attributes(TopicArn=topic["TopicArn"])
            topic_details = topic_details["Attributes"]
            summary_data["sns"][region][topic["TopicArn"]] = {}
            summary_data["sns"][region][topic["TopicArn"]]["DisplayName"] = (
                topic_details["DisplayName"]
            )
            summary_data["sns"][region][topic["TopicArn"]]["Owner"] = topic_details[
                "Owner"
            ]
            summary_data["sns"][region][topic["TopicArn"]]["SubscriptionsConfirmed"] = (
                topic_details["SubscriptionsConfirmed"]
            )
            summary_data["sns"][region][topic["TopicArn"]]["SubscriptionsPending"] = (
                topic_details["SubscriptionsPending"]
            )

    # Write all the data to the output file
    print("Writing all SNS results to file: {}".format(outfile_path))
    with open(outfile_path, "w+") as f:
        f.write(json.dumps(summary_data, indent=4, default=str))

    return summary_data


def summary(data, pacu_main):
    out = ""

    total_topics = 0
    for region in data["sns"]:
        total_topics += len(data["sns"][region])
    out += "Num of SNS topics found: {} \n".format(total_topics)
    return out
