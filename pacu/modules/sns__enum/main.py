#!/usr/bin/env python3
import argparse
import time
import json
from copy import deepcopy

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

        # don't store empty data
        if len(response["Topics"]) == 0:
            del(summary_data["sns"][region])
            continue

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

            summary_data["sns"][region][topic["TopicArn"]]["Subscribers"] = []
            try:
                # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns/client/list_subscriptions_by_topic.html
                subscribers = client.list_subscriptions_by_topic(
                    TopicArn=topic["TopicArn"]
                )
                subscribers = subscribers["Subscriptions"]
                for subscriber in subscribers:
                    summary_data["sns"][region][topic["TopicArn"]][
                        "Subscribers"
                    ].append(
                        {
                            "Protocol": subscriber["Protocol"],
                            "Endpoint": subscriber["Endpoint"],
                        }
                    )
            except Exception as error:
                print(
                    "  Error listing subscribers, likely permissions problem. Error: {}\n".format(
                        error
                    )
                )
                continue

    # Write all the data to the database for storage
    sns_data = deepcopy(session.SNS)
    for key, value in summary_data.items():
        sns_data[key] = value
    session.update(pacu_main.database, SNS=sns_data)

    return summary_data


def summary(data, pacu_main):
    out = ""

    total_topics = 0
    total_users = 0
    for region in data["sns"]:
        total_topics += len(data["sns"][region])
        for topic in data["sns"][region]:
            total_users += len(data["sns"][region][topic]["Subscribers"])
    out += "Num of SNS topics found: {} \n".format(total_topics)
    out += "Num of SNS subscribers found: {} \n".format(total_users)
    return out
