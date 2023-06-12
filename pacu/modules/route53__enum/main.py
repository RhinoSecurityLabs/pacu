#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError

module_info = {
    # Name of the module (should be the same as the filename).
    "name": "route53__enum",
    # Name and any other notes about the author.
    "author": "Aaron Rea - Scalesec",
    # Category of the module. Make sure the name matches an existing category.
    "category": "ENUM",
    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    "one_liner": "Enumerates Route53 hosted zones and query logging configurations",
    # Full description about what the module does and how it works.
    "description": "This module enumerates Route53 hosted zones across an account and correlates them with query logging configs for later use.",
    # A list of AWS services that the module utilizes during its execution.
    "services": ["Route53"],
    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    "prerequisite_modules": [],
    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    "external_dependencies": [],
    # Module arguments to autocomplete when the user hits tab.
    "arguments_to_autocomplete": ["--get_query_logging_config"],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])


def get_hosted_zones(client):
    hosted_zones = []
    paginator = client.get_paginator("list_hosted_zones")
    for hosted_zone in paginator.paginate():
        hosted_zones += hosted_zone["HostedZones"]
    zones = {}

    if len(hosted_zones) > 0:
        for zone in hosted_zones:
            zid = zone["Id"].split("/")[2]
            print(
                f"ZoneID: {zid}  Name: {zone['Name']} Private: {zone['Config']['PrivateZone']} "
            )
            zones[zid] = zone
    else:
        print("No HostedZones found")

    return zones


def get_resource_record_sets_for_zone_id(client, hosted_zone_id):
    record_sets = {}
    all_records_for_zone = []
    paginator = client.get_paginator("list_resource_record_sets")
    for resource_records in paginator.paginate(HostedZoneId=hosted_zone_id):
        all_records_for_zone += resource_records["ResourceRecordSets"]
    record_sets[hosted_zone_id] = {"ResourceRecordSets": all_records_for_zone}
    if len(record_sets[hosted_zone_id]) > 0:
        print(f"ResourceRecordSets for {hosted_zone_id}:")
        for record in record_sets[hosted_zone_id]["ResourceRecordSets"]:
            print(f"Name: {record['Name']} Type: {record['Type']}")
    else:
        print("No ResourceRecordSets found")

    return record_sets


def get_query_logging_config(client):
    configs = client.list_query_logging_configs()["QueryLoggingConfigs"]

    if len(configs) > 0:
        print("QueryLoggingConfigs:")
        for con in configs:
            print(
                f"ZoneID: {con['HostedZoneId']} :: CloudWatchLogsLogGroupArn: {con['CloudWatchLogsLogGroupArn']}"
            )
    else:
        print("No QueryLoggingConfigs found")

    return configs


def zones_plus_config_and_records(zones, configs, records):
    for con in configs:
        if con["HostedZoneId"] in zones.keys():
            zones[con["HostedZoneId"]].update(
                {"CloudWatchLogsLogGroupArn": con["CloudWatchLogsLogGroupArn"]}
            )
            zones[con["HostedZoneId"]].update({"QueryLoggingConfigId": con["Id"]})
    for zone_id in records.keys():
        zones[zone_id].update(records[zone_id])

    return zones


def main(args, pacu_main):
    session = pacu_main.get_active_session()
    print = pacu_main.print
    args = parser.parse_args(args)

    try:
        client = pacu_main.get_boto3_client("route53")
    except ClientError as error:
        print(f"Failed to initialize boto client for route53: {error}")

    data = {}

    try:
        zones = get_hosted_zones(client=client)
    except ClientError as error:
        print(f"Failed to list R53 Hosted Zones: {error}")
        return

    try:
        confs = get_query_logging_config(client=client)
    except ClientError as error:
        print(f"Failed to list R53 Hosted Zone Query Logging Configurations: {error}")
        return

    records = {}
    for hosted_zone_id in zones.keys():
        try:
            records_for_zone = get_resource_record_sets_for_zone_id(
                client=client, hosted_zone_id=hosted_zone_id
            )
        except ClientError as error:
            print(f"Failed to list R53 Resource Record Sets: {error}")
            continue
        records.update(records_for_zone)

    data = zones_plus_config_and_records(zones=zones, configs=confs, records=records)

    session.update(pacu_main.database, Route53=data)

    return data


def summary(data, pacu_main):
    if len(data) > 0:
        hosted_zone_count = len(data)
        total_records = 0
        for zone_id in data.keys():
            total_records += data[zone_id]["ResourceRecordSetCount"]
        return f"Found {hosted_zone_count} hosted zones.\nFound {total_records} resource records."
    else:
        return "No hosted zones found."
