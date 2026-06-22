"""
Tests for sns__enum pagination fix.

Regression coverage for the false-negative introduced by calling
list_topics() and list_subscriptions_by_topic() exactly once per
invocation.  SNS paginates both APIs at 100 items per page, so any
account with >100 topics (or >100 subscriptions on a single topic)
was silently under-reported.

The tests below drive the patched main() through a mock boto3 client
that returns paginated responses and assert that every topic /
subscription across all pages is collected.
"""
import unittest.mock

import boto3
import moto
import pytest


# ---------------------------------------------------------------------------
# Helpers — build a minimal pacu_main stand-in that satisfies the code paths
# exercised by sns__enum.main().
# ---------------------------------------------------------------------------

def _make_mock_session(region: str = "us-east-1"):
    """Return a lightweight mock that pacu_main.get_boto3_client() uses."""
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
        region_name=region,
    )
    return session


def _make_pacu_main(boto3_client_fn, session_data=None):
    """
    Construct a minimal pacu_main duck-typed object that sns__enum.main()
    will accept without importing the real pacu.Main (which needs the full
    DB stack).
    """
    pacu_session = unittest.mock.MagicMock()
    pacu_session.SNS = {}

    pacu_main = unittest.mock.MagicMock()
    pacu_main.get_active_session.return_value = pacu_session
    pacu_main.get_boto3_client.side_effect = boto3_client_fn
    pacu_main.get_regions.return_value = ["us-east-1"]
    pacu_main.print = lambda *a, **kw: None  # silence output in tests
    pacu_main.key_info = unittest.mock.MagicMock()
    pacu_main.fetch_data = unittest.mock.MagicMock()
    return pacu_main


# ---------------------------------------------------------------------------
# Test 1: list_topics pagination — >100 topics (two pages) all enumerated
# ---------------------------------------------------------------------------

@moto.mock_aws
def test_list_topics_follows_next_token():
    """
    Create 105 SNS topics via moto (which respects the 100-item page cap),
    run sns__enum.main(), and assert all 105 are present in the result.
    """
    from pacu.modules.sns__enum.main import main

    region = "us-east-1"
    client = boto3.client(
        "sns",
        region_name=region,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )

    topic_arns = []
    for i in range(105):
        resp = client.create_topic(Name=f"test-topic-{i:03d}")
        topic_arns.append(resp["TopicArn"])

    # Verify moto actually paginates (sanity-check on the fixture itself).
    first_page = client.list_topics()
    assert len(first_page["Topics"]) == 100, (
        "moto did not paginate list_topics at 100; "
        "adjust topic count or check moto version"
    )
    assert "NextToken" in first_page

    def get_client(service, reg):
        assert service == "sns"
        return client

    pacu_main = _make_pacu_main(get_client)
    result = main(["--regions", region], pacu_main)

    reported = result["sns"][region]
    assert len(reported) == 105, (
        f"Expected 105 topics, got {len(reported)}. "
        "Pagination via NextToken was likely not followed."
    )
    for arn in topic_arns:
        assert arn in reported, f"Topic {arn} missing from enumeration result"


# ---------------------------------------------------------------------------
# Test 2: list_subscriptions_by_topic pagination — >100 subs all enumerated
# ---------------------------------------------------------------------------

@moto.mock_aws
def test_list_subscriptions_by_topic_follows_next_token():
    """
    Create 1 SNS topic and 105 email subscriptions, run sns__enum.main(),
    and assert all 105 subscribers appear in the result.

    Note: moto paginates list_subscriptions_by_topic at 100.
    """
    from pacu.modules.sns__enum.main import main

    region = "us-east-1"
    client = boto3.client(
        "sns",
        region_name=region,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )

    topic_arn = client.create_topic(Name="sub-pagination-topic")["TopicArn"]

    for i in range(105):
        client.subscribe(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint=f"user{i:03d}@example.com",
        )

    # Sanity-check: moto must paginate at 100.
    first_page = client.list_subscriptions_by_topic(TopicArn=topic_arn)
    assert len(first_page["Subscriptions"]) == 100, (
        "moto did not paginate list_subscriptions_by_topic at 100; "
        "adjust subscriber count or check moto version"
    )
    assert "NextToken" in first_page

    def get_client(service, reg):
        assert service == "sns"
        return client

    pacu_main = _make_pacu_main(get_client)
    result = main(["--regions", region], pacu_main)

    subscribers = result["sns"][region][topic_arn]["Subscribers"]
    assert len(subscribers) == 105, (
        f"Expected 105 subscribers, got {len(subscribers)}. "
        "Pagination via NextToken for list_subscriptions_by_topic was likely not followed."
    )


# ---------------------------------------------------------------------------
# Test 3: baseline — fewer than 100 topics, no NextToken in play
# ---------------------------------------------------------------------------

@moto.mock_aws
def test_single_page_topics_unaffected():
    """
    Smoke test: 3 topics, no pagination needed.  Ensures the refactor did
    not break the common (< 100 topics) case.
    """
    from pacu.modules.sns__enum.main import main

    region = "us-east-1"
    client = boto3.client(
        "sns",
        region_name=region,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )

    arns = []
    for i in range(3):
        arns.append(client.create_topic(Name=f"small-topic-{i}")["TopicArn"])

    def get_client(service, reg):
        return client

    pacu_main = _make_pacu_main(get_client)
    result = main(["--regions", region], pacu_main)

    assert len(result["sns"][region]) == 3
    for arn in arns:
        assert arn in result["sns"][region]


# ---------------------------------------------------------------------------
# Test 4: empty region — result must not include the region key
# ---------------------------------------------------------------------------

@moto.mock_aws
def test_empty_region_excluded_from_result():
    """
    When no topics exist in a region the module should not store an empty
    dict for that region (existing behaviour, must remain unchanged).
    """
    from pacu.modules.sns__enum.main import main

    region = "us-east-1"
    client = boto3.client(
        "sns",
        region_name=region,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )

    def get_client(service, reg):
        return client

    pacu_main = _make_pacu_main(get_client)
    result = main(["--regions", region], pacu_main)

    assert region not in result["sns"], (
        "Empty region should be excluded from result dict"
    )
