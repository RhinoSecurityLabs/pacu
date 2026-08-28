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


# ---------------------------------------------------------------------------
# Test 5: a terminal page carrying an EMPTY NextToken must end the loop
# ---------------------------------------------------------------------------

class _EmptyTokenClient:
    """
    Fake SNS client whose last page returns ``NextToken: ""`` rather than
    omitting the key.  A bare ``while "NextToken" in response`` loop never
    terminates against this shape, so the loop guard must also test for the
    empty string -- matching the idiom already used by ``glue__enum`` and
    ``transfer_family__enum``.
    """

    #: hard cap so a regression fails fast instead of hanging the suite
    MAX_CALLS = 25

    def __init__(self):
        self.topic_calls = 0
        self.sub_calls = 0

    def list_topics(self, **kwargs):
        self.topic_calls += 1
        if self.topic_calls > self.MAX_CALLS:
            raise AssertionError(
                "list_topics paged more than {} times: the NextToken loop did "
                "not terminate on an empty token".format(self.MAX_CALLS)
            )
        if "NextToken" not in kwargs:
            return {
                "Topics": [{"TopicArn": "arn:aws:sns:us-east-1:000000000000:page1"}],
                "NextToken": "page-2",
            }
        return {
            "Topics": [{"TopicArn": "arn:aws:sns:us-east-1:000000000000:page2"}],
            "NextToken": "",
        }

    def get_topic_attributes(self, TopicArn):
        return {
            "Attributes": {
                "DisplayName": "",
                "Owner": "000000000000",
                "SubscriptionsConfirmed": "1",
                "SubscriptionsPending": "0",
            }
        }

    def list_subscriptions_by_topic(self, **kwargs):
        self.sub_calls += 1
        if self.sub_calls > self.MAX_CALLS:
            raise AssertionError(
                "list_subscriptions_by_topic paged more than {} times: the "
                "NextToken loop did not terminate on an empty token".format(
                    self.MAX_CALLS
                )
            )
        if "NextToken" not in kwargs:
            return {
                "Subscriptions": [
                    {"Protocol": "email", "Endpoint": "a@example.com"}
                ],
                "NextToken": "page-2",
            }
        return {
            "Subscriptions": [
                {"Protocol": "email", "Endpoint": "b@example.com"}
            ],
            "NextToken": "",
        }


def test_empty_next_token_terminates_pagination():
    from pacu.modules.sns__enum.main import main

    region = "us-east-1"
    client = _EmptyTokenClient()

    pacu_main = _make_pacu_main(lambda service, reg: client)
    result = main(["--regions", region], pacu_main)

    # Two pages of topics, both collected, and the loop stopped.
    assert client.topic_calls == 2, (
        "Expected exactly 2 list_topics calls, got {}".format(client.topic_calls)
    )
    assert len(result["sns"][region]) == 2

    # Same for subscriptions, per topic (2 topics x 2 pages).
    assert client.sub_calls == 4, (
        "Expected exactly 4 list_subscriptions_by_topic calls, got {}".format(
            client.sub_calls
        )
    )
    for topic_arn, topic in result["sns"][region].items():
        assert len(topic["Subscribers"]) == 2, (
            "Expected 2 subscribers for {}, got {}".format(
                topic_arn, len(topic["Subscribers"])
            )
        )
