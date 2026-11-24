import base64
import logging

import httpx
import pytest
from jira_fake import BASE_URL, EMAIL, TOKEN, FakeJira
from pydantic import SecretStr

from guardian.core.exceptions import ConfigurationError
from guardian.integrations.jira import adf
from guardian.integrations.jira.client import (
    JiraClient,
    JiraError,
    jira_client_from_settings,
    validate_issue_key,
)


def _client(handler, **kwargs):
    sleeps: list[float] = []
    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = JiraClient(BASE_URL, EMAIL, SecretStr(TOKEN), http, sleep=sleeps.append, **kwargs)
    return client, sleeps


def test_basic_auth_and_myself():
    fake = FakeJira()
    me = fake.client().myself()
    assert me["accountId"] == "acct-guardian"
    auth = fake.requests[0].headers["Authorization"]
    assert auth == "Basic " + base64.b64encode(f"{EMAIL}:{TOKEN}".encode()).decode()
    assert fake.requests[0].url == f"{BASE_URL}/rest/api/3/myself"


def test_rejects_plain_http():
    with pytest.raises(ConfigurationError):
        JiraClient("http://example.atlassian.net", EMAIL, SecretStr(TOKEN))


def test_repr_hides_token():
    assert TOKEN not in repr(FakeJira().client())


def test_create_update_get_issue():
    fake = FakeJira()
    jira = fake.client()
    key = jira.create_issue({"summary": "s", "labels": ["guardian"]})
    assert key == "SEC-1"
    jira.update_issue(key, {"summary": "t"})
    assert jira.get_issue(key, ["summary"])["fields"]["summary"] == "t"
    assert fake.requests[-1].url.params["fields"] == "summary"


def test_search_uses_new_endpoint_and_paginates():
    fake = FakeJira(page_size=2)
    for _ in range(5):
        fake.add_issue(["guardian"])
    keys = [i["key"] for i in fake.client().iter_search("labels = guardian", ["key"])]
    assert keys == ["SEC-1", "SEC-2", "SEC-3", "SEC-4", "SEC-5"]
    searches = fake.calls("POST", "/rest/api/3/search")
    assert {r.url.path for r in searches} == {"/rest/api/3/search/jql"}
    assert len(searches) == 3
    assert not fake.calls("GET", "/rest/api/3/search")


def test_comments_paginate_in_created_order():
    fake = FakeJira(page_size=2)
    key = fake.add_issue(["guardian"])
    for i in range(5):
        fake.add_comment(key, "acct-alice", f"c{i}")
    jira = fake.client()
    texts = [adf.adf_to_text(c["body"]) for c in jira.iter_comments(key)]
    assert texts == ["c0", "c1", "c2", "c3", "c4"]
    assert fake.requests[0].url.params["orderBy"] == "created"
    comment_id = jira.add_comment(key, adf.doc(adf.paragraph("hi")))
    assert comment_id == fake.comments[key][-1]["id"]


def test_transition_by_name():
    fake = FakeJira()
    key = fake.add_issue(["guardian"])
    jira = fake.client()
    assert jira.transition(key, "done") is True
    assert fake.transitioned == [(key, "31")]
    assert jira.transition(key, "Nope") is False


def test_retry_honours_retry_after_on_429():
    fake = FakeJira()
    fake.queued = [
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(503),
    ]
    assert fake.client().myself()["accountId"] == "acct-guardian"
    assert fake.sleeps == [7.0, 2.0]  # Retry-After, then exponential backoff (1 * 2**1)


def test_retry_gives_up_after_max_retries():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(500, json={"errorMessages": ["boom"]})

    client, sleeps = _client(handler)
    with pytest.raises(JiraError) as info:
        client.myself()
    assert info.value.status_code == 500
    assert len(calls) == 4
    assert sleeps == [1.0, 2.0, 4.0]


def test_retry_after_is_capped():
    fake = FakeJira()
    fake.queued = [httpx.Response(429, headers={"Retry-After": "99999"})]
    fake.client().myself()
    assert fake.sleeps == [60.0]


def test_create_is_not_retried_on_5xx_but_is_on_429():
    fake = FakeJira()
    fake.queued = [httpx.Response(502)]
    with pytest.raises(JiraError):
        fake.client().create_issue({"summary": "x", "labels": []})
    assert not fake.issues
    fake.queued = [httpx.Response(429)]
    assert fake.client().create_issue({"summary": "x", "labels": []}) == "SEC-1"


def test_transport_errors_are_retried_then_reported():
    def handler(request):
        msg = "boom"
        raise httpx.ConnectError(msg, request=request)

    client, sleeps = _client(handler)
    with pytest.raises(JiraError, match="connection failed"):
        client.myself()
    assert len(sleeps) == 3

    def slow(request):
        msg = "slow"
        raise httpx.ReadTimeout(msg, request=request)

    client, _ = _client(slow, max_retries=0)
    with pytest.raises(JiraError, match="timed out"):
        client.myself()


def test_error_never_contains_token_or_auth_header(caplog):
    def handler(request):
        echoed = request.headers["Authorization"]
        return httpx.Response(
            401,
            json={"errorMessages": [f"bad credentials {TOKEN} {echoed} for {EMAIL}"]},
        )

    caplog.set_level(logging.DEBUG)
    client, _ = _client(handler)
    with pytest.raises(JiraError) as info:
        client.myself()
    message = str(info.value)
    assert "HTTP 401" in message
    assert "\n" not in message
    encoded = base64.b64encode(f"{EMAIL}:{TOKEN}".encode()).decode()
    for secret in (TOKEN, encoded, EMAIL):
        assert secret not in message
        assert secret not in caplog.text
    assert info.value.__cause__ is None


def test_field_errors_are_exposed():
    def handler(request):
        return httpx.Response(400, json={"errors": {"priority": "Field cannot be set"}})

    client, _ = _client(handler)
    with pytest.raises(JiraError) as info:
        client.create_issue({"summary": "x"})
    assert info.value.field_errors == {"priority": "Field cannot be set"}
    assert "priority: Field cannot be set" in str(info.value)


def test_response_size_cap():
    client, _ = _client(
        lambda r: httpx.Response(200, content=b"{" + b" " * 5000 + b"}"), max_response_bytes=1000
    )
    with pytest.raises(JiraError, match="larger than 1000 bytes"):
        client.myself()


def test_non_object_json_is_an_error():
    client, _ = _client(lambda r: httpx.Response(200, content=b"[1, 2]"))
    with pytest.raises(JiraError, match="unexpected"):
        client.myself()
    client, _ = _client(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(JiraError, match="unexpected"):
        client.myself()


def test_redirects_are_not_followed():
    client, _ = _client(
        lambda r: httpx.Response(302, headers={"Location": "https://evil.example/"})
    )
    assert client.myself() == {}  # 3xx is returned as an empty body, never followed


def test_issue_keys_are_validated_before_use():
    fake = FakeJira()
    with pytest.raises(JiraError):
        fake.client().get_issue("../../admin")
    assert not fake.requests
    assert validate_issue_key("SEC-12") == "SEC-12"


def test_missing_key_or_id_in_response():
    client, _ = _client(lambda r: httpx.Response(201, json={}))
    with pytest.raises(JiraError, match="no issue key"):
        client.create_issue({})
    with pytest.raises(JiraError, match="no comment id"):
        client.add_comment("SEC-1", adf.doc())


def test_client_from_settings(tmp_path):
    from guardian.core.config import GuardianSettings

    settings = GuardianSettings(_env_file=None, jira_email=EMAIL)
    with pytest.raises(ConfigurationError) as info:
        jira_client_from_settings(settings)
    assert "JIRA_BASE_URL" in str(info.value)
    assert "JIRA_EMAIL" not in str(info.value)
    settings = GuardianSettings(
        _env_file=None,
        jira_base_url=BASE_URL,
        jira_email=EMAIL,
        jira_api_token=TOKEN,
        jira_project_key="SEC",
    )
    with jira_client_from_settings(settings) as client:
        assert client.base_url == BASE_URL
