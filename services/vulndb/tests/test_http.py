import os
from dataclasses import replace

import httpx
import pytest

from sleep_vulndb.config import Settings
from sleep_vulndb.http import FeedHttp, FeedHttpError

from conftest import FakeFeeds


URL = "https://feed.test/file.bin"


def client(settings: Settings, handler: httpx.MockTransport) -> FeedHttp:
    return FeedHttp(settings, transport=handler, sleep=lambda _seconds: None)


def test_download_returns_file_and_validators(http: FeedHttp, feeds: FakeFeeds) -> None:
    feeds.serve(URL, b"payload", etag='"v1"')

    with http.download(URL) as download:
        assert download is not None
        with open(download.path, "rb") as stream:
            assert stream.read() == b"payload"
        assert download.etag == '"v1"'
        path = download.path

    assert not os.path.exists(path), "the temporary file is removed after use"


def test_conditional_request_returns_none_when_unchanged(http: FeedHttp, feeds: FakeFeeds) -> None:
    feeds.serve(URL, b"payload", etag='"v1"')

    with http.download(URL, etag='"v1"') as download:
        assert download is None
    assert feeds.requests[-1].headers["If-None-Match"] == '"v1"'
    assert "SLeep-vulndb" in feeds.requests[-1].headers["User-Agent"]


def test_transient_errors_are_retried(settings: Settings) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectError("connection reset", request=request)
        if len(calls) == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    with client(settings, httpx.MockTransport(handler)) as http:
        assert http.get_json(URL) == {"ok": True}
    assert len(calls) == 3


def test_retries_are_limited(settings: Settings) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(502)

    with client(replace(settings, http_retries=1), httpx.MockTransport(handler)) as http:
        with pytest.raises(FeedHttpError, match="HTTP 502"):
            http.get_json(URL)


def test_client_errors_are_not_retried(settings: Settings) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(403)

    with client(settings, httpx.MockTransport(handler)) as http:
        with pytest.raises(FeedHttpError, match="HTTP 403"), http.download(URL):
            pass
    assert len(calls) == 1


def test_missing_json_document_is_none(http: FeedHttp) -> None:
    assert http.get_json("https://feed.test/missing.json") is None


def test_download_size_is_limited(settings: Settings, feeds: FakeFeeds) -> None:
    feeds.serve(URL, b"x" * 2048)
    with client(replace(settings, max_download_bytes=1024), httpx.MockTransport(feeds.handle)) as http:
        with pytest.raises(FeedHttpError, match="exceeds"), http.download(URL):
            pass


def test_lines_can_stop_early(http: FeedHttp, feeds: FakeFeeds) -> None:
    feeds.serve(URL, "first\nsecond\nthird\n")
    with http.lines(URL) as lines:
        assert next(lines) == "first"
