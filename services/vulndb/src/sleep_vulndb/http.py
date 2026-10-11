"""Outbound HTTP for feed downloads.

This is the only code in SLeep that talks to the internet. It sends
conditional requests (ETag / Last-Modified) so unchanged feeds are not
downloaded again, retries transient failures, streams large files to disk,
and refuses files above a size limit.
"""

import logging
import os
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import httpx

from .config import USER_AGENT, Settings


logger = logging.getLogger(__name__)

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class FeedHttpError(RuntimeError):
    pass


@dataclass(frozen=True)
class Download:
    path: str
    etag: str | None
    last_modified: str | None


class FeedHttp:
    def __init__(
        self,
        settings: Settings,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self._sleep = sleep
        self.client = httpx.Client(
            timeout=httpx.Timeout(settings.http_timeout_seconds, connect=15.0),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            proxy=settings.proxy_url,
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "FeedHttp":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @contextmanager
    def download(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> Iterator[Download | None]:
        """Stream ``url`` to a temporary file. Yields None when the server answers 304."""
        headers = {}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        handle, path = tempfile.mkstemp(prefix="sleep-vulndb-")
        os.close(handle)
        try:
            result = self._with_retries(url, lambda: self._stream_to_file(url, headers, path))
            yield result
        finally:
            os.unlink(path)

    def get_json(self, url: str) -> Any | None:
        """GET a JSON document. Returns None for 404 (the record no longer exists)."""

        def attempt() -> Any | None:
            response = self.client.get(url)
            if response.status_code == 404:
                return None
            self._raise_for_status(url, response)
            return response.json()

        return self._with_retries(url, attempt)

    @contextmanager
    def lines(self, url: str) -> Iterator[Iterator[str]]:
        """Stream a text document line by line; the caller may stop early."""
        response = self._with_retries(url, lambda: self._open_stream(url))
        try:
            yield response.iter_lines()
        finally:
            response.close()

    def _open_stream(self, url: str) -> httpx.Response:
        response = self.client.send(self.client.build_request("GET", url), stream=True)
        if response.status_code != 200:
            response.read()
            response.close()
            self._raise_for_status(url, response)
        return response

    def _stream_to_file(self, url: str, headers: dict[str, str], path: str) -> Download | None:
        with self.client.stream("GET", url, headers=headers) as response:
            if response.status_code == 304:
                return None
            if response.status_code != 200:
                response.read()
                self._raise_for_status(url, response)
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > self.settings.max_download_bytes:
                raise FeedHttpError(f"{url}: {declared} bytes exceeds the download limit")
            size = 0
            with open(path, "wb") as output:
                for chunk in response.iter_bytes(1024 * 1024):
                    size += len(chunk)
                    if size > self.settings.max_download_bytes:
                        raise FeedHttpError(f"{url}: download exceeds {self.settings.max_download_bytes} bytes")
                    output.write(chunk)
            logger.info("Downloaded %s (%d bytes)", url, size)
            return Download(
                path=path,
                etag=response.headers.get("ETag"),
                last_modified=response.headers.get("Last-Modified"),
            )

    @staticmethod
    def _raise_for_status(url: str, response: httpx.Response) -> None:
        if response.status_code in RETRYABLE_STATUS:
            raise _Retryable(f"{url}: HTTP {response.status_code}")
        if response.status_code >= 400:
            raise FeedHttpError(f"{url}: HTTP {response.status_code}")

    def _with_retries[T](self, url: str, attempt: Callable[[], T]) -> T:
        attempts = self.settings.http_retries + 1
        for number in range(1, attempts + 1):
            try:
                return attempt()
            except (_Retryable, httpx.TransportError) as error:
                if number == attempts:
                    raise FeedHttpError(f"{url}: {error}") from error
                delay = self.settings.http_backoff_seconds * 2 ** (number - 1)
                logger.warning(
                    "Attempt %d/%d for %s failed: %s; retrying in %.0fs", number, attempts, url, error, delay
                )
                self._sleep(delay)
        raise AssertionError("unreachable")


class _Retryable(Exception):
    pass
