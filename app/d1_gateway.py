"""Small synchronous client for the site's internal D1 gateway.

This module deliberately does not pretend that a remote D1 connection is an
SQLAlchemy transaction.  Callers that need atomicity must submit a batch in a
single request.  The Accounts repository migration can therefore use this
client without putting a Cloudflare API token in the application process.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


class D1GatewayError(RuntimeError):
    """A gateway or D1 execution failure."""


@dataclass(frozen=True)
class Statement:
    sql: str
    params: Sequence[Any] = ()


class D1GatewayClient:
    def __init__(self, url: str, secret: str, *, timeout: float = 10.0) -> None:
        if not url or not secret:
            raise ValueError("D1 gateway URL and secret are required")
        normalized_url = url.rstrip("/")
        self.url = (
            normalized_url
            if normalized_url.endswith("/internal/db")
            else normalized_url + "/internal/db"
        )
        self.secret = secret.encode("utf-8")
        self.timeout = timeout

    def execute(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any]:
        return self._request("single", [Statement(sql, params)])["results"][0]

    def batch(self, statements: Sequence[Statement]) -> list[dict[str, Any]]:
        return self._request("batch", statements)["results"]

    def _request(self, mode: str, statements: Sequence[Statement]) -> dict[str, Any]:
        payload = {
            "requestId": str(uuid.uuid4()),
            "timestamp": int(time.time()),
            "mode": mode,
            "statements": [{"sql": item.sql, "params": list(item.params)} for item in statements],
        }
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        timestamp = str(payload["timestamp"])
        digest = hashlib.sha256(raw).hexdigest()
        message = f"v1\nPOST\n/internal/db\n{payload['requestId']}\n{timestamp}\n{digest}".encode()
        signature = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            self.url,
            data=raw,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "NetHub-D1-Client/1.0",
                "X-DB-Timestamp": timestamp,
                "X-DB-Request-ID": payload["requestId"],
                "X-DB-Signature": signature,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                error_body = json.loads(exc.read().decode("utf-8"))
            except (OSError, UnicodeDecodeError, ValueError):
                error_body = {}
            message = error_body.get("message") or error_body.get("error") or "D1 query failed"
            raise D1GatewayError(str(message)) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise D1GatewayError("D1 gateway request failed") from exc
        results = result.get("results")
        if (
            not isinstance(results, list)
            or len(results) != len(statements)
            or not all(isinstance(item, dict) for item in results)
        ):
            error = result.get("message") or result.get("error") or "D1 query failed"
            raise D1GatewayError(str(error))
        return result
