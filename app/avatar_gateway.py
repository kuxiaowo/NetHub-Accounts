"""Signed server-side access to the Accounts avatar R2 Worker."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

AVATAR_KEY = re.compile(
    r"avatars/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/[0-9a-f]{24}\.webp"
)


class AvatarGatewayError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AvatarGatewayClient:
    def __init__(self, url: str, secret: str, *, timeout: float = 10.0) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Avatar gateway must be an HTTPS origin")
        if len(secret.encode("utf-8")) < 32 or timeout <= 0:
            raise ValueError("Avatar gateway secret or timeout is invalid")
        self.origin = url.rstrip("/")
        self.secret = secret.encode("utf-8")
        self.timeout = timeout

    def public_url(self, key: str) -> str:
        self._validate_key(key)
        return f"{self.origin}/accounts/media/{key}"

    def put(self, key: str, body: bytes) -> None:
        self._request("PUT", key, body)

    def head(self, key: str) -> tuple[int, str] | None:
        response = self._request("HEAD", key, b"", missing_ok=True)
        if response is None:
            return None
        try:
            return int(response.headers["X-Media-Size"]), response.headers["X-Media-SHA256"]
        except (KeyError, TypeError, ValueError) as exc:
            raise AvatarGatewayError("Avatar gateway returned invalid object metadata") from exc

    def delete(self, key: str) -> None:
        self._request("DELETE", key, b"", missing_ok=True)

    @staticmethod
    def _validate_key(key: str) -> None:
        if not AVATAR_KEY.fullmatch(key):
            raise ValueError("Invalid avatar key")

    def _request(self, method: str, key: str, body: bytes, *, missing_ok: bool = False):
        self._validate_key(key)
        path = f"/internal/object/{key}"
        timestamp = str(int(time.time()))
        digest = hashlib.sha256(body).hexdigest()
        message = f"v1\n{method}\n{path}\n{timestamp}\n{digest}".encode()
        signature = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        headers = {
            "User-Agent": "NetHub-Accounts-Avatar/1.0",
            "X-Media-Timestamp": timestamp,
            "X-Media-Content-SHA256": digest,
            "X-Media-Signature": signature,
            "Content-Length": str(len(body)),
        }
        if method == "PUT":
            headers["Content-Type"] = "image/webp"
        request = urllib.request.Request(
            self.origin + "/accounts" + path,
            data=body if method == "PUT" else None,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if method == "PUT" and response.status != 201:
                    raise AvatarGatewayError("Avatar gateway did not create the object")
                if method == "DELETE" and response.status != 204:
                    raise AvatarGatewayError("Avatar gateway did not delete the object")
                if method == "HEAD" and response.status != 200:
                    raise AvatarGatewayError("Avatar gateway did not find the object")
                return response
        except urllib.error.HTTPError as exc:
            if missing_ok and exc.code == 404:
                return None
            raise AvatarGatewayError(
                f"Avatar gateway returned HTTP {exc.code}", status=exc.code
            ) from exc
        except OSError as exc:
            raise AvatarGatewayError("Avatar gateway request failed") from exc
