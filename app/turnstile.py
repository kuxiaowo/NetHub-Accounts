"""Verify single-use Turnstile tokens before account writes."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import current_app, request


class TurnstileUnavailable(Exception):
    pass


def verify_turnstile(action: str) -> bool:
    token = request.form.get("cf-turnstile-response", "")
    if not token or len(token) > 2048:
        return False
    payload = urlencode(
        {
            "secret": current_app.config["TURNSTILE_SECRET_KEY"],
            "response": token,
            "remoteip": request.remote_addr or "",
        }
    ).encode("ascii")
    submission = Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(submission, timeout=4) as response:
            result = json.load(response)
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise TurnstileUnavailable from exc
    return (
        result.get("success") is True
        and result.get("hostname") == current_app.config["TURNSTILE_HOSTNAME"]
        and result.get("action") == action
    )
