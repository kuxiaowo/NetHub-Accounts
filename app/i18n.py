"""Presentation-only language preferences and explicit UI translations."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

from flask import g, render_template, request
from werkzeug.exceptions import HTTPException

ENGLISH = json.loads(
    (Path(__file__).parent / "translations" / "en.json").read_text(encoding="utf-8")
)


def translate(message: str, **values) -> str:
    text = str(message)
    if getattr(g, "language", "zh") == "en":
        text = ENGLISH.get(text, text)
    return text.format(**values) if values else text


def init_i18n(app):
    @app.before_request
    def select_language():
        candidate = request.args.get("lang")
        g.language = (
            candidate if candidate in {"zh", "en"} else request.cookies.get("nethub-language", "zh")
        )
        if g.language not in {"zh", "en"}:
            g.language = "zh"

    @app.after_request
    def remember_language(response):
        if request.args.get("lang") in {"zh", "en"}:
            response.set_cookie(
                "nethub-language",
                g.language,
                max_age=31536000,
                secure=app.config.get("SESSION_COOKIE_SECURE", True),
                samesite="Lax",
            )
        if response.mimetype == "text/html":
            response.headers["Content-Language"] = "en" if g.language == "en" else "zh-CN"
            response.vary.add("Cookie")
        return response

    def language_url(language):
        # Keep OAuth next/state and invitation query values intact.
        pairs = [(key, value) for key, value in request.args.items(multi=True) if key != "lang"]
        return request.path + "?" + urlencode(pairs + [("lang", language)])

    @app.context_processor
    def language_context():
        return {
            "t": translate,
            "language": getattr(g, "language", "zh"),
            "language_url": language_url,
        }

    @app.errorhandler(HTTPException)
    def localized_page_error(error):
        # OAuth, API and machine-readable endpoints retain their protocol response.
        paths = ("/account", "/email/", "/invitations", "/admin", "/login", "/register")
        if (
            not request.path.startswith(paths)
            or request.path.startswith("/admin/analytics/")
            or request.is_json
        ):
            return error
        response = error.get_response()
        default_messages = {
            400: "请求无法处理，请检查输入。",
            403: "你没有权限访问此页面。",
            404: "找不到此页面。",
            409: "状态已变化，请刷新后重试。",
            422: "请检查填写的信息。",
            429: "操作过于频繁，请稍后重试。",
            503: "服务暂时不可用，请稍后重试。",
        }
        message = error.description
        if message == type(error).description:
            message = default_messages.get(error.code, "请检查输入，或稍后重试。")
        response.set_data(render_template("error.html", error=error, error_message=message))
        response.content_type = "text/html; charset=utf-8"
        return response
