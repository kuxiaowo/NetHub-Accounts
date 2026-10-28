from __future__ import annotations

from datetime import timedelta
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from app.extensions import db
from app.models import utc_now
from tests.conftest import create_user, csrf_from
from tests.test_accounts import login


class LanguageLink(HTMLParser):
    url = ""

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "a" and "language-toggle" in values.get("class", ""):
            self.url = values["href"]


def test_language_persists_without_rewriting_oauth_parameters(client):
    destination = "/oauth/authorize?client_id=wiki&state=a%2Bb&redirect_uri=https%3A%2F%2Fwiki.test"
    response = client.get("/login", query_string={"next": destination, "lang": "en"})
    assert response.status_code == 200
    assert '<html lang="en">' in response.text
    assert "Sign in to NetHub" in response.text
    assert 'data-language="en"' in response.text
    assert response.headers["Content-Language"] == "en"
    parser = LanguageLink()
    parser.feed(response.text)
    assert parse_qs(urlsplit(parser.url).query)["next"] == [destination]
    assert parse_qs(urlsplit(parser.url).query)["lang"] == ["zh"]
    assert '<html lang="en">' in client.get("/register").text
    assert '<html lang="zh-CN">' in client.get("/login?lang=zh").text


def test_english_login_error_and_csrf_are_preserved(client):
    page = client.get("/login?lang=en")
    response = client.post(
        "/login",
        data={"csrf_token": csrf_from(page), "username": "missing", "password": "incorrect"},
    )
    assert "Incorrect username or password." in response.text
    assert "用户名或密码错误" not in response.text
    response = client.post("/login", data={"username": "missing", "password": "incorrect"})
    assert response.status_code == 400
    assert "Your form expired" in response.text
    assert response.headers["X-Frame-Options"] == "DENY"


def test_english_account_does_not_translate_user_content(app, client):
    with app.app_context():
        user = create_user()
        user.display_name = "登录"
        user.email = "alice@example.test"
        db.session.commit()
    assert login(client).status_code == 302
    page = client.get("/account?lang=en")
    assert page.status_code == 200
    assert ">登录</h3>" in page.text
    assert 'value="登录"' in page.text
    assert "Save profile" in page.text
    community = client.get("/account/community")
    assert "Email verification" in community.text
    assert "Verify your email first." in community.text
    assert "24 hours" in community.text and "60 seconds" in community.text
    assert "72-hour wait" in community.text and "Valid for 7 days" in community.text
    assert 'name="csrf_token"' in community.text


def test_email_failure_is_english_without_changing_limits(app, client):
    with app.app_context():
        user = create_user()
        user.email = "alice@example.test"
        user.email_verified_at = user.first_email_verified_at = utc_now() - timedelta(days=5)
        db.session.commit()
    login(client)
    page = client.get("/account/community?lang=en")
    response = client.post(
        "/account/email",
        data={"csrf_token": csrf_from(page), "email": "invalid"},
        follow_redirects=True,
    )
    assert "Enter a valid email address." in response.text


def test_invalid_language_uses_safe_default(client):
    response = client.get("/login?lang=%3Cscript%3E")
    assert '<html lang="zh-CN">' in response.text
    assert "nethub-language=" not in response.headers.get("Set-Cookie", "")
