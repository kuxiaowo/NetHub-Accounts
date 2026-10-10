import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from flask import Flask

from app.client_info import _limits, _proof_limits, client_info
from app.device_proof import PROOF_COOKIE, RECOVERY_COOKIE, database, recovery_serializer

HOST = "nethub.wiki"


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@pytest.fixture()
def setup(tmp_path):
    app = Flask(__name__)
    app.config.update(
        TESTING=True, SECRET_KEY="test-secret", DEVICE_PROOF_DB=str(tmp_path / "proof.db")
    )
    app.register_blueprint(client_info)
    _limits.clear()
    _proof_limits.clear()
    return app, app.test_client()


def post(client, body, host=HOST):
    return client.post(
        "/__nethub/client",
        json=body,
        base_url="https://" + host,
        headers={"Origin": "https://" + host, "Sec-Fetch-Site": "same-origin"},
    )


def begin(client, key=None, tokens=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64(n.x.to_bytes(32, "big")),
        "y": b64(n.y.to_bytes(32, "big")),
    }
    response = post(
        client,
        {
            "device_operation": "challenge",
            "public_key": jwk,
            "installation_id": str(uuid.uuid4()),
            "recovery_tokens": tokens or [],
        },
    )
    assert response.status_code == 200
    r = response.json
    a, b = decode_dss_signature(key.sign(r["payload"].encode(), ec.ECDSA(hashes.SHA256())))
    return key, {
        "device_operation": "verify",
        "challenge": r["challenge"],
        "signature": b64(a.to_bytes(32, "big") + b.to_bytes(32, "big")),
    }


def metadata(response):
    return json.loads(base64.urlsafe_b64decode(response.headers["X-Nethub-Client-Info"]))


def test_restore_requires_same_key_and_replay_is_rejected(setup):
    app, client = setup
    original = str(uuid.uuid4())
    client.set_cookie("nethub_browser", original, domain=HOST)
    key, body = begin(client)
    first = post(client, body)
    assert first.status_code == 200
    assert first.headers["X-Nethub-Browser-Id"] == original
    assert post(client, body).status_code == 400
    client.delete_cookie("nethub_browser", domain=HOST)
    client.delete_cookie(PROOF_COOKIE, domain=HOST)
    _, body = begin(client, key)
    second = post(client, body)
    assert second.headers["X-Nethub-Browser-Id"] == original
    assert first.json["key_id"] == second.json["key_id"]
    assert (
        metadata(post(client, {"device_key_id": "forged", "device_proof_status": "verified"}))[
            "device_key_id"
        ]
        == first.json["key_id"]
    )
    client.delete_cookie("nethub_browser", domain=HOST)
    client.delete_cookie(RECOVERY_COOKIE, domain=HOST)
    _, body = begin(client)
    third = post(client, body)
    assert third.headers["X-Nethub-Browser-Id"] != original
    assert third.json["key_id"] != first.json["key_id"]


def test_wrong_signature_origin_expiry_and_spoofed_metadata(setup):
    app, client = setup
    _, body = begin(client)
    bad = {**body, "signature": b64(bytes(64))}
    assert post(client, bad).status_code == 400
    assert post(client, body, "sdgj.tech").status_code == 400
    with app.app_context():
        conn = database()
        conn.execute("UPDATE device_challenges SET expires=?", (int(time.time()) - 1,))
        conn.commit()
        conn.close()
    assert post(client, body).status_code == 400
    result = metadata(post(client, {"device_key_id": "fake", "device_proof_status": "verified"}))
    assert "device_key_id" not in result
    response = client.post(
        "/__nethub/client",
        json={},
        base_url="https://" + HOST,
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_signature_cannot_verify_modified_challenge(setup):
    app, client = setup
    _, body = begin(client)
    with app.app_context():
        conn = database()
        conn.execute("UPDATE device_challenges SET payload=payload || 'changed'")
        conn.commit()
        conn.close()
    assert post(client, body).status_code == 400


def test_proof_cookie_bound_to_browser_and_host(setup):
    app, client = setup
    _, body = begin(client)
    response = post(client, body)
    assert response.status_code == 200
    assert metadata(post(client, {}))["device_proof_status"] == "verified"
    client.set_cookie("nethub_browser", str(uuid.uuid4()), domain=HOST)
    assert "device_key_id" not in metadata(post(client, {}))


def clear_cookies(client):
    for name in ("nethub_browser", PROOF_COOKIE, RECOVERY_COOKIE):
        client.delete_cookie(name, domain=HOST)


def test_signed_replica_restores_identity_with_new_key_but_is_not_old_key_proof(setup):
    app, client = setup
    _, body = begin(client)
    first = post(client, body)
    original = first.headers["X-Nethub-Browser-Id"]
    clear_cookies(client)
    _, body = begin(client, tokens=["bad-replica", first.json["recovery_token"]])
    second = post(client, body)
    assert second.headers["X-Nethub-Browser-Id"] == original
    assert second.json["installation_id"] == first.json["installation_id"]
    assert second.json["key_id"] != first.json["key_id"]
    assert second.json["identity_source"] == "recovery_token"
    snapshot = metadata(post(client, {"device_identity_source": "key"}))
    assert snapshot["device_identity_source"] == "recovery_token"
    assert snapshot["device_key_id"] == second.json["key_id"]
    assert post(client, body).status_code == 400


@pytest.mark.parametrize("variant", ["tampered", "wrong_host", "expired"])
def test_invalid_recovery_replica_cannot_restore_identity(setup, variant):
    from unittest.mock import patch

    app, client = setup
    _, body = begin(client)
    first = post(client, body)
    token = first.json["recovery_token"]
    if variant == "tampered":
        token = token[:-8] + "AAAAAAAA"
    else:
        with app.app_context():
            data = recovery_serializer().loads(token)
            if variant == "wrong_host":
                data["host"] = "sdgj.tech"
                token = recovery_serializer().dumps(data)
            else:
                with patch("itsdangerous.timed.time.time", return_value=time.time() - 31 * 86400):
                    token = recovery_serializer().dumps(data)
    clear_cookies(client)
    _, body = begin(client, tokens=[token])
    second = post(client, body)
    assert second.headers["X-Nethub-Browser-Id"] != first.headers["X-Nethub-Browser-Id"]
    assert second.json["identity_source"] == "new"


def test_recovery_cookie_only_and_signature_required(setup):
    app, client = setup
    _, body = begin(client)
    first = post(client, body)
    client.delete_cookie("nethub_browser", domain=HOST)
    client.delete_cookie(PROOF_COOKIE, domain=HOST)
    _, body = begin(client)
    assert post(client, {**body, "signature": b64(bytes(64))}).status_code == 400
    assert "device_key_id" not in metadata(post(client, {}))
    # The intervening snapshot generated a cookie; the already signed challenge
    # still restores the identity selected from its valid recovery cookie.
    second = post(client, body)
    assert second.headers["X-Nethub-Browser-Id"] == first.headers["X-Nethub-Browser-Id"]
    assert second.json["identity_source"] == "recovery_token"
