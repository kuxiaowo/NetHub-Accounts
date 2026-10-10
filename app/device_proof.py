"""First-party key continuity, never a hardware or real-person identity proof."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from flask import abort, current_app, jsonify, request
from itsdangerous import BadSignature, URLSafeTimedSerializer

PROOF_COOKIE = "__Host-nethub_device_proof"
PROOF_SECONDS = 900
RECOVERY_COOKIE = "__Host-nethub_continuity"
RECOVERY_SECONDS = 30 * 86400
META_FIELDS = {
    "device_key_id",
    "device_verified_at",
    "device_proof_status",
    "client_storage_id",
    "device_identity_source",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def decode(value, length):
    if not isinstance(value, str) or len(value) > 200:
        raise ValueError("invalid encoding")
    result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if len(result) != length:
        raise ValueError("invalid length")
    return result


def public_key(jwk):
    if (
        not isinstance(jwk, dict)
        or jwk.get("kty") != "EC"
        or jwk.get("crv") != "P-256"
        or "d" in jwk
    ):
        raise ValueError("invalid public key")
    normalized = {"kty": "EC", "crv": "P-256"}
    coords = []
    for name in ("x", "y"):
        raw = decode(jwk.get(name), 32)
        normalized[name] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        coords.append(int.from_bytes(raw, "big"))
    key = ec.EllipticCurvePublicNumbers(*coords, ec.SECP256R1()).public_key()
    identity = hashlib.sha256(canonical(normalized).encode()).hexdigest()
    return key, normalized, identity


def database():
    path = Path(
        current_app.config.get("DEVICE_PROOF_DB")
        or Path(current_app.config["ACCOUNTS_ANALYTICS_DB"]).with_name("device-proof.sqlite3")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS device_keys (
          key_id TEXT PRIMARY KEY, public_jwk TEXT NOT NULL, browser_id TEXT NOT NULL,
          first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS device_challenges (
          challenge TEXT PRIMARY KEY, key_id TEXT NOT NULL, public_jwk TEXT NOT NULL,
          browser_id TEXT NOT NULL, host TEXT NOT NULL, installation_id TEXT NOT NULL,
          payload TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS device_challenge_expiry ON device_challenges(expires);
    """)
    return conn


def serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt="nethub-device-proof-v1")


def recovery_serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt="nethub-continuity-v1")


def recovery_metadata(data, host):
    # A bearer token restores a random identifier, never proves the old private key.
    tokens = data.get("recovery_tokens", [])
    if not isinstance(tokens, list):
        tokens = []
    for token in [request.cookies.get(RECOVERY_COOKIE, ""), *tokens[:8]]:
        if not isinstance(token, str) or not 1 <= len(token) <= 2048:
            continue
        try:
            item = recovery_serializer().loads(token, max_age=RECOVERY_SECONDS)
            if item["host"] != host:
                continue
            return {
                "browser_id": str(uuid.UUID(item["browser_id"])),
                "installation_id": str(uuid.UUID(item["installation_id"])),
            }
        except (BadSignature, ValueError, KeyError, TypeError, AttributeError):
            continue
    return {}


def verified_metadata(host):
    try:
        proof = serializer().loads(request.cookies.get(PROOF_COOKIE, ""), max_age=PROOF_SECONDS)
        if proof.get("host") != host or proof.get("browser_id") != request.cookies.get(
            "nethub_browser"
        ):
            return {}
        return {
            "device_key_id": proof["key_id"],
            "device_verified_at": proof["verified_at"],
            "client_storage_id": proof["installation_id"],
            "device_proof_status": "verified",
            "device_identity_source": proof.get("identity_source", "key"),
        }
    except (BadSignature, KeyError, TypeError, AttributeError):
        return {}


def set_browser_cookie(response, identity, host):
    response.set_cookie(
        "nethub_browser",
        identity,
        max_age=30 * 86400,
        secure=True,
        httponly=True,
        samesite="Lax",
        domain="nethub.wiki" if host.endswith("nethub.wiki") else None,
    )


def operation(data, host, cookie_identity):
    now = int(time.time())
    if data["device_operation"] == "challenge":
        try:
            _, jwk, key_id = public_key(data.get("public_key"))
            installation = str(uuid.UUID(data["installation_id"]))
        except (ValueError, TypeError, KeyError):
            abort(400)
        recovery = recovery_metadata(data, host)
        identity = cookie_identity or recovery.get("browser_id") or str(uuid.uuid4())
        source = "cookie" if cookie_identity else "recovery_token" if recovery else "new"
        if recovery and recovery["browser_id"] == identity:
            installation = recovery["installation_id"]
        conn = database()
        try:
            with conn:
                conn.execute("DELETE FROM device_challenges WHERE expires<?", (now,))
                conn.execute("DELETE FROM device_keys WHERE last_seen<?", (now - 30 * 86400,))
                # Cap outstanding challenges as well as the shared request rate limit.
                if conn.execute("SELECT COUNT(*) FROM device_challenges").fetchone()[0] >= 4096:
                    abort(429)
                nonce = secrets.token_urlsafe(32)
                payload = "nethub-device-v1:" + canonical(
                    {
                        "challenge": nonce,
                        "key_id": key_id,
                        "origin": "https://" + host,
                        "purpose": "browser-continuity",
                        "installation_id": installation,
                        "identity_source": source,
                        "expires": now + 120,
                    }
                )
                conn.execute(
                    "INSERT INTO device_challenges VALUES(?,?,?,?,?,?,?,?)",
                    (
                        nonce,
                        key_id,
                        canonical(jwk),
                        identity,
                        host,
                        installation,
                        payload,
                        now + 120,
                    ),
                )
        finally:
            conn.close()
        return jsonify(challenge=nonce, payload=payload)
    if data["device_operation"] != "verify":
        abort(400)
    nonce = data.get("challenge")
    if not isinstance(nonce, str) or len(nonce) > 100:
        abort(400)
    conn = database()
    try:
        # Serialize consumption and key binding; concurrent tabs cannot remap a key.
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM device_challenges WHERE challenge=?", (nonce,)).fetchone()
        if row is None or row["expires"] <= now or row["host"] != host:
            abort(400)
        try:
            signature = decode(data.get("signature"), 64)
            key, _, _ = public_key(json.loads(row["public_jwk"]))
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            )
            key.verify(der, row["payload"].encode(), ec.ECDSA(hashes.SHA256()))
        except (ValueError, TypeError, InvalidSignature):
            abort(400)
        prior = conn.execute(
            "SELECT browser_id FROM device_keys WHERE key_id=?", (row["key_id"],)
        ).fetchone()
        identity = prior["browser_id"] if prior else row["browser_id"]
        conn.execute(
            "INSERT INTO device_keys VALUES(?,?,?,?,?) "
            "ON CONFLICT(key_id) DO UPDATE SET last_seen=excluded.last_seen",
            (row["key_id"], row["public_jwk"], identity, now, now),
        )
        conn.execute("DELETE FROM device_challenges WHERE challenge=?", (nonce,))
        conn.commit()
        proof = {
            "key_id": row["key_id"],
            "host": host,
            "browser_id": identity,
            "installation_id": row["installation_id"],
            "verified_at": now,
            "identity_source": "key"
            if prior
            else json.loads(row["payload"].split(":", 1)[1]).get("identity_source", "new"),
        }
    finally:
        conn.close()
    recovery_token = recovery_serializer().dumps(
        {"host": host, "browser_id": identity, "installation_id": proof["installation_id"]}
    )
    response = jsonify(
        verified=True,
        key_id=proof["key_id"],
        recovery_token=recovery_token,
        installation_id=proof["installation_id"],
        identity_source=proof["identity_source"],
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Nethub-Browser-Id"] = identity
    # The same trusted log channel as existing snapshots; never log signatures/keys.
    info = {
        "device_key_id": proof["key_id"],
        "client_storage_id": proof["installation_id"],
        "device_verified_at": now,
        "device_proof_status": "verified",
        "device_identity_source": proof["identity_source"],
    }
    response.headers["X-Nethub-Client-Info"] = base64.urlsafe_b64encode(
        canonical(info).encode()
    ).decode()
    response.set_cookie(
        PROOF_COOKIE,
        serializer().dumps(proof),
        max_age=PROOF_SECONDS,
        secure=True,
        httponly=True,
        samesite="Strict",
        path="/",
    )
    set_browser_cookie(response, identity, host)
    response.set_cookie(
        RECOVERY_COOKIE,
        recovery_token,
        max_age=RECOVERY_SECONDS,
        secure=True,
        httponly=True,
        samesite="Strict",
        path="/",
    )
    return response
