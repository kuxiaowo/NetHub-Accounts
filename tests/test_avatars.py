from __future__ import annotations

import io
import uuid

import pytest
from PIL import Image

from app import avatars
from app.extensions import db
from app.models import User
from tests.conftest import create_user, csrf_from
from tests.test_accounts import login


def image_bytes(image_format: str = "PNG", *, size=(900, 700), color=(240, 50, 90, 180)):
    output = io.BytesIO()
    mode = "RGBA" if image_format != "JPEG" else "RGB"
    Image.new(mode, size, color[: len(mode)]).save(
        output,
        format=image_format,
        comment=b"metadata that must not survive",
    )
    return output.getvalue()


def test_public_fallback_is_cacheable_and_etag_changes_with_color(app, client):
    with app.app_context():
        user = create_user()
        subject = user.sub

    first = client.get(f"/avatars/{subject}")
    assert first.status_code == 200
    assert first.content_type.startswith("image/svg+xml")
    assert b"#6366f1" in first.data
    assert first.headers["Cache-Control"] == "public, no-cache"
    etag = first.headers["ETag"]
    assert client.get(f"/avatars/{subject}", headers={"If-None-Match": etag}).status_code == 304

    login(client)
    account = client.get("/account")
    changed = client.post(
        "/account/avatar/color",
        data={"csrf_token": csrf_from(account), "avatar_color": "#112233"},
    )
    assert changed.status_code == 302
    updated = client.get(f"/avatars/{subject}")
    assert updated.headers["ETag"] != etag
    assert b"#112233" in updated.data
    assert client.get(f"/avatars/{uuid.uuid4()}").status_code == 404


@pytest.mark.parametrize("image_format", ["JPEG", "PNG", "WEBP"])
def test_upload_reencodes_to_bounded_square_webp(app, client, image_format):
    with app.app_context():
        user = create_user()
        subject = user.sub
    login(client)
    account = client.get("/account")
    response = client.post(
        "/account/avatar",
        data={
            "csrf_token": csrf_from(account),
            "avatar": (io.BytesIO(image_bytes(image_format)), f"source.{image_format.lower()}"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 302

    served = client.get(f"/avatars/{subject}")
    assert served.content_type == "image/webp"
    assert len(served.data) <= app.config["AVATAR_MAX_STORED_BYTES"]
    with Image.open(io.BytesIO(served.data)) as image:
        assert image.size == (512, 512)
        assert image.format == "WEBP"
        assert not image.info.get("exif")
        assert not image.info.get("icc_profile")


def test_replacement_and_delete_clean_up_files(app, client):
    with app.app_context():
        user = create_user()
        user_id = user.id
    login(client)

    def upload(color):
        page = client.get("/account")
        return client.post(
            "/account/avatar",
            data={
                "csrf_token": csrf_from(page),
                "avatar": (io.BytesIO(image_bytes(color=color)), "avatar.png"),
            },
            content_type="multipart/form-data",
        )

    assert upload((200, 20, 20, 255)).status_code == 302
    with app.app_context():
        user = db.session.get(User, user_id)
        first = app.config["AVATAR_UPLOAD_DIR"] / user.sub / user.avatar_file
        assert first.is_file()
    assert upload((20, 20, 200, 255)).status_code == 302
    with app.app_context():
        user = db.session.get(User, user_id)
        second = app.config["AVATAR_UPLOAD_DIR"] / user.sub / user.avatar_file
        assert second.is_file()
        assert second != first
        assert not first.exists()

    page = client.get("/account")
    assert client.post(
        "/account/avatar/delete", data={"csrf_token": csrf_from(page)}
    ).status_code == 302
    assert not second.exists()
    with app.app_context():
        assert db.session.get(User, user_id).avatar_file is None


def test_upload_rejects_bad_input_and_requires_login_and_csrf(app, client):
    with app.app_context():
        create_user()
    assert client.post(
        "/account/avatar", data={"avatar": (io.BytesIO(b"not an image"), "bad.png")}
    ).status_code == 302
    login(client)
    assert client.post(
        "/account/avatar", data={"avatar": (io.BytesIO(b"not an image"), "bad.png")}
    ).status_code == 400
    page = client.get("/account")
    response = client.post(
        "/account/avatar",
        data={
            "csrf_token": csrf_from(page),
            "avatar": (io.BytesIO(b"not an image"), "bad.png"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 302
    assert "不是有效图片".encode() in client.get("/account").data


def test_decoder_rejects_pixel_limit_and_oversized_source(app, monkeypatch):
    with app.app_context():
        monkeypatch.setattr(avatars, "MAX_SOURCE_PIXELS", 100)
        with pytest.raises(avatars.AvatarError, match="像素"):
            avatars._decode_and_compress(image_bytes(size=(11, 10)))
        with pytest.raises(avatars.AvatarError, match="5 MiB"):
            avatars._decode_and_compress(b"x" * (app.config["AVATAR_UPLOAD_MAX_BYTES"] + 1))


def test_decoder_applies_exif_orientation(app):
    source = Image.new("RGB", (400, 200), "red")
    for x in range(200, 400):
        for y in range(200):
            source.putpixel((x, y), (0, 0, 255))
    exif = Image.Exif()
    exif[274] = 6
    raw = io.BytesIO()
    source.save(raw, format="PNG", exif=exif)

    with app.app_context():
        encoded = avatars._decode_and_compress(raw.getvalue())
    with Image.open(io.BytesIO(encoded)) as result:
        top = result.getpixel((256, 80))
        bottom = result.getpixel((256, 432))
        assert top[0] > top[2]
        assert bottom[2] > bottom[0]
        assert not result.getexif()
