from __future__ import annotations

import io
import uuid
from pathlib import Path

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


def test_decoder_rejects_pixel_limit_and_oversized_source(app, monkeypatch, tmp_path):
    oversized_pixels = tmp_path / "oversized-pixels.png"
    oversized_pixels.write_bytes(image_bytes(size=(11, 10)))
    oversized_file = tmp_path / "oversized-file.png"
    oversized_file.write_bytes(b"x" * (app.config["AVATAR_UPLOAD_MAX_BYTES"] + 1))
    with app.app_context():
        monkeypatch.setattr(avatars, "MAX_SOURCE_PIXELS", 100)
        with pytest.raises(avatars.AvatarError, match="像素"):
            avatars._decode_and_compress(oversized_pixels)
        with pytest.raises(avatars.AvatarError, match="5 MiB"):
            avatars._decode_and_compress(oversized_file)


def test_decoder_applies_exif_orientation(app, tmp_path):
    source = Image.new("RGB", (400, 200), "red")
    for x in range(200, 400):
        for y in range(200):
            source.putpixel((x, y), (0, 0, 255))
    exif = Image.Exif()
    exif[274] = 6
    raw = io.BytesIO()
    source.save(raw, format="PNG", exif=exif)

    source_path = tmp_path / "oriented.png"
    source_path.write_bytes(raw.getvalue())
    with app.app_context():
        encoded = avatars._decode_and_compress(source_path)
    with Image.open(io.BytesIO(encoded)) as result:
        top = result.getpixel((256, 80))
        bottom = result.getpixel((256, 432))
        assert top[0] > top[2]
        assert bottom[2] > bottom[0]
        assert not result.getexif()


def test_upload_staging_uses_bounded_reads_and_removes_temporary_file(app):
    class TrackingStream(io.BytesIO):
        largest_read = 0

        def read(self, size=-1):
            self.largest_read = max(self.largest_read, size)
            return super().read(size)

    stream = TrackingStream(image_bytes())
    staged_path: Path | None = None
    with app.app_context():
        with avatars.staged_avatar_upload(stream) as path:
            staged_path = path
            assert path.is_file()
            assert path.stat().st_size == len(stream.getvalue())
        assert stream.largest_read <= avatars.UPLOAD_COPY_CHUNK_BYTES
    assert staged_path is not None
    assert not staged_path.exists()


def test_upload_staging_removes_temporary_file_after_size_error(app, monkeypatch, tmp_path):
    staged_path = tmp_path / "oversized.upload"

    def named_temporary_file(**_kwargs):
        return staged_path.open("w+b")

    monkeypatch.setattr(avatars.tempfile, "NamedTemporaryFile", named_temporary_file)
    oversized = io.BytesIO(b"x" * (app.config["AVATAR_UPLOAD_MAX_BYTES"] + 1))

    with app.app_context(), pytest.raises(avatars.AvatarError, match="5 MiB"):
        with avatars.staged_avatar_upload(oversized):
            pytest.fail("oversized upload must not be yielded")

    assert not staged_path.exists()


def test_avatar_file_response_uses_file_wrapper(app, client):
    with app.app_context():
        user = create_user()
        subject = user.sub
        source_path = app.config["AVATAR_UPLOAD_DIR"].parent / "source.png"
        source_path.write_bytes(image_bytes())
        user.avatar_file = avatars.store_avatar(user, source_path)
        db.session.commit()

    response = client.get(f"/avatars/{subject}", buffered=False)
    assert response.status_code == 200
    assert response.is_streamed
    assert not isinstance(response.response, (bytes, list, tuple))
    response.close()


def test_account_page_exposes_interactive_circle_cropper(app, client):
    with app.app_context():
        create_user()
    login(client)

    page = client.get("/account")
    assert page.status_code == 200
    assert b"data-avatar-crop-stage" in page.data
    assert b"data-avatar-live-preview" in page.data
    assert b"data-avatar-live-canvas" in page.data
    assert b"data-avatar-save disabled" in page.data
    assert "固定圆框".encode() in page.data

    assert b"avatar.js?v=cropper3" in page.data

    script = client.get("/static/avatar.js?v=cropper3")
    assert script.status_code == 200
    assert b"pointerdown" in script.data
    assert b"pointermove" in script.data
    assert b"wheel" in script.data
    assert b"cropInset" in script.data
    assert b"reader.readAsDataURL(file)" in script.data
    assert b"URL.createObjectURL" not in script.data
    assert b"HTMLFormElement.prototype.submit.call(form)" in script.data
