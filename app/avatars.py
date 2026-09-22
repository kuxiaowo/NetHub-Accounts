from __future__ import annotations

import hashlib
import io
import os
import re
import secrets
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from html import escape
from pathlib import Path
from typing import BinaryIO

from flask import Response, current_app, request, send_file
from PIL import Image, ImageOps, UnidentifiedImageError

from .models import User

ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}
MAX_SOURCE_PIXELS = 25_000_000
COLOR_PATTERN = re.compile(r"^#[0-9a-f]{6}$")
DEFAULT_AVATAR_COLOR = "#6366f1"
UPLOAD_COPY_CHUNK_BYTES = 64 * 1024


class AvatarError(ValueError):
    pass


def normalize_avatar_color(value: str | None) -> str:
    color = str(value or "").strip().lower()
    return color if COLOR_PATTERN.fullmatch(color) else DEFAULT_AVATAR_COLOR


def avatar_url(user: User) -> str:
    return f"{current_app.config['OIDC_ISSUER']}/avatars/{user.sub}"


def _user_directory(user: User) -> Path:
    root = Path(current_app.config["AVATAR_UPLOAD_DIR"]).resolve()
    directory = (root / user.sub).resolve()
    if root not in directory.parents:
        raise AvatarError("头像存储路径无效")
    return directory


@contextmanager
def staged_avatar_upload(stream: BinaryIO) -> Iterator[Path]:
    """Copy an upload to disk in bounded chunks and enforce the source size limit."""
    maximum = current_app.config["AVATAR_UPLOAD_MAX_BYTES"]
    temporary_path: Path | None = None
    total = 0
    try:
        with tempfile.NamedTemporaryFile(
            prefix="nethub-avatar-", suffix=".upload", delete=False
        ) as file:
            temporary_path = Path(file.name)
            while True:
                chunk = stream.read(min(UPLOAD_COPY_CHUNK_BYTES, maximum - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise AvatarError("头像文件不能超过 5 MiB")
                file.write(chunk)
        if total == 0:
            raise AvatarError("头像文件不能为空")
        yield temporary_path
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _decode_and_compress(source_path: Path) -> bytes:
    if not source_path.is_file() or source_path.stat().st_size == 0:
        raise AvatarError("头像文件不能为空")
    if source_path.stat().st_size > current_app.config["AVATAR_UPLOAD_MAX_BYTES"]:
        raise AvatarError("头像文件不能超过 5 MiB")
    try:
        with Image.open(source_path) as probe:
            if probe.format not in ALLOWED_FORMATS:
                raise AvatarError("头像只支持 JPEG、PNG 或 WebP")
            if probe.width * probe.height > MAX_SOURCE_PIXELS:
                raise AvatarError("头像图片像素尺寸过大")
            probe.verify()
        with Image.open(source_path) as source:
            image = ImageOps.exif_transpose(source)
            image.load()
            if image.mode not in {"RGB", "RGBA"}:
                image = image.convert("RGBA" if "transparency" in image.info else "RGB")
            size = current_app.config["AVATAR_SIZE_PX"]
            normalized = ImageOps.fit(
                image,
                (size, size),
                method=Image.Resampling.LANCZOS,
                centering=(0.5, 0.5),
            )
            maximum = current_app.config["AVATAR_MAX_STORED_BYTES"]
            initial_quality = min(95, current_app.config["AVATAR_WEBP_QUALITY"])
            for quality in range(initial_quality, 39, -5):
                output = io.BytesIO()
                normalized.save(output, format="WEBP", quality=quality, method=6)
                encoded = output.getvalue()
                if len(encoded) <= maximum:
                    return encoded
    except AvatarError:
        raise
    except (Image.DecompressionBombError, UnidentifiedImageError, OSError, ValueError) as exc:
        raise AvatarError("头像文件不是有效图片") from exc
    raise AvatarError("头像压缩后仍然过大，请换一张图片")


def store_avatar(user: User, source_path: Path) -> str:
    encoded = _decode_and_compress(source_path)
    directory = _user_directory(user)
    directory.mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(12)}.webp"
    target = directory / filename
    temporary = directory / f".{filename}.tmp"
    try:
        temporary.write_bytes(encoded)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return filename


def delete_avatar_file(user: User, filename: str | None) -> None:
    if not filename or not re.fullmatch(r"[0-9a-f]{24}\.webp", filename):
        return
    directory = _user_directory(user)
    target = (directory / filename).resolve()
    if target.parent != directory.resolve():
        return
    try:
        target.unlink()
        directory.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _etag(user: User) -> str:
    value = "|".join(
        [
            user.sub,
            user.avatar_file or "",
            user.avatar_updated_at.isoformat() if user.avatar_updated_at else "",
            user.display_name,
            normalize_avatar_color(user.avatar_color),
        ]
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def avatar_response(user: User) -> Response:
    etag = _etag(user)
    if request.if_none_match.contains(etag):
        response = Response(status=304)
    elif user.avatar_file:
        path = _user_directory(user) / user.avatar_file
        if path.is_file() and path.parent.resolve() == _user_directory(user).resolve():
            response = send_file(path, mimetype="image/webp", conditional=False, etag=False)
        else:
            response = _fallback_response(user)
    else:
        response = _fallback_response(user)
    response.set_etag(etag)
    response.headers["Cache-Control"] = "public, no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _fallback_response(user: User) -> Response:
    initial = next((item for item in user.display_name.strip() if not item.isspace()), "?").upper()
    color = normalize_avatar_color(user.avatar_color)
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">'
        f'<rect width="512" height="512" fill="{color}"/>'
        '<text x="256" y="276" text-anchor="middle" dominant-baseline="middle" '
        'font-family="system-ui,sans-serif" font-size="220" font-weight="700" fill="white">'
        f"{escape(initial)}</text></svg>"
    )
    return Response(svg.encode("utf-8"), content_type="image/svg+xml; charset=utf-8")
