"""Bounded, permission-free client snapshots; Caddy remains the event source."""

from __future__ import annotations

import base64
import json
import math
import time
import uuid
from collections import OrderedDict
from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, request

from .device_proof import META_FIELDS, operation, verified_metadata

client_info = Blueprint("client_info", __name__)
COOKIE = "nethub_browser"
FIELDS = frozenset(
    """
schema page_path language languages timezone timezone_offset locale calendar numbering_system
user_agent platform vendor cookie_enabled webdriver global_privacy_control do_not_track
hardware_concurrency device_memory max_touch_points screen_width screen_height screen_avail_width
screen_avail_height color_depth pixel_depth orientation viewport_width viewport_height pixel_ratio
visual_viewport_scale visibility focused online connection_type effective_type
downlink rtt save_data
dark_mode reduced_motion contrast forced_colors hover pointer_coarse gamut hdr
storage_quota storage_usage storage_persisted battery_level battery_charging battery_charging_time
battery_discharging_time audio_sample_rate video_h264 video_vp9 video_av1 audio_aac audio_opus
webgl_vendor webgl_renderer webgl_version webgl_shading_version
webgl_max_texture_size webgl_extensions
gpu_vendor gpu_architecture gpu_device gpu_description gpu_features
ua_brands ua_mobile ua_platform ua_architecture ua_bitness ua_model ua_platform_version
ua_full_version_list ua_wow64 ua_form_factors canvas_hash audio_hash font_metrics
media_devices permissions api_support navigation_type navigation_duration
dom_content_loaded load_duration
status_ua status_storage status_battery status_gpu status_media status_permissions
status_canvas status_audio
device_key_id device_verified_at device_proof_status client_storage_id
device_identity_source status_device
""".split()
)
_limits: OrderedDict[str, tuple[float, int]] = OrderedDict()
_proof_limits: OrderedDict[str, tuple[float, int]] = OrderedDict()


def clean_snapshot(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("snapshot must be an object")
    result = {}
    for key in sorted(FIELDS & value.keys()):
        item = value[key]
        if item is None or isinstance(item, bool):
            result[key] = item
        elif isinstance(item, (int, float)) and math.isfinite(item) and abs(item) <= 1e15:
            result[key] = item
        elif isinstance(item, str):
            result[key] = item[:512]
        elif isinstance(item, list):
            result[key] = [x[:160] for x in item[:24] if isinstance(x, str)]
    if "page_path" in result:
        path = result["page_path"]
        if not isinstance(path, str) or not path.startswith("/"):
            result.pop("page_path")
        else:
            result["page_path"] = path.split("?", 1)[0].split("#", 1)[0][:256]
    return result


def browser_id(value: str) -> str:
    try:
        return str(uuid.UUID(value)) if len(value) == 36 else ""
    except (ValueError, TypeError, AttributeError):
        return ""


@client_info.get("/__nethub/client.js")
def script():
    response = current_app.send_static_file("client-info.js")
    response.headers["Cache-Control"] = "no-cache"
    return response


@client_info.post("/__nethub/client")
def collect():
    host = request.headers.get("X-Nethub-Site-Host", request.host).lower()
    allowed = {
        "nethub.wiki",
        "auth.nethub.wiki",
        "todolist.nethub.wiki",
        "codex.nethub.wiki",
        "sdgj.tech",
    }
    if current_app.testing:
        allowed.add("localhost")
    origin = urlsplit(request.headers.get("Origin", ""))
    if host not in allowed or origin.netloc.lower() != host or origin.scheme != "https":
        abort(403)
    if request.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin":
        abort(403)
    if request.content_length is None or request.content_length > 16384:
        abort(413)
    if request.mimetype != "application/json":
        abort(415)
    data = request.get_json()
    is_proof = isinstance(data, dict) and "device_operation" in data
    limits = _proof_limits if is_proof else _limits
    identity = browser_id(request.cookies.get(COOKIE, ""))
    rate_key = identity or request.headers.get("CF-Connecting-IP", request.remote_addr or "")[:64]
    now = time.monotonic()
    started, count = limits.get(rate_key, (now, 0))
    if now - started >= 60:
        started, count = now, 0
    limits[rate_key] = (started, count + 1)
    limits.move_to_end(rate_key)
    while len(limits) > 4096:
        limits.popitem(last=False)
    if count >= (60 if is_proof else 20):
        abort(429)
    try:
        if is_proof:
            return operation(data, host, identity)
        snapshot = clean_snapshot(data)
    except ValueError:
        abort(400)
    # Client-provided proof assertions are never trusted. Only a recent server
    # stamp from a successfully consumed cryptographic challenge may supply them.
    for key in META_FIELDS:
        snapshot.pop(key, None)
    snapshot.update(verified_metadata(host))
    encoded = base64.urlsafe_b64encode(
        json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")).encode()
    ).decode()
    if len(encoded) > 10000:
        abort(413)
    identity = identity or str(uuid.uuid4())
    response = current_app.response_class(status=204)
    response.headers["X-Nethub-Client-Info"] = encoded
    response.headers["X-Nethub-Browser-Id"] = identity
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        COOKIE,
        identity,
        max_age=30 * 86400,
        secure=True,
        httponly=True,
        samesite="Lax",
        domain="nethub.wiki" if host.endswith("nethub.wiki") else None,
    )
    return response


@client_info.get("/__nethub/privacy")
def privacy():
    return current_app.send_static_file("client-info-privacy.html")
