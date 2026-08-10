from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
import re
import shutil
import struct
import wave
import zlib
from pathlib import Path, PureWindowsPath
from typing import Any

CONTENT_TYPES = {"text", "image", "audio", "video", "document", "tool_call", "tool_result"}
MIME_ALLOWLIST = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "audio/wav",
    "audio/mpeg",
    "audio/flac",
    "audio/ogg",
    "video/mp4",
    "video/quicktime",
    "video/webm",
    "application/pdf",
    "text/plain",
    "text/csv",
    "application/json",
}
ACTIVE_EXTENSIONS = {".svg", ".svgz", ".html", ".htm", ".docm", ".xlsm", ".pptm"}
BUILT_IN_OFFICIAL_MIME = {"image/png", "image/jpeg", "audio/wav", "text/plain", "text/csv", "application/json"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _magic_mime(path: Path) -> str | None:
    with path.open("rb") as handle:
        head = handle.read(32)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "audio/wav"
    if head.startswith(b"fLaC"):
        return "audio/flac"
    if head.startswith(b"OggS"):
        return "audio/ogg"
    if head.startswith((b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        return "audio/mpeg"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        return "video/quicktime" if brand == b"qt  " else "video/mp4"
    return None


def _inside(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    windows_candidate = PureWindowsPath(relative)
    if ".." in candidate.parts or ".." in windows_candidate.parts:
        raise ValueError("asset path escapes the suite")
    if (
        not relative
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", relative)
        or candidate.is_absolute()
        or windows_candidate.drive
        or candidate.as_posix() != relative
    ):
        raise ValueError("asset must be a local relative path")
    path = root / candidate
    current = root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("asset symlinks are not allowed")
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("asset path escapes the suite") from exc
    if not resolved.is_file() or not os.path.isfile(resolved):
        raise ValueError("asset is not a regular file")
    return resolved


def _snapshot_root(path: Path) -> Path:
    root = path.absolute()
    if any(candidate.is_symlink() for candidate in (root, *root.parents)):
        raise ValueError("asset snapshot paths must not traverse symlinks")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if any(candidate.is_symlink() for candidate in (root, *root.parents)):
        raise ValueError("asset snapshot paths must not traverse symlinks")
    return root


def validate_content_parts(
    value: Any,
    *,
    suite_root: Path,
    official: bool,
    max_asset_bytes: int = 25 * 1024 * 1024,
    max_image_pixels: int = 100_000_000,
    max_audio_seconds: float = 3600.0,
) -> list[str]:
    if isinstance(value, str):
        return [] if value.strip() else ["input text is empty"]
    if not isinstance(value, list) or not value:
        return ["input must be non-empty text or a non-empty content-part array"]

    errors: list[str] = []
    for index, part in enumerate(value):
        prefix = f"input[{index}]"
        if not isinstance(part, dict):
            errors.append(f"{prefix} must be an object")
            continue
        kind = part.get("type")
        if kind not in CONTENT_TYPES:
            errors.append(f"{prefix}.type is invalid")
            continue
        if kind == "text":
            if not isinstance(part.get("text"), str) or not part["text"].strip():
                errors.append(f"{prefix}.text is required")
            continue
        if kind in {"tool_call", "tool_result"}:
            if not isinstance(part.get("name"), str) or not part["name"].strip():
                errors.append(f"{prefix}.name is required")
            if kind == "tool_call" and not isinstance(part.get("arguments"), dict):
                errors.append(f"{prefix}.arguments must be an object")
            continue

        relative = part.get("asset")
        declared = part.get("mime_type")
        if not isinstance(relative, str):
            errors.append(f"{prefix}.asset is required")
            continue
        if Path(relative).suffix.casefold() in ACTIVE_EXTENSIONS:
            errors.append(f"{prefix} active-content file type is not allowed")
            continue
        try:
            path = _inside(suite_root, relative)
        except ValueError as exc:
            errors.append(f"{prefix}: {exc}")
            continue
        size = path.stat().st_size
        if size <= 0 or size > max_asset_bytes:
            errors.append(f"{prefix} asset size is outside 1..{max_asset_bytes} bytes")
        detected = _magic_mime(path)
        guessed = mimetypes.guess_type(path.name)[0]
        effective = detected or guessed
        if not isinstance(declared, str) or declared not in MIME_ALLOWLIST:
            errors.append(f"{prefix}.mime_type is missing or not allowed")
        elif official and declared not in BUILT_IN_OFFICIAL_MIME:
            errors.append(f"{prefix}.mime_type requires an approved sandboxed parser adapter for official runs")
        elif (declared.startswith(("image/", "audio/", "video/")) or declared == "application/pdf") and detected is None:
            errors.append(f"{prefix}.mime_type cannot be verified from file magic")
        elif effective and declared != effective:
            errors.append(f"{prefix}.mime_type does not match file content")
        elif not declared.startswith(kind + "/") and not (kind == "document" and declared in {"application/pdf", "text/plain", "text/csv", "application/json"}):
            errors.append(f"{prefix}.mime_type does not match content type {kind}")
        digest = sha256_file(path)
        pinned = part.get("sha256")
        if official and not isinstance(pinned, str):
            errors.append(f"{prefix}.sha256 is required for official runs")
        elif pinned is not None and pinned != digest:
            errors.append(f"{prefix}.sha256 does not match asset")
        if official:
            for field in ("license", "origin", "personal_data"):
                if not isinstance(part.get(field), str) or not part[field].strip():
                    errors.append(f"{prefix}.{field} is required for official runs")
        if isinstance(declared, str) and declared in MIME_ALLOWLIST:
            metadata = asset_metadata(path, declared)
            if metadata.get("parse_error"):
                errors.append(f"{prefix}: {metadata['parse_error']}")
            if int(metadata.get("pixels", 0)) > max_image_pixels:
                errors.append(f"{prefix} image exceeds {max_image_pixels} pixels")
            if official and metadata.get("animated"):
                errors.append(f"{prefix} animated media requires an approved bounded-frame adapter")
            if float(metadata.get("duration_seconds", 0)) > max_audio_seconds:
                errors.append(f"{prefix} audio exceeds {max_audio_seconds} seconds")
            if declared == "application/pdf":
                folded = path.read_bytes().lower()
                if any(token in folded for token in (b"/javascript", b"/js ", b"/embeddedfile", b"/launch")):
                    errors.append(f"{prefix} PDF contains prohibited active or embedded content")
    return errors


def content_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    chunks: list[str] = []
    for part in value:
        if not isinstance(part, dict):
            continue
        if part.get("type") == "text":
            chunks.append(str(part.get("text", "")))
        elif part.get("type") in {"image", "audio", "video", "document"}:
            chunks.append(f"[{part.get('type')}:{part.get('asset', '')}]")
        elif part.get("type") in {"tool_call", "tool_result"}:
            chunks.append(f"[{part.get('type')}:{part.get('name', '')}]")
    return "\n".join(chunks)


def encoded_content(value: Any, *, suite_root: Path) -> str | list[dict[str, Any]]:
    if isinstance(value, str):
        return value
    encoded: list[dict[str, Any]] = []
    for part in value:
        kind = part["type"]
        if kind == "text":
            encoded.append({"type": "text", "text": part["text"]})
        elif kind in {"image", "audio", "video", "document"}:
            path = _inside(suite_root, str(part["asset"]))
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if part.get("sha256") is not None and part["sha256"] != digest:
                raise ValueError("asset changed after validation")
            encoded.append(
                {
                    "type": kind,
                    "mime_type": part["mime_type"],
                    "sha256": digest,
                    "filename": path.name,
                    "data_base64": base64.b64encode(raw).decode("ascii"),
                }
            )
        else:
            encoded.append(dict(part))
    return encoded


def openai_content(value: Any, *, suite_root: Path) -> str | list[dict[str, Any]]:
    encoded = encoded_content(value, suite_root=suite_root)
    if isinstance(encoded, str):
        return encoded
    parts: list[dict[str, Any]] = []
    for part in encoded:
        kind = part["type"]
        if kind == "text":
            parts.append(part)
        elif kind == "image":
            parts.append({"type": "image_url", "image_url": {"url": f"data:{part['mime_type']};base64,{part['data_base64']}"}})
        elif kind == "audio":
            subtype = str(part["mime_type"]).split("/", 1)[-1].replace("mpeg", "mp3")
            parts.append({"type": "input_audio", "input_audio": {"data": part["data_base64"], "format": subtype}})
        else:
            raise ValueError(f"OpenAI-compatible adapter does not define {kind} input; use the generic JSON adapter")
    return parts


def validate_messages(
    value: Any,
    *,
    suite_root: Path,
    official: bool,
    max_asset_bytes: int,
    max_image_pixels: int = 100_000_000,
    max_audio_seconds: float = 3600.0,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        return ["messages must be a non-empty array"]
    errors: list[str] = []
    roles = {"system", "user", "assistant", "tool"}
    for index, message in enumerate(value):
        if not isinstance(message, dict) or message.get("role") not in roles:
            errors.append(f"messages[{index}].role is invalid")
            continue
        errors.extend(
            f"messages[{index}].{error}"
            for error in validate_content_parts(
                message.get("content"),
                suite_root=suite_root,
                official=official,
                max_asset_bytes=max_asset_bytes,
                max_image_pixels=max_image_pixels,
                max_audio_seconds=max_audio_seconds,
            )
        )
    if isinstance(value[-1], dict) and value[-1].get("role") != "user":
        errors.append("messages must end with a user turn")
    return errors


def encoded_messages(value: list[dict[str, Any]], *, suite_root: Path, openai: bool) -> list[dict[str, Any]]:
    return [
        {
            "role": message["role"],
            "content": openai_content(message["content"], suite_root=suite_root) if openai else encoded_content(message["content"], suite_root=suite_root),
        }
        for message in value
    ]


def _image_dimensions(path: Path, mime_type: str) -> tuple[int, int] | None:
    with path.open("rb") as handle:
        if mime_type == "image/gif":
            head = handle.read(10)
            return struct.unpack("<HH", head[6:10]) if len(head) == 10 else None
        if mime_type == "image/jpeg":
            if handle.read(2) != b"\xff\xd8":
                return None
            for _ in range(512):
                marker = handle.read(2)
                if len(marker) != 2 or marker[0] != 0xFF:
                    return None
                while marker[1] == 0xFF:
                    next_byte = handle.read(1)
                    if not next_byte:
                        return None
                    marker = bytes((0xFF, next_byte[0]))
                if marker[1] in {0xD8, 0xD9}:
                    continue
                length_bytes = handle.read(2)
                if len(length_bytes) != 2:
                    return None
                length = struct.unpack(">H", length_bytes)[0]
                if length < 2:
                    return None
                if marker[1] in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                    data = handle.read(5)
                    return (struct.unpack(">H", data[3:5])[0], struct.unpack(">H", data[1:3])[0]) if len(data) == 5 else None
                handle.seek(length - 2, 1)
    return None


def _png_dimensions(raw: bytes) -> tuple[tuple[int, int] | None, str | None]:
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return None, "invalid PNG signature"
    offset = 8
    dimensions: tuple[int, int] | None = None
    first = True
    while offset + 12 <= len(raw):
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        kind = raw[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(raw):
            return None, "truncated PNG chunk"
        data = raw[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", raw[offset + 8 + length : end])[0]
        if zlib.crc32(kind + data) & 0xFFFFFFFF != expected_crc:
            return None, "PNG chunk CRC mismatch"
        if first and (kind != b"IHDR" or length != 13):
            return None, "PNG must begin with a valid IHDR"
        if kind == b"IHDR":
            dimensions = struct.unpack(">II", data[:8])
            if not all(dimensions):
                return None, "PNG dimensions must be positive"
        if kind == b"IEND":
            if length != 0 or end != len(raw):
                return None, "invalid PNG IEND or trailing data"
            return dimensions, None
        first = False
        offset = end
    return None, "PNG has no complete IEND"


def asset_metadata(path: Path, mime_type: str) -> dict[str, Any]:
    raw = path.read_bytes()
    result: dict[str, Any] = {
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
        "mime_type": mime_type,
        "c2pa_marker_present": b"c2pa" in raw.lower(),
        "c2pa_verified": False,
        "sensitive_metadata_present": any(marker in raw for marker in (b"Exif\x00\x00", b"http://ns.adobe.com/xap/1.0/", b"ID3")),
        "animated": b"acTL" in raw or mime_type == "image/gif",
    }
    if mime_type.startswith("image/"):
        if mime_type == "image/png":
            dimensions, parse_error = _png_dimensions(raw)
            if parse_error:
                result["parse_error"] = parse_error
        else:
            dimensions = _image_dimensions(path, mime_type)
            if mime_type == "image/jpeg" and not raw.endswith(b"\xff\xd9"):
                result["parse_error"] = "JPEG has no end-of-image marker"
        if dimensions:
            result["width"], result["height"] = dimensions
            result["pixels"] = dimensions[0] * dimensions[1]
    elif mime_type == "audio/wav":
        try:
            with wave.open(str(path), "rb") as source:
                frames = source.getnframes()
                rate = source.getframerate()
                result.update(
                    {
                        "channels": source.getnchannels(),
                        "sample_rate": rate,
                        "sample_width_bytes": source.getsampwidth(),
                        "frames": frames,
                        "duration_seconds": frames / rate if rate else 0.0,
                    }
                )
        except (wave.Error, EOFError):
            result["parse_error"] = "invalid WAV container"
    return result


def asset_inventory(cases: list[dict[str, Any]] | tuple[dict[str, Any], ...], *, suite_root: Path, snapshot_dir: Path | None = None) -> list[dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for case in cases:
        values = [case.get("input")]
        values.extend(message.get("content") for message in case.get("messages", []) if isinstance(message, dict))
        for value in values:
            if not isinstance(value, list):
                continue
            for part in value:
                if not isinstance(part, dict) or part.get("type") not in {"image", "audio", "video", "document"}:
                    continue
                path = _inside(suite_root, str(part["asset"]))
                digest = sha256_file(path)
                metadata = asset_metadata(path, str(part["mime_type"]))
                if metadata["sha256"] != digest:
                    raise ValueError("asset changed while its inventory was created")
                entry = inventory.setdefault(digest, metadata)
                if snapshot_dir is not None:
                    snapshot_root = _snapshot_root(snapshot_dir)
                    snapshot = snapshot_root / digest
                    if snapshot.is_symlink():
                        raise ValueError("asset snapshot symlinks are not allowed")
                    if not snapshot.exists():
                        shutil.copyfile(path, snapshot)
                        os.chmod(snapshot, 0o600)
                    if not snapshot.is_file() or sha256_file(snapshot) != digest:
                        raise ValueError("asset snapshot hash mismatch")
                    entry["snapshot"] = snapshot.relative_to(snapshot_root.parent).as_posix()
                cases_for_asset = entry.setdefault("cases", [])
                if case.get("id") not in cases_for_asset:
                    cases_for_asset.append(case.get("id"))
                entry["type"] = part["type"]
                for field in ("license", "origin", "personal_data", "consent_reference"):
                    if field in part:
                        entry[field] = part[field]
    return list(inventory.values())
