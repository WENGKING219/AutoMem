"""Helpers for saving uploaded memory dumps."""

from __future__ import annotations

from pathlib import Path

from config.settings import SUPPORTED_DUMP_EXTENSIONS


def is_supported_dump_name(filename: str) -> bool:
    """Return True when the filename has a supported memory dump extension."""
    return Path(filename or "").suffix.lower() in SUPPORTED_DUMP_EXTENSIONS


def safe_dump_filename(filename: str) -> str:
    """Return a safe filename for storing an uploaded dump."""
    raw_name = str(filename or "memory_dump").replace("\\", "/")
    name = Path(raw_name).name.strip()
    if not name or name in {".", ".."}:
        name = "memory_dump.raw"

    safe_name = ""
    for char in name:
        if char.isalnum() or char in ("-", "_", "."):
            safe_name += char
        else:
            safe_name += "_"
    return safe_name or "memory_dump.raw"


def unique_dump_path(dumps_dir: Path, filename: str) -> Path:
    """Avoid overwriting an existing dump by adding a simple number suffix."""
    candidate = dumps_dir / filename
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while True:
        numbered = dumps_dir / f"{stem}_{counter}{suffix}"
        if not numbered.exists():
            return numbered
        counter += 1


def uploaded_file_signature(uploaded_file) -> str:
    """Return a stable signature for one selected uploaded file."""
    name = safe_dump_filename(getattr(uploaded_file, "name", ""))
    file_id = getattr(uploaded_file, "file_id", "")
    size = getattr(uploaded_file, "size", None)
    if size is None:
        try:
            current = uploaded_file.tell() if hasattr(uploaded_file, "tell") else 0
            if hasattr(uploaded_file, "seek"):
                uploaded_file.seek(0, 2)
                size = uploaded_file.tell()
                uploaded_file.seek(current)
        except Exception:
            size = "unknown"
    return f"{name}:{size}:{file_id}"


def save_uploaded_dump(uploaded_file, dumps_dir: Path) -> Path:
    """Save a Streamlit UploadedFile to the memory dumps directory."""
    safe_name = safe_dump_filename(getattr(uploaded_file, "name", ""))
    if not is_supported_dump_name(safe_name):
        allowed = ", ".join(SUPPORTED_DUMP_EXTENSIONS)
        raise ValueError(f"Unsupported dump type. Allowed extensions: {allowed}")

    dumps_dir.mkdir(parents=True, exist_ok=True)
    destination = unique_dump_path(dumps_dir, safe_name)

    if hasattr(uploaded_file, "seek"):
        uploaded_file.seek(0)

    with destination.open("wb") as handle:
        while True:
            chunk = uploaded_file.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)

    return destination
