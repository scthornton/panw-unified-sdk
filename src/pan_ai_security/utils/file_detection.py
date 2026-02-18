"""File type and MIME detection utilities.

Uses stdlib mimetypes as the primary detection method, with fallback to
file extension analysis. No external dependencies required.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path

# File extensions that WildFire can analyze
WILDFIRE_SUPPORTED_EXTENSIONS: set[str] = {
    # Executables
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx",
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".rtf", ".odt", ".ods", ".odp",
    # Archives
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    # Scripts
    ".js", ".vbs", ".ps1", ".bat", ".cmd", ".wsf", ".hta",
    # Mobile
    ".apk", ".ipa",
    # Images (for steganography analysis)
    ".jar", ".class",
    # Emails
    ".eml", ".msg",
    # Other
    ".swf", ".lnk", ".msi",
}

# MIME types that indicate file content (vs text)
FILE_MIME_PREFIXES: tuple[str, ...] = (
    "application/",
    "image/",
    "audio/",
    "video/",
    "font/",
)

TEXT_MIME_PREFIXES: tuple[str, ...] = (
    "text/",
)


def is_file_path(value: str | Path | bytes) -> bool:
    """Check if a value looks like a file path (vs plain text)."""
    if isinstance(value, bytes):
        return True  # Raw bytes are always treated as file content
    if isinstance(value, Path):
        return True
    if isinstance(value, str):
        # Check if it's a path to an existing file
        try:
            p = Path(value)
            if p.exists() and p.is_file():
                return True
        except (OSError, ValueError):
            pass
        # Check if it has a file extension matching WildFire-supported types
        if "." in value:
            ext = Path(value).suffix.lower()
            if ext in WILDFIRE_SUPPORTED_EXTENSIONS:
                return True
    return False


def detect_mime_type(file: str | Path | bytes, filename: str = "") -> str:
    """Detect MIME type for a file.

    Args:
        file: File path or raw bytes.
        filename: Filename hint when file is bytes.

    Returns:
        MIME type string (e.g., "application/pdf").
    """
    if isinstance(file, (str, Path)):
        path = Path(file)
        mime, _ = mimetypes.guess_type(str(path))
        return mime or "application/octet-stream"
    elif isinstance(file, bytes):
        if filename:
            mime, _ = mimetypes.guess_type(filename)
            return mime or "application/octet-stream"
        # Sniff magic bytes for common types
        return _sniff_magic_bytes(file)
    return "application/octet-stream"


def _sniff_magic_bytes(data: bytes) -> str:
    """Basic magic byte detection for common file types."""
    if len(data) < 4:
        return "application/octet-stream"

    # PDF
    if data[:5] == b"%PDF-":
        return "application/pdf"
    # ZIP (also .docx, .xlsx, .pptx, .jar, .apk)
    if data[:4] == b"PK\x03\x04":
        return "application/zip"
    # PE executable
    if data[:2] == b"MZ":
        return "application/x-dosexec"
    # ELF
    if data[:4] == b"\x7fELF":
        return "application/x-elf"
    # GZIP
    if data[:2] == b"\x1f\x8b":
        return "application/gzip"
    # RAR
    if data[:7] == b"Rar!\x1a\x07\x00":
        return "application/x-rar-compressed"

    return "application/octet-stream"
