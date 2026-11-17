"""Package and verify an onedir Windows release, using only the standard library.

The directory layout avoids onefile runtime extraction. It does not change or
bypass Windows application-control policy or establish trust in unsigned code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile


APP_NAME = "SOARProbe"
MANIFEST = "SHA256SUMS.txt"
REQUIRED_FILES = {
    "SOARProbe.exe",
    "README.md",
    "LICENSE.cdncheck.md",
    "Start-SOARProbe.cmd",
    "_internal/cdn_rules.json",
    "_internal/LICENSE.cdncheck.md",
}
ROOT_NAMES = {"SOARProbe.exe", "README.md", "LICENSE.cdncheck.md", "Start-SOARProbe.cmd", MANIFEST, "_internal"}
SOURCE_ENVIRONMENT_DIRS = {".git", ".venv", ".build-venv", ".build-cache", "__pycache__"}


def _is_link(path):
    # Junctions are Windows reparse points and can expose files outside APP_DIR
    # even when Path.is_symlink() is false.
    return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0)
                                     & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(name):
    if not isinstance(name, str) or not name or any(char in name for char in "\\\r\n\x00:"):
        raise ValueError("Unsafe release member path")
    path = PurePosixPath(name)
    if path.is_absolute() or name != path.as_posix() or any(part in {".", ".."} for part in name.split("/")):
        raise ValueError("Unsafe release member path")
    if any(part.casefold() in SOURCE_ENVIRONMENT_DIRS for part in path.parts):
        raise ValueError("Source or build environment directory in release")
    if any(part.casefold().startswith(("fastapi", "pydantic", "_pydantic_core")) for part in path.parts):
        raise ValueError("Removed FastAPI/Pydantic dependency in release: " + name)
    if path.parts[0] not in ROOT_NAMES:
        raise ValueError("Unexpected release root member: " + path.parts[0])
    if len(path.parts) > 1 and path.parts[0] != "_internal":
        raise ValueError("Only _internal may contain release subdirectories")
    return path


def _validate_files(names):
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("Release has duplicate or case-colliding member paths")
    for name in names:
        _safe_relative(name)
    if "_internal" in names:
        raise ValueError("_internal must be a directory, not a payload file")
    if not REQUIRED_FILES.issubset(names):
        raise ValueError("Release is missing required files: " + ", ".join(sorted(REQUIRED_FILES - set(names))))
    runtimes = sorted(name for name in names
                      if re.fullmatch(r"_internal/python3\d+(?:t|_d)?\.dll", name, re.IGNORECASE))
    if not runtimes:
        raise ValueError("Release is missing its versioned Python runtime DLL in _internal")
    return runtimes


def _parse_manifest(content):
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Release manifest is not UTF-8") from exc
    entries = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("Release manifest contains an invalid line")
        digest, name = match.groups()
        _safe_relative(name)
        if name == MANIFEST or name in entries:
            raise ValueError("Release manifest contains a duplicate or self reference")
        entries[name] = digest
    return entries


def verify_portable_archive(archive_path):
    """Verify the final ZIP, including every payload file and required resource."""
    archive_path = Path(archive_path)
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        names = []
        prefix = APP_NAME + "/"
        for info in infos:
            if not info.filename.startswith(prefix) or info.is_dir():
                raise ValueError("Portable ZIP must contain files below SOARProbe/ only")
            name = info.filename[len(prefix):]
            _safe_relative(name)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                raise ValueError("Portable ZIP contains a symlink or special file")
            names.append(name)
        runtimes = _validate_files(names)
        if MANIFEST not in names:
            raise ValueError("Portable ZIP is missing its full-file manifest")
        if archive.testzip() is not None:
            raise ValueError("Portable ZIP failed CRC verification")
        entries = _parse_manifest(archive.read(prefix + MANIFEST))
        if set(entries) != set(names) - {MANIFEST}:
            raise ValueError("Portable manifest does not cover every payload file exactly")
        for name, expected in entries.items():
            actual = hashlib.sha256(archive.read(prefix + name)).hexdigest()
            if actual != expected:
                raise ValueError("Portable manifest hash mismatch: " + name)
        return {"fileCount": len(names), "payloadFileCount": len(entries),
                "zipSha256": _sha256_file(archive_path), "exeSha256": entries["SOARProbe.exe"],
                "pythonRuntimePaths": runtimes}


def package_portable(app_dir, output_zip):
    """Write a full-file manifest and an atomically replaced verified ZIP."""
    app_dir, output_zip = Path(app_dir), Path(output_zip)
    if not app_dir.is_dir() or _is_link(app_dir):
        raise ValueError("APP_DIR must be a regular onedir application directory")
    if output_zip.is_symlink() or output_zip.exists() and _is_link(output_zip):
        raise ValueError("Output ZIP must not be a symlink")
    app_dir = app_dir.resolve()
    if output_zip.resolve().is_relative_to(app_dir):
        raise ValueError("Output ZIP must be outside APP_DIR")
    files = {}
    for path in app_dir.rglob("*"):
        name = path.relative_to(app_dir).as_posix()
        _safe_relative(name)
        if _is_link(path):
            raise ValueError("Application directory contains a symlink: " + name)
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("Application directory contains a special file: " + name)
        if name != MANIFEST:
            files[name] = path
    _validate_files(list(files))
    manifest_text = "".join(_sha256_file(files[name]) + "  " + name + "\n" for name in sorted(files))
    manifest_path = app_dir / MANIFEST
    # Any symlink at the manifest path was rejected during the full tree walk.
    manifest_path.write_bytes(manifest_text.encode("utf-8"))
    files[MANIFEST] = manifest_path
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".soar-portable-", suffix=".zip", dir=output_zip.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(temporary_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name in sorted(files):
                archive.write(files[name], APP_NAME + "/" + name)
        result = verify_portable_archive(temporary_path)
        os.replace(temporary_path, output_zip)
    finally:
        temporary_path.unlink(missing_ok=True)
    return {"archive": str(output_zip), **result}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Package and verify a complete SOARProbe Windows onedir release")
    parser.add_argument("app_dir", type=Path)
    parser.add_argument("output_zip", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(package_portable(args.app_dir, args.output_zip), sort_keys=True))


if __name__ == "__main__":
    main()
