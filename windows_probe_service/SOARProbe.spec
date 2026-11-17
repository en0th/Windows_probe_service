# Build with 64-bit Python on Windows: python -m PyInstaller SOARProbe.spec
# SOAR_BUILD_LAYOUT=onedir creates the complete portable directory instead.
import os
from pathlib import Path

from PyInstaller.utils.hooks import copy_metadata

service_dir = Path(SPECPATH)
layout = os.environ.get("SOAR_BUILD_LAYOUT", "onefile").strip().lower()
if layout not in {"onefile", "onedir"}:
    raise ValueError("SOAR_BUILD_LAYOUT must be onefile or onedir")
datas = [
    (str(service_dir / "cdn_rules.json"), "."),
    (str(service_dir / "LICENSE.cdncheck.md"), "."),
]
for distribution in ("fastapi", "pydantic", "pydantic_core", "starlette", "uvicorn", "dnspython", "anyio"):
    datas += copy_metadata(distribution)

a = Analysis(
    [str(service_dir / "bootstrap.py")],
    pathex=[str(service_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "uvicorn.logging",
        "uvicorn.loops.asyncio",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.lifespan.on",
        "dns.asyncbackend",
        "dns._asyncio_backend",
        "anyio._backends._asyncio",
        "update_cdn_rules",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["uvloop", "watchfiles", "websockets", "wsproto"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe_options = dict(
    name="SOARProbe",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
if layout == "onedir":
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True,
              contents_directory="_internal", **exe_options)
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False,
                   name="SOARProbe")
else:
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], **exe_options)
