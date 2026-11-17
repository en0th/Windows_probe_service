"""Final portable ZIP contracts, without executing an EXE or using the network."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))
from package_portable import package_portable, verify_portable_archive


class PortableArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.app = self.folder / "build output" / "SOARProbe"
        self.zip = self.folder / "release output" / "SOARProbe-Windows-x64-portable.zip"
        payload = {"SOARProbe.exe": b"MZ-offline-fixture",
                   "README.md": "Offline usage\n".encode(),
                   "LICENSE.cdncheck.md": b"license\n",
                   "Start-SOARProbe.cmd": b"@echo off\r\n",
                   "_internal/cdn_rules.json": b"{}\n",
                   "_internal/LICENSE.cdncheck.md": b"license\n",
                   "_internal/python312.dll": b"MZ-python-runtime-fixture",
                   "_internal/runtime/.hidden-dependency": b"included hidden resource"}
        for name, data in payload.items():
            path = self.app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def rewrite_zip(self, transform):
        with zipfile.ZipFile(self.zip) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        transform(members)
        with zipfile.ZipFile(self.zip, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)

    def test_final_zip_covers_every_file_including_hidden_resources_and_python_runtime(self):
        result = package_portable(self.app, self.zip)
        self.assertEqual(result["payloadFileCount"], 8)
        self.assertEqual(result["fileCount"], 9)
        self.assertEqual(result["zipSha256"], hashlib.sha256(self.zip.read_bytes()).hexdigest())
        self.assertEqual(result["exeSha256"], hashlib.sha256((self.app / "SOARProbe.exe").read_bytes()).hexdigest())
        self.assertEqual(result["pythonRuntimePaths"], ["_internal/python312.dll"])
        with zipfile.ZipFile(self.zip) as archive:
            self.assertIn("SOARProbe/_internal/runtime/.hidden-dependency", archive.namelist())
            manifest = archive.read("SOARProbe/SHA256SUMS.txt")
            self.assertNotIn(b"\r", manifest)
            self.assertIn(b"  SOARProbe.exe\n", manifest)
            self.assertTrue(all(name.startswith("SOARProbe/") for name in archive.namelist()))
        self.assertEqual(verify_portable_archive(self.zip)["exeSha256"], result["exeSha256"])

    def test_missing_python_runtime_or_bundled_policy_prevents_packaging(self):
        runtime = self.app / "_internal/python312.dll"
        runtime.unlink()
        with self.assertRaisesRegex(ValueError, "Python runtime DLL"):
            package_portable(self.app, self.zip)
        self.assertFalse(self.zip.exists())
        runtime.write_bytes(b"MZ")
        (self.app / "_internal/cdn_rules.json").unlink()
        with self.assertRaisesRegex(ValueError, "cdn_rules"):
            package_portable(self.app, self.zip)

    def test_runtime_is_not_bound_to_python_312(self):
        (self.app / "_internal/python312.dll").rename(self.app / "_internal/python311.dll")
        result = package_portable(self.app, self.zip)
        self.assertEqual(result["pythonRuntimePaths"], ["_internal/python311.dll"])

    def test_stable_abi_or_nested_python_dll_does_not_replace_runtime(self):
        (self.app / "_internal/python312.dll").rename(self.app / "_internal/python3.dll")
        nested = self.app / "_internal/runtime/python312.dll"
        nested.write_bytes(b"MZ-nested")
        with self.assertRaisesRegex(ValueError, "Python runtime DLL"):
            package_portable(self.app, self.zip)

    def test_removed_dependency_packages_and_metadata_prevent_packaging(self):
        for name in (
            "_internal/fastapi/__init__.py",
            "_internal/pydantic/__init__.py",
            "_internal/pydantic_core/__init__.py",
            "_internal/_pydantic_core.cp312-win_amd64.pyd",
            "_internal/fastapi-0.128.8.dist-info/METADATA",
            "_internal/pydantic-2.13.5.dist-info/METADATA",
            "_internal/pydantic_core-2.46.5.dist-info/METADATA",
            "_internal/PYDANTIC_CORE-2.46.5.dist-info/METADATA",
        ):
            with self.subTest(member=name):
                removed = self.app / name
                removed.parent.mkdir(parents=True, exist_ok=True)
                removed.write_bytes(b"must-not-ship")
                try:
                    with self.assertRaisesRegex(ValueError, "Removed FastAPI/Pydantic"):
                        package_portable(self.app, self.zip)
                    self.assertFalse(self.zip.exists())
                finally:
                    removed.unlink()
                    if removed.parent != self.app / "_internal":
                        removed.parent.rmdir()

    def test_removed_dependency_in_final_zip_is_rejected(self):
        for name in (
            "_internal/pydantic_core/_pydantic_core.cp312-win_amd64.pyd",
            "_internal/fastapi-0.128.8.dist-info/METADATA",
        ):
            with self.subTest(member=name):
                package_portable(self.app, self.zip)
                self.rewrite_zip(lambda members: members.__setitem__("SOARProbe/" + name, b"must-not-ship"))
                with self.assertRaisesRegex(ValueError, "Removed FastAPI/Pydantic"):
                    verify_portable_archive(self.zip)

    def test_symlinks_and_accidental_secret_or_build_files_are_not_packaged(self):
        link = self.app / "_internal/external.dll"
        try:
            link.symlink_to(self.app / "SOARProbe.exe")
        except OSError:
            pass  # Windows developer mode is not required for the other checks.
        else:
            with self.assertRaisesRegex(ValueError, "symlink"):
                package_portable(self.app, self.zip)
            link.unlink()
        (self.app / "config.json").write_text('{"token":"must-not-ship"}')
        with self.assertRaisesRegex(ValueError, "Unexpected release root"):
            package_portable(self.app, self.zip)
        (self.app / "config.json").unlink()
        (self.app / "_internal/.venv").mkdir()
        with self.assertRaisesRegex(ValueError, "environment"):
            package_portable(self.app, self.zip)

    def test_output_inside_application_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside APP_DIR"):
            package_portable(self.app, self.app / "release.zip")

    def test_payload_tampering_and_unlisted_payload_are_detected(self):
        package_portable(self.app, self.zip)
        self.rewrite_zip(lambda members: members.__setitem__("SOARProbe/SOARProbe.exe", b"tampered"))
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_portable_archive(self.zip)
        package_portable(self.app, self.zip)
        self.rewrite_zip(lambda members: members.__setitem__("SOARProbe/_internal/unlisted.dll", b"not in manifest"))
        with self.assertRaisesRegex(ValueError, "cover every"):
            verify_portable_archive(self.zip)

    def test_unsafe_or_duplicate_member_paths_are_rejected(self):
        package_portable(self.app, self.zip)
        self.rewrite_zip(lambda members: members.__setitem__("SOARProbe/_internal/../escape.dll", b"bad"))
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            verify_portable_archive(self.zip)
        package_portable(self.app, self.zip)
        self.rewrite_zip(lambda members: members.__setitem__("SOARProbe/_internal/CDN_RULES.JSON", b"{}"))
        with self.assertRaisesRegex(ValueError, "case-colliding"):
            verify_portable_archive(self.zip)


if __name__ == "__main__":
    unittest.main()
