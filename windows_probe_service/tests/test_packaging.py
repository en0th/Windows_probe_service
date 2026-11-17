"""Portable/frozen launcher contracts; no real clipboard or network operations."""
from __future__ import annotations

import contextlib
import ctypes
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))
import service
from network_policy import NetworkPolicy


class FrozenRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)

    def write_rules(self, folder, version="offline-bundle"):
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "cdn_rules.json"
        path.write_text(json.dumps({"version": version, "updatedAt": "2026-11-17",
            "cidrs": [{"cidr": "104.16.0.0/13", "provider": "fixture", "source": "offline"}],
            "domainSuffixes": [{"suffix": "edge.example.invalid", "provider": "fixture", "source": "offline"}]}), encoding="utf-8")
        return path

    def test_source_resource_is_independent_of_working_directory(self):
        other = self.folder / "unrelated-working-directory"
        other.mkdir()
        self.write_rules(other, "must-not-use-cwd")
        previous = Path.cwd()
        try:
            os.chdir(other)
            with patch.object(sys, "frozen", False, create=True):
                actual = service.resource_path("cdn_rules.json")
            self.assertEqual(Path(actual).resolve(), SERVICE_DIR / "cdn_rules.json")
        finally:
            os.chdir(previous)

    def test_frozen_resources_use_extraction_directory(self):
        bundle = self.folder / "_MEI-offline"
        expected = self.write_rules(bundle)
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", str(bundle), create=True):
            self.assertEqual(Path(service.resource_path("cdn_rules.json")), expected)
            self.assertEqual(Path(service.resolve_rules_path(self.folder / "persistent")), expected)

    def test_explicit_persistent_rule_override_is_used(self):
        bundle = self.folder / "_MEI-offline"
        self.write_rules(bundle)
        persistent = self.folder / "persistent"
        expected = self.write_rules(persistent, "custom-updated-rules")
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", str(bundle), create=True):
            actual = service.resolve_rules_path(persistent)
        self.assertEqual(Path(actual), expected)
        self.assertEqual(NetworkPolicy(actual).version, "custom-updated-rules")

    def test_corrupt_override_does_not_silently_revert_to_bundle(self):
        bundle = self.folder / "_MEI-offline"
        self.write_rules(bundle)
        persistent = self.folder / "persistent"
        persistent.mkdir()
        (persistent / "cdn_rules.json").write_text("{broken", encoding="utf-8")
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", str(bundle), create=True):
            selected = service.resolve_rules_path(persistent)
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            NetworkPolicy(selected)

    def test_config_token_persists_across_different_extraction_directories(self):
        persistent = self.folder / "persistent"
        tokens = []
        for name in ("_MEI-first-run", "_MEI-second-run"):
            bundle = self.folder / name
            bundle.mkdir()
            with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", str(bundle), create=True), patch.object(service, "default_data_dir", return_value=persistent):
                settings = service.load_settings()
            tokens.append(settings.token)
            self.assertFalse((bundle / "config.json").exists())
        self.assertEqual(tokens[0], tokens[1])
        self.assertTrue((persistent / "config.json").is_file())

    def test_self_test_reads_bundle_without_secret_files_or_network(self):
        forbidden = AssertionError("self-test must not start a service or probe")
        with patch.object(service, "load_settings", side_effect=forbidden), \
             patch.object(service, "create_app", side_effect=forbidden), \
             patch("dns.asyncresolver.Resolver", side_effect=forbidden), \
             patch("socket.socket", side_effect=forbidden), \
             patch("windows_icmp.ping", side_effect=forbidden), \
             patch("asyncio.open_connection", side_effect=forbidden):
            result = service.run_self_test()
        self.assertIsInstance(result, dict)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["httpStack"], "starlette")
        self.assertEqual(result["validationImplementation"], "python")
        self.assertIs(result["pydanticCoreBundled"], False)
        self.assertIs(result["customDnsServers"], True)
        self.assertEqual(result["dnsServers"], list(service.DEFAULT_DNS_SERVERS))
        self.assertEqual(set(result["dependencies"]), {"starlette", "uvicorn", "dnspython"})
        self.assertNotIn("token", json.dumps(result).lower())
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_frozen_self_test_rejects_legacy_modules_hidden_in_archive(self):
        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "_MEIPASS", str(self.folder), create=True), \
             patch("importlib.util.find_spec", return_value=object()):
            with self.assertRaisesRegex(RuntimeError, "remains in the bundle"):
                service.run_self_test()

    def test_frozen_self_test_rejects_bare_or_nested_legacy_binary(self):
        for relative in ["_pydantic_core.cp312-win_amd64.pyd", "nested/pydantic_core/core.pyd"]:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as directory:
                bundle = Path(directory)
                binary = bundle / relative
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.touch()
                with patch.object(sys, "frozen", True, create=True), \
                     patch.object(sys, "_MEIPASS", str(bundle), create=True), \
                     patch("importlib.util.find_spec", return_value=None):
                    with self.assertRaisesRegex(RuntimeError, "remains in bundled files"):
                        service.run_self_test()

    def test_frozen_self_test_reports_fixed_python_runtime(self):
        bundle = self.folder / "_internal"
        self.write_rules(bundle)
        (bundle / "LICENSE.cdncheck.md").write_text("offline fixture", encoding="utf-8")
        runtime = bundle / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        runtime.touch()
        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "_MEIPASS", str(bundle), create=True), \
             patch.object(sys, "executable", str(self.folder / "SOARProbe.exe")), \
             patch("importlib.util.find_spec", return_value=None):
            result = service.run_self_test()
        self.assertEqual(result["bundleLayout"], "onedir")
        self.assertEqual(result["nativeDependencies"]["pythonRuntime"], str(runtime.resolve()))

    def test_self_test_cli_does_not_create_configuration(self):
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["SOARProbe.exe", "--self-test"]), \
             patch.object(service, "load_settings", side_effect=AssertionError("configuration must not be opened")), \
             contextlib.redirect_stdout(stdout):
            service.main()
        self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")

    def test_copy_token_delegates_to_native_clipboard_without_printing(self):
        token = "offline-pairing-token-not-a-real-secret"
        stdout = io.StringIO()
        with patch.object(service.os, "name", "nt"), \
             patch.object(service, "_windows_clipboard_write") as clipboard, \
             contextlib.redirect_stdout(stdout):
            service.copy_token_to_clipboard(token)
        clipboard.assert_called_once_with(token)
        self.assertNotIn(token, stdout.getvalue())

    def test_copy_token_rejects_non_windows_without_calling_clipboard(self):
        with patch.object(service.os, "name", "posix"), patch.object(service, "_windows_clipboard_write") as clipboard:
            with self.assertRaises((OSError, RuntimeError)):
                service.copy_token_to_clipboard("offline-token")
        clipboard.assert_not_called()

    def clipboard_fixture(self, set_succeeds=True):
        user32, kernel32 = MagicMock(), MagicMock()
        memory = ctypes.create_string_buffer(256)
        kernel32.GetConsoleWindow.return_value = 42
        kernel32.GlobalAlloc.return_value = 1234
        kernel32.GlobalLock.return_value = ctypes.addressof(memory)
        user32.OpenClipboard.side_effect = lambda owner: 1 if owner else 0
        user32.EmptyClipboard.return_value = 1
        user32.SetClipboardData.side_effect = lambda kind, handle: handle if set_succeeds else 0
        libraries = {"user32": user32, "kernel32": kernel32}
        dll = patch.object(ctypes, "WinDLL", side_effect=lambda name, **kwargs: libraries[name], create=True)
        return user32, kernel32, memory, dll

    def test_native_clipboard_has_owner_and_transfers_unicode_memory(self):
        user32, kernel32, memory, dll = self.clipboard_fixture()
        with dll:
            service._windows_clipboard_write("offline-token")
        user32.OpenClipboard.assert_called_once_with(42)
        user32.SetClipboardData.assert_called_once_with(13, 1234)
        user32.CloseClipboard.assert_called_once_with()
        kernel32.GlobalUnlock.assert_called_once_with(1234)
        kernel32.GlobalFree.assert_not_called()
        expected = "offline-token".encode("utf-16-le") + b"\0\0"
        self.assertEqual(memory.raw[:len(expected)], expected)

    def test_native_clipboard_frees_memory_when_transfer_fails(self):
        user32, kernel32, memory, dll = self.clipboard_fixture(set_succeeds=False)
        with dll, self.assertRaises(OSError):
            service._windows_clipboard_write("offline-token")
        user32.CloseClipboard.assert_called_once_with()
        kernel32.GlobalFree.assert_called_once_with(1234)


if __name__ == "__main__":
    unittest.main()
