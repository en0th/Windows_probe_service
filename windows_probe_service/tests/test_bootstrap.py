"""Startup failures before FastAPI loads, and portable directory resources."""
from __future__ import annotations

import builtins
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))
import bootstrap
import service


class BootstrapTests(unittest.TestCase):
    def fail_import(self, error):
        original = builtins.__import__

        def importing(name, *args, **kwargs):
            if name == "service":
                raise error
            return original(name, *args, **kwargs)
        return patch("builtins.__import__", side_effect=importing)

    def invoke_failure(self, argv, *, stdin_tty=True, stdout_tty=True, stderr_tty=True,
                       cmd_launcher=False, error=None):
        output = io.StringIO()
        output.isatty = lambda: stderr_tty
        stdin = Mock(isatty=Mock(return_value=stdin_tty))
        error = error or ImportError("DLL load failed: application control policy blocked this file")
        with self.fail_import(error), patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "argv", argv), patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", Mock(isatty=Mock(return_value=stdout_tty))), \
             patch.object(sys, "stderr", output), patch("builtins.input") as pause, \
             patch.dict(os.environ, {"SOAR_PROBE_CMD_LAUNCH": "1" if cmd_launcher else "0"}), \
             patch.object(service, "load_settings", side_effect=AssertionError("must not read configuration")):
            status = bootstrap.launch()
        return status, output.getvalue(), pause

    def test_success_delegates_arguments_and_exit_status_to_service(self):
        fake = types.SimpleNamespace(launch=Mock(return_value=7))
        argv = ["SOARProbe.exe", "--self-test"]
        with patch.dict(sys.modules, {"service": fake}), patch.object(sys, "argv", argv), \
             patch("builtins.input") as pause:
            self.assertEqual(bootstrap.launch(), 7)
            self.assertEqual(sys.argv, argv)
        fake.launch.assert_called_once_with()
        pause.assert_not_called()

    def test_native_import_policy_failure_survives_before_service_launcher(self):
        status, output, pause = self.invoke_failure(["SOARProbe.exe"])
        self.assertEqual(status, 1)
        self.assertIn("Traceback", output)
        self.assertIn("ImportError", output)
        self.assertIn("Smart App Control", output)
        self.assertIn("does not change", output)
        pause.assert_called_once()

    def test_chinese_policy_message_is_recognized(self):
        status, output, _ = self.invoke_failure(["SOARProbe.exe", "--self-test"],
            error=ImportError("DLL load failed: 应用程序控制策略已阻止此文件。"))
        self.assertEqual(status, 1)
        self.assertIn("Windows application control blocked", output)

    def test_automation_commands_and_redirected_streams_never_pause(self):
        cases = [(["SOARProbe.exe", "--self-test"], True, True, True),
                 (["SOARProbe.exe", "--no-interactive"], True, True, True),
                 (["SOARProbe.exe"], False, True, True),
                 (["SOARProbe.exe"], True, False, True),
                 (["SOARProbe.exe"], True, True, False)]
        for argv, stdin_tty, stdout_tty, stderr_tty in cases:
            with self.subTest(argv=argv, stdin_tty=stdin_tty, stdout_tty=stdout_tty, stderr_tty=stderr_tty):
                status, _, pause = self.invoke_failure(argv, stdin_tty=stdin_tty,
                                                       stdout_tty=stdout_tty,
                                                       stderr_tty=stderr_tty)
                self.assertEqual(status, 1)
                pause.assert_not_called()

    def test_cmd_launcher_owns_pause_for_import_and_bootloader_failures(self):
        status, _, pause = self.invoke_failure(["SOARProbe.exe"], cmd_launcher=True)
        self.assertEqual(status, 1)
        pause.assert_not_called()

    def test_startup_diagnostic_does_not_dump_arguments_or_environment(self):
        secret = "test-only-pairing-value-not-a-real-token"
        with patch.dict(os.environ, {"SOAR_PROBE_TEST_SECRET": secret}):
            status, output, _ = self.invoke_failure(["SOARProbe.exe", "--unused", secret],
                error=ImportError("Missing bundled dependency"))
        self.assertEqual(status, 1)
        self.assertNotIn(secret, output)
        self.assertNotIn("SOAR_PROBE_TEST_SECRET", output)
        self.assertNotIn("application control blocked", output)
        self.assertIn("_internal", output)

    def test_closed_console_input_does_not_replace_import_failure(self):
        with patch("builtins.input", side_effect=EOFError), \
             patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "argv", ["SOARProbe.exe"]), \
             patch.object(sys, "stdin", Mock(isatty=Mock(return_value=True))), \
             patch.object(sys, "stdout", Mock(isatty=Mock(return_value=True))), \
             patch.object(sys, "stderr", Mock(isatty=Mock(return_value=True))), \
             patch.dict(os.environ, {"SOAR_PROBE_CMD_LAUNCH": "0"}):
            bootstrap._pause_for_double_click()


class PortableResourceTests(unittest.TestCase):
    def test_onedir_internal_resources_and_persistent_config_remain_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            internal = root / "SOAR portable package" / "_internal"
            internal.mkdir(parents=True)
            (internal / "cdn_rules.json").write_text(json.dumps({"version": "portable-fixture"}), encoding="utf-8")
            persistent = root / "persistent configuration"
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.object(sys, "frozen", True, create=True), \
                     patch.object(sys, "_MEIPASS", str(internal), create=True):
                    self.assertEqual(service.resource_path("cdn_rules.json"), internal / "cdn_rules.json")
                    self.assertEqual(service.resolve_rules_path(persistent), internal / "cdn_rules.json")
                    first = service.load_settings(persistent)
                    second = service.load_settings(persistent)
                self.assertEqual(first.token, second.token)
                self.assertTrue((persistent / "config.json").is_file())
                self.assertFalse((internal / "config.json").exists())
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
