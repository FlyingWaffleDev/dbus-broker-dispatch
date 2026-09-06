#!/usr/bin/env python3
"""Check login hooks without touching the host's buses or service managers."""

import contextlib
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
BACKENDS = ("openrc", "runit", "dinit", "s6")


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.runtime = self.root / "runtime ,%;=é"
        self.runtime.mkdir(mode=0o700)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "commands"
        for name in ("bash", "sleep", "od", "awk", "timeout"):
            (self.bin / name).symlink_to(shutil.which(name))
        for name in ("rc-service", "sv", "dinitctl", "s6-svc"):
            path = self.bin / name
            path.write_text(
                '#!/bin/sh\n'
                'printf "%s\\n" "$@" > "$MOCK_LOG"\n'
                'exit "${MOCK_RESULT:-1}"\n'
            )
            path.chmod(0o755)
        self.env = {
            "PATH": str(self.bin), "HOME": str(self.root),
            "XDG_RUNTIME_DIR": str(self.runtime), "MOCK_LOG": str(self.log),
            # Never let ambient service-control variables select a system service.
            "SVDIR": "/must-not-use", "DINIT_SOCKET_PATH": "/must-not-use",
        }
        self.listen(self.runtime / "dinitctl")

    def listen(self, path):
        listener = self.stack.enter_context(socket.socket(socket.AF_UNIX))
        listener.bind(str(path))
        listener.listen()

    def run_hook(self, backend, changes=None, shell="/bin/sh"):
        env = self.env | (changes or {})
        hook = ROOT / "init" / backend / "dbus-broker-dispatch.sh"
        result = subprocess.run(
            [shell, "-eu", "-c",
             '. "$1"; printf "%s" "${DBUS_SESSION_BUS_ADDRESS:-}"',
             "profile-test", str(hook)],
            env=env, capture_output=True, text=True, timeout=12,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout

    def test_preserve_address_and_backend_selection(self):
        for shell in ("/bin/sh", "/bin/bash"):
            for backend in BACKENDS:
                with self.subTest(shell=shell, backend=backend):
                    address = "unix:path=/private/forwarded-bus"
                    self.assertEqual(self.run_hook(backend, {
                        "DBUS_SESSION_BUS_ADDRESS": address,
                    }, shell), address)
                    self.assertEqual(self.run_hook(backend, {
                        "DBUS_BROKER_DISPATCH_INIT": "none",
                    }, shell), "")
        self.assertFalse(self.log.exists())

    def test_missing_runtime_and_failed_start_allow_login(self):
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                self.assertEqual(self.run_hook(backend, {"XDG_RUNTIME_DIR": ""}), "")
                self.assertEqual(self.run_hook(backend), "")

    def test_existing_socket_is_reused_without_control_commands(self):
        self.listen(self.runtime / "bus")
        for backend in ("runit", "dinit", "s6"):
            for shell in ("/bin/sh", "/bin/bash"):
                with self.subTest(backend=backend, shell=shell):
                    self.assertEqual(unquote(self.run_hook(backend, shell=shell)),
                                     f"unix:path={self.runtime}/bus")
        self.assertFalse(self.log.exists())

    def test_delayed_start_and_explicit_user_control_paths(self):
        for backend, args, overrides in (
            ("runit", ["up", str(self.root / "custom service/dbus")], {
                "DBUS_BROKER_DISPATCH_RUNIT_SERVICE": str(self.root / "custom service/dbus"),
            }),
            ("s6", ["-u", str(self.runtime / "service/dbus")], {}),
            ("dinit", ["--user", "--socket-path", str(self.runtime / "dinitctl"),
                       "start", "--no-wait", "dbus"], {}),
        ):
            with self.subTest(backend=backend):
                self.log.unlink(missing_ok=True)
                ready = threading.Event()

                def create_socket_after_request():
                    while not ready.wait(0.02):
                        if self.log.exists():
                            self.listen(self.runtime / "bus")
                            return

                thread = threading.Thread(target=create_socket_after_request)
                thread.start()
                try:
                    address = self.run_hook(backend, overrides | {"MOCK_RESULT": "0"})
                    self.assertEqual(unquote(address), f"unix:path={self.runtime}/bus")
                    self.assertEqual(self.log.read_text().splitlines(), args)
                finally:
                    ready.set()
                    thread.join()
                    (self.runtime / "bus").unlink(missing_ok=True)

    def test_missing_commands_and_relative_paths_do_not_start_services(self):
        for name in ("sv", "dinitctl", "s6-svc"):
            (self.bin / name).unlink()
        for backend in ("runit", "dinit", "s6"):
            self.assertEqual(self.run_hook(backend), "")
            self.assertEqual(self.run_hook(backend, {"XDG_RUNTIME_DIR": "relative"}), "")
        self.assertFalse(self.log.exists())

    def test_successful_control_without_socket_times_out(self):
        for backend in ("runit", "dinit", "s6"):
            with self.subTest(backend=backend):
                self.assertEqual(self.run_hook(backend, {"MOCK_RESULT": "0"}), "")


if __name__ == "__main__":
    unittest.main()
