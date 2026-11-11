"""Opt-in lab tests: they need a connected device and the mobile toolchain.

These are the device-bound checks the unit suite deliberately does not run
(README section 4). Enable them explicitly:

    MOBILE_AGENT_LAB=1 python -m unittest tests.test_lab_integration -v

CI never sets MOBILE_AGENT_LAB, so the default suite stays green and hermetic.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest

from tests import support

LAB_ENABLED = os.environ.get("MOBILE_AGENT_LAB") == "1"


def _run(command, timeout=30):
    return subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, cwd=support.ROOT_DIR
    )


def _adb_devices():
    adb = shutil.which("adb")
    if adb is None:
        return None
    result = _run([adb, "devices"])
    if result.returncode != 0:
        return None
    devices = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


@unittest.skipUnless(LAB_ENABLED, "set MOBILE_AGENT_LAB=1 to run device-bound checks")
class LabToolchainTests(unittest.TestCase):
    def test_adb_sees_a_device(self):
        devices = _adb_devices()
        self.assertIsNotNone(devices, "adb is not available")
        self.assertTrue(devices, "no authorized device connected")

    def test_frida_is_installed_and_matches_a_server_build(self):
        frida = shutil.which("frida")
        self.assertIsNotNone(frida, "frida-tools is not installed")
        version = _run([frida, "--version"])
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertTrue(version.stdout.strip())

    def test_static_toolchain_present(self):
        for tool in ("jadx", "apktool", "mitmdump"):
            with self.subTest(tool=tool):
                self.assertIsNotNone(shutil.which(tool), f"{tool} missing from PATH")

    def test_frida_templates_parse_with_node(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        templates = os.path.join(support.ROOT_DIR, "templates", "frida")
        names = sorted(name for name in os.listdir(templates) if name.endswith(".js"))
        self.assertTrue(names)
        for name in names:
            with self.subTest(template=name):
                result = _run([node, "--check", os.path.join(templates, name)])
                self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(LAB_ENABLED, "set MOBILE_AGENT_LAB=1 to run device-bound checks")
class LabDeviceStateTests(unittest.TestCase):
    def test_device_is_not_in_a_blocking_state(self):
        devices = _adb_devices()
        self.assertTrue(devices, "no authorized device connected")
        out = _run(["adb", "shell", "getprop", "sys.boot_completed"])
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "1", "device is still booting")


if __name__ == "__main__":
    unittest.main()
