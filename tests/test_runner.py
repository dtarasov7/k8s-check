import sys
import unittest

from kdiag.runner import DEFAULT_PATH, run_process


class RunnerTest(unittest.TestCase):
    def test_success(self):
        result = run_process([sys.executable, "-c", "print('ok')"], 2, 1024)
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"ok\n", result.stdout)
        self.assertFalse(result.truncated)

    def test_output_limit_terminates_process(self):
        result = run_process([sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"], 2, 128)
        self.assertTrue(result.truncated)
        self.assertEqual(128, len(result.stdout))

    def test_timeout_terminates_process(self):
        result = run_process([sys.executable, "-c", "import time; time.sleep(5)"], 0.1, 128)
        self.assertTrue(result.timed_out)

    def test_missing_binary_is_unsupported(self):
        result = run_process(["/definitely/missing/kdiag-command"], 1, 128)
        record = result.record("missing")
        self.assertEqual("unsupported", record["status"])
        self.assertIn("command unavailable", record["error"])

    def test_deckhouse_binary_directory_is_in_safe_path(self):
        self.assertEqual("/opt/deckhouse/bin", DEFAULT_PATH.split(":")[0])


if __name__ == "__main__":
    unittest.main()
