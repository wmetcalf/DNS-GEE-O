import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import server_common


class RunDNSGeeoTests(unittest.TestCase):
    @patch("tools.server_common.subprocess.check_output")
    def test_run_dnsgeeo_allows_https_doh_url(self, mock_check_output):
        mock_check_output.return_value = b"[]"

        server_common.run_dnsgeeo(
            ["example.com"],
            dns="https://dns.google/dns-query",
            doh=True,
        )

        args = mock_check_output.call_args.args[0]
        self.assertIn("--doh", args)
        dns_index = args.index("--dns")
        self.assertEqual(args[dns_index + 1], "https://dns.google/dns-query")


if __name__ == "__main__":
    unittest.main()
