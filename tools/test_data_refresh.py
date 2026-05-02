import pathlib
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import data_refresh


class PSLPrivateEntryTests(unittest.TestCase):
    def test_iter_psl_private_entries_preserves_owner_comments(self):
        psl_text = textwrap.dedent("""
            // ===BEGIN ICANN DOMAINS===
            com
            // ===BEGIN PRIVATE DOMAINS===
            // GitHub, Inc.: https://github.com
            github.io
            // Heroku, Inc.
            *.herokuapp.com
            !ignored.herokuapp.com
            """).strip()

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(psl_text)
            psl_path = handle.name

        try:
            entries = list(data_refresh.iter_psl_private_entries(psl_path))
        finally:
            pathlib.Path(psl_path).unlink(missing_ok=True)

        self.assertEqual(
            entries,
            [
                ("github.io", "GitHub, Inc."),
                ("herokuapp.com", "Heroku, Inc."),
                ("ignored.herokuapp.com", "Heroku, Inc."),
            ],
        )


if __name__ == "__main__":
    unittest.main()
