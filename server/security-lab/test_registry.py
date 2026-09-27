import unittest

from diagnostics import scanner_failure
from registry import blobs, digest, manifest


class RegistryFixtureTests(unittest.TestCase):
    def test_manifest_references_exact_fixture_blobs(self):
        import json
        parsed = json.loads(manifest)
        self.assertIn(parsed["config"]["digest"], blobs)
        self.assertIn(parsed["layers"][0]["digest"], blobs)
        self.assertEqual(digest(manifest), "sha256:" + __import__("hashlib").sha256(manifest).hexdigest())

    def test_failure_never_accepts_scanner_output(self):
        secret = "https://example.test/blob?signature=DO_NOT_LOG"
        self.assertNotIn(secret, str(scanner_failure(1)))
        with self.assertRaises(TypeError):
            scanner_failure(1, secret)


if __name__ == "__main__":
    unittest.main()
