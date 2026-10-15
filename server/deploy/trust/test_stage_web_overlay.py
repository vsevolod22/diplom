"""Small disposable-only qualification of the NEW web staging helper.

No Docker, application import, UI build/server, original output mutation or
network. Synthetic package/profile paths are under a fresh owned temp root.
"""

from contextlib import redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import stage_web_overlay as web


class WebOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dip-web-overlay-test-", dir="/private/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / "package"
        self.package.mkdir(mode=0o700)
        self.dist = self.package / "dist"
        (self.dist / "assets").mkdir(parents=True)
        self.repo = self.root / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "server/deploy").mkdir(parents=True)
        (self.repo / "src/public.ts").write_text("export const publicFixture = true;\n")
        (self.repo / "server/deploy/stand.Dockerfile").write_text("COPY --from=build /app/dist /usr/share/nginx/html\n")
        self.files = {"admin.html": b"<html>admin</html>", "assets/app-Abc123.js": b"export const fixture=1;", "index.html": b"<html>index</html>"}
        for name, data in self.files.items():
            (self.dist / name).write_bytes(data)
        self.rows = [{"path": name, "bytes": len(data), "sha256": web.digest(data)}
                     for name, data in sorted(self.files.items())]
        self.profile = web.Profile(package=str(self.package), repo=str(self.repo),
                                   context=str(self.root / "context"), count=len(self.rows),
                                   total=sum(row["bytes"] for row in self.rows),
                                   source_pins=(("src/public.ts", web.digest((self.repo / "src/public.ts").read_bytes())),),
                                   dockerfile_sha256=web.digest((self.repo / "server/deploy/stand.Dockerfile").read_bytes()))
        self.set_manifest(self.rows)

    def set_manifest(self, rows):
        data = web.encoded({"format": "public-built-assets-v1", "files": rows})
        (self.package / "public-assets-manifest.json").write_bytes(data)
        self.profile = replace(self.profile, manifest_sha256=web.digest(data))

    def test_inventory_is_readonly_and_frozen(self):
        receipt = web.prepare(self.profile)
        self.assertEqual(receipt["mode"], "inventory-only")
        self.assertFalse(Path(self.profile.context).exists())
        self.assertFalse(receipt["dockerExecuted"])
        self.assertFalse(receipt["servingQualified"])
        self.assertEqual(receipt["assetFiles"], 3)
        self.assertEqual(len(receipt["buildContextFiles"]), 5)

    def test_stage_exact_merge_context_under_restrictive_umask(self):
        previous = os.umask(0o077)
        try:
            receipt = web.prepare(self.profile, stage=True)
        finally:
            os.umask(previous)
        context = Path(self.profile.context)
        self.assertEqual(stat.S_IMODE(context.stat().st_mode), 0o700)
        for directory in [context / "dist", context / "dist/assets"]:
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        for name, data in self.files.items():
            target = context / "dist" / name
            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertEqual((context / "Dockerfile").read_text(), f"FROM {web.BASE_IMAGE}\nCOPY dist/ /usr/share/nginx/html/\n")
        ignore = (context / ".dockerignore").read_text()
        self.assertTrue(ignore.startswith("**\n!Dockerfile\n!.dockerignore\n!dist/\ndist/*\n!dist/assets/\ndist/assets/*\n"))
        self.assertNotIn("!dist/assets/*", ignore)
        self.assertNotIn("staged-manifest", ignore)
        self.assertEqual(json.loads((context / "staged-manifest.json").read_bytes()), receipt)
        self.assertEqual(set(p.name for p in context.iterdir()), {"Dockerfile", ".dockerignore", "dist", "staged-manifest.json"})

    def test_manifest_paths_and_duplicate_rows_refused_before_asset_reads(self):
        for known in web.PUBLIC_DOTTED_ASSETS:
            web.public_path(known)
        for bad in [".env", "../index.html", "assets/private.key", "assets/notice.js", "assets/LICENSE.js", "assets/app.js.map", "assets/nested/app.js", "assets/app+bad.js", "assets/mermaid.core-unknown.js"]:
            with self.subTest(path=bad):
                rows = [dict(row) for row in self.rows]
                rows[1]["path"] = bad
                self.set_manifest(rows)
                with mock.patch.object(web, "asset_bytes", side_effect=AssertionError("payload read")):
                    with self.assertRaises(web.Refused):
                        web.prepare(self.profile)
        self.set_manifest([self.rows[0], self.rows[0], self.rows[2]])
        with self.assertRaises(web.Refused):
            web.prepare(self.profile)

    def test_unexpected_private_dist_filename_never_opened(self):
        # Synthetic filename only: no bytes exist or are read from a private file.
        fd = os.open(self.dist / ".env", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with mock.patch.object(web, "asset_bytes", side_effect=AssertionError("payload read")):
            with self.assertRaisesRegex(web.Refused, "UNEXPECTED_DIST_NAME"):
                web.prepare(self.profile)
        self.assertFalse(Path(self.profile.context).exists())

    def test_symlink_file_directory_and_ancestor_refused(self):
        asset = self.dist / "assets/app-Abc123.js"
        asset.unlink()
        asset.symlink_to(self.dist / "index.html")
        with self.assertRaises(OSError):
            web.prepare(self.profile)
        asset.unlink()
        asset.write_bytes(self.files["assets/app-Abc123.js"])
        alias = self.root / "alias"
        alias.symlink_to(self.package, target_is_directory=True)
        with self.assertRaises(OSError):
            web.prepare(replace(self.profile, package=str(alias)))
        (self.dist / "assets").rename(self.dist / "saved-assets")
        (self.dist / "assets").symlink_to(self.dist / "saved-assets", target_is_directory=True)
        with self.assertRaises(OSError):
            web.prepare(self.profile)

    def test_hardlink_fifo_and_oversize_refused_without_payload(self):
        asset = self.dist / "assets/app-Abc123.js"
        os.link(asset, self.root / "second-link")
        with self.assertRaisesRegex(web.Refused, "FILE_METADATA"):
            web.prepare(self.profile)
        (self.root / "second-link").unlink()
        asset.unlink()
        os.mkfifo(asset)
        with self.assertRaisesRegex(web.Refused, "FILE_METADATA"):
            web.prepare(self.profile)  # O_NONBLOCK means no FIFO hang.
        asset.unlink()
        with asset.open("wb") as handle:
            handle.truncate(web.MAX_FILE_BYTES + 1)
        with self.assertRaisesRegex(web.Refused, "FILE_METADATA"):
            web.prepare(self.profile)

    def test_asset_manifest_and_current_source_pin_drift_refused(self):
        asset = self.dist / "assets/app-Abc123.js"
        asset.write_bytes(b"changed")
        with self.assertRaisesRegex(web.Refused, "ASSET_PIN"):
            web.prepare(self.profile)
        asset.write_bytes(self.files["assets/app-Abc123.js"])
        with self.assertRaisesRegex(web.Refused, "MANIFEST_PIN"):
            web.prepare(replace(self.profile, manifest_sha256="0" * 64))
        (self.repo / "src/public.ts").write_text("changed source")
        with self.assertRaisesRegex(web.Refused, "SOURCE_PIN"):
            web.prepare(self.profile)
        self.assertFalse(Path(self.profile.context).exists())

    def test_existing_context_refused_and_failed_stage_retained(self):
        context = Path(self.profile.context)
        context.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            web.prepare(self.profile, stage=True)
        context.rmdir()
        with mock.patch.object(web, "write_exclusive", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                web.prepare(self.profile, stage=True)
        self.assertTrue(context.is_dir())
        self.assertFalse((context / "staged-manifest.json").exists())

    def test_cli_authority_and_fixed_inputs_precede_all_io(self):
        valid = ["--stage", "--authorize-reviewed-stage", "--manifest-sha256", web.MANIFEST_SHA256]
        cases = [[], valid[:1] + valid[2:], valid + ["--context", "/private/tmp/foreign"],
                 ["--inventory-only", "--authorize-reviewed-stage", "--manifest-sha256", web.MANIFEST_SHA256],
                 ["--inventory-only", "--manifest-sha256", "0" * 64]]
        with mock.patch.object(web, "prepare", side_effect=AssertionError("IO before CLI fence")):
            for args in cases:
                with self.subTest(args=args), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        web.main(args)
                    self.assertEqual(error.exception.code, 2)

    def test_directory_rebinding_is_detected(self):
        with self.assertRaisesRegex(web.Refused, "DIRECTORY_REBOUND"):
            with web.tree(str(self.package)):
                self.package.rename(self.root / "rebound-original")
                self.package.mkdir(mode=0o700)


if __name__ == "__main__":
    unittest.main()
