import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name('prepare-db-release.py')
spec = importlib.util.spec_from_file_location('prepare_db_release', MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.candidate = self.root / 'candidate'
        self.candidate.mkdir()
        self.output = self.root / 'release'

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, entries):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w:gz') as archive:
            for name, body, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(body) if kind == tarfile.REGTYPE else 0
                archive.addfile(member, io.BytesIO(body) if kind == tarfile.REGTYPE else None)
        raw = layer.getvalue()
        (self.candidate / 'layer.tar.gz').write_bytes(raw)
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                    'layers': [{'mediaType': module.MEDIA, 'size': len(raw), 'digest': digest(raw)}]}
        bytes_ = json.dumps(manifest).encode()
        (self.candidate / 'manifest.json').write_bytes(bytes_)
        return digest(bytes_), digest(raw)

    def entries(self):
        return [('trivy.db', b'db contents', tarfile.REGTYPE),
                ('metadata.json', b'{"Version":2,"UpdatedAt":"2026-10-04T08:52:32.606987838Z","DownloadedAt":"0001-01-01T00:00:00Z","NextUpdate":"2026-10-05T08:52:32.60698742Z"}', tarfile.REGTYPE)]

    def test_valid_archive_creates_gzip_of_db_not_the_oci_tar(self):
        manifest, layer = self.fixture(self.entries())
        result = module.convert(self.candidate, self.output, manifest, layer)
        self.assertEqual((self.output / 'db/trivy.db').read_bytes(), b'db contents')
        import gzip
        self.assertEqual(gzip.decompress((self.output / 'bundle.bin').read_bytes()), b'db contents')
        self.assertEqual(result['db'], digest(b'db contents')[7:])
        self.assertNotEqual(result['bundle'], layer[7:])
        self.assertNotEqual(json.loads((self.output / 'db/metadata.json').read_text())['DownloadedAt'], '0001-01-01T00:00:00Z')
        with self.assertRaises(ValueError):
            module.convert(self.candidate, self.output, manifest, layer)

    def test_compressed_large_pax_header_is_rejected_before_tarfile_allocation(self):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w:gz', format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo('trivy.db')
            info.size = 2
            info.pax_headers = {'comment': 'A' * (3 * 1024 * 1024)}
            archive.addfile(info, io.BytesIO(b'db'))
        compressed = layer.getvalue()
        self.assertLess(len(compressed), 100_000)
        (self.candidate / 'layer.tar.gz').write_bytes(compressed)
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                    'layers': [{'mediaType': module.MEDIA, 'size': len(compressed), 'digest': digest(compressed)}]}
        raw = json.dumps(manifest).encode()
        (self.candidate / 'manifest.json').write_bytes(raw)
        with self.assertRaises(ValueError):
            module.convert(self.candidate, self.output, digest(raw), digest(compressed))
        self.assertFalse(self.output.exists())

    def test_invalid_archives_and_digests_never_publish_a_candidate(self):
        variants = [self.entries() + [('../../escape', b'bad', tarfile.REGTYPE)],
                    self.entries() + [('trivy.db', b'duplicate', tarfile.REGTYPE)],
                    self.entries()[:-1] + [('metadata.json', b'x' * 4097, tarfile.REGTYPE)],
                    self.entries() + [('other', b'', tarfile.SYMTYPE)],
                    self.entries()[:-1]]
        for index, entries in enumerate(variants):
            with self.subTest(index=index):
                manifest, layer = self.fixture(entries)
                with self.assertRaises((ValueError, UnicodeError)):
                    module.convert(self.candidate, self.output, manifest, layer)
                self.assertFalse(self.output.exists())
        manifest, layer = self.fixture(self.entries())
        with self.assertRaises(ValueError):
            module.convert(self.candidate, self.output, digest(b'wrong'), layer)
        self.assertFalse(self.output.exists())
        with self.assertRaises(ValueError):
            module.convert(self.candidate, self.output, manifest, digest(b'wrong'))
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
