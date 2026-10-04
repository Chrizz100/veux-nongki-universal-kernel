#!/usr/bin/env python3
"""Regression tests for repeat installs, changed repo files, and path validation."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
import veux_zip_install as installer


class InstallTests(unittest.TestCase):
    def archive(self, path, rows):
        records = {}
        with zipfile.ZipFile(path, 'w') as archive:
            for name, before, after in rows:
                records[name] = dict(before_sha256=installer.sha(before) if before is not None else None,
                                     after_sha256=installer.sha(after), mode=0o644)
                archive.writestr(name, after)
            archive.writestr(installer.MANIFEST, json.dumps({'schema': 1, 'files': records}))
        return installer.sha(path.read_bytes())

    def test_first_install_and_repeat_preserve_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'; root.mkdir()
            file = root / 'common/a.py'; file.parent.mkdir(); file.write_bytes(b'base')
            archive = Path(tmp) / 'payload.zip'
            digest = self.archive(archive, [('common/a.py', b'base', b'fixed'), ('docs/proof.txt', None, b'proof')])
            self.assertEqual(installer.install(archive, root, digest), 2)
            self.assertEqual(installer.install(archive, root, digest), 0)
            self.assertEqual(file.read_bytes(), b'fixed')

    def test_unknown_change_blocks_every_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'; (root / 'common').mkdir(parents=True)
            first = root / 'common/a.py'; first.write_bytes(b'base')
            second = root / 'common/b.py'; second.write_bytes(b'later fix')
            archive = Path(tmp) / 'payload.zip'
            digest = self.archive(archive, [('common/a.py', b'base', b'new'), ('common/b.py', b'base', b'old payload')])
            with self.assertRaisesRegex(ValueError, 'refusing overwrite'):
                installer.install(archive, root, digest)
            self.assertEqual(first.read_bytes(), b'base')
            self.assertEqual(second.read_bytes(), b'later fix')

    def test_bad_hash_missing_and_invalid_target_fail_without_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'; root.mkdir(); archive = Path(tmp) / 'payload.zip'
            digest = self.archive(archive, [('common/a.py', None, b'new')])
            with self.assertRaisesRegex(ValueError, 'checksum'):
                installer.install(archive, root, '0' * 64)
            with self.assertRaises(FileNotFoundError):
                installer.install(Path(tmp) / 'missing.zip', root, digest)
            for name in ['../escape', 'common/../../escape', '/tmp/escape', 'common/sweet/a', '.github/workflows/a.yml']:
                digest = self.archive(archive, [(name, None, b'new')])
                with self.assertRaisesRegex(ValueError, 'invalid target'):
                    installer.install(archive, root, digest)
            self.assertEqual(list(root.iterdir()), [])

    def test_linked_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'; root.mkdir()
            outside = Path(tmp) / 'outside'; outside.mkdir()
            (root / 'common').symlink_to(outside, target_is_directory=True)
            archive = Path(tmp) / 'payload.zip'
            digest = self.archive(archive, [('common/a.py', None, b'new')])
            with self.assertRaisesRegex(ValueError, 'linked target'):
                installer.install(archive, root, digest)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
