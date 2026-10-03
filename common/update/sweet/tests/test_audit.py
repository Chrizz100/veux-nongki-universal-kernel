#!/usr/bin/env python3
"""Offline unit tests and a real local-Git archive roundtrip; no kernel build."""
from __future__ import annotations
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SCRIPT_DIR = REPO / 'common' / 'scripts' / 'sweet'
sys.path.insert(0, str(SCRIPT_DIR))
import audit


class ConfigTests(unittest.TestCase):
    def test_active_values(self):
        p = audit.parse_config('CONFIG_A=y\nCONFIG_B=m\nCONFIG_C=27\nCONFIG_D=0xff\n')['values']
        self.assertEqual(p, {'CONFIG_A':'y','CONFIG_B':'m','CONFIG_C':'27','CONFIG_D':'0xff'})

    def test_disabled(self):
        self.assertEqual(audit.parse_config('# CONFIG_A is not set\n')['values'], {'CONFIG_A':'n'})

    def test_noncanonical_disabled_is_not_an_assignment(self):
        p = audit.parse_config('#CONFIG_A is not set\nCONFIG_B=y\n')
        self.assertNotIn('CONFIG_A', p['values'])
        self.assertEqual(len(p['commented_directives']), 1)

    def test_commented_active_is_not_active(self):
        p = audit.parse_config('#CONFIG_A=y\nCONFIG_B=y\n')
        self.assertNotIn('CONFIG_A', p['values'])

    def test_conflicting_duplicate_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            audit.parse_config('CONFIG_A=y\n# CONFIG_A is not set\n')

    def test_identical_duplicate_is_reported(self):
        p = audit.parse_config('CONFIG_A=y\nCONFIG_A=y\n')
        self.assertEqual(len(p['identical_duplicates']), 1)

    def test_strings(self):
        p = audit.parse_config('CONFIG_S="a b \\"x\\""\nCONFIG_E=""\n')['values']
        self.assertEqual(p['CONFIG_E'], '""')

    def test_crlf(self):
        self.assertEqual(audit.parse_config('CONFIG_A=y\r\n')['values'], {'CONFIG_A':'y'})

    def test_bad_syntax(self):
        with self.assertRaises(ValueError):
            audit.parse_config('CONFIG_A=not-valid\n')

    def test_empty_is_rejected(self):
        with self.assertRaises(ValueError):
            audit.parse_config('# only comment\n')

    def test_diff_does_not_turn_absence_into_n(self):
        diff = audit.compare_configs({'CONFIG_A':'n'}, {})
        self.assertEqual(diff['missing'], [{'symbol':'CONFIG_A','stock':'n'}])

    def test_changed_and_added(self):
        d = audit.compare_configs({'CONFIG_A':'y'}, {'CONFIG_A':'m','CONFIG_B':'y'})
        self.assertEqual(d['changed'][0]['candidate'], 'm')
        self.assertEqual(d['added'][0]['symbol'], 'CONFIG_B')


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = json.loads(audit.SOURCE_LOCK.read_text())
        cls.stock_raw = (audit.DEVICE_REFERENCE/'stock.config').read_bytes()
        cls.stock = audit.parse_config(cls.stock_raw.decode())['values']

    def test_stock_hash(self):
        self.assertEqual(hashlib.sha256(self.stock_raw).hexdigest(), self.lock['stock_config_sha256'])

    def test_stock_hash_detects_mutation(self):
        self.assertNotEqual(hashlib.sha256(self.stock_raw + b'x').hexdigest(), self.lock['stock_config_sha256'])

    def test_original_defconfig_exact_git_blob(self):
        self.assertEqual(audit.git_blob((audit.OEM_REFERENCE/'sweet-r-oss.defconfig').read_bytes()),
                         self.lock['sources']['sweet-r-oss']['defconfig_blob'])

    def test_k6a_defconfig_exact_git_blob(self):
        self.assertEqual(audit.git_blob((audit.OEM_REFERENCE/'sweet_k6a-r-oss.defconfig').read_bytes()),
                         self.lock['sources']['sweet_k6a-r-oss']['defconfig_blob'])

    def test_stock_has_all_43_guard_keys(self):
        result = audit.critical_gate(self.stock, self.stock)
        self.assertTrue(result['passed'])
        self.assertEqual(result['checked'], 43)

    def test_fingerprint_drop_blocks(self):
        changed = dict(self.stock); changed.pop('CONFIG_FINGERPRINT_FS_TEE')
        self.assertFalse(audit.critical_gate(self.stock, changed)['passed'])

    def test_haptic_drop_blocks(self):
        changed = dict(self.stock); changed['CONFIG_INPUT_AW8624_HAPTIC'] = 'n'
        self.assertFalse(audit.critical_gate(self.stock, changed)['passed'])

    def test_modversions_drop_blocks(self):
        changed = dict(self.stock); changed['CONFIG_MODVERSIONS'] = 'n'
        self.assertFalse(audit.critical_gate(self.stock, changed)['passed'])

    def test_overlayfs_drop_blocks(self):
        changed = dict(self.stock); changed['CONFIG_OVERLAY_FS'] = 'n'
        self.assertFalse(audit.critical_gate(self.stock, changed)['passed'])

    def test_battery_auth_drop_blocks(self):
        changed = dict(self.stock); changed['CONFIG_BATT_VERIFY_BY_DS28E16'] = 'n'
        self.assertFalse(audit.critical_gate(self.stock, changed)['passed'])

    def test_known_literal_counts_old(self):
        p = audit.parse_config((audit.OEM_REFERENCE/'sweet-r-oss.defconfig').read_text())
        d = audit.compare_configs(self.stock, p['values'])
        self.assertEqual((len(p['values']),d['same'],len(d['changed']),len(d['added'])), (782,763,2,17))

    def test_known_literal_counts_new(self):
        p = audit.parse_config((audit.OEM_REFERENCE/'sweet_k6a-r-oss.defconfig').read_text())
        d = audit.compare_configs(self.stock, p['values'])
        self.assertEqual((len(p['values']),d['same'],len(d['changed']),len(d['added'])), (782,757,5,20))

    def test_no_release_approval(self):
        self.assertFalse(self.lock['release_eligible'])
        self.assertEqual(self.lock['mode'], 'source_and_kconfig_audit_only')


class LocalGitRoundtripTests(unittest.TestCase):
    """A real local repository is cloned, checked and archived, without networking."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sweet-audit-test-')
        self.base = Path(self.temp.name)
        self.origin = self.base/'origin'; self.origin.mkdir()
        self.output = self.base/'output'; self.output.mkdir()
        self.log = self.output/'commands.log'
        subprocess.run(['git','init','--quiet',str(self.origin)],check=True)
        subprocess.run(['git','-C',str(self.origin),'config','user.email','audit-test@example.invalid'],check=True)
        subprocess.run(['git','-C',str(self.origin),'config','user.name','Local audit test'],check=True)
        (self.origin/'Makefile').write_text('VERSION = 4\nPATCHLEVEL = 14\nSUBLEVEL = 180\n')
        (self.origin/'Kconfig').write_text('config FINGERPRINT_FS_TEE\n\tbool "Test fixture"\n# config FAKE\n')
        (self.origin/'link').symlink_to('Kconfig')
        subprocess.run(['git','-C',str(self.origin),'add','.'],check=True)
        subprocess.run(['git','-C',str(self.origin),'commit','--quiet','-m','Fixture'],check=True)
        self.commit = audit.git_output(self.origin,'rev-parse','HEAD')

    def tearDown(self):
        self.temp.cleanup()

    def test_pinned_checkout_and_archive_preserve_bytes_and_symlink(self):
        dest = self.base/'checkout'
        audit.acquire_source(str(self.origin),self.commit,dest,self.log)
        archive = audit.archive_source(dest,'fixture',self.commit,self.output,self.log)
        with tarfile.open(archive) as tf:
            self.assertEqual(tf.extractfile('fixture/Kconfig').read(),(self.origin/'Kconfig').read_bytes())
            self.assertTrue(tf.getmember('fixture/link').issym())
            self.assertEqual(tf.getmember('fixture/link').linkname,'Kconfig')
        verified = audit.verify_source_archive(dest,archive,'fixture',self.commit)
        self.assertTrue(verified['all_git_blobs_matched'])
        self.assertEqual((verified['entries'],verified['symlinks']),(3,1))
        self.assertEqual(audit.git_output(dest,'rev-parse','HEAD'),self.commit)
        self.assertEqual(audit.git_output(dest,'status','--porcelain'),'')

    def test_archive_missing_files_is_rejected(self):
        archive = self.output/'incomplete.tar.gz'
        with tarfile.open(archive,'w:gz'):
            pass
        with self.assertRaisesRegex(ValueError,'omits'):
            audit.verify_source_archive(self.origin,archive,'fixture',self.commit)

    def test_archive_altered_contents_are_rejected(self):
        archive = self.output/'altered.tar.gz'
        with tarfile.open(archive,'w:gz') as tf:
            data = b'changed contents'
            info = tarfile.TarInfo('fixture/Kconfig'); info.size = len(data)
            info.mode = 0o644
            tf.addfile(info,io.BytesIO(data))
        with self.assertRaisesRegex(ValueError,'differ from Git blob'):
            audit.verify_source_archive(self.origin,archive,'fixture',self.commit)

    def test_kconfig_inventory_is_lexical(self):
        inv = audit.inventory_kconfig(self.origin)
        self.assertIn('CONFIG_FINGERPRINT_FS_TEE', inv['symbols'])
        self.assertNotIn('CONFIG_FAKE', inv['symbols'])
        self.assertEqual(inv['files_scanned'],1)

    def test_invalid_commit_is_rejected(self):
        with self.assertRaises(ValueError):
            audit.acquire_source(str(self.origin),'main',self.base/'checkout',self.log)

    def test_existing_directory_is_not_overwritten(self):
        with self.assertRaises(FileExistsError):
            audit.acquire_source(str(self.origin),self.commit,self.origin,self.log)

    def test_archive_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            audit.archive_source(self.origin,'../bad',self.commit,self.output,self.log)

    def test_command_failure_propagates(self):
        with self.assertRaises(RuntimeError):
            audit.run([sys.executable,'-c','raise SystemExit(7)'],self.log)

    def test_checksum_manifest(self):
        (self.output/'x').write_bytes(b'hello')
        audit.save_checksums(self.output)
        digest, name = (self.output/'SHA256SUMS.txt').read_text().strip().split('  ',1)
        self.assertEqual((digest,name),(hashlib.sha256(b'hello').hexdigest(),'x'))

    def test_version_parser(self):
        self.assertEqual(audit.version_from_makefile((self.origin/'Makefile').read_text()),'4.14.180')

    def test_version_parser_rejects_missing_fields(self):
        with self.assertRaises(ValueError):
            audit.version_from_makefile('VERSION = 4\n')


if __name__ == '__main__':
    unittest.main()
