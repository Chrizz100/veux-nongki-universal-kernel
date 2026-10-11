#!/usr/bin/env python3
"""No-network host regression gates for the VEUX 35217 six-lineage updater.

These tests do not claim a kernel compile. CI must perform source and build gates.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[1]
SCRIPTS=REPO/'common/scripts'
sys.path.insert(0,str(SCRIPTS))
import veux_fleet_35217_nm21_r1 as fleet
import veux_fleet_awinic_r1 as payload

BASE_HEADER='''#define NOMOUNT_BASE_VERSION "21"
enum {
 NM_CMD_UNSPEC = 0,
 NM_CMD_GET_VERSION,
 NM_CMD_ADD_RULE,
};
struct nm_payload {
 u64 magic;
 u32 cmd;
 u32 target_uid;
 int status;
 u32 arg1;
 u32 data_size;
 char buffer[4068];
} __attribute__((packed));
struct nm_rule_hdr { u32 flags; u32 uid; u16 v_len; u16 r_len; } __attribute__((packed));
struct nm_del_hdr { u32 uid; u16 v_len; } __attribute__((packed));
'''


class FleetTests(unittest.TestCase):
    def test_exact_six_kernel_matrix(self):
        self.assertEqual(fleet.KERNELS,('5.4.274','5.4.292','5.4.293','5.4.300','5.4.301','5.4.302'))
        self.assertEqual(len(set(fleet.KERNELS)),6)

    def test_build_provenance_and_canonical_base(self):
        self.assertEqual(fleet.GOOD_SIX_RUN,37745338419)
        self.assertEqual(fleet.GOOD_274_RUN,38131689108)
        self.assertEqual(fleet.GOOD_274_IMAGE_SHA256,
                         'a55edc3f13f7cb663b055d99cb2636e2e41259e8031d688840f4d1032e64172a')
        self.assertEqual(fleet.TARGETS['resukisu']['version'],'35217')
        self.assertEqual(fleet.TARGETS['resukisu']['uapi'],5)
        self.assertEqual(fleet.TARGETS['resukisu']['commit'],
                         'c9246641b9eee8b9986050e8bf1832f88da880c2')
        self.assertEqual(fleet.BUILT_NOMOUNT21,
                         'c7f63e3feb4125d591b6969a33aac04feb40f8ba')
        self.assertEqual(fleet.TARGETS['nomount']['commit'],
                         '1ded61dc908c511072162fa0bee44e6ccdb7b4c7')
        self.assertEqual(fleet.TARGETS['susfs']['commit'],
                         '5326e21a7eb232f9e21debdd5164e99bee3d1e2f')

    def test_no_old_35203_or_nomount20_base_reused(self):
        self.assertNotEqual(fleet.TARGETS['resukisu']['commit'],
                            '8770c7e324a22895703c4916b8a16520e0b81c79')
        self.assertNotEqual(fleet.TARGETS['nomount']['commit'],
                            'c5fad9d8f97c5a207f7342fd91789449915ea047')
        self.assertTrue(all('base' not in target and 'ahead' not in target
                            for target in fleet.TARGETS.values()))

    def test_wire_protocol_same_with_private_vfs_changes(self):
        other=BASE_HEADER+'struct private_vfs { int field; };\n'
        proof=fleet.validate_wire_abi(BASE_HEADER,other)
        self.assertEqual(set(proof),{'enum','nm_payload','nm_rule_hdr','nm_del_hdr'})
        self.assertTrue(all(x=='IDENTICAL' for x in proof.values()))

    def test_wire_protocol_changed_fails_closed(self):
        for new in (BASE_HEADER.replace('char buffer[4068]','char buffer[4067]'),
                    BASE_HEADER.replace('NM_CMD_ADD_RULE,','NM_CMD_ADD_RULE,\n NM_CMD_SUSPICIOUS_NEW,'),
                    BASE_HEADER.replace('u32 target_uid','u64 target_uid'),
                    BASE_HEADER.replace('u16 r_len','u32 r_len'),
                    BASE_HEADER.replace('u16 v_len','u32 v_len')):
            with self.subTest(new=new[:60]):
                with self.assertRaisesRegex(fleet.FleetBlocked,'WIRE_ABI_CHANGED'):
                    fleet.validate_wire_abi(BASE_HEADER,new)

    def test_wire_protocol_missing_or_duplicated_fails_closed(self):
        for new in (BASE_HEADER.replace('struct nm_del_hdr','struct erased'),
                    BASE_HEADER+BASE_HEADER):
            with self.assertRaisesRegex(fleet.FleetBlocked,'WIRE_DECLARATION_MISSING_OR_DUPLICATED'):
                fleet.validate_wire_abi(BASE_HEADER,new)

    def test_reject_mismatched_nomount_version(self):
        with self.assertRaisesRegex(fleet.FleetBlocked,'NOT_NOMOUNT_21'):
            fleet.validate_wire_abi(BASE_HEADER,BASE_HEADER.replace('"21"','"20"'))

    def test_safe_upstream_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'repo';(root/'kernel/include').mkdir(parents=True)
            (root/'uapi').mkdir()
            (root/'kernel/include/uapi').symlink_to('../../uapi')
            links=fleet.safe_symlinks(root)
            self.assertEqual(links,[{'path':'kernel/include/uapi','target':'../../uapi'}])

    def test_reject_symlink_escapes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'repo';root.mkdir()
            target=Path(d)/'outsider';target.write_text('secret')
            (root/'outside').symlink_to('../outsider')
            with self.assertRaisesRegex(fleet.FleetBlocked,'ESCAPING_UPSTREAM_SYMLINK'):
                fleet.safe_symlinks(root)

    def test_reject_absolute_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'repo';root.mkdir()
            (root/'abs').symlink_to(Path(d).resolve())
            with self.assertRaisesRegex(fleet.FleetBlocked,'ABSOLUTE_UPSTREAM_SYMLINK'):
                fleet.safe_symlinks(root)

    def test_reject_cyclic_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'repo';root.mkdir()
            (root/'a').symlink_to('b')
            (root/'b').symlink_to('a')
            with self.assertRaisesRegex(fleet.FleetBlocked,'BROKEN_OR_CYCLIC_SYMLINK'):
                fleet.safe_symlinks(root)

    def test_reject_ambiguous_upstream_response(self):
        with patch.object(fleet,'run',return_value='abc  ref\nabc  ref'):
            with self.assertRaisesRegex(fleet.FleetBlocked,'AMBIGUOUS_UPSTREAM_REF'):
                fleet.remote_head('https://github.com/maxsteeel/nomount.git','refs/heads/master')

    def test_reject_wrong_git_remote(self):
        with self.assertRaisesRegex(fleet.FleetBlocked,'UNKNOWN_SOURCE_HOST'):
            fleet.remote_head('file:///tmp/malicious','refs/heads/master')

    def test_build_requires_reviewed_lineage_and_explicit_optin(self):
        with self.assertRaisesRegex(fleet.FleetBlocked,'UNKNOWN_KERNEL'):
            fleet.build(Path('/tmp'),Path('/tmp'), '5.10.99',4)
        with self.assertRaisesRegex(fleet.FleetBlocked,'INVALID_BUILD_JOBS'):
            fleet.build(Path('/tmp'),Path('/tmp'), '5.4.274',0)

    def test_protected_source_files_match_current_repo(self):
        # This test does not confuse the historical component pins with 35217.
        for relative, expected in fleet.CODE_BLOBS.items():
            f=REPO/relative
            if not f.exists():
                self.skipTest('requires complete checked-out GitHub repo')
            self.assertEqual(fleet.git_blob(f.read_bytes()),expected,relative)

    def test_immutable_awinic_package_integrity(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)/'assets'
            hashes=payload.extract(folder)
            self.assertEqual(set(hashes),set(payload.FILES_SHA256))
            self.assertEqual(hashes['VEUX_AWINIC_R2_GETTER_CANDIDATE.patch'],
                             fleet.AWINIC_PATCH_SHA256)
            for name in hashes:
                self.assertEqual(hashlib.sha256((folder/name).read_bytes()).hexdigest(),hashes[name])

    def test_awinic_package_refuses_overwrite_and_bad_payload(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)/'assets';payload.extract(folder)
            with self.assertRaisesRegex(ValueError,'ALREADY_EXISTS'):
                payload.extract(folder)
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)/'assets'
            with patch.object(payload,'PAYLOAD_B85','invalid payload'):
                with self.assertRaises(Exception):
                    payload.extract(folder)
            self.assertFalse(folder.exists())

    def test_awinic_original_offline_host_tests(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)/'assets';payload.extract(folder)
            p=subprocess.run([sys.executable,'-m','unittest','-v','test_awinic_candidate'],
                             cwd=folder,capture_output=True,text=True,timeout=60)
            self.assertEqual(p.returncode,0,p.stdout+'\n'+p.stderr)

    def test_workflow_is_matrix_and_fail_closed(self):
        try:
            from ruamel.yaml import YAML
        except ImportError:
            self.skipTest('requires pinned YAML parser on GitHub runner')
        path=REPO/'.github/workflows/VEUX_V4_Fleet_35217_NM21_Update_R1.yml'
        y=YAML(typ='safe');y.version=(1,2);y.allow_duplicate_keys=False
        o=y.load(path.read_text())
        self.assertEqual(o['permissions'],{'contents':'read'})
        self.assertEqual(list(o['on']),['workflow_dispatch'])
        self.assertFalse(o['on']['workflow_dispatch']['inputs']['enable_build']['default'])
        self.assertEqual(o['jobs']['fleet']['strategy']['matrix']['kernel'],list(fleet.KERNELS))
        self.assertFalse(o['jobs']['fleet']['strategy']['fail-fast'])
        self.assertGreaterEqual(o['jobs']['fleet']['strategy']['max-parallel'],2)
        text=path.read_text()
        self.assertNotIn('git push ',text)
        self.assertNotIn('contents: write',text)
        self.assertNotIn('promote --bundle',text)
        self.assertIn('ACTIONLINT_FLEET=PASS',text)
        self.assertIn('NO_MAIN_PROMOTION=PASS',text)


if __name__=='__main__':
    unittest.main(verbosity=2)
