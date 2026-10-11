#!/usr/bin/env python3
"""Offline regression test for the fail-closed, CURRENT_BUILD-based V4 resolver."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common/scripts'))
import VEUX_V4_Engine_Compat_R1 as patcher


class MigrationTests(unittest.TestCase):
    BASE = '''\nimport re\ndef resolve(work):\n    base = m["stable"]["commit"]\n    entry.update(uapi=4)\n    require("KERNEL_SU_UAPI_VERSION = 4;")\n    match = re.search(r'#define NOMOUNT_VERSION "([^\\\"]+)"', x)\n\ndef parse_env(path):\n    return {}\n'''

    def test_replacement_keeps_other_code(self):
        new = patcher.prepare(self.BASE)
        self.assertIn('def parse_env(path):', new)
        self.assertIn('from veux_current_components import checked_uapi', new)
        self.assertIn('NOMOUNT_BASE_VERSION', new)
        self.assertIn('COMPATIBILITY-REVIEW.json', new)
        compile(new, '<candidate>', 'exec')
        self.assertEqual(new.count(patcher.MARKER), 1)

    def test_replacement_rejects_double_migration_or_drift(self):
        new = patcher.prepare(self.BASE)
        with self.assertRaises(patcher.MigrationBlocked):
            patcher.prepare(new)
        with self.assertRaises(patcher.MigrationBlocked):
            patcher.prepare(self.BASE.replace('uapi=4', 'uapi=5'))
        with self.assertRaises(patcher.MigrationBlocked):
            patcher.prepare(self.BASE + '\ndef parse_env(path):\n')

    def test_blob_digest_is_native_git_blob(self):
        self.assertEqual(patcher.git_blob(b'hello\n'),
                         'ce013625030ba8dba906f756967f9e9ca394464a')

    def test_prepare_staged_output_and_preserve_original(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp=Path(temp)
            repo=tmp/'checkout'
            engine=repo/patcher.ENGINE_PATH
            resolver=repo/patcher.RESOLVER_PATH
            contract=repo/patcher.CURRENT_PATH
            for p in (engine,resolver,contract):p.parent.mkdir(parents=True,exist_ok=True)
            engine.write_text(self.BASE)
            resolver.write_text('# resolver source baseline fixture\n')
            targets={
                name: {'commit':commit, 'url':'https://example.org/'+name+'.git',
                       'ref':'refs/heads/main',
                       **({'uapi':5} if name=='resukisu' else {})}
                for name,commit in patcher.EXPECTED_INTEGRATED.items()
            }
            data={'status':'compile-package-static-validated','device_pass_inferred':False,
                  'targets':targets,'lineages':{
                      f'5.4.{n}':{'targets':targets}
                      for n in (274,292,293,300,301,302)}}
            contract.write_text(json.dumps(data))
            before=(engine.read_bytes(),resolver.read_bytes(),contract.read_bytes())
            output=tmp/'out'
            with mock.patch.object(patcher,'EXPECTED_ENGINE_BLOB',patcher.git_blob(before[0])), \
                 mock.patch.object(patcher,'EXPECTED_RESOLVER_BLOB',patcher.git_blob(before[1])), \
                 mock.patch('sys.argv', ['migration','--repo',str(repo),'--output',str(output)]):
                self.assertEqual(patcher.main(),0)
                self.assertEqual((engine.read_bytes(),resolver.read_bytes(),contract.read_bytes()),before)
                replacement=(output/patcher.ENGINE_PATH).read_text()
                compile(replacement,'replacement','exec')
                self.assertIn('CURRENT_BUILD-authoritative UAPI5/NoMount21',replacement)
                evidence=json.loads((output/'VEUX_V4_ENGINE_MIGRATION_R1.json').read_text())
                self.assertFalse(evidence['kernel_build_approved'])
                self.assertFalse(evidence['repository_modified'])
            inside=repo/'bad-output'
            with mock.patch.object(patcher,'EXPECTED_ENGINE_BLOB',patcher.git_blob(before[0])), \
                 mock.patch.object(patcher,'EXPECTED_RESOLVER_BLOB',patcher.git_blob(before[1])), \
                 mock.patch('sys.argv', ['migration','--repo',str(repo),'--output',str(inside)]):
                self.assertEqual(patcher.main(),1)
            self.assertFalse(inside.exists())

    def test_baseline_cannot_be_symlinked(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            outside=root/'real-engine'
            outside.write_text(self.BASE)
            repo=root/'repo'
            (repo/'common/scripts').mkdir(parents=True)
            (repo/'common/scripts/veux_update_engine.py').symlink_to(outside)
            with self.assertRaises(patcher.MigrationBlocked):
                patcher.under(repo, patcher.ENGINE_PATH)

    def test_runtime_scenarios(self):
        old = patcher.EXPECTED_INTEGRATED
        HEAD = dict(resukisu='a'*40, susfs=old['susfs'], nomount='b'*40)
        targets = {
            x: {'commit': old[x], 'ref': 'refs/heads/main' if x == 'resukisu' else
                ('refs/heads/master' if x == 'nomount' else 'refs/heads/gki-android13-5.10'),
                'url': 'https://github.com/example/' + x + '.git',
                'version': {'resukisu':'35203','susfs':'2.3.0','nomount':'20'}[x],
                **({'uapi':5} if x=='resukisu' else {}),
                **({'version_kind':'kernel-wire-version'} if x=='nomount' else {})}
            for x in old
        }
        def scenario(susfs_blocker=True, nomount_v21=True, unsafe_link=False):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                rep = root / 'repo'; rep.mkdir()
                contract = rep / 'common/contracts/CURRENT_BUILD.json'; contract.parent.mkdir(parents=True)
                fleet = {f'5.4.{n}':{'targets':targets} for n in (274,292,293,300,301,302)}
                contract.write_text(json.dumps({'targets': targets, 'lineages':fleet,
                    'status':'compile-package-static-validated','device_pass_inferred':False}))
                donor_sources = root/'donors'
                for comp in old:
                    base = donor_sources/comp
                    base.mkdir(parents=True)
                    if comp=='resukisu':
                        (base/'kernel/include').mkdir(parents=True)
                        (base/'uapi').mkdir()
                        (base/'uapi/supercall.h').write_text('UAPI5 test\n')
                        (base/'kernel/Kbuild').write_text('expr 30000 + $(KSU_LOCAL_VERSION) + 700\n'
                            + 'include $(KSU_SRC)/tools/susfs_compat.mk\n')
                        (base/'kernel/tools').mkdir()
                        (base/'kernel/tools/susfs_compat.mk').write_text(
                            '$(error Please wait susfs update.)' if susfs_blocker else '# updated')
                        os.symlink('../../uapi' if not unsafe_link else '../../../../../../etc',
                                   base/'kernel/include/uapi')
                    if comp=='susfs':
                        (base/'kernel_patches/include/linux').mkdir(parents=True)
                        (base/'kernel_patches/include/linux/susfs.h').write_text('#define SUSFS_VERSION "2.3.0"\n')
                    if comp=='nomount':
                        (base/'kernel/src').mkdir(parents=True)
                        (base/'kernel/src/nomount.h').write_text(
                            ('#define NOMOUNT_BASE_VERSION "21"\n#define NOMOUNT_VERSION NOMOUNT_BASE_VERSION\n'
                             '#define NOMOUNT_COMMIT_COUNT "999"\n') if nomount_v21
                            else '#define NOMOUNT_VERSION "20"\n')
                def do_git(_repo, *args):
                    if args[0] == 'cat-file': return 'commit'
                    if args[0] == 'diff': return ''  # tests for key blockers separately
                    if args[0] == 'rev-list': return '4532' if str(_repo).endswith('resukisu') else '20'
                    if args[0] == 'describe': return 'v4.2.0-rc3'
                    if args[0] == 'rev-parse': return 'c'*40
                    raise AssertionError(('git', args))
                def do_run(args, timeout=None):
                    if args[:2] == ['git','ls-remote']:
                        match = next(x for x in old if x in args[-2])
                        return HEAD[match] + '\t' + args[-1]
                    if 'merge-base' in args:
                        return ''
                    raise AssertionError(('run', args))
                def checkout(_url, _commit, dest, full=False):
                    comp = dest.name
                    shutil.copytree(donor_sources/comp, dest, symlinks=True)
                def require(ok, message):
                    if not ok:
                        raise RuntimeError(message)
                def write_json(path, obj):
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_text(json.dumps(obj))
                fake_module=types.ModuleType('veux_current_components')
                fake_module.checked_uapi=lambda donor: 5
                previous=sys.modules.get('veux_current_components')
                sys.modules['veux_current_components']=fake_module
                try:
                    scope={
                        'check_repo':lambda: ({'golden_contract':'golden'}, {'lineages':fleet}),
                        'REPO':rep, 'COMPONENTS':tuple(old), 'SHA':re.compile(r'[0-9a-f]{40}\Z'),
                        'require':require, 'git':do_git, 'run':do_run, 'checkout':checkout,
                        'digest':lambda p:'0'*64, 'write_json':write_json, 'Path':Path,
                        'os':os,'re':re,'json':json,'Blocked':RuntimeError}
                    exec(patcher.NEW_RESOLVER,scope)
                    output=root/'out'
                    if susfs_blocker or nomount_v21 or unsafe_link:
                        with self.assertRaises(RuntimeError) as caught:
                            scope['resolve'](output)
                        if unsafe_link:
                            self.assertIn('symlink',str(caught.exception))
                        else:
                            report=json.loads((output/'COMPATIBILITY-REVIEW.json').read_text())
                            self.assertFalse(report['build_approved'])
                            self.assertEqual(report['components']['resukisu']['base'],old['resukisu'])
                            if susfs_blocker:
                                self.assertIn('Please wait susfs update', str(caught.exception))
                            if nomount_v21:
                                self.assertIn('NoMount 20 -> 21', str(caught.exception))
                    else:
                        result=scope['resolve'](output)
                        self.assertTrue(result['build_approved'])
                        self.assertEqual(result['components']['nomount']['version'],'20')
                        self.assertEqual(result['components']['resukisu']['uapi'],5)
                        self.assertTrue((output/'targets.json').exists())
                finally:
                    if previous is None:
                        del sys.modules['veux_current_components']
                    else: sys.modules['veux_current_components']=previous
        for settings in ((True,True,False),(False,True,False),(False,False,False),(False,False,True)):
            with self.subTest(settings=settings):
                scenario(*settings)


if __name__ == '__main__':
    unittest.main(verbosity=2)
