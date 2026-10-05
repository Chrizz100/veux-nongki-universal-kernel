#!/usr/bin/env python3
"""Fail-closed wakeup integration tests against actual reconstructed source."""
import argparse
import copy
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import veux_update_engine as e
import veux_wakeup_fixes as w
import veux_release_device as device
import veux_release as release
import veux_device_fixes as fixes
import veux_rpm_fixes as rpm
import veux_config_compat as compat

SOURCE = None
SYMBOLS = ['wakeup_reason_init', 'last_resume_reason_show', 'last_suspend_time_show']

class WakeupTests(unittest.TestCase):
    def fixture(self, root):
        folder, data, _ = w.load()
        repo, src, work = root/'repo', root/'source', root/'work'
        shutil.copytree(folder, repo/w.PAYLOAD)
        e.write_json(repo/'common/update/source-recipes.json',e.config())
        for name in data['files']:
            p=src/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(SOURCE/name,p)
        subprocess.run(['git','apply','--reverse','--check',str(folder/data['patch'])],cwd=src,check=True)
        subprocess.run(['git','apply','--reverse',str(folder/data['patch'])],cwd=src,check=True)
        work.mkdir()
        return repo,src,work,data

    def test_first_apply_reapply_and_post_compile_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo,src,work,data=self.fixture(Path(tmp))
            with mock.patch.object(e,'REPO',repo):
                proof=w.apply(src,w.KERNEL,work)
                self.assertEqual(proof,w.apply(src,w.KERNEL,work))
                w.verify_source(src,w.KERNEL,proof)
                self.assertEqual(json.loads((work/'WAKEUP-FIXES.json').read_text()),proof)
                self.assertIn('ASSERTIONS=66',(work/'wakeup-host-tests.log').read_text())
                (src/'kernel/power/wakeup_reason.c').write_text('modified during compile')
                with self.assertRaisesRegex(e.Blocked,'changed during build'):
                    w.verify_source(src,w.KERNEL,proof)

    def test_bad_inputs_never_partly_apply(self):
        modes=('source','new_file_exists','missing_source','manifest','patch','test',
               'symlink_file','symlink_parent','recipe','mixed_state')
        for mode in modes:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                repo,src,work,data=self.fixture(Path(tmp));folder=repo/w.PAYLOAD
                target=src/'kernel/power/Makefile'
                if mode=='source':target.write_text('unreviewed\n')
                elif mode=='new_file_exists':(src/'kernel/power/wakeup_reason.c').write_text('custom\n')
                elif mode=='missing_source':target.unlink()
                elif mode in ('manifest','patch','test'):
                    p=folder/('manifest.json' if mode=='manifest' else data[mode]);p.write_text(p.read_text()+'\n# drift\n')
                elif mode=='symlink_file':
                    target.rename(target.with_name('saved'));target.symlink_to('saved')
                elif mode=='symlink_parent':
                    target.parent.rename(src/'kernel/saved');(src/'kernel/power').symlink_to('saved',target_is_directory=True)
                elif mode=='recipe':
                    cfg=e.config();cfg['lineages'][w.KERNEL]['blob']='0'*40;e.write_json(repo/'common/update/source-recipes.json',cfg)
                elif mode=='mixed_state':shutil.copy2(SOURCE/'kernel/power/Makefile',target)
                before={p.relative_to(src).as_posix():p.read_bytes() for p in src.rglob('*') if p.is_file()}
                with mock.patch.object(e,'REPO',repo),self.assertRaises(e.Blocked):w.apply(src,w.KERNEL,work)
                after={p.relative_to(src).as_posix():p.read_bytes() for p in src.rglob('*') if p.is_file()}
                self.assertEqual(after,before);self.assertFalse((work/'WAKEUP-FIXES.json').exists())

    def test_host_failure_preserves_every_preimage(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo,src,work,data=self.fixture(Path(tmp));original_run=e.run
            before=w.inventory(src,data)
            def run(command,**kwargs):
                if any(str(x).endswith('test_wakeup.py') for x in command):
                    raise subprocess.CalledProcessError(1,command)
                return original_run(command,**kwargs)
            with mock.patch.object(e,'REPO',repo),mock.patch.object(e,'run',side_effect=run):
                with self.assertRaises(subprocess.SubprocessError):w.apply(src,w.KERNEL,work)
            self.assertEqual(w.inventory(src,data),before)

    def test_other_five_lineages_have_no_source_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for label in set(e.config()['lineages'])-{w.KERNEL}:
                self.assertEqual(w.apply(root,label,root),[])
                w.verify_source(root,label,[]);w.verify_result(label,{})
                self.assertEqual(w.verify_build(label,root),[])
            self.assertEqual(list(root.iterdir()),[])

    def test_link_gate_requires_object_and_all_abi_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);obj=root/'build/kernel/power/wakeup_reason.o';obj.parent.mkdir(parents=True)
            obj.write_bytes(b'compiled fixture');smap=root/'build/System.map'
            stats=root/'build/drivers/base/power/wakeup_stats.o';stats.parent.mkdir(parents=True)
            stats.write_bytes(b'compiled stats fixture')
            for missing in (None,*SYMBOLS):
                smap.write_text(''.join('ffffff00 t '+n+'.cfi\n' for n in SYMBOLS if n!=missing))
                if missing is None:self.assertEqual(w.verify_build(w.KERNEL,root),SYMBOLS)
                else:
                    with self.assertRaisesRegex(e.Blocked,'symbol not linked'):w.verify_build(w.KERNEL,root)
            for missing in (obj, stats):
                saved=missing.read_bytes();missing.write_bytes(b'')
                with self.assertRaisesRegex(e.Blocked,'object empty'):w.verify_build(w.KERNEL,root)
                missing.unlink()
                with self.assertRaisesRegex(e.Blocked,'not a regular file'):w.verify_build(w.KERNEL,root)
                missing.write_bytes(saved)

    def test_real_r3_map_accepts_bodies_and_rejects_jump_table_only(self):
        fixture = Path(__file__).with_name('fixtures') / 'wakeup-run-37335256954.map'
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),
                         'b3abc616eb77d5b63c02e129db73e144ef4b6048d84b3710c2bb4d918a545f0d')
        symbols = fixture.read_text()
        self.assertEqual(w.verify_symbols(symbols), SYMBOLS)
        for missing in SYMBOLS:
            with self.subTest(missing=missing):
                # Keep the real trampoline and initcall entry: neither may
                # substitute for the missing compiled function body.
                remaining = '\n'.join(line for line in symbols.splitlines()
                                      if not (line.split()[2].startswith(missing + '$')
                                              and not line.endswith('.cfi_jt')))
                self.assertIn(missing + '$', remaining)
                with self.assertRaisesRegex(e.Blocked, 'symbol not linked: ' + missing):
                    w.verify_symbols(remaining)

    def test_symbol_name_and_type_boundaries(self):
        tag = '$e7a9be69868996ddc7b91d92771f8869'
        for suffix in ('', '.cfi', tag, tag + '.cfi'):
            for kind in ('t', 'T'):
                with self.subTest(valid=suffix, kind=kind):
                    symbols = ''.join('ffffff00 ' + kind + ' ' + n + suffix + '\n' for n in SYMBOLS)
                    self.assertEqual(w.verify_symbols(symbols), SYMBOLS)
        invalid = [('', suffix, 't') for suffix in
                   ('.cfi_jt', tag + '.cfi_jt', '.cold', '.invalid', '_extra',
                    '$123', '$' + 'g' * 32, tag + '0', tag + ' extra')]
        invalid += [('prefix_', '', 't'), ('__initcall_', '', 'd')]
        invalid += [('', '', kind) for kind in ('U', 'D', 'd', 'b', 'R', 'W')]
        for missing in SYMBOLS:
            for prefix, suffix, kind in invalid:
                with self.subTest(missing=missing, prefix=prefix, suffix=suffix, kind=kind):
                    symbols = ''.join('ffffff00 t ' + n + '\n' for n in SYMBOLS if n != missing)
                    symbols += 'ffffff00 ' + kind + ' ' + prefix + missing + suffix + '\n'
                    with self.assertRaisesRegex(e.Blocked, 'symbol not linked: ' + missing):
                        w.verify_symbols(symbols)

    def test_failed_build_retains_image_and_object_only_as_diagnostics(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); work = root/'work'; public = root/'public'; diag = root/'diagnostics'
                public.mkdir()
                paths = ('build/arch/arm64/boot/Image', 'build/kernel/power/wakeup_reason.o',
                         'build/drivers/base/power/wakeup_stats.o')
                for rel in paths:
                    p = work/rel; p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(b'\x00compiled fixture\xff')
                if failed:
                    e.write_json(work/'BLOCKED.json', {'reason': 'post-compile fixture'})
                device.preserve_device_diagnostics(work, public, diag)
                for rel in paths:
                    self.assertEqual((diag/rel).exists(), failed)
                    if failed:
                        self.assertEqual((diag/rel).read_bytes(), (work/rel).read_bytes())
                self.assertEqual(list(public.iterdir()), [])

    def test_promotion_blocks_missing_forged_or_unlinked_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e.write_json(root/'bundle/targets.json',{'lineages':[w.KERNEL]})
            args=argparse.Namespace(bundle=root/'bundle',artifacts=root/'artifacts')
            row=dict(device_fixes=fixes.expected(w.KERNEL),rpm_fixes=rpm.expected(w.KERNEL),
                     config_compat=compat.expected_proof(),config_audit=compat.reference_report(),
                     wakeup_fixes=w.expected(w.KERNEL),wakeup_linked_symbols=SYMBOLS)
            for mode in ('good','missing','forged','unlinked'):
                candidate=copy.deepcopy(row)
                if mode=='missing':candidate.pop('wakeup_fixes')
                if mode=='forged':candidate['wakeup_fixes'][0]['host_tests']=False
                if mode=='unlinked':candidate['wakeup_linked_symbols']=[]
                e.write_json(args.artifacts/w.KERNEL/'RESULT.json',candidate)
                with mock.patch.object(release,'promote') as promote:
                    if mode=='good':device.promote(args);promote.assert_called_once_with(args)
                    else:
                        with self.assertRaisesRegex(e.Blocked,'wakeup'):device.promote(args)
                        promote.assert_not_called()

    def test_hook_removal_and_wrong_time_math_fail_actual_c_tests(self):
        folder,_,_=w.load()
        mutations=[('drivers/base/power/wakeup_stats.c','dev->parent = NULL;', 'dev->parent = parent;'),
                   ('drivers/base/power/wakeup_stats.c','if (!ws->name[0])','if (ws->name[0])'),
                   ('kernel/power/wakeup_reason.c','ktime_sub(offset, last_stime)','ktime_sub(mono, last_monotime)'),
                   ('kernel/power/wakeup_reason.c','if (!capture_reasons || wakeup_reason != RESUME_NONE)', 'if (wakeup_reason != RESUME_NONE)'),
                   ('drivers/base/power/wakeup.c','log_suspend_abort_reason("%s", reason);','log_suspend_abort_reason("removed");')]
        for name,old,new in mutations:
            with self.subTest(mutation=old),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp)/'src';shutil.copytree(SOURCE,stage)
                p=stage/name;s=p.read_text();self.assertEqual(s.count(old),1);p.write_text(s.replace(old,new))
                result=subprocess.run(['python3',str(folder/'test_wakeup.py'),str(stage)],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True)
    args,rest=parser.parse_known_args();SOURCE=args.source.resolve()
    unittest.main(argv=['test_veux_wakeup_fixes.py',*rest],verbosity=2)
