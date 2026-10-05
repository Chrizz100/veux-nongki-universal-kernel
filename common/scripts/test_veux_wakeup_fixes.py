#!/usr/bin/env python3
"""Fail-closed wakeup integration tests against actual reconstructed source."""
import argparse
import copy
import json
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
            for missing in (None,*SYMBOLS):
                smap.write_text(''.join('ffffff00 t '+n+'.cfi\n' for n in SYMBOLS if n!=missing))
                if missing is None:self.assertEqual(w.verify_build(w.KERNEL,root),SYMBOLS)
                else:
                    with self.assertRaisesRegex(e.Blocked,'symbol not linked'):w.verify_build(w.KERNEL,root)
            obj.write_bytes(b'')
            with self.assertRaisesRegex(e.Blocked,'object empty'):w.verify_build(w.KERNEL,root)

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
        mutations=[('kernel/power/wakeup_reason.c','ktime_sub(offset, last_stime)','ktime_sub(mono, last_monotime)'),
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
