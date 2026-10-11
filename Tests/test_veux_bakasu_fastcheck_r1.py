"""Deterministic offline tests for the safe BakaSU/ReSukiSU fast check."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
script = HERE/'common/scripts/veux_bakasu_fastcheck_r1.py'
spec = importlib.util.spec_from_file_location('veux_bakasu_fastcheck_r1', script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
PIN='c9246641b9eee8b9986050e8bf1832f88da880c2'
HEAD='f6cb7e70c10ebde149f3121ae68b945514fd0801'
SOURCE_OLD = '# nothing blocking\n'
SOURCE_NEW = SOURCE_OLD + '$(error Please wait susfs update.)\n'
HEADER='static const __u32 KERNEL_SU_UAPI_VERSION = 5;'

def compare(changed=None, ahead=9, behind=0, base=PIN):
    return {'status':'ahead' if ahead else 'identical',
            'ahead_by':ahead,'behind_by':behind,
            'merge_base_commit':{'sha':base},
            'files':[{'filename':x} for x in changed or []]}

class Tests(unittest.TestCase):
    def test_pinned_target_from_repo_ast(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'targets.py'
            p.write_text('TARGETS={"resukisu":{"commit":"'+PIN+'"},'
                '"susfs":{"commit":"'+PIN+'"},"nomount":{"commit":"'+PIN+'"}}\n')
            self.assertEqual(mod.pinned_targets(p)['resukisu']['commit'],PIN)

    def test_reject_nonliteral_target(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'targets.py';p.write_text('TARGETS=eval("data")')
            with self.assertRaises((ValueError, mod.CheckBlocked)):
                mod.pinned_targets(p)

    def test_no_update(self):
        result=mod.analyse(PIN,PIN,compare([],0),SOURCE_OLD,HEADER)
        self.assertEqual(result['status'],'NO_NEW_KERNEL_UPDATE')
        self.assertFalse(result['build_approved'])

    def test_newer_safe_header_requires_preflight(self):
        result=mod.analyse(PIN,HEAD,compare(['manager/app/build.gradle.kts']),SOURCE_OLD,HEADER)
        self.assertEqual(result['status'],'READY_FOR_SIX_KERNEL_PREFLIGHT_NOT_APPROVED')
        self.assertFalse(result['build_approved'])

    def test_latest_real_susfs_blocker(self):
        result=mod.analyse(PIN,HEAD,compare(['kernel/tools/susfs_compat.mk','kernel/feature/selinux_hide.c']),SOURCE_NEW,HEADER)
        self.assertEqual(result['status'],'BLOCKED_BY_UPSTREAM_SUSFS')
        self.assertTrue(result['upstream_susfs_build_blocker'])
        self.assertTrue(result['requires_review'])

    def test_detect_critical_changes(self):
        result=mod.analyse(PIN,HEAD,compare(['kernel/feature/selinux_hide.c']),SOURCE_OLD,HEADER)
        self.assertEqual(result['status'],'REQUIRES_KERNEL_COMPATIBILITY_REVIEW')
        self.assertEqual(result['critical_kernel_files_changed'],['kernel/feature/selinux_hide.c'])

    def test_uapi_mismatch_blocks(self):
        result=mod.analyse(PIN,HEAD,compare(),SOURCE_OLD,HEADER.replace('= 5','= 6'))
        self.assertEqual(result['status'],'BLOCKED_UAPI_CHANGED')

    def test_missing_uapi_is_error(self):
        with self.assertRaisesRegex(mod.CheckBlocked,'UAPI_VERSION_MISSING'):
            mod.analyse(PIN,HEAD,compare(),SOURCE_OLD,'// no version')

    def test_reject_history_rewrite(self):
        for obj in [compare(behind=1),compare(base='0'*40),{'status':'diverged','ahead_by':9,'behind_by':1,'merge_base_commit':{'sha':PIN}}]:
            with self.subTest(obj=obj), self.assertRaisesRegex(mod.CheckBlocked,'HISTORY_REWRITE'):
                mod.analyse(PIN,HEAD,obj,SOURCE_OLD,HEADER)

    def test_reject_malformed_comparison(self):
        with self.assertRaisesRegex(mod.CheckBlocked,'Invalid compare'):
            mod.analyse(PIN,HEAD,compare()|{'files':9},SOURCE_OLD,HEADER)

    def test_report_text_is_truthful(self):
        r=mod.analyse(PIN,HEAD,compare(['kernel/tools/susfs_compat.mk']),SOURCE_NEW,HEADER)
        text=mod.report_text(r)
        self.assertIn('SUSFS_BUILD_BLOCKER: YES',text)
        self.assertIn('NO new kernel build',text)

    def test_get_file_from_base64_api(self):
        def fetch(_url):
            return {'type':'file','encoding':'base64','content':base64.b64encode(HEADER.encode()).decode()}
        self.assertEqual(mod.get_file(fetch,'uapi/supercall.h',HEAD),HEADER)

    def test_get_file_rejects_external_content(self):
        with self.assertRaisesRegex(mod.CheckBlocked,'Unexpected content'):
            mod.get_file(lambda _: {'type':'symlink','encoding':'utf-8','content':'outside'}, 'uapi/supercall.h',HEAD)

    def test_inspect_integration_with_fake_repository_and_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / '.git').mkdir()
            source = root / mod.WORKER
            source.parent.mkdir(parents=True)
            source.write_text('TARGETS={"resukisu":{"commit":"'+PIN+'"},'
                              '"susfs":{"commit":"'+PIN+'"},'
                              '"nomount":{"commit":"'+PIN+'"}}')
            def fake_api(url):
                if url.endswith('/branches/main'):
                    return {'commit': {'sha': HEAD}}
                if '/compare/' in url:
                    return compare(['kernel/tools/susfs_compat.mk',
                                    'kernel/feature/selinux_hide.c'])
                if 'kernel/tools/susfs_compat.mk?' in url:
                    return {'type':'file','encoding':'base64',
                            'content':base64.b64encode(SOURCE_NEW.encode()).decode()}
                if 'uapi/supercall.h?' in url:
                    return {'type':'file','encoding':'base64',
                            'content':base64.b64encode(HEADER.encode()).decode()}
                raise AssertionError('Unexpected API request: '+url)
            with patch.dict('os.environ', {'GITHUB_REPOSITORY': mod.REPOSITORY}):
                result = mod.inspect(root, fake_api)
            self.assertEqual(result['status'], 'BLOCKED_BY_UPSTREAM_SUSFS')
            self.assertEqual(result['commits_ahead'], 9)
            self.assertFalse(result['build_approved'])

    def test_read_only_flags_present(self):
        r=mod.analyse(PIN,HEAD,compare(),SOURCE_NEW,HEADER)
        self.assertFalse(r['repository_modified'])
        self.assertFalse(r['kernel_compilation_performed'])
        self.assertFalse(r['device_pass_inferred'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
