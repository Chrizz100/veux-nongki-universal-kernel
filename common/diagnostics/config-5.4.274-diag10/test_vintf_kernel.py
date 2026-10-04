#!/usr/bin/env python3
"""Reproduce the captured mismatch and test failure before candidate publication."""
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import vintf_kernel as v

HERE = Path(__file__).resolve().parent
BASELINE = (HERE/'diag09-actual.config').read_bytes()


def set_option(data, key, value):
    text = data.decode()
    line = 'CONFIG_'+key+'='+value if value != 'n' else '# CONFIG_'+key+' is not set'
    pattern = r'(?m)^(?:CONFIG_'+re.escape(key)+r'=.*|# CONFIG_'+re.escape(key)+r' is not set)$'
    if re.search(pattern, text):
        return re.sub(pattern, lambda _: line, text).encode()
    return (text.rstrip()+'\n'+line+'\n').encode()


def repaired_fixture():
    data = BASELINE
    for key in v.REQUIRED_ENABLE+v.DEPENDENCY_ENABLE:
        data = set_option(data, key, 'y')
    for key in v.REQUIRED_DISABLE:
        data = set_option(data, key, 'n')
    return data


class VintfTests(unittest.TestCase):
    def test_device_evidence_reproduces_eleven_failures(self):
        result = v.evaluate(BASELINE)
        self.assertEqual((result['requirements'],result['passed']), (261,250))
        self.assertEqual({r['key'] for r in result['failures']},
                         {'CONFIG_'+k for k in v.REQUIRED_ENABLE})
        self.assertEqual(result['groups_applied'],5)
        self.assertEqual(result['groups_skipped'],4)
        self.assertFalse(result['device'])

    def test_previously_embedded_stock_text_hides_mismatch(self):
        stock = (HERE/'source/arch/arm64/configs/stock_defconfig').read_bytes()
        result = v.evaluate(stock)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['passed'],261)
        self.assertNotEqual(v.options(stock),v.options(BASELINE))

    def test_each_required_setting_is_enforced(self):
        candidate = repaired_fixture()
        self.assertEqual(v.require_compatible(candidate,BASELINE)['status'],'PASS')
        for key in v.REQUIRED_ENABLE+v.DEPENDENCY_ENABLE:
            with self.subTest(key=key), self.assertRaises(v.e.Blocked):
                v.require_compatible(set_option(candidate,key,'n'),BASELINE)

    def test_no_permissive_cfi_forced_loading_or_missing_builtins(self):
        candidate = repaired_fixture()
        for key,value in [(x,'y') for x in v.REQUIRED_DISABLE]+[('NOMOUNT','n'),('KSU','m'),('TEST_DRIVER','m')]:
            with self.subTest(key=key), self.assertRaises(v.e.Blocked):
                v.require_compatible(set_option(candidate,key,value),BASELINE)

    def test_cpu_or_level_or_version_cannot_silently_skip_requirements(self):
        with self.assertRaises(v.e.Blocked):
            v.require_compatible(set_option(repaired_fixture(),'ARM64','n'),BASELINE)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'matrix.xml'
            root=ET.parse(HERE/'rom-kernel-requirements.xml').getroot()
            root.set('level','6'); ET.ElementTree(root).write(path)
            with self.assertRaises(v.e.Blocked):v.evaluate(BASELINE,path)
        with self.assertRaises(v.e.Blocked):v.evaluate(BASELINE,kernel='5.4.60')

    def test_typed_matching_and_absent_options(self):
        self.assertTrue(v.matches('n','tristate','n'))
        self.assertFalse(v.matches('m','tristate','y'))
        self.assertTrue(v.matches('0x1000','int','4096'))
        self.assertTrue(v.matches('3','range','1-0x3'))
        self.assertFalse(v.matches('4','range','1-0x3'))
        self.assertTrue(v.matches('""','string',''))
        with self.assertRaises(v.e.Blocked):v.matches('x','unsupported','x')
        with self.assertRaises(v.e.Blocked):v.options(b'CONFIG_A=y\nCONFIG_A=n\n')

    def test_compiler_evidence_requires_active_protection(self):
        command='clang -flto=thin -fsanitize=cfi -fsanitize-cfi-cross-dso -fstack-protector-strong '
        symbols='ffff0000 T __cfi_check\nffff0010 T __stack_chk_fail\n'
        v.compiler_evidence(command,symbols)
        for changed in [command.replace('-fsanitize=cfi',''),
                        command.replace('-fsanitize-cfi-cross-dso',''),
                        command+'-fno-stack-protector ',
                        command+'-fsanitize-recover=cfi ']:
            with self.assertRaises(v.e.Blocked):v.compiler_evidence(changed,symbols)
        with self.assertRaises(v.e.Blocked):v.compiler_evidence(command,'')

    def test_actual_kconfig_declares_scheduler_dependency(self):
        source=(HERE/'source/lib/Kconfig.debug').read_text()
        block=source.split('config SCHED_DEBUG\n',1)[1].split('\nconfig ',1)[0]
        self.assertIn('depends on DEBUG_KERNEL && PROC_FS',block)
        argv=v.configure_argv(Path('/source'),Path('/out'))
        self.assertIn('DEBUG_KERNEL',argv)
        self.assertIn('CFI_CLANG',argv)

    def test_wrapper_configures_and_blocks_before_compile(self):
        import config_audit as a
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'src';out=root/'old';out.mkdir();src.mkdir()
            (out/'.config').write_bytes(BASELINE)
            called=[]
            def fake_run(argv,*args,**kwargs):
                called.append([str(x) for x in argv])
                return ''
            def fake_compile(label,state,targets,work,jobs):
                build=work/'build';build.mkdir()
                (build/'.config').write_bytes(BASELINE)
                a.e.run(['make','olddefconfig'],log=work/'configure.log',env={})
                self.fail('must reject unresolved Kconfig before compilation')
            with mock.patch.object(a,'apply',return_value={}), \
                 mock.patch.object(a.e,'run',side_effect=fake_run), \
                 mock.patch.object(a.e,'compile_kernel',side_effect=fake_compile):
                with self.assertRaisesRegex(v.e.Blocked,'ROM kernel requirements unmet'):
                    with a.compiler_audit(root/'reports'):
                        a.e.compile_kernel('5.4.274',{'source':str(src),'variables':['O='+str(out)]},{},root,1)
            self.assertIn('DEBUG_KERNEL',called[0])
            self.assertEqual(called[1],['make','olddefconfig'])
            self.assertTrue((root/'reports/VINTF-PREBUILD.json').is_file())


if __name__ == '__main__':
    unittest.main()
