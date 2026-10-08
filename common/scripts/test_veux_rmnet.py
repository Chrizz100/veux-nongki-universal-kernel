#!/usr/bin/env python3
"""Host regressions for same-build RMNET evidence and the real shipped shell scripts."""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import veux_rmnet as r


def tiny_elf(name='rmnet_shs', release='5.4.274-test', crc=0x1234, extra_import=False):
    strings = b'\0init_module\0cleanup_module\0__cfi_check\0unproved\0'
    symbols = b'\0' * 24
    for symbol in ['init_module', 'cleanup_module', '__cfi_check']:
        symbols += struct.pack('<IBBHQQ', strings.index(symbol.encode()), 0x12, 0, 1, 0, 4)
    if extra_import:
        symbols += struct.pack('<IBBHQQ', strings.index(b'unproved'), 0x10, 0, 0, 0, 0)
    info = ('name=' + name + '\0depends=\0vermagic=' + release +
            ' SMP preempt mod_unload modversions aarch64\0').encode()
    note = struct.pack('<III', 4, 8, 3) + b'GNU\0' + b'12345678'
    sections = [('', b'\0', 0), ('.text', b'code', 1), ('.strtab', strings, 3),
                ('.symtab', symbols, 2), ('.modinfo', info, 1),
                ('__versions', struct.pack('<Q', crc) + b'module_layout\0' + b'\0' * 42, 1),
                ('.note.gnu.build-id', note, 7)]
    names = b'\0' + b''.join(n.encode()+b'\0' for n, _, _ in sections[1:]) + b'.shstrtab\0'
    sections.append(('.shstrtab', names, 3))
    data = bytearray(b'\0' * 64)
    headers = []
    for n, content, kind in sections:
        off = len(data)
        data.extend(content)
        headers.append((names.index(n.encode()+b'\0') if n else 0, kind, 0, 0, off,
                        len(content), 2 if n == '.symtab' else 0, 0, 1, 24 if n == '.symtab' else 0))
    table = len(data)
    for h in headers:
        data.extend(struct.pack('<IIQQQQIIQQ', *h))
    data[:16] = b'\x7fELF\x02\x01\x01' + b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 1, 183, 1, 0, 0, table, 0, 64, 0, 0, 64, len(headers), len(headers)-1)
    return bytes(data)


class EvidenceTests(unittest.TestCase):
    def test_module_pair_and_dynamic_versions(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'test.ko'
            for name in r.PAIR:
                for crc in (0x1234, 0x55667788):
                    p.write_bytes(tiny_elf(name, '5.4.274-new', crc))
                    result = r.inspect_module(p, {'module_layout': crc}, '5.4.274-new', name)
                    self.assertEqual(result['checked_crcs'], 1)
                    self.assertTrue(result['cfi'])

    def test_wrong_module_layout(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'x.ko'; p.write_bytes(tiny_elf())
            with self.assertRaisesRegex(ValueError, 'module_layout'):
                r.inspect_module(p, {'module_layout': 9}, '5.4.274-test', 'rmnet_shs')

    def test_missing_strong_import_proof(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'x.ko'; p.write_bytes(tiny_elf(extra_import=True))
            with self.assertRaisesRegex(ValueError, 'strong imports'):
                r.inspect_module(p, {'module_layout': 0x1234}, '5.4.274-test', 'rmnet_shs')

    def test_wrong_name_and_release(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'x.ko'; p.write_bytes(tiny_elf())
            for release, name in [('5.4.274-wrong', 'rmnet_shs'), ('5.4.274-test', 'rmnet_offload')]:
                with self.assertRaises(ValueError):
                    r.inspect_module(p, {'module_layout': 0x1234}, release, name)

    def test_external_dependency_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'x.ko'
            p.write_bytes(tiny_elf().replace(b'depends=\0',b'depends=x'))
            with self.assertRaises(ValueError): r.inspect_module(p, {'module_layout':0x1234},'5.4.274-test','rmnet_shs')

    def test_elf_truncation(self):
        blob = tiny_elf()
        for n in (0, 12, 63, 80, len(blob)-1):
            with self.subTest(n=n), self.assertRaises(ValueError): r.Elf64(blob[:n])

    def test_bad_section_table(self):
        blob = bytearray(tiny_elf()); struct.pack_into('<Q', blob, 40, 2**60)
        with self.assertRaises(ValueError): r.Elf64(bytes(blob))

    def test_duplicate_and_truncated_versions(self):
        item = struct.pack('<Q',1)+b'module_layout\0'+b'\0'*42
        for data in (b'', item[:-1], item+item):
            with self.assertRaises(ValueError): r.versions_from(data)

    def test_exports_require_actual_kernel(self):
        for data in (b'', b'0x1 module_layout external EXPORT_SYMBOL\n',
                     b'0x1 module_layout vmlinux EXPORT_SYMBOL\n'*2):
            with self.assertRaises(ValueError): r.exports_from(data)

    def test_kernel_notes(self):
        image = b'\0'*64+b'GNU\0'+b'1234'
        sm = b'1000 T _text\n1040 R __start_notes\n1048 R __stop_notes\n'
        self.assertEqual(r.note_from_kernel(image,sm), b'GNU\0'+b'1234')
        with self.assertRaises(ValueError): r.note_from_kernel(image, sm.replace(b'1048',b'ffff'))
        with self.assertRaises(ValueError): r.note_from_kernel(image, sm+sm)

    def test_package_path_escape(self):
        with tempfile.TemporaryDirectory() as td:
            for n in ('../evil','/evil','a/../evil'):
                with self.assertRaises(ValueError): r.write_zip(Path(td)/'x.zip',{n:(b'x',0o644)})


def proof_for(image=b'kernel', config=b'config', notes=b'kernel-notes'):
    rows={}
    for name in r.PAIR:
        rows[name]={'name':name,'sha256':r.digest(name.encode()),'note_sha256':r.digest((name+'-note').encode()),
                    'depends':[],'checked_crcs':1,'cfi':True,'init':True,'exit':True}
    h=r.digest(config)
    return {'kernel':r.KERNEL,'kernelrelease':'5.4.274-test','compile':True,'image_sha256':r.digest(image),
            'config_audit':{'actual_config_sha256':h},
            'rmnet':{'format':r.FORMAT,'kernel':r.KERNEL,'kernelrelease':'5.4.274-test',
            'image_sha256':r.digest(image),'config_sha256':h,'symvers_sha256':r.digest(b'exports'),
            'kernel_notes_sha256':r.digest(notes),'build':True,'module_abi':True,
            'device':False,'installed_on_device':False,'modules':rows}}


class PackageTests(unittest.TestCase):
    def prepare(self, td):
        root=Path(td);work=root/'work';public=root/'public';work.mkdir();public.mkdir()
        (work/'rmnet-payload').mkdir()
        for name in r.PAIR:(work/'rmnet-payload'/(name+'.ko')).write_bytes(name.encode())
        row=proof_for(); row['package_file']='Kernel_test_AnyKernel.zip'
        r.write_zip(public/row['package_file'],{'Image':(b'kernel',0o644),'anykernel.sh':
            (b'# script\ndo.modules=0\ndump_boot;\nwrite_boot;\n',0o755)})
        row['package_sha256']=r.digest(public/row['package_file'])
        return work,public,row

    def test_real_asset_packaging_and_unchanged_image(self):
        with tempfile.TemporaryDirectory() as td:
            work,public,row=self.prepare(td);r.augment_package(row,work,public)
            r.verify_package(row,public)
            with zipfile.ZipFile(public/row['package_file']) as z:
                self.assertEqual(z.read('Image'),b'kernel')
                script=z.read('anykernel.sh').decode()
                self.assertLess(script.index('install.sh'),script.index('write_boot;'))
                self.assertIn('do.modules=0',script)
                self.assertEqual(sum(n.endswith('.ko') for n in z.namelist()),2)
            self.assertFalse(row['rmnet']['device'])

    def test_payload_tamper_blocks_before_package_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            work,public,row=self.prepare(td);before=(public/row['package_file']).read_bytes()
            (work/'rmnet-payload/rmnet_shs.ko').write_bytes(b'wrong')
            with self.assertRaises(ValueError):r.augment_package(row,work,public)
            self.assertEqual((public/row['package_file']).read_bytes(),before)

    def test_proofs_bound_to_current_build(self):
        row=proof_for();r.verify_proof(row)
        for key in ('kernel','image_sha256','kernelrelease'):
            bad=copy.deepcopy(row);bad[key]='wrong'
            with self.assertRaises(ValueError):r.verify_proof(bad)
        bad=copy.deepcopy(row);bad['config_audit']['actual_config_sha256']='a'*64
        with self.assertRaises(ValueError):r.verify_proof(bad)

    def test_proofs_cannot_infer_device_pass(self):
        for key in ('device','installed_on_device'):
            row=proof_for();row['rmnet'][key]=True
            with self.assertRaises(ValueError):r.verify_proof(row)

    def test_missing_module_or_init(self):
        row=proof_for();del row['rmnet']['modules']['rmnet_shs']
        with self.assertRaises(ValueError):r.verify_proof(row)
        row=proof_for();row['rmnet']['modules']['rmnet_shs']['init']=False
        with self.assertRaises(ValueError):r.verify_proof(row)

    def test_zip_repeat_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            a,b=Path(td)/'a.zip',Path(td)/'b.zip';data={'z':(b'abc',0o644),'a':(b'xx',0o700)}
            r.write_zip(a,data);r.write_zip(b,data);self.assertEqual(a.read_bytes(),b.read_bytes())


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.adb=self.root/'data/adb';self.bin=self.root/'bin';self.sys=self.root/'sys'
        for p in (self.adb,self.bin,self.sys/'kernel',self.sys/'class/net/rmnet_data0',self.root/'props',self.root/'notes'):
            p.mkdir(parents=True,exist_ok=True)
        self.release='5.4.274-test';self.notes=b'kernel-notes';(self.sys/'kernel/notes').write_bytes(self.notes)
        self.events=self.root/'events';self.events.write_text('')
        self.payload=self.root/'payload';self.payload.mkdir()
        self.base=self.adb/'veux-rmnet';self.common=self.adb/'boot-completed.d'
        self.gen=self.base/r.digest(self.notes)
        self.exec('getprop',f'#!/bin/sh\ncat "{self.root}/props/$1" 2>/dev/null || true\n')
        self.exec('uname',f'#!/bin/sh\necho "{self.release}"\n')
        self.exec('busybox','#!/bin/sh\nif [ "$1" = --list ]; then echo flock; exit 0; fi\nexec "$@"\n')
        self.ksud=self.adb/'ksud';self.ksud.write_text('#!/bin/sh\necho --wait\n');self.ksud.chmod(0o700)
        self.exec('insmod',f'''#!/bin/sh
name=$(basename "$1" .ko)
echo "load:$name" >> '{self.events}'
[ ! -e '{self.root}/fail_load' ] || exit 1
mkdir -p '{self.sys}/module/'"$name"'/notes'
echo live > '{self.sys}/module/'"$name"'/initstate'
cp '{self.root}/notes/'"$name" '{self.sys}/module/'"$name"'/notes/.note.gnu.build-id'
''')
        self.exec('rmmod',f'''#!/bin/sh
echo "unload:$1" >> '{self.events}'
[ ! -e '{self.root}/busy' ] || exit 1
rm -rf '{self.sys}/module/'"$1"
''')
        for name in r.PAIR:
            (self.payload/(name+'.ko')).write_bytes(name.encode())
            (self.root/'notes'/name).write_bytes((name+'-note').encode())
        for name in ('launcher.sh','runtime.sh','install.sh'):
            code=(r.ASSETS/name).read_text()
            code=code.replace('PATH=/system/bin:/system/xbin:/vendor/bin',f'PATH={self.bin}:/usr/bin:/bin')
            code=code.replace('/data/adb/ksu/bin/busybox',str(self.bin/'busybox'))
            code=code.replace('/data/adb',str(self.adb)).replace('/sys/kernel/notes',str(self.sys/'kernel/notes'))
            code=code.replace('SYS=/sys',f'SYS={self.sys}').replace('/system/bin/insmod',str(self.bin/'insmod'))
            code=code.replace('/system/bin/rmmod',str(self.bin/'rmmod'))
            code=code.replace('OWNER_UID=0',f'OWNER_UID={os.getuid()}')
            (self.payload/name).write_text(code)
        self.identity={'FORMAT':r.FORMAT,'KERNEL_RELEASE':self.release,'KERNEL_NOTES_SHA256':r.digest(self.notes),
                       'OFFLOAD_NOTE_SHA256':r.digest(b'rmnet_offload-note'),'SHS_NOTE_SHA256':r.digest(b'rmnet_shs-note')}
        (self.payload/'identity.txt').write_text(''.join(k+'='+v+'\n' for k,v in self.identity.items()))
        self.refresh()
        self.prop('sys.boot_completed','1')
        for f in ('offload','shs'):self.prop('persist.vendor.data.'+f+'_ko_load','1')

    def tearDown(self):self.tmp.cleanup()
    def exec(self,name,code):
        p=self.bin/name;p.write_text(code);p.chmod(0o700)
    def prop(self,key,value):(self.root/'props'/key).write_text(value+'\n')
    def refresh(self):
        paths=[p for p in self.payload.iterdir() if p.name!='SHA256SUMS']
        (self.payload/'SHA256SUMS').write_text(''.join(r.digest(p)+'  '+p.name+'\n' for p in sorted(paths)))
        for p in self.payload.iterdir():p.chmod(0o700 if p.suffix=='.sh' else 0o600)
    def runsh(self,*args):
        return subprocess.run(['sh',*map(str,args)],env=dict(os.environ,PATH=str(self.bin)+':/usr/bin:/bin'),
                              capture_output=True,text=True,timeout=10)
    def install(self):
        p=self.runsh(self.payload/'install.sh',self.payload)
        self.assertEqual(p.returncode,0,p.stderr+p.stdout)
        return p
    def control(self,name='rmnet_shs'):
        return self.runsh(self.gen/'runtime.sh','reconcile',name)

    def test_all_shipped_shells_parse_in_bash_and_posix_sh(self):
        for script in r.ASSETS.glob('*.sh'):
            for shell in ('sh','bash'):
                p=subprocess.run([shell,'-n',str(script)],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr)

    def test_installer_does_not_load_and_is_repeatable(self):
        self.install();before={p.relative_to(self.adb):p.read_bytes() for p in self.adb.rglob('*') if p.is_file()}
        self.install();after={p.relative_to(self.adb):p.read_bytes() for p in self.adb.rglob('*') if p.is_file()}
        self.assertEqual(before,after);self.assertEqual(self.events.read_text(),'')

    def test_dynamic_load_and_unload(self):
        self.install()
        for name in r.PAIR:
            p=self.control(name);self.assertEqual(p.returncode,0,p.stderr+p.stdout)
            self.assertTrue((self.sys/'module'/name).exists())
            self.assertEqual(self.control(name).returncode,0)
            prop='persist.vendor.data.'+r.PAIR[name]+'_ko_load';self.prop(prop,'0')
            self.assertEqual(self.control(name).returncode,0)
            self.assertFalse((self.sys/'module'/name).exists())
        self.assertEqual(len(self.events.read_text().splitlines()),4)

    def test_wrong_kernel_notes_never_loads(self):
        self.install();(self.sys/'kernel/notes').write_bytes(b'wrong')
        self.assertNotEqual(self.control().returncode,0);self.assertEqual(self.events.read_text(),'')

    def test_payload_tamper_never_loads(self):
        self.install();(self.gen/'rmnet_shs.ko').write_bytes(b'wrong')
        self.assertNotEqual(self.control().returncode,0);self.assertEqual(self.events.read_text(),'')

    def test_before_boot_and_disabled_never_loads(self):
        self.install();self.prop('sys.boot_completed','0');self.assertEqual(self.control().returncode,0)
        self.prop('sys.boot_completed','1');(self.base/'disabled').touch()
        self.assertNotEqual(self.control().returncode,0);self.assertEqual(self.events.read_text(),'')

    def test_failed_load_is_not_pass(self):
        self.install();(self.root/'fail_load').touch()
        p=self.control();self.assertNotEqual(p.returncode,0);self.assertIn('LOAD_FAILED',p.stdout)

    def test_busy_unload_is_not_forced(self):
        self.install();self.assertEqual(self.control().returncode,0)
        (self.root/'busy').touch();self.prop('persist.vendor.data.shs_ko_load','0')
        p=self.control();self.assertNotEqual(p.returncode,0);self.assertIn('BUSY',p.stdout)
        self.assertTrue((self.sys/'module/rmnet_shs').exists())
        self.assertNotIn('-f',self.events.read_text())

    def test_foreign_loaded_module_untouched(self):
        self.install();self.assertEqual(self.control().returncode,0)
        (self.sys/'module/rmnet_shs/notes/.note.gnu.build-id').write_bytes(b'foreign')
        before=self.events.read_text();self.prop('persist.vendor.data.shs_ko_load','0')
        self.assertNotEqual(self.control().returncode,0);self.assertEqual(self.events.read_text(),before)

    def test_missing_interface_never_loads(self):
        self.install();(self.sys/'class/net/rmnet_data0').rmdir()
        self.assertNotEqual(self.control().returncode,0);self.assertEqual(self.events.read_text(),'')

    def test_undefined_property_does_not_enable(self):
        self.install();self.prop('persist.vendor.data.shs_ko_load','unexpected')
        self.assertEqual(self.control().returncode,0);self.assertEqual(self.events.read_text(),'')

    def test_symlink_destination_rejected(self):
        target=self.root/'elsewhere';target.mkdir();self.base.symlink_to(target,target_is_directory=True)
        p=self.runsh(self.payload/'install.sh',self.payload)
        self.assertNotEqual(p.returncode,0);self.assertEqual(list(target.iterdir()),[])

    def test_foreign_launcher_preserved(self):
        self.common.mkdir();p=self.common/'50-veux-rmnet.sh';p.write_text('foreign')
        result=self.runsh(self.payload/'install.sh',self.payload)
        self.assertNotEqual(result.returncode,0);self.assertEqual(p.read_text(),'foreign')

    def test_changed_generation_is_not_overwritten(self):
        self.install();p=self.gen/'rmnet_shs.ko';p.write_bytes(b'foreign')
        result=self.runsh(self.payload/'install.sh',self.payload)
        self.assertNotEqual(result.returncode,0);self.assertEqual(p.read_bytes(),b'foreign')

    def test_wait_mode_handles_property_change_without_polling(self):
        self.install()
        self.ksud.write_text(f'''#!/bin/sh
case "$*" in *--help*) echo --wait; exit 0;; esac
case "$*" in *--wait*) ;; *) exit 9;; esac
if [ ! -f '{self.root}/changed' ]; then
  touch '{self.root}/changed'
  echo 0 > '{self.root}/props/persist.vendor.data.offload_ko_load'
  exit 0
fi
touch '{self.base}/disabled'
exit 2
''')
        code=(self.gen/'runtime.sh').read_text();code=code[:code.index('case "${1:-}" in')]
        code+='\nwatch_property rmnet_offload persist.vendor.data.offload_ko_load\n'
        temporary=self.gen/'watch-test.sh';temporary.write_text(code)
        result=self.runsh(temporary)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.events.read_text().splitlines(),['load:rmnet_offload','unload:rmnet_offload'])



class BuildFlowTests(unittest.TestCase):
    def prepared(self, td):
        root=Path(td);work=root/'5.4.274';out=work/'build';src=work/'src'
        out.mkdir(parents=True);src.mkdir()
        config=('CONFIG_MODULES=y\nCONFIG_MODULE_UNLOAD=y\nCONFIG_MODVERSIONS=y\n'
                'CONFIG_CFI_CLANG=y\nCONFIG_THINLTO=y\nCONFIG_STACKPROTECTOR_STRONG=y\n'
                '# CONFIG_MODULE_FORCE_LOAD is not set\n# CONFIG_MODULE_FORCE_UNLOAD is not set\n').encode()
        (out/'.config').write_bytes(config)
        (out/'Module.symvers').write_text('0x1234 module_layout vmlinux EXPORT_SYMBOL\n')
        elf=tiny_elf();notes=r.Elf64(elf).section('.note.gnu.build-id')
        old=b'.note.gnu.build-id\0';new=b'.notes\0'.ljust(len(old),b'\0')
        (out/'vmlinux').write_bytes(elf.replace(old,new))
        image=out/'Image';image.write_bytes(b'\0'*64+notes)
        (out/'System.map').write_text(f'1000 T _text\n1040 R __start_notes\n{0x1040+len(notes):x} R __stop_notes\n')
        for name,folder in r.PAIR.items():
            p=src/'techpack/datarmnet-ext'/folder;p.mkdir(parents=True)
            (p/'Kbuild').write_text('obj-m += '+name+'.o\n')
            (p/'unit.c').write_text('int implementation(void) {return 0;}\n')
        state={'source':str(src),'variables':['O=old','ARCH=arm64','CC=clang'],
               'env':{'PATH':'/usr/bin:/bin:'+str(work/'source-temp/bin')}}
        row=proof_for(image.read_bytes(),config,notes);row.pop('rmnet')
        return work,out,src,image,state,row

    def fake(self, out, events, fail=None):
        def run(args,**kw):
            events.append(args)
            Path(kw['log']).write_text('fixture compile\n')
            self.assertNotIn('VEUX_CAPTURE',kw['env'])
            self.assertEqual(kw['env']['PATH'],'/usr/bin:/bin')
            self.assertIn('O='+str(out),args)
            if args[-1]=='modules_prepare':return ''
            source=Path(next(a[2:] for a in args if a.startswith('M=')))
            name=next(n for n,f in r.PAIR.items() if f==source.name)
            self.assertIn('KBUILD_EXTRA_SYMBOLS=',args)
            (source/(name+'.ko')).write_bytes(tiny_elf(name,crc=0x1234 if fail!='crc' else 0x42))
            flags='-fsanitize=cfi -flto=thin -fstack-protector-strong'
            (source/'.unit.o.cmd').write_text(flags if fail!='cfi' else '-O2')
            if fail=='symvers':(out/'Module.symvers').write_text('changed')
            if fail=='config':(out/'.config').write_text('changed')
            return ''
        return run

    def test_actual_build_function_checks_pair_and_preserves_base(self):
        import sys,types
        with tempfile.TemporaryDirectory() as td:
            work,out,src,image,state,row=self.prepared(td);events=[]
            before={n:(out/n).read_bytes() for n in ('.config','Module.symvers','Image')}
            with patch.dict(sys.modules,{'veux_update_engine':types.SimpleNamespace(run=self.fake(out,events))}):
                proof=r.build_modules(state,work,image,row,2)
            r.verify_proof(row)
            self.assertEqual(len(events),3)
            self.assertEqual(set(proof['modules']),set(r.PAIR))
            self.assertEqual(before,{n:(out/n).read_bytes() for n in before})
            self.assertEqual(len(list((work/'rmnet-payload').glob('*.ko'))),2)

    def test_source_compile_protection_and_same_build_drift_fail(self):
        import sys,types
        for failure in ('crc','cfi','symvers','config'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as td:
                work,out,src,image,state,row=self.prepared(td)
                with patch.dict(sys.modules,{'veux_update_engine':types.SimpleNamespace(run=self.fake(out,[],failure))}):
                    with self.assertRaises(ValueError):r.build_modules(state,work,image,row,2)
                self.assertNotIn('rmnet',row)

    def test_candidate_missing_requirement_is_not_silently_accepted(self):
        self.assertTrue(r.requested({'candidate_manual_build':True,'rmnet_required':[r.KERNEL]},r.KERNEL))
        self.assertFalse(r.requested({'rmnet_required':[r.KERNEL]},'5.4.302'))
        self.assertTrue(r.requested({'candidate_manual_build':True},r.KERNEL))
        for value in ([],['other'],[r.KERNEL,r.KERNEL],'5.4.274',None):
            with self.subTest(value=value),self.assertRaises(ValueError):
                r.requested({'candidate_manual_build':True,'rmnet_required':value},r.KERNEL)

    def test_package_identity_tamper_fails_even_with_recomputed_zip_checksums(self):
        with tempfile.TemporaryDirectory() as td:
            work,public,row=PackageTests().prepare(td);r.augment_package(row,work,public)
            package=public/row['package_file']
            with zipfile.ZipFile(package) as z:
                members={i.filename:(z.read(i),(i.external_attr>>16)&0o777) for i in z.infolist()}
            members['rmnet/identity.txt']=(members['rmnet/identity.txt'][0].replace(b'5.4.274-test',b'5.4.274-wrong'),0o600)
            sums=''.join(r.digest(data)+'  '+n.removeprefix('rmnet/')+'\n' for n,(data,_) in sorted(members.items())
                         if n.startswith('rmnet/') and n!='rmnet/SHA256SUMS')
            members['rmnet/SHA256SUMS']=(sums.encode(),0o600)
            r.write_zip(package,members);row['package_sha256']=r.digest(package)
            with self.assertRaisesRegex(ValueError,'identity'):r.verify_package(row,public)

    def test_missing_installer_call_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            work,public,row=PackageTests().prepare(td);r.augment_package(row,work,public)
            package=public/row['package_file']
            with zipfile.ZipFile(package) as z:
                members={i.filename:(z.read(i),(i.external_attr>>16)&0o777) for i in z.infolist()}
            members['anykernel.sh']=(b'dump_boot;\nwrite_boot;\n',0o755)
            r.write_zip(package,members);row['package_sha256']=r.digest(package)
            with self.assertRaises(ValueError):r.verify_package(row,public)

if __name__=='__main__':unittest.main(verbosity=2)
