#!/usr/bin/env python3
"""Release regression tests using temporary sources and a local Git remote."""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile
import veux_update_engine as e
import veux_release as r

class ReleaseTests(unittest.TestCase):
    def source(self, root):
        for name, data in {'fs/test.c':'old', 'include/linux/test.h':'header',
                           'KernelSU/kernel/Kbuild':'build', 'KernelSU/uapi/supercall.h':'uapi',
                           'KernelSU/LICENSE':'license'}.items():
            p=root/name; p.parent.mkdir(parents=True, exist_ok=True);p.write_text(data)
        (root/'KernelSU/kernel/include').mkdir()
        (root/'KernelSU/kernel/include/uapi').symlink_to('../../uapi')
        (root/'drivers').mkdir();(root/'drivers/kernelsu').symlink_to('../KernelSU/kernel')

    def targets(self):
        return {'components':{c:{'version':v,'commit':'a'*40} for c,v in zip(e.COMPONENTS,['35184','2.3.0','20'])}}

    def test_identity_rejects_path_and_output_injection(self):
        t=self.targets()
        self.assertEqual(r.identity('5.4.274',t['components']), 'Kernel_5.4.274_ReSukiSU_35184_SUSFS_2.3.0_NoMount_20')
        for v in ('../../x','20\nartifact_name=x','20/x',''):
            t['components']['nomount']['version']=v
            with self.assertRaises(e.Blocked):r.identity('5.4.274',t['components'])

    def test_overlay_replay_and_tamper_fail_before_writes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'src';self.source(src)
            pristine=root/'pristine';shutil.copytree(src,pristine,symlinks=True)
            before=r.inventory(src);(src/'fs/test.c').write_text('new');(src/'include/linux/test.h').unlink()
            (src/'fs/added.c').write_text('added')
            folder=root/'overlay';r.save_overlay(src,before,folder,'5.4.274',self.targets())
            r.apply_overlay(pristine,folder,'5.4.274',self.targets())
            self.assertEqual(r.inventory(pristine),r.inventory(src))
            with self.assertRaises(e.Blocked):r.apply_overlay(pristine,folder,'5.4.274',self.targets())
            fresh=root/'fresh';self.source(fresh)
            (folder/'files/fs/test.c').write_text('tampered')
            with self.assertRaises(e.Blocked):r.apply_overlay(fresh,folder,'5.4.274',self.targets())
            self.assertEqual((fresh/'fs/test.c').read_text(),'old')

    def test_boot_copy_requires_verified_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'static').mkdir();(root/'static/boot.img').write_bytes(b'boot')
            public=root/'public';public.mkdir()
            row={'kernel':'5.4.274','static_boot':True,'static_boot_sha256':e.digest(root/'static/boot.img')}
            r.publish_files(row,root,public,self.targets());r.verify_boot(row,public)
            (public/row['boot_file']).write_bytes(b'bad')
            with self.assertRaises(e.Blocked):r.verify_boot(row,public)
            row['static_boot']=False
            with self.assertRaises(e.Blocked):r.publish_files(row,root,public,self.targets())

    def test_package_contains_installation_files_and_license_only(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);public=root/'public';public.mkdir();image=root/'Image';image.write_bytes(b'kernel')
            def checkout(url, commit, dest):
                for name in ('tools/ak3-core.sh','META-INF/com/google/android/update-binary',
                             'META-INF/com/google/android/updater-script','LICENSE','WORK-NOTES.txt','RESULT.json'):
                    p=dest/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
            with mock.patch.object(e,'checkout',side_effect=checkout),mock.patch.object(e,'git',return_value='tree'), \
                 mock.patch.object(e,'config',return_value={'ak3':{'repo':'fixture','commit':'a'*40,'tree':'tree'}}):
                package=e.package_kernel(image,self.targets(),{'kernel':'5.4.274'},root,public)
            with zipfile.ZipFile(package) as z:
                self.assertEqual(set(z.namelist()),{'Image','anykernel.sh','LICENSE','tools/ak3-core.sh',
                    'META-INF/com/google/android/update-binary','META-INF/com/google/android/updater-script'})
                self.assertEqual(z.read('Image'),b'kernel')
            self.assertEqual(package.name,r.identity('5.4.274',self.targets()['components'])+'_AnyKernel.zip')

    def test_worker_publishes_final_files_and_retains_overlay_after_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);label='5.4.274';bundle=root/'bundle';bundle.mkdir()
            t=self.targets();t.update(repository_sha=e.git(e.REPO,'rev-parse','HEAD'),
                golden_sha256=e.digest(e.REPO/e.config()['golden_contract']),lineages=[label])
            e.write_json(bundle/'targets.json',t)
            args=argparse.Namespace(kernel=label,bundle=bundle,work=root/'builds'/label,
                public=root/'public'/label,overlays=root/'overlays',jobs=1)
            def materialize(label,work):
                src=work/'source';self.source(src);return {'source':str(src)}
            def integrate(src,*rest):(src/'fs/test.c').write_text('updated')
            def compile(label,state,targets,work,jobs):
                image=work/'Image';image.write_bytes(b'image')
                return image,{'kernel':label,'compile':True,'image_sha256':e.digest(image)}
            def package(image,targets,result,work,public):
                (public/'kernel.zip').write_bytes(b'package');result.update(package=True,package_file='kernel.zip')
                e.write_json(public/'PACKAGE-STATUS.json',result)
            def boot(image,result,work):
                p=work/'static/boot.img';p.parent.mkdir();p.write_bytes(b'boot')
                result.update(static_boot=True,static_boot_sha256=e.digest(p),device=False)
            with mock.patch.object(e,'materialize',side_effect=materialize), \
                 mock.patch.object(e,'prepare_dtb_reference',return_value={}), \
                 mock.patch.object(e,'apply_update',side_effect=integrate), \
                 mock.patch.object(e,'compile_kernel',side_effect=compile), \
                 mock.patch.object(e,'package_kernel',side_effect=package), \
                 mock.patch.object(e,'static_boot',side_effect=boot), \
                 mock.patch.dict(os.environ,{'GITHUB_OUTPUT':str(root/'outputs')}):
                r.run_worker(args)
            self.assertFalse(args.work.exists())
            row=json.loads((args.public/'RESULT.json').read_text())
            self.assertEqual(row['integration_overlay_sha256'],e.digest(args.overlays/label/'overlay.json'))
            self.assertEqual(set(p.name for p in args.public.iterdir()),
                             {'kernel.zip',row['boot_file'],'RESULT.json','SHA256SUMS.txt'})
            self.assertEqual((root/'outputs').read_text(),'artifact_name='+row['artifact_name']+'\n')
            r.verify_boot(row,args.public)

    def test_workflow_uploads_each_success_before_next_build_and_promotes_last(self):
        w=e.yaml_read(e.REPO/'.github/workflows/veux-all-in-one-updater-v4.yml')
        steps=w['jobs']['update']['steps']; names=[s['name'] for s in steps]
        self.assertNotIn('Run the same engine for all six sources',names)
        for label in e.config()['lineages']:
            i=names.index('Build and validate '+label)
            self.assertEqual(names[i+1],'Publish '+label)
            self.assertIn('outputs.artifact_name',steps[i+1]['with']['name'])
        self.assertGreater(names.index('Commit validated sources to main'),names.index('Publish 5.4.302'))
        self.assertFalse(steps[0]['with']['persist-credentials'])
        for s in steps:
            if 'run' in s:
                subprocess.run(['bash','-n'],input=s['run'],text=True,check=True)

    def fixture(self, root):
        repo=root/'repo';repo.mkdir();remote=root/'remote.git'
        e.run(['git','init','--bare','-q',remote]);e.git(repo,'init','-q','-b','main')
        e.git(repo,'config','user.name','test');e.git(repo,'config','user.email','test@example.invalid')
        (repo/'golden').write_text('immutable')
        for c in e.COMPONENTS:(repo/f'common/upstream/{c}').mkdir(parents=True)
        (repo/'common/contracts').mkdir(parents=True)
        e.git(repo,'add','.');e.git(repo,'commit','-qm','base');e.git(repo,'remote','add','origin',str(remote));e.git(repo,'push','-q','origin','main')
        bundle=root/'bundle';bundle.mkdir();t=self.targets()
        for c in e.COMPONENTS:
            donor=bundle/c;donor.mkdir();e.git(donor,'init','-q');e.git(donor,'config','user.name','test');e.git(donor,'config','user.email','test@example.invalid')
            part='kernel_patches' if c=='susfs' else 'kernel'
            (donor/part).mkdir();(donor/part/'source.c').write_text(c);(donor/'LICENSE').write_text('license')
            e.git(donor,'add','.');e.git(donor,'commit','-qm','source');t['components'][c]['commit']=e.git(donor,'rev-parse','HEAD')
        t.update(repository_sha=e.git(repo,'rev-parse','HEAD'),golden_sha256=e.digest(repo/'golden'),lineages=list(e.config()['lineages']))
        e.write_json(bundle/'targets.json',t)
        arts=root/'artifacts';overlays=root/'overlays'
        for label in t['lineages']:
            folder=arts/label;folder.mkdir(parents=True)
            with zipfile.ZipFile(folder/'kernel.zip','w') as z:z.writestr('Image',b'image')
            (folder/'boot.img').write_bytes(b'boot')
            e.write_json(overlays/label/'overlay.json',{'kernel':label,'targets':t['components'],'edits':{}})
            row={'kernel':label,'repository_sha':t['repository_sha'],'targets':t['components'],
                 'target_manifest_sha256':e.digest(bundle/'targets.json'),'compile':True,'package':True,'static_boot':True,'device':False,
                 'package_file':'kernel.zip','package_sha256':e.digest(folder/'kernel.zip'),
                 'image_sha256':e.hashlib.sha256(b'image').hexdigest(),'boot_file':'boot.img',
                 'static_boot_sha256':e.digest(folder/'boot.img'),'integration_overlay_sha256':e.digest(overlays/label/'overlay.json')}
            e.write_json(folder/'RESULT.json',row)
        return repo,t,argparse.Namespace(bundle=bundle,artifacts=arts,overlays=overlays,output=root/'promotion')

    def test_promotion_pushes_only_after_six_validated_results(self):
        with tempfile.TemporaryDirectory() as d:
            repo,t,args=self.fixture(Path(d))
            def normalized(donor,entry,dest):shutil.copytree(donor/'kernel',dest)
            with mock.patch.object(e,'REPO',repo), mock.patch.object(e,'check_repo',return_value=({'golden_contract':'golden'},{})), \
                 mock.patch.object(e,'config',return_value={'golden_contract':'golden'}), mock.patch.object(e,'normalized_resukisu',side_effect=normalized):
                r.promote(args)
            head=e.git(repo,'rev-parse','HEAD')
            self.assertNotEqual(head,t['repository_sha'])
            self.assertEqual(e.git(repo,'ls-remote','origin','refs/heads/main').split()[0],head)
            self.assertEqual((repo/'golden').read_text(),'immutable')
            manifest=json.loads((repo/r.CURRENT).read_text());self.assertEqual(len(manifest['lineages']),6)
            self.assertFalse(manifest['device_pass_inferred'])
            self.assertFalse(e.git(repo,'status','--porcelain'))

    def test_promotion_blocks_corrupt_boot_and_moved_main(self):
        for mode in ('boot','moved'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                repo,t,args=self.fixture(Path(d))
                if mode=='boot':(args.artifacts/t['lineages'][0]/'boot.img').write_bytes(b'bad')
                else:
                    other=Path(d)/'other';e.run(['git','clone','-q','--branch','main',repo/'../remote.git',other])
                    (other/'new').write_text('concurrent change');e.git(other,'add','new')
                    e.git(other,'-c','user.name=test','-c','user.email=test@example.invalid','commit','-qm','concurrent')
                    e.git(other,'push','-q','origin','main')
                with mock.patch.object(e,'REPO',repo),mock.patch.object(e,'check_repo',return_value=({'golden_contract':'golden'},{})), \
                     mock.patch.object(e,'config',return_value={'golden_contract':'golden'}), \
                     mock.patch.object(e,'normalized_resukisu',side_effect=lambda donor,entry,dest:shutil.copytree(donor/'kernel',dest)):
                    with self.assertRaises(e.Blocked):r.promote(args)
                self.assertEqual(e.git(repo,'rev-parse','HEAD'),t['repository_sha'])
                self.assertFalse(e.git(repo,'status','--porcelain'))

if __name__=='__main__':unittest.main(verbosity=2)
