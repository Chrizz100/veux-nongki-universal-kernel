#!/usr/bin/env python3
"""Compile extracted RPM driver C functions against a bounded fake rpmsg transport.

--fixture: local structural/runtime model, no kernel source claim.
--source: exact revised kernel C function from same build work tree.
No actual hardware, driver linking or device PASS is asserted.
"""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
import hashlib
import re
import shutil
import types
from unittest.mock import patch
import veux_rpm24 as rpm24

# Local fixture preserves exact reviewed source function body and its transport
# branch after rpm-sleep-r1. CI --source instead extracts actual build-tree C.
FLUSH_ORIGINAL = '''static int msm_rpm_flush_requests(bool print)
{
\tstruct rb_node *t;
\tint ret;
\tint count = 0;

\tfor (t = rb_first(&tr_root); t; t = rb_next(t)) {

\t\tstruct slp_buf *s = rb_entry(t, struct slp_buf, node);
\t\tunsigned int type = get_rsc_type(s->buf);
\t\tunsigned int id = get_rsc_id(s->buf);

\t\tif (!s->valid)
\t\t\tcontinue;

\t\tset_msg_id(s->buf, msm_rpm_get_next_msg_id());

\t\tret = msm_rpm_trysend_smd_buffer(s->buf, get_buf_len(s->buf));

\t\tif (ret) {
\t\t\tpr_err("Failed to send sleep request: %d\\n", ret);
\t\t\treturn ret;
\t\t}
\t\ttrace_rpm_smd_send_sleep_set(get_msg_id(s->buf), type, id);

\t\ts->valid = false;
\t\tcount++;

'''+rpm24.OLD_TRAILING+'''\t}
\treturn 0;
}
'''

SENDER = '''static int msm_rpm_trysend_smd_buffer(char *buf, uint32_t size)
{
\tint ret;
\tint count = 0;

\tdo {
\t\tret = rpmsg_trysend(rpm->rpm_channel, buf, size);
\t\tif (!ret)
\t\t\tbreak;
\t\tudelay(10);
\t\tcount++;
\t} while (count < trysend_count);

\treturn ret;
}
'''
ENTER = '''int msm_rpm_enter_sleep(bool print, const struct cpumask *cpumask)
{
\tint ret = 0;

\tif (standalone)
\t\treturn 0;

\tif (probe_status)
\t\treturn 0;

\tret = smd_mask_receive_interrupt(true, cpumask);
\tif (!ret) {
\t\tret = msm_rpm_flush_requests(print);
\t\tif (ret)
\t\t\tsmd_mask_receive_interrupt(false, NULL);
\t}
\treturn ret;
}
'''
PREAMBLE=r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define MAX_WAIT_ON_ACK 24
struct rb_node {struct rb_node *next;};
struct rb_root {struct rb_node *first;};
struct slp_buf {struct rb_node node; char *buf; bool valid;};
struct payload { unsigned index, msg_id; };
struct cpumask {int pad;};
struct mock_rpm {void *rpm_channel;};
static struct mock_rpm stub;
static struct mock_rpm *rpm=&stub;
static struct rb_root tr_root;
static struct slp_buf rows[48];
static struct payload payloads[48];
static int trysend_count=20;
static bool standalone;
static int probe_status;
static unsigned next_msg_id, send_calls, successes, warnings, traces, delay_calls;
static int fail_index=-1, failure_count=0, forced_error=-5;
static int receive_masked, unmask_calls, mask_calls;
#define rb_entry(ptr,type,member) ((type*)((char*)(ptr)-offsetof(type,member)))
static struct rb_node *rb_first(struct rb_root *r) {return r->first;}
static struct rb_node *rb_next(struct rb_node *p) {return p->next;}
static unsigned get_rsc_type(char *b) {return ((struct payload*)b)->index;}
static unsigned get_rsc_id(char *b) {return ((struct payload*)b)->index;}
static unsigned get_msg_id(char *b) {return ((struct payload*)b)->msg_id;}
static void set_msg_id(char *b,unsigned id) {((struct payload*)b)->msg_id=id;}
static unsigned get_buf_len(char *b) {(void)b;return sizeof(struct payload);}
static unsigned msm_rpm_get_next_msg_id(void) {return ++next_msg_id;}
static int rpmsg_trysend(void *ch,void *buf,uint32_t size) {
  struct payload *p=buf;(void)ch;(void)size;++send_calls;
  if((int)p->index==fail_index && failure_count>0) {--failure_count;return forced_error;}
  ++successes;return 0;
}
static void udelay(unsigned us) {(void)us;++delay_calls;}
#define WARN_ON(c) do { if(c) ++warnings; }while(0)
#define pr_err(...) do {} while(0)
static void trace_rpm_smd_send_sleep_set(unsigned id,unsigned typ,unsigned resource) {
   (void)id;(void)typ;(void)resource;++traces;
}
static int smd_mask_receive_interrupt(bool mask,const struct cpumask *cpumask){
  (void)cpumask;if(mask){++mask_calls;}else{++unmask_calls;}receive_masked=mask;return 0;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
  if (argc!=6) return 2;
  int total=atoi(argv[1]),invalid_first=atoi(argv[2]),retry=atoi(argv[3]);
  fail_index=atoi(argv[4]);failure_count=atoi(argv[5]);
  if(total<0 || total>40 || invalid_first<0 || invalid_first>total) return 3;
  tr_root.first=total?&rows[0].node:NULL;
  for(int i=0;i<total;++i){
    payloads[i].index=i;
    rows[i].node.next=i+1<total?&rows[i+1].node:NULL;
    rows[i].buf=(char*)&payloads[i]; rows[i].valid=i>=invalid_first;
  }
  int rc=msm_rpm_enter_sleep(true,NULL),pending=0;
  for(int i=0;i<total;++i) pending+=rows[i].valid;
  printf("{\"rc\":%d,\"pending\":%d,\"sends\":%u,\"successes\":%u,"
         "\"warnings\":%u,\"traces\":%u,\"ids\":%u,\"masked\":%d,"
         "\"unmask\":%d",rc,pending,send_calls,successes,warnings,traces,
         next_msg_id,receive_masked,unmask_calls);
  if(retry){
     failure_count=0;
     unsigned old_sends=send_calls,old_success=successes;
     int rc2=msm_rpm_enter_sleep(true,NULL),p2=0;
     for(int i=0;i<total;++i)p2+=rows[i].valid;
     printf(",\"retry_rc\":%d,\"retry_pending\":%d,"
            "\"retry_sends\":%u,\"retry_success\":%u",
            rc2,p2,send_calls-old_sends,successes-old_success);
  }
  puts("}");return 0;
}
'''


def get_function(s,name):
    start=re.search(r'(?m)^(?:static )?int '+re.escape(name)+r'\([^\n]*',s)
    if start is None:
        raise AssertionError('missing actual C function: '+name)
    brace=s.index('{',start.start());depth=0
    for i in range(brace,len(s)):
        if s[i]=='{':depth+=1
        if s[i]=='}':
            depth-=1
            if not depth:return s[start.start():i+1]
    raise AssertionError('unterminated function: '+name)


def model_text(source=None):
    if source is None:
        old=FLUSH_ORIGINAL
        assert old.count(rpm24.OLD_TRAILING)==1
        return (old.replace(rpm24.INSERT_ANCHOR,rpm24.INSERT_ANCHOR+rpm24.NEW_GUARD,1)
                   .replace(rpm24.OLD_TRAILING,'',1)),SENDER,ENTER
    raw=Path(source).read_text()
    assert hashlib.sha256(raw.encode()).hexdigest() != rpm24.PREVIOUS_SHA256
    assert rpm24.NEW_GUARD in get_function(raw,'msm_rpm_flush_requests')
    assert rpm24.OLD_TRAILING not in get_function(raw,'msm_rpm_flush_requests')
    assert rpm24.patch(raw.encode())==raw.encode()
    return tuple(get_function(raw,n) for n in ('msm_rpm_flush_requests','msm_rpm_trysend_smd_buffer','msm_rpm_enter_sleep'))


def run_tests(source=None):
    flush,sender,enter=model_text(source)
    if source is None:
        assert 'if (ret)' in flush and rpm24.NEW_GUARD in flush
    with tempfile.TemporaryDirectory(prefix='veux-rpm24-host-') as temp:
        root=Path(temp)
        binaries={}
        for variant,fl in [('before', FLUSH_ORIGINAL), ('after',flush)]:
            target=root/(variant+'.c')
            target.write_text(PREAMBLE+sender+fl+enter+MAIN)
            program=root/variant
            p=subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                '-Wno-unused-function','-Wno-unused-parameter','-O2',str(target),'-o',str(program)],
                capture_output=True,text=True)
            assert p.returncode==0,(p.stdout,p.stderr)
            binaries[variant]=program
        def go(kind,n,invalid,retry,fail,tries):
            out=subprocess.check_output([str(binaries[kind]),*map(str,(n,invalid,retry,fail,tries))],text=True)
            return json.loads(out)
        tests=0
        for n in (0,1,2,22,23,24,25,26,40):
            b=go('before',n,0,1,-1,0); a=go('after',n,0,1,-1,0)
            assert a['successes']==min(n,24) and a['pending']==max(0,n-24)
            assert a['rc']==(-28 if n>24 else 0)
            assert a['warnings']==0 and a['traces']==a['successes']
            assert a['ids']==a['successes'] and a['sends']==a['successes']
            assert a['masked']==(1 if n<=24 else 0)
            assert a['retry_rc']==0 and a['retry_pending']==0
            assert a['retry_sends']==a['pending'] and a['retry_success']==a['pending']
            if n==24:assert b['rc']==-28 and a['rc']==0 and b['pending']==a['pending']==0
            if n==25:assert b['pending']==a['pending']==1 and a['retry_sends']==1
            tests+=1
        for n,invalid in ((26,2),(40,16),(40,17),(25,1),(24,1)):
            a=go('after',n,invalid,1,-1,0)
            v=n-invalid
            assert a['rc']==(-28 if v>24 else 0)
            assert a['pending']==max(0,v-24)
            assert a['successes']==min(v,24)
            assert a['retry_pending']==0 and a['retry_success']==a['pending']
            tests+=1
        for n,fail,tries in ((24,0,20),(24,23,20),(25,0,20),
                             (25,12,20),(25,23,20),(40,23,20)):
            a=go('after',n,0,1,fail,tries)
            assert a['rc']==-5 and a['pending']==n-fail
            assert a['successes']==fail and a['warnings']==0 and a['traces']==fail
            assert a['unmask']==1 and a['masked']==0
            # The no-send-error retry must still respect the 24-message ceiling.
            expected_remaining=n-fail
            assert a['retry_rc']==(-28 if expected_remaining>24 else 0)
            assert a['retry_success']==min(expected_remaining,24)
            assert a['retry_pending']==max(0,expected_remaining-24)
            tests+=1
        for n,fail,tries in ((24,0,19),(25,10,19),(24,23,19)):
            a=go('after',n,0,0,fail,tries)
            assert a['rc']==0 if n==24 else a['rc']==-28
            assert a['pending']==max(0,n-24)
            assert a['successes']==min(n,24)
            tests+=1
        assert tests==23
        return tests


class Unit(unittest.TestCase):
    def test_guard_in_place(self):
        revised,sender,enter=model_text()
        self.assertEqual(revised.count(rpm24.NEW_GUARD),1)
        self.assertEqual(revised.count('if (ret) {'),1)
        self.assertEqual(revised.count('count++;'),1)
        self.assertNotIn(rpm24.OLD_TRAILING,revised)
        self.assertEqual(SENDER.count('rpmsg_trysend'),1)

    def test_only_274(self):
        self.assertEqual(rpm24.KERNEL,'5.4.274')
        for label in ('5.4.292','5.4.293','5.4.300','5.4.301','5.4.302'):
            self.assertEqual(rpm24.apply(Path('/unused'),label,Path('/unused')),[])

    def test_edited_sources_rejected(self):
        for text in (FLUSH_ORIGINAL.replace('count++;','count+=2;'),
                     FLUSH_ORIGINAL.replace('if (ret) {','if (!ret) {'),
                     FLUSH_ORIGINAL.replace('MAX_WAIT_ON_ACK','MAX_WAIT_ON_ACK + 1')):
            with self.assertRaises(ValueError):rpm24.patch(text.encode())

    def test_runtime_cases(self):
        self.assertEqual(run_tests(),23)

    def test_worker_stage_runs_real_source_cases_without_full_kernel_copy(self):
        """Fail if RPM24 re-adds a full-tree wakeup unittest before wakeup.apply."""
        from contextlib import nullcontext
        with tempfile.TemporaryDirectory(prefix='rpm24-worker-real-') as temp:
            root=Path(temp)
            src=root/'source'
            source=src/rpm24.SOURCE
            source.parent.mkdir(parents=True)
            before=(FLUSH_ORIGINAL+'\n'+SENDER+'\n'+ENTER).encode()
            source.write_bytes(before)
            repo=root/'repo'
            scripts=repo/'common/scripts'
            scripts.mkdir(parents=True)
            shutil.copy2(Path(__file__),scripts/'test_veux_rpm24.py')
            shutil.copy2(Path(rpm24.__file__),scripts/'veux_rpm24.py')
            work=root/'work'
            work.mkdir()
            calls=[]
            def run(argv,**kwargs):
                argv=[str(x) for x in argv]
                calls.append(argv)
                r=subprocess.run(argv,capture_output=True,text=True,
                                 timeout=kwargs.get('timeout',45))
                Path(kwargs['log']).write_text(r.stdout+r.stderr)
                if r.returncode:
                    raise subprocess.CalledProcessError(r.returncode,argv,r.stdout,r.stderr)
            def inside(path,scope):
                Path(path).resolve().relative_to(Path(scope).resolve())
                return Path(path)
            def write_json(path,row):
                Path(path).write_text(json.dumps(row,indent=2))
            engine=types.SimpleNamespace(REPO=repo,run=run,inside=inside,
                                         write_json=write_json)
            with patch.dict(sys.modules,{'veux_update_engine':engine}), \
                 patch.object(rpm24,'PREVIOUS_SHA256',hashlib.sha256(before).hexdigest()):
                first=rpm24.apply(src,rpm24.KERNEL,work)
                second=rpm24.apply(src,rpm24.KERNEL,work)
                self.assertEqual(first,second)
                rpm24.verify_source(src,rpm24.KERNEL,first)
                rpm24.verify_result(rpm24.KERNEL,{'rpm24_fixes':first})
            self.assertEqual(len(calls),2)
            self.assertTrue(all(cmd[-2]=='--source' and
                         cmd[-1].endswith('rpm24-tested.c') for cmd in calls))
            self.assertTrue(all('test_veux_rpm24.py' in ' '.join(cmd) for cmd in calls))
            self.assertFalse((work/'wakeup-source-regression.log').exists())
            self.assertFalse((work/'rpm24-tested.c').exists())
            self.assertIn('SCENARIOS=23',(work/'rpm24-host-tests.log').read_text())
            self.assertEqual(first[0]['max_buffered'],24)

    def test_failed_rpm24_c_test_leaves_source_unmodified(self):
        """A host-test failure must never partly apply the RPM24 repair."""
        for problem in ('test_exit', 'timeout'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temp:
                root=Path(temp);src=root/'src';work=root/'work';work.mkdir()
                target=src/rpm24.SOURCE;target.parent.mkdir(parents=True)
                before=(FLUSH_ORIGINAL+'\n'+SENDER+'\n'+ENTER).encode()
                target.write_bytes(before)
                def inside(path,scope):
                    Path(path).resolve().relative_to(Path(scope).resolve())
                    return Path(path)
                def failing_run(*args,**kwargs):
                    if problem=='timeout':raise subprocess.TimeoutExpired(args[0],1)
                    raise subprocess.CalledProcessError(1,args[0])
                engine=types.SimpleNamespace(REPO=root,run=failing_run,
                                             inside=inside,write_json=lambda *a: None)
                with patch.dict(sys.modules,{'veux_update_engine':engine}),                      patch.object(rpm24,'PREVIOUS_SHA256',hashlib.sha256(before).hexdigest()):
                    with self.assertRaises((subprocess.TimeoutExpired,subprocess.CalledProcessError)):
                        rpm24.apply(src,rpm24.KERNEL,work)
                self.assertEqual(target.read_bytes(),before)
                self.assertFalse((work/'rpm24-tested.c').exists())
                self.assertFalse((work/'RPM24.json').exists())

    def test_wakeup_source_suite_is_not_called_before_wakeup_patch(self):
        body=Path(rpm24.__file__).read_text()
        self.assertNotIn("e.run([sys.executable, wakeup_test",body)
        self.assertNotIn("shutil.copytree(SOURCE",body)
        self.assertIn("wakeup.apply plus verify_source",body)


    def test_composite_after_compile_restores_rpm_r1_and_runs_existing_verifier(self):
        """The R3 kernel compile passed, but its postcompile hash check was stale."""
        import sys
        with tempfile.TemporaryDirectory(prefix='rpm24-composite-') as tmp:
            root=Path(tmp)
            src=root/'kernel';driver=src/rpm24.SOURCE
            driver.parent.mkdir(parents=True)
            r1=(FLUSH_ORIGINAL+'\n'+SENDER+'\n'+ENTER).encode()
            previous_sha=hashlib.sha256(r1).hexdigest()
            r1_proof=[{'id':'rpm-sleep-r1','sha':previous_sha}]
            expected_calls=[]
            def legacy_verify(stage,label,proof):
                assert label==rpm24.KERNEL and proof==r1_proof
                assert (Path(stage)/rpm24.SOURCE).read_bytes()==r1
                expected_calls.append('original RPM R1 validator actually invoked')
            rpm_stub=types.ModuleType('veux_rpm_fixes')
            rpm_stub.verify_source=legacy_verify
            with patch.dict(sys.modules,{'veux_rpm_fixes':rpm_stub}), \
                 patch.object(rpm24,'PREVIOUS_SHA256',previous_sha):
                r24=rpm24.patch(r1)
                driver.write_bytes(r24)
                proof=[{'id':rpm24.ID,'max_buffered':24,'host_tested':True,
                        'device':False,'source_sha256':rpm24.sha(r24)}]
                self.assertEqual(rpm24.reconstruct_previous(r24),r1)
                rpm24.verify_composed_source(src,rpm24.KERNEL,r1_proof,proof)
                self.assertEqual(len(expected_calls),1)
                self.assertEqual(driver.read_bytes(),r24)
                # A one-byte source drift cannot pass after compilation.
                driver.write_bytes(r24+b'\n')
                with self.assertRaises(ValueError):
                    rpm24.verify_composed_source(src,rpm24.KERNEL,r1_proof,proof)
                driver.write_bytes(r24)
                # A forged new proof or forged old baseline is rejected.
                tampered=[dict(proof[0],source_sha256='0'*64)]
                with self.assertRaises(ValueError):
                    rpm24.verify_composed_source(src,rpm24.KERNEL,r1_proof,tampered)
                with self.assertRaises(AssertionError):
                    rpm24.verify_composed_source(src,rpm24.KERNEL,[{'id':'wrong'}],proof)
                self.assertEqual(driver.read_bytes(),r24)
                self.assertEqual(len(expected_calls),1)

    def test_composite_legacy_hash_proof_is_not_disabled(self):
        """Reconstruction must fail when the postimage belongs to another R1."""
        with tempfile.TemporaryDirectory(prefix='rpm24-tamper-') as tmp:
            p=Path(tmp)/rpm24.SOURCE;p.parent.mkdir(parents=True)
            old=(FLUSH_ORIGINAL+'\n'+SENDER+'\n'+ENTER).encode()
            with patch.object(rpm24,'PREVIOUS_SHA256',rpm24.sha(old)):
                new=rpm24.patch(old)
                self.assertEqual(rpm24.reconstruct_previous(new),old)
            with self.assertRaisesRegex(ValueError,'predecessor'):
                rpm24.reconstruct_previous(new)


if __name__=='__main__':
    if len(sys.argv)==1:
        unittest.main(verbosity=2)
    elif len(sys.argv)==3 and sys.argv[1]=='--source':
        n=run_tests(sys.argv[2]);print(f'RPM24_HOST_C_SOURCE=PASS; SCENARIOS={n}; DEVICE_PASS=NO')
    else:
        sys.exit('Usage: test_veux_rpm24.py [--source path/to/patched/rpm-smd.c]')
