#!/usr/bin/env python3
"""GPL-2.0-only. Compile exact RPM functions with a simulated transport.

This is a host regression test, not a kernel build or hardware test.
"""
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'sources/rpm-custom.c'
EXPECTED = '6e75d6e45479b0e1821249b51388b928bf7f4b9abf568cfcbd8a9f5d4e834cf3'
OUT = None


def function(text, name):
    match = re.search(r'^(?:static )?(?:int|void) ' + re.escape(name) + r'\(', text, re.M)
    if not match:
        raise ValueError('Function absent: ' + name)
    start = text.index('{', match.start())
    depth = 0
    for pos in range(start, len(text)):
        depth += (text[pos] == '{') - (text[pos] == '}')
        if depth == 0:
            return text[match.start():pos + 1]
    raise ValueError('Unterminated function: ' + name)


PREAMBLE = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define MAX_WAIT_ON_ACK 24
struct rb_node { struct rb_node *next; };
struct rb_root { struct rb_node *first; };
struct slp_buf { struct rb_node node; char *buf; bool valid; };
struct payload { unsigned int index, msg_id; };
struct cpumask { int unused; };
struct mock_rpm { void *rpm_channel; };
static struct mock_rpm mock_rpm;
static struct mock_rpm *rpm = &mock_rpm;
static struct rb_root tr_root;
static struct slp_buf rows[40];
static struct payload payloads[40];
static int trysend_count = 20;
static bool standalone;
static int probe_status;
static unsigned int next_msg_id;
static int fail_index, failure_count, injected_errno;
static int send_calls, successes, warnings, traces, delays;
static int receive_masked, mask_calls, unmask_calls, mpm_calls, mask_error;
#define rb_entry(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
static struct rb_node *rb_first(struct rb_root *r) { return r->first; }
static struct rb_node *rb_next(struct rb_node *n) { return n->next; }
static unsigned int get_rsc_type(char *b) { return ((struct payload *)b)->index; }
static unsigned int get_rsc_id(char *b) { return ((struct payload *)b)->index; }
static unsigned int get_msg_id(char *b) { return ((struct payload *)b)->msg_id; }
static void set_msg_id(char *b,unsigned int id) { ((struct payload *)b)->msg_id=id; }
static unsigned int get_buf_len(char *b) { (void)b; return sizeof(struct payload); }
static unsigned int msm_rpm_get_next_msg_id(void) { return ++next_msg_id; }
static int rpmsg_trysend(void *ch, void *buf, uint32_t size) {
    struct payload *p = buf; (void)ch; (void)size; ++send_calls;
    if ((int)p->index == fail_index && failure_count > 0) {
        --failure_count; return injected_errno;
    }
    ++successes; return 0;
}
static void udelay(unsigned int us) { (void)us; ++delays; }
#define WARN_ON(condition) do { if (condition) ++warnings; } while (0)
#define pr_err(...) do {} while (0)
static void trace_rpm_smd_send_sleep_set(unsigned int m,unsigned int t,unsigned int i) {
    (void)m; (void)t; (void)i; ++traces;
}
static int smd_mask_receive_interrupt(bool mask, const struct cpumask *cpumask) {
    (void)cpumask;
    if (mask) { ++mask_calls; if(mask_error) return mask_error; }
    else ++unmask_calls;
    receive_masked=mask; return 0;
}
static void msm_mpm_enter_sleep(struct cpumask *mask) { (void)mask; ++mpm_calls; }
'''

MAIN = r'''
int main(int argc, char **argv) {
    if(argc != 7) return 2;
    int total=atoi(argv[1]); fail_index=atoi(argv[2]);
    failure_count=atoi(argv[3]); injected_errno=atoi(argv[4]);
    int retry=atoi(argv[5]); mask_error=atoi(argv[6]);
    if(total < 0 || total > 40) return 3;
    tr_root.first=total ? &rows[0].node : NULL;
    for(int i=0;i<total;++i) {
        payloads[i].index=(unsigned)i;
        rows[i].node.next=(i+1<total) ? &rows[i+1].node : NULL;
        rows[i].buf=(char *)&payloads[i]; rows[i].valid=true;
    }
    int rc=system_sleep_enter(NULL), pending=0;
    for(int i=0;i<total;++i) pending+=rows[i].valid;
    printf("{\"rc\":%d,\"pending\":%d,\"send_calls\":%d,\"successes\":%d,"
           "\"warnings\":%d,\"traces\":%d,\"delays\":%d,\"masked\":%d,"
           "\"unmask_calls\":%d,\"mpm_calls\":%d",rc,pending,send_calls,successes,
           warnings,traces,delays,receive_masked,unmask_calls,mpm_calls);
    if(retry) {
        failure_count=0; mask_error=0;
        int old_sends=send_calls, old_success=successes;
        int second=system_sleep_enter(NULL), remaining=0;
        for(int i=0;i<total;++i) remaining+=rows[i].valid;
        printf(",\"retry_rc\":%d,\"retry_pending\":%d,\"retry_sends\":%d,"
               "\"retry_successes\":%d",second,remaining,send_calls-old_sends,successes-old_success);
    }
    puts("}"); return 0;
}
'''


def main():
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    original = raw.decode()
    old_function = function(original, 'msm_rpm_flush_requests')
    old = '\t\tWARN_ON(ret != 0);\n'
    new = ('\t\tif (ret) {\n'
           '\t\t\tpr_err("Failed to send sleep request: %d\\n", ret);\n'
           '\t\t\treturn ret;\n'
           '\t\t}\n')
    assert old_function.count(old) == 1
    fixed_function = old_function.replace(old, new)
    candidate = original.replace(old_function, fixed_function, 1)
    if len(sys.argv) != 2:
        raise SystemExit('usage: test_rpm_sleep.py FIXED_RPM_SOURCE')
    supplied = Path(sys.argv[1]).read_bytes()
    assert supplied == candidate.encode(), 'RPM candidate differs from reviewed correction'
    candidate = supplied.decode()
    stock = (ROOT / 'sources/rpm-stock-source.c').read_text()
    assert function(stock, 'msm_rpm_flush_requests') == old_function
    assert function(stock, 'msm_rpm_trysend_smd_buffer') == function(original, 'msm_rpm_trysend_smd_buffer')
    OUT.mkdir(exist_ok=True)
    (OUT / 'rpm-smd.fixed.c').write_text(candidate)
    patch = ''.join(difflib.unified_diff(original.splitlines(True), candidate.splitlines(True),
        fromfile='a/drivers/rpmsg/rpm-smd.c', tofile='b/drivers/rpmsg/rpm-smd.c'))
    (OUT / '0001-rpm-preserve-unsent-sleep-requests.patch').write_text(patch)
    pm = (ROOT / 'sources/system_pm_rpm.c').read_text()
    functions = ['msm_rpm_trysend_smd_buffer', 'msm_rpm_flush_requests', 'msm_rpm_enter_sleep']
    binaries = {}
    for name, text in [('original', original), ('fixed', candidate), ('xiaomi-source', stock)]:
        unit = PREAMBLE + '\n'.join(function(text, n) for n in functions)
        unit += '\n' + function(pm, 'system_sleep_enter') + '\n' + MAIN
        source = OUT / (name + '-host.c'); source.write_text(unit)
        binary = OUT / (name + '-host')
        command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                   '-O2', str(source), '-o', str(binary)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        binaries[name] = binary
    cases = []
    for n in [0, 1, 23, 24, 25, 40]:
        cases.append((f'success_boundary_{n}', [n,-1,0,-5,1,0]))
    for n in [1,2,19,20,21,40]:
        cases.append((f'transport_attempts_{n}', [1,0,n,-5,1,0]))
    for err in [-5,-11,-12,-16,-19,-22,-110]:
        cases.append((f'error_{abs(err)}', [3,1,20,err,1,0]))
    cases += [('last_slot_failure',[24,23,20,-11,1,0]),
              ('next_batch_failure',[25,24,20,-11,0,0]),
              ('mask_failure',[3,-1,0,-5,1,-16])]
    results = []
    reproduced = 0
    for name, args in cases:
        rows = {n: json.loads(subprocess.check_output([str(binary), *map(str,args)], text=True))
                for n,binary in binaries.items()}
        assert rows['original'] == rows['xiaomi-source'], name
        n, index, fails, err, retry, mask_err = args
        send_failure = not mask_err and 0 <= index < min(n,24) and fails >= 20
        f=rows['fixed']
        if mask_err:
            assert f['rc']==mask_err and f['pending']==n and f['send_calls']==0 and f['mpm_calls']==0, name
        elif send_failure:
            assert f['rc']==err and f['pending']==n-index and f['successes']==index, name
            assert f['masked']==0 and f['unmask_calls']==1 and f['mpm_calls']==0, name
            assert f['warnings']==0 and f['traces']==index, name
            assert rows['original']['pending'] < f['pending'], name
            reproduced += 1
        else:
            assert f == rows['original'], name
            assert f['rc'] == (-28 if n>=24 else 0), name
            assert f['pending']==max(0,n-24), name
        if retry:
            assert f['retry_rc']==0 and f['retry_pending']==0, name
            assert f['retry_sends']==f['pending'] and f['retry_successes']==f['pending'], name
        results.append({'case':name,'args':args,'transport_failure_reproduced':send_failure,'results':rows})
    summary={'host_cases_passed':len(results),'transport_failure_cases':reproduced,
             'original_source_sha256':EXPECTED,
             'fixed_source_sha256':hashlib.sha256(candidate.encode()).hexdigest(),
             'patch_sha256':hashlib.sha256(patch.encode()).hexdigest(),
             'stock_source_flush_and_retry_identical':True,
             'kernel_build':False,'device_test':False,'repo_integrated':False,
             'transport_and_tree_simulated':True,'cases':results}
    (OUT/'RESULTS.json').write_text(json.dumps(summary,indent=2)+'\n')
    assert len(results) == 22 and reproduced == 11
    print('RPM_SLEEP_HOST_TESTS=PASS; CASES=22; REPRODUCED_FAILURE_CASES=11')


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='veux-rpm-host-') as temporary:
        OUT = Path(temporary)
        main()
