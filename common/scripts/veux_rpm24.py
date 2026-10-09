#!/usr/bin/env python3
"""VEUX 5.4.274: fix false -ENOSPC at exactly 24 RPM sleep requests.

Install only after the existing rpm-sleep-r1 stage. Existing limits and
transport failure handling must remain effective; no IRQ, buffer or ACK hack.
"""
import hashlib
from pathlib import Path
import re

KERNEL = '5.4.274'
SOURCE = 'drivers/rpmsg/rpm-smd.c'
PREVIOUS_SHA256 = '8c7416abec4c2c28ccc9829ad9f6abaee2c42bdcfda8fd8420236c6b1cb5c655'
ID = 'rpm24-boundary-r1'
NEW_GUARD = '''\t\t/*
\t\t * Each valid request occupies one of the 24 buffered slots.
\t\t * Refuse the 25th BEFORE modifying its message or sending it;
\t\t * the existing suspend caller will unmask RX and retry later.
\t\t */
\t\tif (count >= MAX_WAIT_ON_ACK) {
\t\t\tpr_err("Error: more than %d requests are buffered\\n",
\t\t\t\t\t\tMAX_WAIT_ON_ACK);
\t\t\treturn -ENOSPC;
\t\t}

'''
OLD_TRAILING = '''\t\t/*
\t\t * RPM acks need to be handled here if we have sent 24
\t\t * messages such that we do not overrun SMD buffer. Since
\t\t * we expect only sleep sets at this point (RPM PC would be
\t\t * disallowed if we had pending active requests), we need not
\t\t * process these sleep set acks.
\t\t */
\t\tif (count >= MAX_WAIT_ON_ACK) {
\t\t\tpr_err("Error: more than %d requests are buffered\\n",
\t\t\t\t\t\t\tMAX_WAIT_ON_ACK);
\t\t\treturn -ENOSPC;
\t\t}
'''
INSERT_ANCHOR = '\t\tif (!s->valid)\n\t\t\tcontinue;\n\n'


def require(ok, reason):
    if not ok:
        raise ValueError('RPM24: ' + reason)


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def function_span(source):
    """Return the unique brace-delimited msm_rpm_flush_requests function."""
    begin = re.search(r'(?m)^static int msm_rpm_flush_requests\(bool print\)\s*\{', source)
    require(begin is not None, 'flush function not found')
    require(len(re.findall(r'(?m)^static int msm_rpm_flush_requests\(', source)) == 1,
            'ambiguous flush function')
    depth = 0
    for i in range(source.index('{', begin.start()), len(source)):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return begin.start(), i+1
    raise ValueError('RPM24: unterminated flush function')


def patch(blob):
    """Fail closed: only the reviewed post-rpm-sleep-r1 function is accepted."""
    require(isinstance(blob, bytes), 'source not bytes')
    raw = blob.decode('utf-8')
    a,b = function_span(raw)
    old = raw[a:b]
    if NEW_GUARD in old and OLD_TRAILING not in old:
        require(old.count(NEW_GUARD) == 1, 'duplicate new guard')
        require(old.count('count++;') == 1, 'counter changed')
        return blob
    require(sha(blob) == PREVIOUS_SHA256, 'not the already-vetted rpm-sleep-r1 source')
    require(old.count(INSERT_ANCHOR) == 1, 'valid request check changed')
    require(old.count(OLD_TRAILING) == 1, 'trailing boundary changed')
    require('WARN_ON(ret != 0)' not in old, 'old transport loss regression present')
    require('if (ret) {' in old and 'return ret;' in old and 's->valid = false;' in old,
            'transport error preservation missing')
    revised = old.replace(INSERT_ANCHOR, INSERT_ANCHOR+NEW_GUARD, 1).replace(OLD_TRAILING, '', 1)
    require(revised.count(NEW_GUARD) == 1 and 'count++;' in revised,
            'bad boundary transformation')
    return (raw[:a]+revised+raw[b:]).encode()


def reconstruct_previous(blob):
    """Reconstruct the exact rpm-sleep-r1 predecessor (read-only)."""
    require(isinstance(blob, bytes), 'composite source is not bytes')
    raw = blob.decode('utf-8')
    a, b = function_span(raw)
    current = raw[a:b]
    require(current.count(NEW_GUARD) == 1 and OLD_TRAILING not in current,
            'not the reviewed RPM24 boundary postimage')
    # In the genuine driver, the old post-send check followed count++ with
    # one blank line. Restore it exactly; no other code is altered.
    previous = current.replace(NEW_GUARD, '', 1)
    anchor = '\t\ts->valid = false;\n\t\tcount++;\n\n'
    require(previous.count(anchor) == 1, 'send/accounting anchor changed')
    previous = previous.replace(anchor, anchor + OLD_TRAILING, 1)
    recovered = (raw[:a] + previous + raw[b:]).encode('utf-8')
    require(sha(recovered) == PREVIOUS_SHA256,
            'composite driver does not reconstruct the reviewed RPM sleep predecessor')
    return recovered


def apply(src, label, work):
    """Called by the release worker after rpm.apply, before kernel compilation."""
    if label != KERNEL:
        return []
    import subprocess
    import sys
    from pathlib import Path
    import veux_update_engine as e
    path = Path(src) / SOURCE
    e.inside(path, src)
    require(path.is_file() and not path.is_symlink(), 'missing or linked RPM driver')
    before = path.read_bytes()
    after = patch(before)
    # Test the exact generated function with a simulated RPM tree/transport.
    work = Path(work)
    test = e.REPO / 'common/scripts/test_veux_rpm24.py'
    staged = work / 'rpm24-tested.c'
    require(not staged.exists() and not staged.is_symlink(), 'stale RPM24 stage')
    staged.write_bytes(after)
    try:
        # The Wakeup repair is applied and tested by the regular worker
        # AFTER this RPM24 stage (wakeup.apply plus verify_source and
        # verify_build). Do not invoke the independent wakeup unit suite on
        # the entire reconstructed kernel tree: it copies SOURCE as a fixture
        # and was run here before wakeup.apply, causing errors and a timeout.
        # This stage verifies only the RPM24 C source via bounded host tests.
        e.run([sys.executable, test, '--source', staged],
              log=work / 'rpm24-host-tests.log', timeout=180)
        require(path.read_bytes() == before, 'driver changed during test')
        path.write_bytes(after)
    finally:
        staged.unlink(missing_ok=True)
    proof = {'id': ID, 'kernel': KERNEL, 'source': SOURCE,
             'source_sha256': sha(after), 'post_rpm_sleep_sha256': PREVIOUS_SHA256,
             'max_buffered': 24, 'host_tested': True, 'device': False}
    e.write_json(work / 'RPM24.json', proof)
    print('RPM24_BOUNDARY_HOST=PASS; EXACTLY_24=PASS; 25TH_BLOCKED=YES; DEVICE_PASS=NO',flush=True)
    return [proof]


def verify_source(src, label, proof):
    if label != KERNEL:
        require(proof == [], 'unexpected RPM24 proof on other lineage')
        return
    require(len(proof) == 1 and proof[0].get('id') == ID and
            proof[0].get('max_buffered') == 24 and proof[0].get('host_tested') is True
            and proof[0].get('device') is False,
            'missing RPM24 proof')
    require(sha((Path(src)/SOURCE).read_bytes()) == proof[0].get('source_sha256'),
            'RPM24 source drift after test')
    # Reuse deterministic and idempotent semantic validation.
    require(patch((Path(src)/SOURCE).read_bytes()) == (Path(src)/SOURCE).read_bytes(),
            'RPM24 postimage not recognized')


def verify_composed_source(src, label, rpm_proof, rpm24_proof):
    """Preserve BOTH existing RPM gates when the same C file has two fixes.

    Run the old RPM verifier on an exact virtual predecessor copy. This keeps
    the established hash/provenance gate rather than disabling or weakening it.
    The live RPM24 source is never edited, and the extracted precursor must
    SHA-match rpm-sleep-r1 precisely.
    """
    import tempfile
    import veux_rpm_fixes as rpm
    verify_source(src, label, rpm24_proof)
    if label != KERNEL:
        rpm.verify_source(src, label, rpm_proof)
        return
    original = reconstruct_previous((Path(src) / SOURCE).read_bytes())
    with tempfile.TemporaryDirectory(prefix='veux-rpm24-predecessor-') as scratch:
        root = Path(scratch)
        dest = root / SOURCE
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(original)
        # This is the unmodified, manifest-bound verifier from the RPM R1 fix.
        rpm.verify_source(root, label, rpm_proof)


def verify_result(label, row):
    if label != KERNEL:
        require(not row.get('rpm24_fixes'), 'RPM24 proof on wrong lineage')
        return
    proof = row.get('rpm24_fixes')
    require(isinstance(proof, list) and len(proof) == 1, 'missing RPM24 result')
    entry = proof[0]
    require(entry.get('id') == ID and entry.get('source') == SOURCE
            and entry.get('max_buffered') == 24 and entry.get('host_tested') is True
            and entry.get('device') is False and entry.get('post_rpm_sleep_sha256') == PREVIOUS_SHA256,
            'unexpected RPM24 result metadata')
    require(isinstance(entry.get('source_sha256'),str)
            and re.fullmatch('[0-9a-f]{64}', entry['source_sha256']),
            'invalid RPM24 source digest')
