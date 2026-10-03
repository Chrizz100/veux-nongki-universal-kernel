from pathlib import Path
import json,sys,subprocess,hashlib
base=Path('/mnt/data/sweet_r42_work');sys.path.insert(0,str(base/'repo/common/scripts/sweet'));import audit
s=base/'sources/sweet_k6a-r-oss'
before=audit.workspace_state(s,audit.K6A_STUB_COMMIT)
(base/'r41_failure_reproduction.json').write_text(json.dumps({'old_check_would_fail': bool(before['git_status']), 'source_state':before, 'local_config_equal_to_ci': (base/'local-k6a-out/.config').read_bytes()==(base/'sweet_k6a-r-oss/resolved.config').read_bytes()},indent=2))
assert before['passed'] and len(before['accepted_oem_generated'])==6
for item in before['accepted_oem_generated']:(s/item['path']).unlink()
assert audit.workspace_state(s)['passed']
stock=base/'repo/device/sweet/reference/stock.config';reference=audit.parse_config(stock.read_text())['values'];result={}
for branch,pin in [('sweet-r-oss','758bb7ef50af360e728662a1ed3b3a1b977a2f13'),('sweet_k6a-r-oss',audit.K6A_STUB_COMMIT)]:
 source=base/'sources'/branch;work=base/'r42-integration'/branch;output=work/'evidence';output.mkdir(parents=True)
 ref=audit.git_output(source,'rev-parse','HEAD')
 report={'branch':branch,'upstream_commit':pin,'local_reconstructed_snapshot_commit':ref,'source_tree':audit.git_output(source,'rev-parse','HEAD^{tree}'),'compiler_note':'Local HOST GCC 14, only real Kconfig, not cross kernel compilation; compared with CI GCC11 result.'}
 audit.audit_kconfig(source,ref,pin,stock,work,output,reference,report,cc='gcc',cross_compile='')
 report['resolved_config_byte_identical_to_ci']= (output/'resolved.config').read_bytes()==(base/branch/'resolved.config').read_bytes()
 assert report['resolved_config_byte_identical_to_ci']
 assert report['olddefconfig_ok'] and report['olddefconfig_idempotent']
 assert report['source_unchanged'] and report['kconfig_workspace_integrity_ok']
 report['resolved_sha256']=audit.sha256(output/'resolved.config')
 report['critical_missing_count']=len(report['critical_config_gate']['failures'])
 report['active_missing_count']=len(report['all_active_stock_options']['missing_or_changed'])
 audit.write_json(output/'local_validation.json',report);audit.save_checksums(output)
 result[branch]=report
 (base/'real_kconfig_validation_r42.json').write_text(json.dumps(result,indent=2))
 print(branch, 'PASS', 'exact_config_match',report['resolved_config_byte_identical_to_ci'],'critical_missing',report['critical_missing_count'],'active_missing',report['active_missing_count'],flush=True)
