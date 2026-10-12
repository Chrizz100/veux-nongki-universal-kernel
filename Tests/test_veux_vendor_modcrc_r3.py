#!/usr/bin/env python3
"""Offline ELF CRC parser tests. No privileged access and no module loading."""
from __future__ import annotations
import json
from pathlib import Path
import struct
import sys
import unittest
REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'common/scripts'))
import veux_vendor_modcrc_r3 as abi

def elf_module(crc: int, symbol='module_layout', *, bad_stride=False) -> bytes:
    records=struct.pack('<Q56s',crc,symbol.encode().ljust(56,b'\0'))
    if bad_stride: records=records[:-1]
    strs=b'\0.shstrtab\0__versions\0'
    blob=bytearray(64)
    name_off=64
    blob.extend(strs)
    data_off=len(blob)
    blob.extend(records)
    while len(blob)%8:blob.append(0)
    sht_off=len(blob)
    headers=[(0,0,0,0,0,0,0,0,0,0),
             (1,3,0,0,name_off,len(strs),0,0,1,0),
             (11,1,0,0,data_off,len(records),0,0,8,0)]
    for row in headers:blob.extend(struct.pack('<IIQQQQIIQQ',*row))
    struct.pack_into('<16sHHIQQQIHHHHHH',blob,0,
                     b'\x7fELF\x02\x01\x01'+b'\0'*9,
                     1,183,1,0,0,sht_off,0,64,0,0,64,3,1)
    return bytes(blob)

class ABIParser(unittest.TestCase):
    def test_symvers_reads_module_layout(self):
        self.assertEqual(abi.symvers_table(b'0xbff14f69\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\t\n')['module_layout'],
                         0xbff14f69)

    def test_fake_elf_extracts_module_crc(self):
        self.assertEqual(abi.module_versions(elf_module(0xbff14f69))['module_layout'],0xbff14f69)

    def test_crc_match_is_not_global_vendor_compatibility_claim(self):
        s=b'0xbff14f69\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\n'
        r=abi.audit(s,{'check.ko':elf_module(0xbff14f69)})
        self.assertEqual(r['modules']['check.ko']['status'],'MATCH_FOR_SHARED_SYMBOLS')
        self.assertEqual(r['module_layout_kernel_crc'],'0xbff14f69')

    def test_crc_mismatch_reproduces_module_layout_failure(self):
        s=b'0xbff14f69\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\n'
        r=abi.audit(s,{'broken.ko':elf_module(0xdeadbeef)})
        self.assertEqual(r['modules']['broken.ko']['status'],'MISMATCH')
        self.assertEqual(r['modules']['broken.ko']['mismatches'][0]['symbol'],'module_layout')

    def test_truncated_elf_denied(self):
        with self.assertRaises(abi.ModuleDataError):abi.module_versions(b'abc')

    def test_non_elf_denied(self):
        with self.assertRaisesRegex(abi.ModuleDataError,'Not an ELF'):
            abi.module_versions(b'X'*300)

    def test_invalid_stride_rejected(self):
        with self.assertRaisesRegex(abi.ModuleDataError,'stride'):
            abi.module_versions(elf_module(0xbff14f69,bad_stride=True))

    def test_unknown_export_is_reported_as_incomplete_coverage(self):
        s=b'0xbff14f69\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\n'
        r=abi.audit(s,{'vendor.ko':elf_module(5,'module_layout')})
        self.assertEqual(r['modules']['vendor.ko']['status'],'MISMATCH')

    def test_kernel_without_module_layout_is_denied(self):
        s=b'0x00000001\tfoo\tvmlinux\tEXPORT_SYMBOL\n'
        with self.assertRaisesRegex(abi.ModuleDataError,'lacks module_layout'):
            abi.audit(s,{'check.ko':elf_module(0xbff14f69)})

    def test_malformed_module_never_claims_compatibility(self):
        s=b'0xbff14f69\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\n'
        result=abi.audit(s,{'not-a-module.ko':b'bad'})
        self.assertEqual(result['modules']['not-a-module.ko']['status'],'INCONCLUSIVE')

    def test_duplicate_export_crc_is_blocked(self):
        s=b'0x00000001\tfoo\tvmlinux\tEXPORT_SYMBOL\n0x00000002\tfoo\tvmlinux\tEXPORT_SYMBOL\n'
        with self.assertRaisesRegex(abi.ModuleDataError,'Conflicting CRC'):
            abi.symvers_table(s)

    def test_32_bit_elf_is_rejected_if_abi_not_expected(self):
        wrong=bytearray(elf_module(0xbff14f69));wrong[4]=1
        with self.assertRaises(abi.ModuleDataError):abi.module_versions(bytes(wrong))

    def test_no_module_data_yields_zero_exported_symbols_error(self):
        with self.assertRaisesRegex(abi.ModuleDataError,'Empty Module.symvers'):
            abi.symvers_table(b'')

    def test_unsupported_sections_are_not_silently_accepted(self):
        bad=bytearray(elf_module(0xbff14f69));bad[0x3c:0x3e]=b'\xff\xff'
        with self.assertRaises(abi.ModuleDataError):abi.module_versions(bytes(bad))

if __name__=='__main__':unittest.main(verbosity=2)
