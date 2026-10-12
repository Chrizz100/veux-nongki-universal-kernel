#!/usr/bin/env python3
"""Read-only comparison of Android kernel Module.symvers with ELF .ko __versions.

No modversions forcing, no module insertion, and no modification to the ROM.
The vendor .ko bytes must actually be supplied to verify compatibility.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

class ModuleDataError(ValueError):
    pass

def symvers_table(data: bytes) -> dict[str,int]:
    symbols = {}
    for row in data.decode('utf-8', errors='strict').splitlines():
        if not row.strip():continue
        items = row.split()
        if len(items) < 3 or not items[0].startswith('0x'):
            raise ModuleDataError('Unexpected Module.symvers line: '+row[:140])
        name=items[1]
        crc=int(items[0],16)
        if name in symbols and symbols[name]!=crc:
            raise ModuleDataError('Conflicting CRC for '+name)
        symbols[name]=crc
    if not symbols:
        raise ModuleDataError('Empty Module.symvers')
    return symbols

def sections(data: bytes) -> dict[str,bytes]:
    if len(data)<64 or data[:4]!=b'\x7fELF':
        raise ModuleDataError('Not an ELF object')
    bits=data[4];little=data[5]
    if little!=1 or bits not in (1,2):
        raise ModuleDataError('Unsupported ELF endianness or class')
    if bits==2:
        header=struct.unpack_from('<HHIQQQIHHHHHH',data,16)
        shoff,shentsize,shnum,shstrndx=header[5],header[10],header[11],header[12]
        fmt='<IIQQQQIIQQ'
    else:
        header=struct.unpack_from('<HHIIIIIHHHHHH',data,16)
        shoff,shentsize,shnum,shstrndx=header[5],header[10],header[11],header[12]
        fmt='<IIIIIIIIII'
    minimum=struct.calcsize(fmt)
    if shnum==0 or shentsize<minimum or shstrndx>=shnum:
        raise ModuleDataError('Unsupported section table')
    if shoff>len(data) or shnum*shentsize>len(data)-shoff:
        raise ModuleDataError('Section table outside ELF')
    sh=[]
    for i in range(shnum):
        row=struct.unpack_from(fmt,data,shoff+i*shentsize)
        name, typ, _,_,off,size,*_=row
        if off>len(data) or size>len(data)-off:
            raise ModuleDataError('Section outside ELF')
        sh.append((name,typ,off,size))
    off,size=sh[shstrndx][2:4]
    names=data[off:off+size]
    result={}
    for idx,(nameoff,_,off,length) in enumerate(sh):
        if nameoff>=len(names):continue
        end=names.find(b'\0',nameoff)
        if end<0:continue
        name=names[nameoff:end].decode('ascii',errors='replace')
        if name in result:raise ModuleDataError('Duplicate ELF section '+name)
        result[name]=data[off:off+length]
    return result

def module_versions(data: bytes) -> dict[str,int]:
    sec=sections(data)
    if '__versions' not in sec:
        raise ModuleDataError('No __versions section (possibly CONFIG_MODVERSIONS mismatch)')
    records=sec['__versions']
    if len(records)%64:
        raise ModuleDataError('Unexpected __versions record stride (expected aarch64 64-bit ABI)')
    out={}
    for p in range(0,len(records),64):
        crc=struct.unpack_from('<Q',records,p)[0] & 0xffffffff
        name=records[p+8:p+64].split(b'\0',1)[0].decode('ascii',errors='strict')
        if not name:continue
        if name in out:raise ModuleDataError('Duplicate __versions symbol '+name)
        out[name]=crc
    if 'module_layout' not in out:
        raise ModuleDataError('Missing module_layout in __versions')
    return out

def audit(symvers: bytes, modules: dict[str,bytes]) -> dict:
    exported=symvers_table(symvers)
    if 'module_layout' not in exported:
        raise ModuleDataError('Kernel Module.symvers lacks module_layout export')
    output={'module_layout_kernel_crc':f'0x{exported["module_layout"]:08x}',
            'kernel_exported_symbols':len(exported),'module_count':len(modules),'modules':{}}
    for name,data in sorted(modules.items()):
        entry={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
        try:
            versions=module_versions(data)
            mismatches=[{'symbol':n,'expected_crc':f'0x{exported[n]:08x}',
                         'module_crc':f'0x{v:08x}'} for n,v in sorted(versions.items())
                        if n in exported and exported[n]!=v]
            entry.update(status='MISMATCH' if mismatches else 'MATCH_FOR_SHARED_SYMBOLS',
                         module_layout_module_crc=f'0x{versions["module_layout"]:08x}',
                         matching_symbols=sum(1 for n,v in versions.items() if n in exported and exported[n]==v),
                         absent_symbols=sorted(n for n in versions if n not in exported),
                         mismatches=mismatches)
        except ModuleDataError as e:
            entry.update(status='INCONCLUSIVE', reason=str(e))
        output['modules'][name]=entry
    return output

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--symvers',type=Path,required=True)
    p.add_argument('--module',type=Path,action='append',default=[])
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    if not args.module: p.error('At least one --module .ko is required')
    names={}
    for path in args.module:
        if path.name in names: p.error('Duplicate module basename '+path.name)
        names[path.name]=path.read_bytes()
    result=audit(args.symvers.read_bytes(),names)
    output=json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n'
    if args.output:
        args.output.write_text(output)
    else:print(output,end='')
    # A malformed/unsupported .ko is not a successful compatibility result.
    return 1 if any(x['status']!='MATCH_FOR_SHARED_SYMBOLS'
                    for x in result['modules'].values()) else 0
if __name__=='__main__':
    raise SystemExit(main())
