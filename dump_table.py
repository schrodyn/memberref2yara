#!/usr/bin/env python
import sys
import dnfile

from hashlib import sha256

filename = sys.argv[1]
sha256hash = ''

with open(filename, 'rb') as fh_in:
    sha256hash = sha256(fh_in.read()).hexdigest()

pe = dnfile.dnPE(filename)

#tbl = pe.net.mdtables.MemberRef
tbl = pe.net.mdtables.TypeRef

tbl_num_rows =\
    pe.get_offset_from_rva(tbl.num_rows)

tbl_row_size =\
    pe.get_offset_from_rva(tbl.row_size)

tbl_bytes = pe.get_data(tbl.rva, (tbl_num_rows*tbl_row_size))

hex_str = ''

for i in range(0, len(tbl_bytes), 6):
    a = tbl_bytes[i:i+2].hex()
    b = tbl_bytes[i+4:i+6].hex()
    hex_str += f'{a}[2]{b}'


rule = '''
import "pe"

rule DotNet_Tbl_{}
{{

    meta:
        hash = "{}"

    strings:
        $ = {{{}}}

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0
        and uint32be(
            pe.rva_to_offset(
                uint32(
                    pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address)+8
                )
            )
        ) == 0x42534a42
        and all of them
}}
    '''

print(rule.format(tbl.name, sha256hash, hex_str))

with open(f'{filename}_tbl_{tbl.name}.bin', 'wb') as fh_out:
    fh_out.write(tbl_bytes)

