#!/usr/bin/env python
import sys
import pefile
import struct
import vstruct
import vstruct.defs.pe

from enum import Enum
from vstruct.primitives import *

MetaDataTables = v_enum()
MetaDataTables.Module = 0
MetaDataTables.TypeRef = 1
MetaDataTables.TypeDef = 2
MetaDataTables.FieldPtr = 3
MetaDataTables.Field = 4
MetaDataTables.MethodPtr = 5
MetaDataTables.Method = 6
MetaDataTables.ParamPtr = 7
MetaDataTables.Param = 8
MetaDataTables.InterfaceImpl = 9
MetaDataTables.MemberRef = 10
MetaDataTables.Constant = 11
MetaDataTables.CustomAttribute = 12
MetaDataTables.FieldMarshal = 13
MetaDataTables.DeclSecurity = 14
MetaDataTables.ClassLayout = 15
MetaDataTables.FieldLayout = 16
MetaDataTables.StandAloneSig = 17
MetaDataTables.EventMap = 18
MetaDataTables.EventPtr = 19
MetaDataTables.Event = 20
MetaDataTables.PropertyMap = 21
MetaDataTables.PropertyPtr = 22
MetaDataTables.Property = 23
MetaDataTables.MethodSemantics = 24
MetaDataTables.MethodImpl = 25
MetaDataTables.ModuleRef = 26
MetaDataTables.TypeSpec = 27
MetaDataTables.ImplMap = 28
MetaDataTables.FieldRva = 29
MetaDataTables.EncLog = 30
MetaDataTables.EncMap = 31
MetaDataTables.Assembly = 32
MetaDataTables.AssemblyProcessor = 33
MetaDataTables.AssemblyOS = 34
MetaDataTables.AssemblyRef = 35
MetaDataTables.AssemblyRefProcessor = 36
MetaDataTables.AssemblyRefOS = 37
MetaDataTables.File = 38
MetaDataTables.ExportedType = 39
MetaDataTables.ManifestResource = 40
MetaDataTables.NestedClass = 41
MetaDataTables.GenericParam = 42
MetaDataTables.MethodSpec = 43
MetaDataTables.GenericParamConstraint = 44

# TODO: This is gonna byte me in the ass. Assuming WORD offset size.
# YOLO.
class TableRowSizes(Enum):
    Module = 10
    TypeRef = 6
    TypeDef = 14
    FieldPtr = 0
    Field = 6
    MethodPtr = 0
    Method = 14
    ParamPtr = 0
    Param = 6
    InterfaceImpl = 4
    MemberRef = 6

cliHdr_Flags = v_enum()
cliHdr_Flags.COMIMAGE_FLAGS_ILONLY               = 0x00001
cliHdr_Flags.COMIMAGE_FLAGS_32BITREQUIRED        = 0x00002
cliHdr_Flags.COMIMAGE_FLAGS_IL_LIBRARY           = 0x00004
cliHdr_Flags.COMIMAGE_FLAGS_STRONGNAMESIGNED     = 0x00008
cliHdr_Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT    = 0x00010
cliHdr_Flags.COMIMAGE_FLAGS_TRACKDEBUGDATA       = 0x10000

class CLIHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.cb                       = v_uint32()
        self.MajorRuntimeVersion      = v_uint16()
        self.MinorRuntimeVersion      = v_uint16()
        self.MetaData                 = vstruct.defs.pe.IMAGE_DATA_DIRECTORY()
        self.flags                    = cliHdr_Flags
        self.Resources                = vstruct.defs.pe.IMAGE_DATA_DIRECTORY()
        self.StrongNameSignature      = vstruct.defs.pe.IMAGE_DATA_DIRECTORY()
        self.CodeManagerTable         = vstruct.defs.pe.IMAGE_DATA_DIRECTORY()
        self.VTableFixups             = vstruct.defs.pe.IMAGE_DATA_DIRECTORY()
        self.ExportAddressTableJumps  = vstruct.defs.pe.IMAGE_DATA_DIRECTORY()
        self.ManagedNativeHeader      = vstruct.defs.pe.IMAGE_DATA_DIRECTORY()

# MetaData header
class MetaDataHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.Signature      = v_int32()
        self.MajorVersion   = v_int16()
        self.MinorVersion   = v_int16()
        self.Reserved       = v_int32()
        self.Length         = v_int32()
        self.Version        = v_str()
        self.Flags          = v_int16()
        self.StreamHeaders  = v_int16()

    # Dynamically update string length
    def pcb_Length(self):
        self.vsGetField('Version').vsSetLength(self.Length)

# The #~ Stream (MetaData Tables Stream) Header
class MetaDataStreamHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.Reserved1        = v_uint32()
        self.MajorVersion     = v_uint8()
        self.MinorVersion     = v_uint8()
        self.HeapOffsetSizes  = v_uint8()
        self.Reserved2        = v_uint8()
        self.Valid            = v_uint64()
        self.Sorted           = v_uint64()


class StreamHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.Offset = v_uint32()
        self.Size   = v_uint32()
        self.Name   = v_zstr()


def main():

    filename = sys.argv[1]

    file_bytes = open(filename, 'rb').read()
    pe = pefile.PE(data=file_bytes)
    doc = pe.dump_dict()
    base_addr = pe.OPTIONAL_HEADER.ImageBase
    text_section = None

    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')
        if name == '.text':
            text_section = section
            break

    raw_size = text_section.SizeOfRawData
    section_data = text_section.get_data()

    cliHdr = CLIHeader()
    cliHdr.vsParse(section_data[8:8+len(cliHdr)])
    print(cliHdr.tree())

    # RVA and size of the metadata header.
    metadata_rva = cliHdr.MetaData.VirtualAddress
    # https://www.informit.com/articles/article.aspx?p=25350&seqNum=3
    metadata_offset = text_section.get_offset_from_rva(metadata_rva)
    metadata_size = cliHdr.MetaData.Size

    metadata = bytearray(file_bytes[metadata_offset:metadata_offset+metadata_size])

    vs_metadata_hdr = MetaDataHeader()
    vs_metadata_hdr.vsParse(metadata)

    print(f'Metadata header RVA: 0x{metadata_rva:x}')
    print(f'Metadata header file offset: 0x{metadata_offset:x}')
    print(f'Metadata header size: 0x{metadata_size:x}')
    print(vs_metadata_hdr.tree())

    version_len = vs_metadata_hdr.Length
    num_streams = vs_metadata_hdr.StreamHeaders

    # Parse Stream Headers
    streams_start = len(vs_metadata_hdr)
    pos = streams_start
    stream_hdr = StreamHeader()

    for i in range(num_streams):
        stream_name = b''

        for i in range(8, 60, 4):
            stream_name += metadata[pos+i:pos+i+4]
            if stream_name.endswith(b'\x00'):
                stream_hdr.vsParse(metadata[pos:pos+8+len(stream_name)])
                pos+=(8+len(stream_name))
                break

        if stream_hdr.Name == '#~':
            break

    print(stream_hdr.tree())

    stream_name = stream_name.decode().rstrip('\x00')
    assert stream_name == '#~'

    meta_stream_start = metadata_offset+stream_hdr.Offset
    meta_stream_end = metadata_offset+stream_hdr.Offset+stream_hdr.Size
    print(f'metadata_stream_start: 0x{meta_stream_start:x}')
    print(f'metadata_stream_end: 0x{meta_stream_end:x}')

    # Now we know where the #~ header starts.
    md_stream_header = MetaDataStreamHeader()
    md_stream_header.vsParse(file_bytes[meta_stream_start:])

    # Retrieve table bit mask QWORD
    valid_tables = md_stream_header.Valid
    valid_tables_arr = [int(x) for x in bin(valid_tables)[2:]]
    print(f'Valid Tables: 0x{valid_tables:x}')
    print(f'{valid_tables_arr}')

    # Table counts
    '''
    https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-clr-metadata-3/
    Following the two bitvectors are a series of uint32 values
    specifying the rowcounts of all the tables present in the metadata,
    ordered by their table number
    '''
    valid_tables_arr.reverse()
    cur_pos = meta_stream_start+len(md_stream_header)
    md_stream_header.vsAddField('TableRowCounts', vstruct.VArray())

    offset_to_memberref = 0
    size_of_memberref = 0
    for i in range(len(valid_tables_arr)):
        if valid_tables_arr[i] == 1:
            c = struct.unpack('<I', file_bytes[cur_pos:cur_pos+4])[0]
            print(f'{MetaDataTables.vsReverseMapping(i)} row count: {c}')
            md_stream_header.TableRowCounts.vsAddElement(v_uint32(c))

            if i < 0xa:
                size = TableRowSizes[MetaDataTables.vsReverseMapping(i)].value
                offset_to_memberref+=c*size

            if i == 0xa:
                size_of_memberref =\
                    TableRowSizes[MetaDataTables.vsReverseMapping(i)].value*c
            cur_pos+=4

    print(md_stream_header.tree())

    start_of_tables = meta_stream_start+len(md_stream_header)
    loc_of_memberref = start_of_tables + offset_to_memberref

    print(f'TableRowCounts size: {len(md_stream_header.TableRowCounts)}')
    print(f'memberref = 0x{loc_of_memberref:x}')
    print(f'size_of_memberref = 0x{size_of_memberref:x}')
    print(f'end_of_memberref = 0x{(loc_of_memberref+size_of_memberref):x}')

    memberref_data =\
        file_bytes[
            loc_of_memberref:(loc_of_memberref+size_of_memberref)
        ]

    # for each 6 byte chunk mask out Name
    # | WORD | [2] | WORD |
    hex_str = ''
    for i in range(0, len(memberref_data), 6):
        a = memberref_data[i:i+2].hex()
        b = memberref_data[i+4:i+6].hex()
        hex_str += f'{a}[2]{b}'

    rule = '''
import "pe"
rule memberRef_{}
{{
    strings:
        $ = {{{}}}
    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0
        and uint32be(
            pe.rva_to_offset(
                uint32(
                    pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address)+8
                )
            )
        ) == 0x42534a42
        and any of them
}}
    '''

    print(rule.format(filename, hex_str))

    # For bin diffing during testing.
    with open(f'{filename}_memberref.bin', 'wb') as fh_out:
        fh_out.write(memberref_data)

if __name__ == '__main__':
    main()

# EOF
