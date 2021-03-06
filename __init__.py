from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag
from binaryninja.enums import SectionSemantics
from binaryninja.enums import SymbolType
from binaryninja.log import log_error
from binaryninja.log import log_info
from binaryninja.types import Symbol

import struct
import traceback

# 2-3 compatibility
from binaryninja import range

arch = ""

class aoutView(BinaryView):
    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    def round(self, number, base, direction):
        if (direction == "up"):
            a = (number // base) * base
            a += base
        else:
            a = (number // base) * base
            a += base
        return a

    def check_magic(self, magic_bytes):
        magic_dict = {
            b'\x00\x00\x01\xeb': "68020",
            b'\x00\x00\x02\x47': "x86",
            b'\x00\x00\x02\xab': "intel 960",
            b'\x00\x00\x03\x17': "sparc",
            b'\x00\x00\x03\x8b': "mips 3000 BE", #32
            b'\x00\x00\x04\x07': "att dsp 3210",
            b'\x00\x00\x04\x8b': "mips 4000 BE", #64
            b'\x00\x00\x05\x17': "amd 29000",
            b'\x00\x00\x05\xab': "armv7",
            b'\x00\x00\x06\x47': "ppc",
            b'\x00\x00\x06\xeb': "mips 4000 LE",
            b'\x00\x00\x07\x97': "dec alpha",
            b'\x00\x00\x08\x4b': "mips 3000 LE",
            b'\x00\x00\x09\x07': "sparc64",
            b'\x00\x00\x8a\x97': "x86_64",
            b'\x00\x00\x8b\x6b': "ppc64",
            b'\x00\x00\x8c\x47': "aarch64",
        }
        try:
            return magic_dict[magic_bytes]
        except:
            return False

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 0x4)
        if (self.check_magic(self, hdr) != False):
            return True
        return False

    def init_common(self):
        self.hdr = self.raw.read(0, 0x28)
        self.hdr_offset = 0x28
        self.padding_size = 0x18
        self.entry_addr = struct.unpack(">L", self.hdr[0x14:0x18])[0]
        self.load_addr = struct.unpack(">L", self.hdr[0x24:0x28])[0]
        self.size = struct.unpack(">L", self.hdr[0x04:0x08])[0]         # text
        self.data_size = struct.unpack(">L", self.hdr[0x08:0xC])[0]     # data
        self.bss_size = struct.unpack(">L", self.hdr[0xC:0x10])[0]      # bss
        self.syms_size = struct.unpack(">L", self.hdr[0x10:0x14])[0]    # syms
        #log_error("size: " + str(hex(self.size)))
        arch = self.check_magic(self.hdr[0x0:0x4])
        if (arch != False):
            self.platform = Architecture[arch].standalone_platform               
            # this is super not how you do this so don't try it
            #self.platform.system_call_convention = {'sysr1': 0, 'open': 14}
            #log_info(str(self.platform.system_calls))
        else:
            log_info("Not a valid a.out file!")
            return False

    def init_archthings(self):
        try:
            if self.init_common() == False:
                return
            
            #   For example: bv.add_user_section("<section_name>", <section_start_address>, <section_size>, SectionSemantics.ReadOnlyCodeSectionSemantics)
            self.add_user_section(".text", self.load_addr, self.size, SectionSemantics.ReadOnlyCodeSectionSemantics)

            # register _main symbol
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.entry_addr, "_main"))

            # add_auto_segment(start, length, data_offset, data_length, flags)
            # add .text segment for r-x
            self.add_auto_segment(
                self.load_addr,                                                     # start of segment
                self.size,                                                          # length of segment
                self.hdr_offset,                                                    # offset into file
                self.size,                                                          # size again?
                SegmentFlag.SegmentContainsCode |                                   # Constains code
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable         # rwx bits
            )

            # padding from 0x3FEE - 0x4006 = 24 bytes or 0x18
            # start_data = (end_text + 0x18)
            # ReadWriteDataSectionSemantics

            '''
            When a Plan 9 binary file is executed, a memory image of
            three segments is set up: the text segment, the data seg-
            ment, and the stack.  The text segment begins at a virtual
            address which is a multiple of the machine-dependent page
            size.  The text segment consists of the header and the first
            text bytes of the binary file.  The entry field gives the
            virtual address of the entry point of the program.  The data
            segment starts at the first page-rounded virtual address
            after the text segment.  It consists of the next data bytes
            of the binary file, followed by bss bytes initialized to
            zero.  The stack occupies the highest possible locations in
            the core image, automatically growing downwards.  The bss
            segment may be extended by brk(2).
            '''


            # 0x400988 - 0x204a8a = data_segment_offset = 0x1fbefe
            # round to next page, default smallest 4KB

            #self.data_segment_offset = 0x400988 - 0x204a8a - 0x998

            #log_info(hex(self.data_segment_offset))
            
            self.data_segment_offset = self.round(self.load_addr + self.size + self.padding_size, 0x200000, "up")

            #log_info(hex(self.data_segment_offset))
            
            self.data_segment_offset -= 0x28 # header

            self.add_user_section(".data", self.data_segment_offset, self.data_size, SectionSemantics.ReadWriteDataSectionSemantics)
            # add .data segment for rw-
            self.add_auto_segment(
                self.data_segment_offset,                                           # virtual address of segment                        # start of segment
                self.data_size,                                                     # length of segment
                self.size,                                                          # offset into file
                self.data_size,                                                     # size of this segment
                SegmentFlag.SegmentContainsData |                                   # Contains data
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable           # rwx bits
            )

            self.add_user_section(".rodata", self.data_segment_offset, self.data_size, SectionSemantics.ReadWriteDataSectionSemantics)
            # add .rodata segment for r--
            self.add_auto_segment(
                self.data_segment_offset,                                           # virtual address of segment                        # start of segment
                self.data_size,                                                     # length of segment
                self.size,                                                          # offset into file
                self.data_size,                                                     # size of this segment
                SegmentFlag.SegmentContainsData |                                   # Contains data
                SegmentFlag.SegmentReadable #| SegmentFlag.SegmentWritable           # rwx bits
            )

            #log_info('Looking at: {0:08x} for start of .data segment'.format(self.load_addr + self.size))

            self.add_user_section(".bss", self.load_addr + self.size + self.padding_size + self.data_size + self.data_segment_offset, self.bss_size, SectionSemantics.ReadWriteDataSectionSemantics)
            # add .bss segment for rw-
            self.add_auto_segment( 
                self.data_size + self.data_segment_offset,                          # start of segment
                self.bss_size,                                                      # length of segment
                self.size + self.padding_size + self.data_size,                     # offset into file
                self.bss_size,                                                      # size again?
                SegmentFlag.SegmentContainsData |                                   # Contains data
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable           # rwx bits
            )

            self.add_user_section(".syms", self.load_addr + self.size + self.padding_size + self.data_size + self.bss_size + self.data_segment_offset,
                self.syms_size, SectionSemantics.ReadOnlyDataSectionSemantics)
             # add .syms segment for r--
            self.add_auto_segment(
                self.data_size + self.bss_size + self.data_segment_offset,                          # start of segment
                self.syms_size,                                                                         # length of segment
                self.size + self.padding_size + self.data_size + self.bss_size,                         # offset into file
                self.syms_size,                                                                         # size again
                SegmentFlag.SegmentContainsData |                                                       # Contains data
                SegmentFlag.SegmentReadable # | SegmentFlag.SegmentWritable                             # rwx bits
            )


            # skip to .syms section of binary
            syms_start = self.size + self.padding_size + self.data_size + self.bss_size
            # round syms_start to next % 16 for padding
            #           header + round func
            syms_start += 0x18
            syms_start = self.round(syms_start, 0x10, "up")

            # for now, skip to _main
            syms_start += 0x26D

            #log_info(hex(syms_start))
            sysm_end = len(self.raw) - syms_start
            syms = self.raw.read(syms_start, sysm_end)

            #arch = self.check_magic(self.hdr[0x0:0x4])
            if (arch != False):
                #self.add_entry_point(Architecture[arch].standalone_platform, self.entry_addr)
                self.add_entry_point(self.entry_addr)
            else:
                log_info("Not a valid a.out file!")
                return False
            return True
        except:
            log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr


class aout9View(aoutView):
    name = "aout"
    long_name = "9 a.out Parser/Disassembler"

    def init(self):
        return self.init_archthings()


aout9View.register()
