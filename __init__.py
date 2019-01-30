from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag
from binaryninja.log import log_error

import struct
import traceback

# 2-3 compatibility
from binaryninja import range

arch = ""

class aoutView(BinaryView):
    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 0x28)
        if len(hdr) < 0x28:
            return False
        return True

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
            return "Not a valid a.out file"

    def init_common(self):
        self.hdr = self.raw.read(0, 0x28)
        self.hdr_offset = 0x28
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
        else:
            log_error("Not a valid a.out file!")
            return False

    def init_archthings(self):
        try:
            self.init_common()
            self.add_auto_segment(self.load_addr, self.size, self.hdr_offset, self.size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_auto_segment(self.load_addr + self.size, self.data_size, self.hdr_offset, self.data_size, 
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
            self.add_auto_segment(self.load_addr + self.size + self.data_size, self.bss_size, self.hdr_offset,
                self.bss_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_auto_segment(self.load_addr + self.size + self.data_size + self.bss_size, self.syms_size,
                self.hdr_offset, self.syms_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

            '''
            Notes for future from binja console:
            Analysis results may be improved by adding sections with ReadOnlyCodeSectionSemantics.
            For example: bv.add_user_section("<section_name>", <section_start_address>, <section_size>, SectionSemantics.ReadOnlyCodeSectionSemantics)

            '''


            #arch = self.check_magic(self.hdr[0x0:0x4])
            if (arch != False):
                #self.add_entry_point(Architecture[arch].standalone_platform, self.entry_addr)
                self.add_entry_point(self.entry_addr)
            else:
                log_error("Not a valid a.out file!")
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
