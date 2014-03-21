import psycopg2

from PyBochsConfig import *
from Helpers import *
import sys

import pydasm

# TODO
#  - check reconstruction code against extract.py 

class IAT( PEList):

    def __init__( self, pe_obj, offset):

        self.offset = offset
        self.pe_obj = pe_obj

        PEList.__init__( self, self.pe_obj, self.offset, "I")

        count = 0
        self.imports_info = []
        self.pe_images = {}
        self.pe_image_counts = {}

        print "Going up the possible IAT: 0x%08x" % offset

        while 0 != self[ count]: # and None != self.pe_obj.getExportByAddress( self[ count]):

            function_address = self[ count]

            memoryregion = self.pe_obj.memorydump.memoryregion.process.getMemoryRegionByAddress( function_address)
            if not memoryregion:
                break
            if memoryregion.tag not in self.pe_images:
                self.pe_images[memoryregion.tag] = PE(CopyingStringBackend(memoryregion.latest_dump().data()), memoryregion.tag, True)
            export = self.pe_images[memoryregion.tag].Exports.by_va( function_address)
            if not export:
                break

            function_name = export[ 2]

            if memoryregion.tag in self.pe_image_counts:
                self.pe_image_counts[memoryregion.tag] += 1
            else:
                self.pe_image_counts[memoryregion.tag] = 1


            self.imports_info.append( { "name": function_name, "image": memoryregion.tag})
            print "0x%08x:0x%08x:%s!%s" % ( count, \
                function_address, \
                memoryregion.tag, \
                function_name)
            count += 1

        self.len = count #FIXME what about a non-zero entry that's nowhere to be found in any image?

        for name in self.pe_image_counts:
            print "%s: %u" %( name, self.pe_image_counts[ name])

        self.normalize()

    def normalize(self):

        image_max = 0
        image_name = ""
        self.HintNameTable = ""

        # determine the name of the DLL providing the majority of imports in this IAT
        for name in self.pe_image_counts:
            if self.pe_image_counts[ name] > image_max:
                image_max = self.pe_image_counts[ name]
                image_name = name

        successful = True

        for index in range( self.len):
            # image_name is the name of the DLL that holds the majority in this IAT
            # need to fetch images before working on them
            # self is to be treated as a list

            if self.imports_info[ index][ "image"] != image_name:
                print image_name, "0x%08x" % self[ index],
                function_name = self.imports_info[ index][ "name"]
                forwarded_image = self.pe_obj.memorydump.memoryregion.process.getMemoryRegionByAddress(self[index])
                forwarded_name = forwarded_image.tag.rpartition("\\")[2].partition(".")[0] + "." + function_name
                # FIXME!!! don't need tag, but our own image name here
                #export = self.pe_images[forwarded_image.tag].Exports.by_forwarder(forwarded_name)
                export = self.pe_images[image_name].Exports.by_forwarder(forwarded_name)
                successful &= ( None != export)

                if successful:
                    self.imports_info[ index][ "image"] = image_name
                    self.imports_info[ index][ "name"] = export[ 2]
                    self[ index] = self.pe_obj.Headers.OptionalHeader.WindowsSpecific.ImageBase + export[ 1]
                    print "Found %s in" % export[ 2], image_name, "0x%08x" % self[ index]

            if not successful:
                print "Couldn't find export for forwarded name %s" % forwarded_name, export
#                for rva in self.pe_images[forwarded_image.tag].Exports.ExportAddressTable:
#                    print self.pe_images[ forwarded_image.tag].Exports.by_rva(rva)
#                raise Exception( "Couldn't fix up IAT properly for DLL %s" % image_name)

            # create the Hint/Name Table, use a hint of 0 for all imports
            # self.imports_info[ index][ "HintNameTableOffset"] = len( self.HintNameTable)
            # self.HintNameTable += "\x00\x00" + self.imports_info[ index][ "name"]

        print "Decided on %s: %u" % (image_name, image_max)
        self.image_name = str(image_name)

class ReconstructedPE(PE):
    def __init__(self, memorydump):
        self.memorydump = memorydump
        self.pg_connection = self.memorydump.pg_connection
        self.pg_cursor = self.pg_connection.cursor()
        PE.__init__(self, CopyingStringBackend(self.memorydump.data()), self.memorydump.tag(), True)
        self.fix_entrypoint()
        self.fix_sections()
        self.fix_imports()


    def fix_entrypoint( self):
        # for now, assume that the time of hitting the entrypoint equals the time of dump
        self.pg_cursor.execute( "SELECT dest FROM %s WHERE timestamp = %%s" % self.memorydump.memoryregion.process.analysis.branches_table, (self.memorydump.timestamp,))
        (entrypoint,) = self.pg_cursor.fetchone()
        imagebase = self.Headers.OptionalHeader.WindowsSpecific.ImageBase
        if imagebase != self.memorydump.memoryregion.base:
            raise Exception( "Actual and PE Header Image Base do not match")
        self.Headers.OptionalHeader.Standard.AddressOfEntryPoint = entrypoint - imagebase
        print "Set new entrypoint to 0x%08x" % entrypoint

    def fix_sections( self):
        self.Headers.OptionalHeader.Standard.SizeOfCode = 0
        self.Headers.OptionalHeader.Standard.SizeOfInitializedData = 0
        self.Headers.OptionalHeader.Standard.SizeOfUninitializedData = 0
        self.Headers.OptionalHeader.Standard.BaseOfCode = len( self.backend) #FIXME len( self.backend) not pretty
        self.Headers.OptionalHeader.Standard.BaseOfData = len( self.backend)
 
        section_alignment = self.Headers.OptionalHeader.WindowsSpecific.SectionAlignment
        # set file alignment to section alignment, as we want to save the dump
        # largely as-is
        self.Headers.OptionalHeader.WindowsSpecific.FileAlignment = section_alignment
        imagebase = self.Headers.OptionalHeader.WindowsSpecific.ImageBase

        # align() function: if x is aligned  return x else pad
        align = lambda x: x + (( x % section_alignment) and section_alignment - (x % section_alignment))

        # needed within the loop:
        branches = self.memorydump.memoryregion.branches()
        executed = []
        executed.extend([branch[1] for branch in branches])
        executed.extend([branch[2] for branch in branches])
        executed = set(executed)

        # sections should be in ascending order and adjacent, according to the specs
        # FIXME: research whether the windows PE loader really needs that
        for sct in self.Headers.SectionHeaders:
            sct.VirtualSize = align( sct.VirtualSize)
            sct.PointerToRawData = sct.VirtualAddress
            sct.SizeOfRawData = sct.VirtualSize
            # this is a memory dump, therefore all out sections contain initialized data now
            sct.Characteristics &= ~IMAGE_SCN_CNT_UNINITIALIZED_DATA
            sct.Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA

            # FIXME: fore now, mark all sections read/write
            sct.Characteristics |= IMAGE_SCN_MEM_READ
            sct.Characteristics |= IMAGE_SCN_MEM_WRITE

            # determine whether code was executed within this section:
            #  - code was executed at all branch sources and branch targets
            if executed.intersection( set(xrange(sct.VirtualAddress + imagebase, sct.VirtualSize + imagebase))):
                sct.Characteristics |= IMAGE_SCN_MEM_EXECUTE
                sct.Characteristics |= IMAGE_SCN_CNT_CODE

            if sct.Characteristics & IMAGE_SCN_CNT_CODE and sct.VirtualAddress < self.Headers.OptionalHeader.Standard.BaseOfCode:
                self.Headers.OptionalHeader.Standard.BaseOfCode = sct.VirtualAddress
            elif sct.Characteristics & IMAGE_SCN_CNT_CODE:
                self.Headers.OptionalHeader.Standard.SizeOfCode += sct.VirtualSize
            elif sct.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA and sct.VirtualAddress < self.Headers.OptionalHeader.Standard.BaseOfData:
                self.Headers.OptionalHeader.Standard.BaseOfData = sct.VirtualAddress
            elif sct.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
                self.Headers.OptionalHeader.Standard.SizeOfInitializedData += sct.VirtualSize

    def find_IATs( self):
        indirections = []

        # "find" the IATs from the import section
        iat_count = 0
        self.IATs = []

        # FIXME see if we can do without the initial imports
        # IDA Pro for instance doesn't like it when the IATs are spread across the whole file
        for ide in self.Imports.ImportDirectoryTable:
            self.IATs.append( IAT( self, self.rva2raw( ide.ImportAddressTableRVA)))
            iat_count += 1

        imagebase = self.Headers.OptionalHeader.WindowsSpecific.ImageBase
        imagesize = self.Headers.OptionalHeader.WindowsSpecific.SizeOfImage
        if imagesize != len(self.backend):
            raise Exception( "SizeOfImage %u != size of dump %u" % ( imagesize, len(self.backend)))

        # select all branches from inside the image to outside of the image
        # those are likely to be API calls
        for (_, source, target, _) in self.memorydump.memoryregion.branches_outbound():

            # fetch the instruction at the source of the call
            insn = pydasm.get_instruction( self.backend.read( source - imagebase, 50), pydasm.MODE_32) # FIXME use real x86 instruction length limit here

            # as the instruction is the source of a branch, it should be a branch instruction
            # and its single operand should be the branch target operand we need
            # in the case of heavily self-modifying code, it might be necessary to check
            # for legal branch instructions as well
            #
            # the only kind of branch that is useful to us as it is, is an indirect jump
            # referencing a memory address, as all we only have a memory dump, and no register
            # values available. again, heavily self-modifying code might fool this method
            #
            # So if the operand is a memory reference and not based on any register,
            # append the displacement to the list of memory references used in branch targets
            if None != insn and pydasm.OPERAND_TYPE_MEMORY == insn.op1.type and pydasm.REGISTER_NOP == insn.op1.basereg:
                indirections.append( insn.op1.displacement)

                insn_formatted = pydasm.get_instruction_string( insn, pydasm.FORMAT_INTEL, 0)
                print "Source: 0x%08x, Target: 0x%08x, Jump instruction: %s, indirect operand is 0x%08x, value there is 0x%08x" \
                     % (source, target, insn_formatted, insn.op1.displacement, \
                     getUnsignedInt( self.backend, imagebase, insn.op1.displacement))

        # now sort the list of indirections so that it is easier to find the first such reference.
        indirections.sort()

        if len( indirections) == 0:
            print "Failed to find indirect calls, returning"
            return

        offset = indirections[0]

        # now move down in memory until we find the first memory reference that does not
        # point to within any DLL memory image and that is not NULL
        print "Going down the possible IAT: 0x%08x" % offset

        while True:
            if offset == imagebase:
                break
            memoryreference = getUnsignedInt( self.backend, imagebase, offset)
            memoryregion = self.memorydump.memoryregion.process.getMemoryRegionByAddress( memoryreference)
            if memoryreference not in (0,0x7fffffff,0xffffffff) and \
               None == self.memorydump.memoryregion.process.getMemoryRegionByAddress( memoryreference):
                print "found no image at 0x%08x" % memoryreference
                offset += 4
                break
            offset -= 4

        iat_start = offset
        print "0x%08x" % iat_start

        while True:
            if offset == imagebase + imagesize:
                break
            memoryreference = getUnsignedInt( self.backend, imagebase, offset)
            memoryregion = self.memorydump.memoryregion.process.getMemoryRegionByAddress( getUnsignedInt( self.backend, imagebase, offset))
            if memoryreference not in (0,0x7fffffff,0xffffffff) and \
               None == self.memorydump.memoryregion.process.getMemoryRegionByAddress( memoryreference):
                print "found no image at 0x%08x" % memoryreference
                offset -= 4
                break
            offset += 4

        iat_end = offset
        print "0x%08x" % iat_end

        offset = iat_start

        # create IAT list
        while offset <= iat_end:
            memoryreference = getUnsignedInt( self.backend, imagebase, offset)
            if memoryreference not in (0,0x7fffffff,0xffffffff):
                self.IATs.append( IAT(self, self.rva2raw(offset-imagebase)))
                offset += len(self.IATs[iat_count])*4
                iat_count += 1
            else:
                offset += 4



    def fix_imports( self):
        # approach:
        # - find IATs:
        # - reconstruct Import Directory
        #    - in place or append a new one
        #    - what to do with the original import directory?
        # - fix the IATs
        # - update data directory
        self.find_IATs()

        # Size of one Import Directory Entry is 20 bytes
        ide_size = 20

        new_import_section = GenericStruct()
        new_import_section.buf = "" # to avoid unicode string issues
        new_import_section.import_directory = []

        # we're going to append to the end of the image
        imagesize = self.Headers.OptionalHeader.WindowsSpecific.SizeOfImage

        # reserve space for all import directories
        for iat in self.IATs:
            offset = len( new_import_section.buf)
            new_import_section.buf += "\0" * ide_size
            ide = ImportDirectoryEntry(ObjectBackend( new_import_section) , offset) # FIXME is this correct?
            new_import_section.import_directory.append( ide)

        # All-Zero import directory entry
        new_import_section.buf += "\0" * ide_size


        for i in range( len( self.IATs)):
            iat = self.IATs[ i]
            ide = new_import_section.import_directory[ i]
            rva = len( new_import_section.buf) + imagesize

            ide.NameRVA = rva
            new_import_section.buf += iat.image_name.rpartition('\\')[2] + "\0"

            rva = len( new_import_section.buf) + imagesize
            ide.ImportAddressTableRVA = iat.offset

            for j in range(len( iat)):
                rva = len( new_import_section.buf) + imagesize
                if rva % 2:
                    new_import_section.buf += "\0"
                    rva += 1
                # add Hint/Name Table Entry
                new_import_section.buf += "\0\0" + str( iat.imports_info[j]["name"]) + "\0"
                iat[ j] = rva

            # zero-terminate the IAT
            new_import_section.buf += "\0\0\0\0"

        # FIXME create a new section instead of extending the last mess:
        # check if there's space after the section headers
        # aditionally check if that space is all-zero
        # increase the number of section in the COFF Header by one
        # create a new section header at that location
        # append the new import section to the PE buffer
        # put meaningful values into the new section header
        # fix the import data directory

        section_alignment = self.Headers.OptionalHeader.WindowsSpecific.SectionAlignment
        align = lambda x: x + (( x % section_alignment) and section_alignment - (x % section_alignment))

        # section-align the new import section
        length = len( new_import_section.buf)
        diff = align( length) - length
        new_import_section.buf += "\0" * diff

        offset = self.Headers.SectionHeaders[ -1].offset
        length = len( self.Headers.SectionHeaders[ -1])

        if align( offset) - offset >= length:
            # create a new section
            section = SectionHeader( self, offset + length)

            # section-align the image, if it is not aligned already
            length = len( self.backend)
            diff = align(length) - length
            self.backend.append( "\0" * diff)

            section.VirtualAddress = length + diff
            section.VirtualSize = len( new_import_section.buf)
            section.PointerToRawData = section.VirtualAddress
            section.SizeOfRawData = section.VirtualSize
            section.Name = ".pandora"
            section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE # from PE document for .idata section

            section.PointerToRelocations = 0
            section.PointerToLineNumbers = 0
            section.NumberOfRelocations = 0
            section.NumberOfLineNumbers = 0

            self.Headers.OptionalHeader.DataDirectories.ImportTable.VirtualAddress = section.VirtualAddress
            self.Headers.OptionalHeader.DataDirectories.ImportTable.Size = section.VirtualSize
            self.backend.append( new_import_section.buf)


            # add the new section to the section header list
            self.Headers.COFFFileHeader.NumberOfSections += 1
            self.Headers.OptionalHeader.WindowsSpecific.SizeOfImage += section.VirtualSize
            self.Headers.SectionHeaders.append( section)

        else:
            raise Exception( "No space for additional section header. Boohooo :( !")

        # clear bound imports
        self.Headers.OptionalHeader.DataDirectories.BoundImport.VirtualAddress = 0
        self.Headers.OptionalHeader.DataDirectories.BoundImport.Size = 0


        self.fix_sections() # to update SizeOfCode, SizeOfData, etc.


class MemoryDump(object):
    def __init__(self, memoryregion, timestamp):
        self.memoryregion = memoryregion
        self.timestamp = timestamp
        self.pg_connection = self.memoryregion.pg_connection
        self.pg_cursor = self.pg_connection.cursor()

    def data(self):
        self.pg_cursor.execute( 'SELECT data FROM %s WHERE process=%%s AND timestamp=%%s AND region=%%s' % self.memoryregion.process.analysis.dumps_table, (self.memoryregion.process.pdb, self.timestamp, self.memoryregion.base))
        return self.pg_cursor.fetchone()[0]

    def reason(self):
        self.pg_cursor.execute( 'SELECT reason FROM %s WHERE process=%%s AND timestamp=%%s AND region=%%s' % self.memoryregion.process.analysis.dumps_table, (self.memoryregion.process.pdb, self.timestamp, self.memoryregion.base))
        return self.pg_cursor.fetchone()[0]

    def tag(self):
        self.pg_cursor.execute( 'SELECT tag FROM %s WHERE process=%%s AND timestamp=%%s AND region=%%s' % self.memoryregion.process.analysis.dumps_table, (self.memoryregion.process.pdb, self.timestamp, self.memoryregion.base))
        return self.pg_cursor.fetchone()[0]

    def eip(self):
        self.pg_cursor.execute( 'SELECT eip FROM %s WHERE process=%%s AND timestamp=%%s AND region=%%s' % self.memoryregion.process.analysis.dumps_table, (self.memoryregion.process.pdb, self.timestamp, self.memoryregion.base))
        return self.pg_cursor.fetchone()[0]

    def __repr__(self):
        return "<MemoryRegion:\n      eip: %u\n   reason: %u\n      tag: %s\n    length: %u\n>" % (self.eip(), self.reason(), self.tag(), len(self.data()))

    def repair_image(self, force=False):
        if not (self.reason() & DUMP_IMAGE) and not force:
            raise Exception('Not an image, can\'t repair')





class MemoryRegion(object):
   def __init__(self, process, base):
      self.process = process
      self.base = base
      self.pg_connection = self.process.pg_connection
      self.pg_cursor = self.pg_connection.cursor()
      self.pg_cursor.execute( 'SELECT firstseen, size,tag FROM %s WHERE process=%%s and base=%%s' % self.process.analysis.memoryregions_table, (self.process.pdb, self.base))
      self.firstseen, self.size, self.tag = self.pg_cursor.fetchone()

   def dumps(self):
      self.pg_cursor.execute( 'SELECT timestamp FROM %s WHERE process=%%s and region=%%s' % self.process.analysis.dumps_table, (self.process.pdb, self.base))
      dumps = {}
      for dump in self.pg_cursor.fetchall():
          dumps[dump[0]] = MemoryDump(self,dump[0])
      return dumps # FIXME just do this in __init__ instead?

   def latest_dump(self):
      self.pg_cursor.execute( 'SELECT timestamp FROM %s WHERE process=%%s and region=%%s ORDER BY timestamp DESC LIMIT 1' % self.process.analysis.dumps_table, (self.process.pdb, self.base))
      dump = self.pg_cursor.fetchone()
      return dump and MemoryDump(self,dump[0])

   def contains(self, address):
       return self.base <= address and address <= self.base + self.size

   def __repr__(self):
       return "<MemoryRegion at 0x%08x, size 0x%08x, tag '%s'>" % (self.base, self.size, self.tag)

   def branches(self):
        self.pg_cursor.execute('SELECT timestamp, source, dest, type FROM %s WHERE process=%%s AND (%%s <= source AND source <= %%s) OR (%%s <= dest AND dest <= %%s)' % self.process.analysis.branches_table, (self.process.pdb,self.base,self.base+self.size,self.base,self.base+self.size))
        return self.pg_cursor.fetchall()

   def branches_outbound(self):
        self.pg_cursor.execute('SELECT timestamp, source, dest, type FROM %s WHERE process=%%s AND (%%s <= source AND source <= %%s) AND NOT (%%s <= dest AND dest <= %%s)' % self.process.analysis.branches_table, (self.process.pdb,self.base,self.base+self.size,self.base,self.base+self.size))
        return self.pg_cursor.fetchall()

   def writes_from(self):
        self.pg_cursor.execute('SELECT timestamp, instruction, dest FROM %s WHERE process=%%s AND (%%s <= instruction AND instruction <= %%s)' % self.process.analysis.writes_table, (self.process.pdb,self.base,self.base+self.size))
        return self.pg_cursor.fetchall()

   def writes_to(self):
       pass


class Process(object):
    def __init__(self, analysis, firstseen):
        self.analysis = analysis
        self.firstseen = firstseen
        self.pg_connection = self.analysis.pg_connection
        self.pg_cursor = self.pg_connection.cursor()
        self.pg_cursor.execute( "SELECT imagename, pid, ppid, pdb FROM %s WHERE firstseen=%%s" % self.analysis.processes_table, (self.firstseen,))
        self.imagename, self.pid, self.ppid, self.pdb = self.pg_cursor.fetchone()

    def memoryregions(self):
        self.pg_cursor.execute( "SELECT base FROM %s WHERE process=%%s" % self.analysis.memoryregions_table, (self.pdb,))
        return[MemoryRegion(self,memoryregion[0]) for memoryregion in  self.pg_cursor.fetchall()]

    def __repr__(self):
        return "<Process '%s'\n    PID: %u\n   PPID: %u\n    PDB: 0x%08x\n>" % (self.imagename, self.pid, self.ppid, self.pdb)

    def branches(self):
        self.pg_cursor.execute('SELECT timestamp, source, dest, type FROM %s WHERE process=%%s' % self.analysis.branches_table, (self.pdb,))
        return self.pg_cursor.fetchall()

    def getMemoryRegionByAddress( self, address):
        for memoryregion in self.memoryregions():
            imagebase = memoryregion.base
            imagesize = memoryregion.size
            # first match wins
            if imagebase <= address and address < imagebase + imagesize:
                return memoryregion

        return None


class Analysis(object):
    def __init__(self, analyses, timestamp):
        self.analyses = analyses
        self.pg_connection = self.analyses.pg_connection
        self.pg_cursor = self.pg_connection.cursor()
        self.timestamp = timestamp
        self.pg_cursor.execute("SELECT samplename FROM analyses WHERE timestamp=%s", (self.timestamp,))
        self.samplename = self.pg_cursor.fetchone()[0]
        self.processes_table = 'analysis_%u_processes' % self.timestamp
        self.branches_table = 'analysis_%u_branches' % self.timestamp
        self.writes_table = 'analysis_%u_writes' % self.timestamp
        self.memoryregions_table = 'analysis_%u_memoryregions' % self.timestamp
        self.dumps_table = 'analysis_%u_dumps' % self.timestamp

    def count_processes(self):
        self.pg_cursor.execute('SELECT COUNT(*) FROM %s' % self.processes_table)
        return self.pg_cursor.fetchone()[0]

    def count_memoryregions(self):
        self.pg_cursor.execute('SELECT COUNT(*) FROM %s' % self.memoryregions_table)
        return self.pg_cursor.fetchone()[0]

    def count_branches(self):
        self.pg_cursor.execute('SELECT COUNT(*) FROM %s' % self.branches_table)
        return self.pg_cursor.fetchone()[0]

    # FIXME just playing around
    def distinct_branch_targets(self):
        self.pg_cursor.execute('SELECT DISTINCT dest FROM %s' % self.branches_table)
        return self.pg_cursor.fetchall()

    def distinct_branch_sources(self):
        self.pg_cursor.execute('SELECT DISTINCT source FROM %s AS branch_sources' % self.branches_table)
        return self.pg_cursor.fetchall()

    def count_distinct_branch_targets(self):
        self.pg_cursor.execute('SELECT COUNT(*) FROM (SELECT DISTINCT dest FROM %s) AS branch_targets' % self.branches_table)
        return self.pg_cursor.fetchone()[0]

    def count_distinct_branch_sources(self):
        self.pg_cursor.execute('SELECT COUNT(*) FROM (SELECT DISTINCT source FROM %s) AS branch_sources' % self.branches_table)
        return self.pg_cursor.fetchone()[0]

    def count_writes(self):
        self.pg_cursor.execute('SELECT COUNT(*) FROM %s' % self.writes_table)
        return self.pg_cursor.fetchone()[0]

    def count_dumps(self):
        self.pg_cursor.execute('SELECT COUNT(*) FROM %s' % self.dumps_table)
        return self.pg_cursor.fetchone()[0]

    def processes(self):
        self.pg_cursor.execute('SELECT firstseen FROM %s' % self.processes_table)
        return [Process(self, firstseen[0]) for firstseen in self.pg_cursor.fetchall()]

    def sample_processes(self):
        self.pg_cursor.execute("SELECT firstseen FROM %s WHERE imagename LIKE '%s'" % (self.processes_table, self.samplename))
        return [Process(self, firstseen[0]) for firstseen in self.pg_cursor.fetchall()]

    def branches(self):
        self.pg_cursor.execute('SELECT timestamp, process, source, dest, type FROM %s' % self.branches_table)
        return self.pg_cursor.fetchall()


    def __repr__(self):
        return "<Analysis from %s:\n   %u processes\n   %u memory regions\n   %u branches\n   %u writes\n   %u dumps\n>" % (self.timestamp, self.count_processes(), self.count_memoryregions(), self.count_branches(), self.count_writes(), self.count_dumps())


class Analyses(object):
    def __init__( self, pg_connection):
        self.pg_connection = pg_connection
        self.pg_cursor = self.pg_connection.cursor()
        self.pg_cursor.execute( "SELECT timestamp, samplename FROM analyses")
        analyses = dict(self.pg_cursor.fetchall())
        self.analyses = {}
        for timestamp in analyses:
            self.analyses[timestamp] = Analysis( self, timestamp)

    def latest( self):
        self.pg_cursor.execute("SELECT timestamp FROM analyses ORDER BY timestamp DESC LIMIT 1")
        timestamp = self.pg_cursor.fetchone()[0]
        return self.analyses[timestamp]

postgres_connection = psycopg2.connect( user = DB_USER, password = DB_PASS, database = DB_DATABASE)
postgres_cursor = postgres_connection.cursor()

analyses = Analyses(postgres_connection)
analysis = analyses.latest()
#analysis = analyses.analyses[analyses.analyses.keys()[-2]]

print analysis.processes()
print analysis.sample_processes()
print analysis.sample_processes()[0].memoryregions()
print analysis.sample_processes()[0].memoryregions()[0].dumps()

reconstructions = []

for timestamp,dump in analysis.sample_processes()[0].memoryregions()[0].dumps().items():
    if not dump.reason() & DUMP_INITIAL:
        foo = ReconstructedPE(dump)
        open('test.out','w').write(foo.backend.buf)


