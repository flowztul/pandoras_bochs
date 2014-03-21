import PyBochsC
from Structures import *
from Helpers import *

def Stack( arguments):
    attributes = [ ( "return_address", "I")]
    attributes.extend( arguments)
    d = { "attributes": attributes}
    t = type( "Stack", (StructuredData,), d)
    return t

def stack_dump():
    ESP = PyBochsC.genreg( PyBochsC.REG_ESP)
    print "ESP: 0x%08x\n" % ESP
    for i in xrange( ESP, ESP+20, 4):
        print "0x%08x" % struct.unpack( "I", PyBochsC.vmem_read( i, 4, PyBochsC.creg( 3)))


def SkipMessageBox( function_invocation):
    print "MessageBox() called, attempting to skip"
    esp = function_invocation.initial_esp
    esp += len( function_invocation.stack)
    M_OK = 4234 # FIXME
    print "a"
    PyBochsC.set_eip( function_invocation.stack.return_address)
    print "b"
    PyBochsC.set_genreg( PyBochsC.REG_ESP, esp)
    print "c"
    PyBochsC.set_genreg( PyBochsC.REG_EAX, IDOK)
    print "d"

def GetProcAddressCall( function_invocation):

    # don't track GetProcAddress from within DLLs
    vad = function_invocation.function_call_watchpoint.process.vad_tree.by_address( \
              function_invocation.stack.return_address)
    try:
        name = vad.ControlArea.deref().FilePointer.deref().FileName.str()
    except:
        name = ""
 
    # image = function_invocation.function_call_watchpoint.process.get_image_by_address( function_invocation.stack.return_address)
    if name.lower().endswith( '.dll'):
        function_invocation.irrelevant = True
        return
    else:
        function_invocation.irrelevant = False

    lpProcName = function_invocation.stack.lpProcName
    if lpProcName.pointer & 0xffff0000 == 0:
        # high-order word is 0: import by ordinal
        function_invocation.proc_name = None
        function_invocation.ordinal = lpProcName.pointer
        function_invocation.pointer = None

    else:
        name = str( lpProcName.deref()) # need to copy it now!
        function_invocation.proc_name = name
        function_invocation.ordinal = None
        function_invocation.pointer = lpProcName.pointer
    function_invocation.return_address = function_invocation.stack.return_address
    function_invocation.module = function_invocation.stack.hModule

def GetProcAddressReturn( function_return):
        if function_return.function_invocation.irrelevant:
            return
        proc_name = function_return.function_invocation.proc_name
        ordinal = function_return.function_invocation.ordinal
        pointer = function_return.function_invocation.pointer
        module = function_return.function_invocation.module
        return_address = function_return.function_invocation.return_address
        eax = function_return.eax
        if ordinal:
            print "GetProcAddress( 0x%08x, 0x%04x): 0x%08x" % ( module, ordinal, eax)
        else:
            print "GetProcAddress( 0x%08x, (0x%08x:'%s')): 0x%08x" % ( module, pointer, proc_name, eax)

        process = function_return.function_invocation.function_call_watchpoint.process
        new_watchpoint = ResolvedFunctionWatchpoint( process, eax, proc_name, return_address)
        process.watchpoints.add_function_call_watchpoint( new_watchpoint)

        # identify each call to GetProcAddress by its return address
        # keep track of how many times each call to GetProcAddress is invoked
        # useful to get a better metric to indicate end of unpacking
        #   as a ratio: number of resolved functions called / number of invocations of GetProcAddress
        #   to indicate GetProcAddress loops, for IAT resolving (look for write clusters within the loop)
        #               careful: IAT might be generated and later memcopied
        if not hasattr( process, "GetProcAddress_locations"):
            process.GetProcAddress_locations = {}
        if return_address not in process.GetProcAddress_locations:
            process.GetProcAddress_locations[ return_address] = 0
        process.GetProcAddress_locations[ return_address] += 1


class FunctionInvocation( object):

    def __init__( self, function_call_watchpoint):
        self.function_call_watchpoint = function_call_watchpoint
        self.initial_esp = PyBochsC.genreg( PyBochsC.REG_ESP)
        process = self.function_call_watchpoint.process
        self.stack = Stack( self.function_call_watchpoint.function_definition)( process.backend, self.initial_esp)
        self.function_return_watchpoint = FunctionReturnWatchpoint( self)
        # FIXME not thread safe!
        # FIXME also: how to deal with returns, if the return address is overwritten (should be unlikely in library functions?)
        # FIXME what about exception handling?
        if self.function_call_watchpoint.create_return_watchpoint:
            self.function_call_watchpoint.process.watchpoints.add_function_return_watchpoint( self.function_return_watchpoint)

        if self.function_call_watchpoint.on_call == None:
            print "%s() called, arguments are:" % self.function_call_watchpoint.function_name
            print "%25s" % self.stack # FIXME GetProcAddress can accept an ordinal instead of a LPCSTR in lpname
        else:
            self.function_call_watchpoint.on_call( self)

class ResolvedFunctionWatchpoint( object):
    def __init__( self, process, function_address, function_name, return_address):
        self.process = process
        self.function_address = function_address
        self.function_name = function_name
        self.return_address = return_address # return address of the initial call to GetProcAddress
        self.create_return_watchpoint = False
        self.function_definition = ( [ ], "I")
        self.on_return = False
        self.on_call = False

    def visit( self):
        ESP = PyBochsC.genreg( PyBochsC.REG_ESP)
        stack = Stack( self.function_definition[ 0])( self.process.backend, ESP)
        image = self.process.get_image_by_address( stack.return_address)
        if None == image or not image.BaseDllName.lower().endswith( '.dll'):
            if not hasattr( self.process, "resolved_functions_called"):
                self.process.resolved_functions_called = {}
            if self.return_address not in self.process.resolved_functions_called:
                self.process.resolved_functions_called[ self.return_address] = {}
            if self.function_name not in self.process.resolved_functions_called[self.return_address]:
                self.process.innovate()
                self.process.resolved_functions_called[self.return_address][ self.function_name] = 0
                print "%50s called %4u times, %03u/%03u functions resolved at 0x%08x called, ratio %f" % ( self.function_name, self.process.resolved_functions_called[self.return_address][ self.function_name],  len( self.process.resolved_functions_called[self.return_address]), self.process.GetProcAddress_locations[ self.return_address], self.return_address, float(len( self.process.resolved_functions_called[self.return_address])/float(self.process.GetProcAddress_locations[ self.return_address])))
            self.process.resolved_functions_called[self.return_address][ self.function_name] += 1
        return False
    #FIXME
    # only accumulate function calls from the image
    # alternatively, only from modified memory
    # for that, parse stack for return address


class FunctionCallWatchpoint( object):
    def __init__( self, process, function_address):
        self.process = process
        self.function_address = function_address
        self.function_name = self.process.symbols[ function_address][2]
        self.on_call, self.on_return, self.create_return_watchpoint = WatchpointDefinitions[ self.function_name]
        self.function_definition = FunctionDefinitions[ self.function_name][ 0]

    def visit( self):
        invocation = FunctionInvocation( self)

        # returns whether this watchpoint can be deleted
        return False


class FunctionReturnWatchpoint( object):
    def __init__( self, function_invocation):
        self.function_invocation = function_invocation

    def visit( self):
        self.eax = PyBochsC.genreg( PyBochsC.REG_EAX)
        self.esp = PyBochsC.genreg( PyBochsC.REG_ESP)
        self.raw = struct.pack( "I", self.eax)
        if self.function_invocation.function_call_watchpoint.on_return == None:
            print "%s() returned 0x%08x, current esp is 0x%08x, esp on function invocation was 0x%08x, 0x%02x" % ( self.function_invocation.function_call_watchpoint.function_name, self.eax, self.esp, self.function_invocation.initial_esp, len( self.function_invocation.stack))
        else:
            self.function_invocation.function_call_watchpoint.on_return( self)

        # FIXME would need to instantiate a string-backend here, to correctly deal with arbitrary return types :/
        # return_type = FunctionDefinitions[ self.function_invocation.function_call_watchpoint.function_name][ 1]

        # returns whether this watchpoint can be deleted, this should be ok for function returns
        return True

class EntryPointWatchpoint( FunctionCallWatchpoint):
    def __init__( self, process, entrypoint_address):
        self.process = process
        self.function_address = entrypoint_address
        self.function_name = "EntryPoint"
        # self.function_definition = FunctionDefinitions[ self.function_name][ 0]

    def visit( self):
        print "Visited the entrypoint"

        # Entrypoint normally does not get any arguments
        # it in turn calls main(), WinMain() or DllMain() with the correct args

        #initial_esp = PyBochsC.genreg( PyBochsC.REG_ESP)
        #self.stack = Stack( self.function_definition)( self.process.backend, initial_esp)
        #print "%s" % self.stack

        print PyBochsC.registers()
        self.process.vad_tree.dump()
        print "InMemoryOrderModuleList"
        print "-----------------------"
        LdrData = self.process.eprocess.Peb.deref().Ldr.deref()
        image = LdrData.InMemoryOrderModuleList.next()
        while None != image:
            print "0x%08x +0x%08x: %s" % (image.DllBase, image.SizeOfImage, image.FullDllName)

            image = LdrData.InMemoryOrderModuleList.next()
        print "-----------------------"

#        self.process.dump_images( "EntryPoint")
        return False

class Watchpoints( object):

    def __init__( self, process):
        self.process = process
        self.function_call_watchpoints = {}
        self.function_return_watchpoints = {}

    def add_function_call_watchpoint( self, function_call_watchpoint):
        page = function_call_watchpoint.function_address / PAGESIZE
        if page not in self.function_call_watchpoints:
            self.function_call_watchpoints[ page] = {}
        # FIXME Uniqueness not guaranteed
        if function_call_watchpoint.function_address not in self.function_call_watchpoints[ page]:
            self.function_call_watchpoints[ page][ function_call_watchpoint.function_address] = []
        self.function_call_watchpoints[ page][ function_call_watchpoint.function_address].append( function_call_watchpoint)

    def add_function_return_watchpoint( self, function_return_watchpoint):
        return_address = function_return_watchpoint.function_invocation.stack.return_address
        page = return_address / PAGESIZE
        if page not in self.function_return_watchpoints:
            self.function_return_watchpoints[ page] = {}
        if return_address not in self.function_return_watchpoints[ page]:
            self.function_return_watchpoints[ page][ return_address] = []
        # FIXME Uniqueness not guaranteed
        self.function_return_watchpoints[ page][ return_address].append( function_return_watchpoint)


    def visit_location( self, address):
        page = address / PAGESIZE
        if page not in self.function_call_watchpoints:
            pass
        elif address in self.function_call_watchpoints[ page]:
            for watchpoint in self.function_call_watchpoints[ page][address]:
                watchpoint.visit()
        if page not in self.function_return_watchpoints:
            pass
        elif address in self.function_return_watchpoints[ page]:
            for watchpoint in self.function_return_watchpoints[ page][address]:
                watchpoint.visit()
            self.function_return_watchpoints[ page][ address] = []


def print_args( function_name, process):
    ESP = PyBochsC.genreg( PyBochsC.REG_ESP)
    stack = Stack( FunctionDefinitions[ function_name][0])( process.backend, ESP)
    print "%s(" % function_name,
    for arg_def in FunctionDefinitions[ name][ 0]:
        arg = getattr( stack, arg_def[ 0])
        if hasattr( arg, "deref"):
            print arg.deref(),
        else:
            print arg,
    print ")"

FunctionDefinitions = {
    "LoadLibraryA": (
        [
            ( "lpFileName", P(STR)),
        ],
        "I"
    ),

    "LoadLibraryW": (
        [ 
            ( "lpFileName", P(WSTR)),
        ],
        "I"
    ),

    "GetProcAddress": (
        [
            ( "hModule", "I"),
            ( "lpProcName", P(STR)), 
        # FIXME can also be by ordinal, then the pointer's low-order half-word
        # is used, and the high-order half-word must be zero!
        ],
        "I"
    ),
    "VirtualAllocEx": (
        [
            ( "hProcess", "I"),
            ( "lpAddress", "I"),
            ( "dwSize", "I"),
            ( "flAllocationType", "I"),
            ( "flProtect", "I")
        ],
        "I"
    ),
    "OpenProcess": (
        [
            ( "dwDesiredAccess", "I"),
            ( "bInheritHandle", "I"), # BOOL
            ( "dwProcessId", "I")
        ],
        "I"
    ),
    "ExitProcess": (
        [
            ( "uExitCode", "I"),
        ],
        "I" # VOID
    ),
    "CreateProcessA": (
        [
            ( "lpApplicationName", P(STR)),
            ( "lpCommandLine", P(STR, True)),
            ( "lpProcessAttributes", "I"), # LPSECURITY_ATTRIBUTES
            ( "lpThreadAttributes", "I"),  # LPSECURITY_ATTRIBUTES
            ( "bInheritHandle", "I"),      # BOOL
            ( "dwCreationFlags", "I"),
            ( "lpEnvironment", "I"),       # LPVOID
            ( "lpCurrentDirectory", P(STR, True)),
            ( "lpStartupInfo", "I"),       # LPSTARTUPINFO
            ( "lpProcessInformation", "I") # LPPROCESS_INFORMATION (output parameter)
        ],
        "I" # BOOL
    ),
    "CreateProcessW": (
        [
            ( "lpApplicationName", P(WSTR)),
            ( "lpCommandLine", P(WSTR, True)),
            ( "lpProcessAttributes", "I"), # LPSECURITY_ATTRIBUTES
            ( "lpThreadAttributes", "I"),  # LPSECURITY_ATTRIBUTES
            ( "bInheritHandle", "I"),      # BOOL
            ( "dwCreationFlags", "I"),
            ( "lpEnvironment", "I"),       # LPVOID
            ( "lpCurrentDirectory", P(WSTR, True)),
            ( "lpStartupInfo", "I"),       # LPSTARTUPINFO
            ( "lpProcessInformation", "I") # LPPROCESS_INFORMATION (output parameter)
        ],
        "I" # BOOL
    ),
    "CreateFileA": (
        [
            ( "lpFileName", P(STR)),
            ( "dwDesiredAccess", "I"),
            ( "dwSharedMode", "I"),
            ( "lpSecurityAttributes", "I"), # LPSECURITY_ATTRIBUTES
            ( "dwCreationDisposition", "I"),
            ( "dwFlagsAndAttributes", "I"),
            ( "hTemplateFile", "I"),        # HANDLE
        ],
        "I"                                 # HANDLE
    ),
    "CreateFileW": (
        [
            ( "lpFileName", P(WSTR)),
            ( "dwDesiredAccess", "I"),
            ( "dwSharedMode", "I"),
            ( "lpSecurityAttributes", "I"), # LPSECURITY_ATTRIBUTES
            ( "dwCreationDisposition", "I"),
            ( "dwFlagsAndAttributes", "I"),
            ( "hTemplateFile", "I"),        # HANDLE
        ],
        "I"                                 # HANDLE
    ),
    "CreateServiceA": ( # FIXME what can be NULL, what is not really a string, etc etc
        [
            ( "hSCManager", "I"), # SC_HANDLE
            ( "lpServiceName", P(STR) ),
            ( "lpDisplayName", P(STR) ),
            ( "dwDesiredAccess", "I"),
            ( "dwServiceType", "I"),
            ( "dwStartType", "I"),
            ( "dwErrorControl", "I"),
            ( "lpBinaryPathName", P(STR) ),
            ( "lpLoadOrderGroup", P(STR) ),
            ( "lpdwTagId", "I"), # LPDWORD
            ( "lpDependencies", P(STR) ),
            ( "lpServiceStartName", P(STR) ),
            ( "lpPassword", P(STR) ),
        ],
        "I" # SC_HANDLE
    ),
    "CreateServiceW": (
        [
            ( "hSCManager", "I"), # SC_HANDLE
            ( "lpServiceName", P(WSTR) ),
            ( "lpDisplayName", P(WSTR) ),
            ( "dwDesiredAccess", "I"),
            ( "dwServiceType", "I"),
            ( "dwStartType", "I"),
            ( "dwErrorControl", "I"),
            ( "lpBinaryPathName", P(WSTR) ),
            ( "lpLoadOrderGroup", P(WSTR) ), 
            ( "lpdwTagId", "I"), # LPDWORD
            ( "lpDependencies", P(WSTR) ),
            ( "lpServiceStartName", P(WSTR) ),
            ( "lpPassword", P(WSTR) ),
        ],
        "I" # SC_HANDLE
    ),
    "StartServiceA": (
        [
            ( "hService", "I"), #SC_HANDLE
            ( "dwNumServiceArgs", "I"),
            ( "lpServiceArgVectors", "I") # LPCTSTR* (vector of string pointers
        ],
        "I" # BOOL
    ),
    "StartServiceW": (
        [
            ( "hService", "I"), #SC_HANDLE
            ( "dwNumServiceArgs", "I"),
            ( "lpServiceArgVectors", "I") # LPCTSTR* (vector of string pointers
        ],
        "I" # BOOL
    ),
    "MessageBoxA": (
        [
            ( "hWnd", "I"), # HWND
            ( "lpText", P(STR)),
            ( "lpCaption", P(STR, True)), # may be NULL
            ( "uType", "I")
        ],
        "I"
    ),
    "MessageBoxW": (
        [
            ( "hWnd", "I"), # HWND
            ( "lpText", P(WSTR)),
            ( "lpCaption", P(WSTR, True)), # may be NULL
            ( "uType", "I")
        ],
        "I"
    ),
    "MapViewOfFileEx": (
        [
            ( "hFileMappingObject", "I"), # HANDLE
            ( "dwDesiredAccess", "I"),
            ( "dwFileOffsetHigh", "I"),
            ( "dwFileOffsetLow", "I"),
            ( "dwNumberOfBytesToMap", "I"), # SIZE_T
            ( "lpBaseAddress", "I") # LPVOID
        ],
        "I" # LPVOID
    ),
    "CreateFileMappingA": (
        [
            ( "hFile", "I"), # HANDLE
            ( "lpAttributes", "I"), # LPSECURITY_ATTRIBUTES
            ( "flProtect", "I"),
            ( "dwMaximumSizeHigh", "I"),
            ( "dwMaximumSizeLow", "I"),
            ( "lpName", P(STR, True)) # May be NULL
        ],
        "I" # HANDLE
    ),
    "CreateFileMappingW": (
        [
            ( "hFile", "I"), # HANDLE
            ( "lpAttributes", "I"), # LPSECURITY_ATTRIBUTES
            ( "flProtect", "I"),
            ( "dwMaximumSizeHigh", "I"),
            ( "dwMaximumSizeLow", "I"),
            ( "lpName", P(WSTR, True)) # May be NULL
        ],
        "I" # HANDLE
    ),
    "OpenFileMappingA": (
        [
            ( "dwDesiredAccess", "I"),
            ( "bInheritHandle", "I"), # BOOL
            ( "lpName", P(STR)) # Should not be NULL?
        ],
        "I" # HANDLE
    ),
    "OpenFileMappingW": (
        [
            ( "dwDesiredAccess", "I"),
            ( "bInheritHandle", "I"), # BOOL
            ( "lpName", P(STR)) # Should not be NULL?
        ],
        "I" # HANDLE
    ),
    "GetProcAddress": (
        [
            ( "hModule", "I"),        # HMODULE
            ( "lpProcName", P(STR))   # Might be an ordinal!
        ],
        "I" # FAPPROC
    ),
    "WinMain": (
        [
            ( "hInstance", "I"),        # HINSTANCE
            ( "hPrevInstance", "I"),    # HINSTANCE
            ( "lpCmdLine", P(STR)),     # Command Line, excluding the program name
            ( "nCmdShow", "i")          # M
        ],
        "I"
    ),
}

WatchpointDefinitions = {
#    "VirtualAllocEx": ( None, None, True),
#    "OpenProcess":( None, None, True),
#    "CreateProcessA":( None, None, True),
#    "CreateProcessW":( None, None, True),
#    "WinExec":( None, None, True),
#    "CreateFileA":( None, None, True),
#    "CreateFileW":( None, None, True),
#    "CreateServiceA":( None, None, True),
#    "CreateServiceW":( None, None, True),
#    "StartServiceA":( None, None, True),
#    "StartServiceW":( None, None, True),
#    "MessageBoxA":( SkipMessageBox, None, False),
#    "MessageBoxW":( SkipMessageBox, None, False),
    "MessageBoxA":( None, None, False),
    "MessageBoxW":( None, None, False),
#    "MapViewOfFileEx":( None, None, True),
#    "CreateFileMappingA":( None, None, True),
#    "CreateFileMappingW":( None, None, True),
#    "OpenFileMappingA":( None, None, True),
#    "OpenFileMappingW":( None, None, True),
#    "OpenFileA":( None, None, True),
#    "OpenFileW":( None, None, True),
    "GetProcAddress": ( GetProcAddressCall, GetProcAddressReturn, True),
    }

