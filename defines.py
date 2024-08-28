from ctypes import *
from ctypes import wintypes

DWORD = wintypes.DWORD
LPWSTR = wintypes.LPWSTR
LPCSTR = wintypes.LPCSTR
WORD = wintypes.WORD
LPBYTE = wintypes.LPBYTE
HANDLE = wintypes.HANDLE
PVOID = wintypes.LPVOID
ULONG_PTR = wintypes.ULONG
LONG = wintypes.LONG
DWORD64 = wintypes.ULARGE_INTEGER
UBYTE = c_ubyte

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010

STARTF_USESHOWWINDOW = 0x00000001
SW_SHOWNORMAL = 1

PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
EXCEPTION_NOT_HANLDED = 0x80010001

TH32CS_SNAPTHREAD = 0x00000004
THREAD_ALL_ACCESS   = 0x001F03FF

CONTEXT_AMD_64 = 0x100000
CONTEXT_CONTROL = CONTEXT_AMD_64 | 0x01
CONTEXT_INTEGER = CONTEXT_AMD_64 | 0x02
CONTEXT_SEGMENTS = CONTEXT_AMD_64 | 0x04
CONTEXT_FLOATING_POINT = CONTEXT_AMD_64 | 0x08
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD_64 | 0x10

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_FLOATING_POINT | CONTEXT_INTEGER)


EXCEPTION_DEBUG_EVENT = 1

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_SINGLE_STEP = 0x80000004

class STARTUPINFOW(Structure):
    _fields_=[
        ("dw",DWORD),
        ("lpReserved",LPWSTR),
        ("lpDesktop",LPWSTR),
        ("lpTitle",LPWSTR),
        ("dwX",DWORD),
        ("dwY",DWORD),
        ("dwXSize",DWORD),
        ("dwYSize",DWORD),
        ("dwXCountChars",DWORD),
        ("dwYCountChars",DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",DWORD),
        ("wShowWindow",WORD),
        ("cbReserved2",WORD),
        ("lpReserved2",LPBYTE),
        ("hStdInput",HANDLE),
        ("hStdOutput",HANDLE),
        ("hStdError",HANDLE)
    ]

class PROCESSINFORMATION(Structure):
    _fields_=[
        ("hProcess",HANDLE),
        ("hThread",HANDLE),
        ("dwProcessId",DWORD),
        ("dwThreadId",DWORD)
    ]

class EXCEPTION_RECORD(Structure):
    pass

EXCEPTION_RECORD._fields_=[
    ("ExceptionCode",DWORD),
    ("ExceptionFlags",DWORD),
    ("ExceptionRecord",POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",PVOID),
    ("NumberParameters",DWORD),
    ("ExceptionInformation",ULONG_PTR * 15)
]

class EXCEPTION_DEBUG_INFO(Structure):
    _fields_=[
        ("ExceptionRecord",EXCEPTION_RECORD),
        ("dwFirstChance",DWORD)
    ]

class DEBUG_EVENT_UNION(Union):
    _fields_=[
        ("Exception",EXCEPTION_DEBUG_INFO)
        #this struct has other fields but this is the one
        #we are interested in
    ]

class DEBUG_EVENT(Structure):
    _fields_=[
        ("dwDebugEventCode",DWORD),
        ("dwProcessId",DWORD),
        ("dwThreadId",DWORD),
        ("u",DEBUG_EVENT_UNION)
    ]


class THREADENTRY32(Structure):
    _fields_=[
        ("dwSize",DWORD),
        ("cntUsage",DWORD),
        ("th32ThreadId",DWORD),
        ("th32OwnerProcessId",DWORD),
        ("tpBasePri",LONG),
        ("tpDeltaPri",LONG),
        ("dwFlags",DWORD)
    ]


class M128A(Structure):
    _fields_=[
        ("low",DWORD64),
        ("high",DWORD64)
    ]


class NEON128(Structure):
    _fields_=[
        ("low",DWORD64),
        ("high",DWORD64)
    ]

class XMM_SAVE_AREA32(Structure):
    _fields_=[
        ("ControlWord",WORD),
        ("StatusWord",WORD),
        ("TagWord",UBYTE),
        ("Reserved1",UBYTE),
        ("ErrorOpcode",WORD),
        ("ErrorOffset",DWORD),
        ("ErrorSelector",WORD),
        ("Reserved2",WORD),
        ("DataOffset",DWORD),
        ("DataSelector",WORD),
        ("Reserved3",WORD),
        ("MxCsr",DWORD),
        ("MxCsr_Mask",DWORD),
        ("FloatRegisters",M128A * 8),
        ("XmmRegisters",M128A * 16),
        ("Reserved4",UBYTE * 96)
    ]


class DUMMYSTRUCTNAME(Structure):
    _fields_=[
        ("Header",M128A * 2),
        ("Legacy",M128A * 8),
        ("Xmm0",M128A),
        ("Xmm1",M128A),
        ("Xmm2",M128A),
        ("Xmm3",M128A),
        ("Xmm4",M128A),
        ("Xmm5",M128A),
        ("Xmm6",M128A),
        ("Xmm7",M128A),
        ("Xmm8",M128A),
        ("Xmm9",M128A),
        ("Xmm10",M128A),
        ("Xmm11",M128A),
        ("Xmm12",M128A),
        ("Xmm13",M128A),
        ("Xmm14",M128A),
        ("Xmm15",M128A),
    ]


class DUMMYUNIONNAME(Union):
    _fields_=[
        ("FltSave",XMM_SAVE_AREA32),
        ("Q",NEON128 * 16),
        ("D",DWORD64 * 32),
        ("DUMMYSTRUCTNAME",DUMMYSTRUCTNAME),
        ("S",DWORD * 32)
    ]


class CONTEXT(Structure):
    _fields_=[
        ("P1Home",DWORD64),
        ("P2Home",DWORD64),
        ("P3Home",DWORD64),
        ("P4Home",DWORD64),
        ("P5Home",DWORD64),
        ("P6Home",DWORD64),
        ("ContextFlags",DWORD),
        ("MxCsr",DWORD),
        ("SegCs",WORD),
        ("SegDs",WORD),
        ("SegEs",WORD),
        ("SegFs",WORD),
        ("SegGs",WORD),
        ("SegSs",WORD),
        ("EFlags",DWORD),
        ("Dr0",DWORD64),
        ("Dr1",DWORD64),
        ("Dr2",DWORD64),
        ("Dr3",DWORD64),
        ("Dr6",DWORD64),
        ("Dr7",DWORD64),
        ("Rax",DWORD64),
        ("Rcx",DWORD64),
        ("Rdx",DWORD64),
        ("Rbx",DWORD64),
        ("Rsp",DWORD64),
        ("Rbp",DWORD64),
        ("Rsi",DWORD64),
        ("Rdi",DWORD64),
        ("R8",DWORD64),
        ("R9",DWORD64),
        ("R10",DWORD64),
        ("R11",DWORD64),
        ("R12",DWORD64),
        ("R13",DWORD64),
        ("R14",DWORD64),
        ("R15",DWORD64),
        ("Rip",DWORD64),
        ("DUMMYUNIONNAME",DUMMYUNIONNAME),
        ("VectorRegister",M128A * 26),
        ("VectorControl",DWORD64),
        ("DebugControl",DWORD64),
        ("LastBranchToRip",DWORD64),
        ("LastBranchFromRip",DWORD64),
        ("LastExceptionToRip",DWORD64),
        ("LastExceptionFromRip",DWORD64),
    ]