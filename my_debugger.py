from ctypes import *
from defines import *

kernel32 = windll.kernel32

class debugger():

    def __init__(self):
        self.process_handle = None
        self.thread_handle = None
        self.debugger_active = False
        self.exception_address = None
        self.breakpoints = {}
        self.pid = None
        self.context = None

    #creates a new process for debugging
    def load(self,path_to_exe):

        creation_flags = DEBUG_PROCESS

        startup_info = STARTUPINFOW()
        startup_info.cb = sizeof(startup_info)

        process_info = PROCESSINFORMATION()

        if kernel32.CreateProcessW(
            path_to_exe,
            None,
            None,
            None,
            None,
            creation_flags,
            None,
            None,
            byref(startup_info),
            byref(process_info)
        ):
            print("[*] Process created succesfully")
            print("[*] Process ID is ",process_info.dwProcessId)

            self.process_handle = self.open_process(process_info.dwProcessId)

        else:
            print("[*] Process not created.Error ",kernel32.GetLastError())

    
    #return a process handle
    def open_process(self,pid):

        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)

        if process_handle is not None:
            return process_handle
        else:
            print("Could not obtain valid process handle.Error :",kernel32.GetLastError())


    #attaches to an existing process for debugging
    def attach(self,pid):

        self.process_handle = self.open_process(pid)

        if kernel32.DebugActiveProcess(pid):
            print("[*] Successfully attached to the running process")
            self.pid = pid
            self.debugger_active = True
            
        else:
            print("[*] Could not attach to process.Error ",kernel32.GetLastError())


    def run(self):
        while self.debugger_active:
            self.get_debug_event()


    def get_debug_event(self):

        continue_status = DBG_CONTINUE

        debug_event = DEBUG_EVENT()

        if kernel32.WaitForDebugEvent(byref(debug_event),INFINITE):

            self.thread_handle = self.open_thread_handle(debug_event.dwThreadId)
            self.context = self.get_thread_context(thread_handle=self.thread_handle)

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:

                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                exception_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode

                if exception_code == EXCEPTION_BREAKPOINT:
                    print("Hit a breakpoint at address %#x" % self.exception_address)
                    continue_status = self.handle_breakpoint_exception()

            kernel32.ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,continue_status)
            

    def handle_breakpoint_exception(self):

        if not self.exception_address in self.breakpoints.keys():
            print("[*] this is a windows defined breakpoint")
            print()

        else:
            print("[*] this is user defined breakpoint")
            original_byte = self.breakpoints[self.exception_address]

            self.write_process_memory(self.exception_address,original_byte)

            print("Register state")
            print("Rax %#x " % self.context.Rax)
            print("Rbx %#x " % self.context.Rbx)
            print("Rcx %#x " % self.context.Rcx)
            print("Rdx %#x " % self.context.Rdx)
            print("Rsi %#x " % self.context.Rsi)
            print("Rdi %#x " % self.context.Rdi)
            print("Rsp %#x " % self.context.Rsp)
            print("Rbp %#x " % self.context.Rbp)
            print()

            self.context = self.get_thread_context(thread_handle=self.thread_handle)
            self.context.Rip -= 1
            kernel32.SetThreadContext(self.thread_handle,byref(self.context))


        return DBG_CONTINUE
    
    
    def detach(self):

        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Successfully detached from the active process")
        else:
            print("[*] Could not detach from active process.Error : ",kernel32.GetLastError())


    def enumerate_threads(self):

        thread_ids = []

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,self.pid)

        if snapshot is not None:

            thread_entry = THREADENTRY32()
            thread_entry.dwSize = sizeof(thread_entry)

            success = kernel32.Thread32First(snapshot,byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessId == self.pid:
                    thread_ids.append(thread_entry.th32ThreadId)

                success = kernel32.Thread32Next(snapshot,byref(thread_entry))

            kernel32.CloseHandle(snapshot)
            return thread_ids

        else:
            print("Could not obtain thread snapshot.Error :",kernel32.GetLastError())
            return None
        

    def open_thread_handle(self,tid):

        thread_handle = kernel32.OpenThread(THREAD_ALL_ACCESS,False,tid)

        if thread_handle is not None:
            return thread_handle
        else:
            print("[*] Could not obtain a valid thread handle.Error : ",kernel32.GetLastError())


    def get_thread_context(self,tid=None,thread_handle=None):

        if thread_handle is None:
            thread_handle = self.open_thread_handle(tid)

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if kernel32.GetThreadContext(thread_handle,byref(context)):
            return context
        else:
            print("[*] Could not obtain the thread context.Error : ",kernel32.GetLastError())
            return None


    def get_func_address(self,file,func_name):

        kernel32.GetModuleHandleW.argtypes = [LPWSTR]
        kernel32.GetModuleHandleW.restype = HANDLE
        module_handle = kernel32.GetModuleHandleW(file)

        if module_handle is None:
            print("[*] Could not obtain module handle.Error : ",kernel32.GetLastError())
            return None
        
        kernel32.GetProcAddress.argtypes = [HANDLE,LPCSTR]
        kernel32.GetProcAddress.restype = PVOID
        func_address = kernel32.GetProcAddress(module_handle,func_name)

        kernel32.CloseHandle.argtypes = [HANDLE]
        kernel32.CloseHandle(module_handle)

        return func_address
    

    def read_process_memory(self,address,num_bytes):
        
        data = create_string_buffer(num_bytes)
        bytes_read = c_ulong(0)

        kernel32.ReadProcessMemory.argtypes = [HANDLE,PVOID,c_char_p,c_uint,POINTER(c_ulong)]

        if kernel32.ReadProcessMemory(self.process_handle,address,data,num_bytes,byref(bytes_read)):
            return data.value
        else:
            return None

    def write_process_memory(self,address,data):

        bytes_written = c_ulong(0)
        p_data = c_char_p(data)

        kernel32.WriteProcessMemory.argtypes = [HANDLE,PVOID,c_char_p,c_uint,POINTER(c_ulong)]

        if kernel32.WriteProcessMemory(self.process_handle,address,p_data,len(data),byref(bytes_written)):
            return True
        else:
            return False

    def set_break_point(self,address):
        print("Setting a breakpoint at address %#x " % address)
        print()
        try:
            original_byte = self.read_process_memory(address,1)

            self.write_process_memory(address,b'\xCC')
            self.breakpoints[address] = original_byte

        except:
            print("Error reading/writing process : ",kernel32.GetLastError())
