import my_debugger

debugger = my_debugger.debugger()

#Run printf_loop.py on a separate terminal and enter of the process id of the running process
pid = int(input("Enter pid to be debugged : "))

debugger.attach(pid)

printf_address = debugger.get_func_address("msvcrt.dll",b"printf")

print()

#setting a breakpoint when printf is called
print("Setting breakpoint at printf call")
debugger.set_break_point(printf_address)

debugger.run()

debugger.detach()