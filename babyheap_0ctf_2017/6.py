from pwn import *

context.log_level="debug"
#io=process("./a.out")

io=gdb.debug("./a.out")
#gdb.attach(io)
#pause()
io.interactive()

