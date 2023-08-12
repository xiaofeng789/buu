from pwn import *
#context(os='linux', arch='amd64', kernel='amd64')
context.log_level="debug"
#context.terminal=["tmux","splitw","-h"]
#io=gdb.debug("./pwn10")
libc=ELF("/home/yun/2.23/libc-2.23.so")
io=process("./pwn10")
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
#gdb.attach(io)

def Allocate(size):
    ru(b"Command:")
    sl(b"1")
    ru(b"Size:")
    sl(str(size))

def Fill(idx,content):
    ru(b"Command:")
    sl(b"2")
    ru(b"Index:")
    sl(str(idx))
    ru(b"Size:")
    sl(str(len(content)))
    ru(b"Content: ")
    sl(content)
def Free(idx):
    ru(b"Command:")
    sl(b"3")
    ru(b"Index:")
    sl(str(idx))

def Dump(idx):
    ru(b"Command:")
    sl(b"4")
    ru(b"Index:")
    sl(str(idx))
    
Allocate(0x60)  #0


Allocate(0x60) #1
Allocate(0x60) #2
Allocate(0x60) #3
Allocate(0x60) #4
print('looc==============================')
gdb.attach(io)
pause()

Free(4)
print('free4==================================')
gdb.attach(io)
pause()
Free(3)
print('free3==================================')
gdb.attach(io)
pause()
Free(2)
print('free2==================================')
gdb.attach(io)
pause()
Allocate(0x60)
print('looc==============================')
gdb.attach(io)
pause()
Allocate(0x60)
print('looc==============================')
gdb.attach(io)
pause()
io.interactive()


